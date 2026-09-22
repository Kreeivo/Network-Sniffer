"""
DMX / Art-Net Network Inspector
================================
A passive monitoring dashboard for lighting networks.

What it does
------------
* Broadcasts ArtPoll and listens for ArtPollReply -> discovers every
  Art-Net device on the network with its real configured name, IP, MAC,
  device style (node / controller / media server...) and patched universes.
* Passively watches ArtDmx traffic on UDP 6454 -> live per-source and
  per-universe frame rates, bandwidth and active channel counts.
* Best-effort general LAN scan (ping sweep + ARP table + reverse DNS) ->
  surfaces non-Art-Net gear such as managed switches or show-control PCs.
* Serves a live dashboard over HTTP + WebSocket (default port 8058).

Design notes
------------
* Binds UDP 6454 with SO_REUSEADDR/SO_REUSEPORT so it can run alongside a
  console/visualiser on the same machine without stealing the port.
* Needs NO admin rights, NO raw sockets, NO packet-capture drivers:
  Art-Net is broadcast UDP, so a normal socket sees everything.
* A plain unmanaged switch has no IP address, so no software can list it
  directly - it is invisible at layer 3. Managed switches (with a
  management IP) do appear in the LAN scan.

Run:  python app.py            (dashboard on http://localhost:8058)
      python app.py --help     (options)
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import platform
import re
import socket
import struct
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Deque, Dict, List, Optional, Tuple

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

try:
    import psutil
    HAVE_PSUTIL = True
except ImportError:
    HAVE_PSUTIL = False

# --------------------------------------------------------------------------- #
#  Art-Net protocol (Artistic Licence, public spec) - listen-only subset
# --------------------------------------------------------------------------- #

ARTNET_PORT = 6454
ARTNET_ID = b"Art-Net\x00"

OP_POLL, OP_POLL_REPLY, OP_DMX, OP_SYNC = 0x2000, 0x2100, 0x5000, 0x5200
OPCODE_NAMES = {
    0x2000: "ArtPoll", 0x2100: "ArtPollReply", 0x5000: "ArtDmx",
    0x5200: "ArtSync", 0x6000: "ArtAddress", 0x8000: "ArtTodRequest",
    0x8100: "ArtTodData", 0x8200: "ArtTodControl", 0x8300: "ArtRdm",
    0xF800: "ArtIpProg", 0xF900: "ArtIpProgReply",
}
STYLE_NAMES = {
    0x00: "Node", 0x01: "Controller", 0x02: "Media Server", 0x03: "Router",
    0x04: "Backup Device", 0x05: "Configuration", 0x06: "Visualiser",
}


def _cstr(raw: bytes) -> str:
    return raw.split(b"\x00", 1)[0].decode("latin-1", errors="replace").strip()


def _mac(raw: bytes) -> str:
    if len(raw) != 6 or raw == b"\x00" * 6:
        return ""
    return ":".join(f"{b:02X}" for b in raw)


def identify(data: bytes) -> Optional[int]:
    """OpCode of a raw UDP payload, or None if it isn't Art-Net."""
    if len(data) < 10 or data[:8] != ARTNET_ID:
        return None
    return struct.unpack_from("<H", data, 8)[0]


def build_artpoll() -> bytes:
    # ProtVer 14, TalkToMe=0x02 (reply on state change too), Priority 0
    return ARTNET_ID + struct.pack("<H", OP_POLL) + bytes([0, 14, 0x02, 0x00])


def parse_poll_reply(data: bytes, fallback_ip: str) -> Optional[dict]:
    b = data[10:]
    if len(b) < 100:
        return None

    def seg(off, ln):
        return b[off:off + ln] if len(b) >= off + ln else b""

    ip_raw = seg(0, 4)
    ip = ".".join(str(x) for x in ip_raw) if len(ip_raw) == 4 else fallback_ip
    net_sw = b[8] if len(b) > 8 else 0
    sub_sw = b[9] if len(b) > 9 else 0
    style_byte = b[190] if len(b) > 190 else 0

    num_ports = min(((b[162] << 8) | b[163]) if len(b) >= 164 else 0, 4)
    good_in, good_out = seg(168, 4), seg(172, 4)
    sw_in, sw_out = seg(176, 4), seg(180, 4)
    base = (net_sw & 0x7F) << 8 | (sub_sw & 0x0F) << 4

    in_unis, out_unis = [], []
    for i in range(num_ports):
        if i < len(good_in) and good_in[i] & 0x80 and i < len(sw_in):
            in_unis.append(base | (sw_in[i] & 0x0F))
        if i < len(good_out) and good_out[i] & 0x80 and i < len(sw_out):
            out_unis.append(base | (sw_out[i] & 0x0F))

    return {
        "ip": ip,
        "mac": _mac(seg(191, 6)),
        "short_name": _cstr(seg(16, 18)),
        "long_name": _cstr(seg(34, 64)) or _cstr(seg(16, 18)),
        "node_report": _cstr(seg(98, 64)),
        "style": STYLE_NAMES.get(style_byte, f"Unknown (0x{style_byte:02X})"),
        "input_universes": sorted(set(in_unis)),
        "output_universes": sorted(set(out_unis)),
    }


def parse_dmx(data: bytes) -> Optional[dict]:
    b = data[10:]
    if len(b) < 8:
        return None
    length = min((b[6] << 8) | b[7], len(b) - 8)
    payload = b[8:8 + length]
    return {
        "sequence": b[2],
        "universe": ((b[5] & 0x7F) << 8) | b[4],
        "length": length,
        "active_channels": sum(1 for x in payload if x),
    }

# --------------------------------------------------------------------------- #
#  Rolling-rate helpers
# --------------------------------------------------------------------------- #

WINDOW = 3.0


def now() -> float:
    return time.time()


class Rate:
    """Rolling bytes/packets-per-second over a short window."""
    __slots__ = ("ev",)

    def __init__(self):
        self.ev: Deque[Tuple[float, int]] = deque()

    def add(self, size: int):
        t = now()
        self.ev.append((t, size))
        self._trim(t)

    def _trim(self, t: float):
        cut = t - WINDOW
        while self.ev and self.ev[0][0] < cut:
            self.ev.popleft()

    def bps(self) -> float:
        t = now()
        self._trim(t)
        if not self.ev:
            return 0.0
        return sum(s for _, s in self.ev) / max(0.25, t - self.ev[0][0])

    def pps(self) -> float:
        t = now()
        self._trim(t)
        if not self.ev:
            return 0.0
        return len(self.ev) / max(0.25, t - self.ev[0][0])

# --------------------------------------------------------------------------- #
#  Data model + stats engine
# --------------------------------------------------------------------------- #

@dataclass
class Device:
    ip: str
    mac: str = ""
    short_name: str = ""
    long_name: str = ""
    node_report: str = ""
    style: str = ""
    input_universes: list = field(default_factory=list)
    output_universes: list = field(default_factory=list)
    first_seen: float = field(default_factory=now)
    last_seen: float = field(default_factory=now)
    identified: bool = False          # True once we've had an ArtPollReply
    packets_total: int = 0
    bytes_total: int = 0
    bytes_per_sec: float = 0.0
    packets_per_sec: float = 0.0

    def to_dict(self):
        d = asdict(self)
        d["online"] = (now() - self.last_seen) < 12.0
        return d


@dataclass
class LanDevice:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    last_seen: float = field(default_factory=now)

    def to_dict(self):
        d = asdict(self)
        d["online"] = (now() - self.last_seen) < 150.0
        return d


@dataclass
class Universe:
    universe: int
    source_ip: str
    fps: float = 0.0
    active_channels: int = 0
    last_length: int = 0
    bytes_per_sec: float = 0.0
    last_sequence: int = 0
    last_seen: float = field(default_factory=now)

    def to_dict(self):
        d = asdict(self)
        d["online"] = (now() - self.last_seen) < 5.0
        return d


class Engine:
    def __init__(self):
        self.devices: Dict[str, Device] = {}
        self.lan: Dict[str, LanDevice] = {}
        self.universes: Dict[str, Universe] = {}
        self.dev_rate: Dict[str, Rate] = {}
        self.uni_rate: Dict[str, Rate] = {}
        self.uni_frames: Dict[str, Deque[float]] = {}
        self.global_rate = Rate()
        self.opcodes: Dict[str, int] = {}
        self.started = now()
        self.local_ips: List[str] = []

    def on_packet(self, data: bytes, src_ip: str):
        op = identify(data)
        if op is None:
            return
        self.opcodes[OPCODE_NAMES.get(op, f"0x{op:04X}")] = \
            self.opcodes.get(OPCODE_NAMES.get(op, f"0x{op:04X}"), 0) + 1
        self.global_rate.add(len(data))

        dev = self.devices.setdefault(src_ip, Device(ip=src_ip))
        dev.last_seen = now()
        dev.packets_total += 1
        dev.bytes_total += len(data)
        r = self.dev_rate.setdefault(src_ip, Rate())
        r.add(len(data))
        dev.bytes_per_sec = r.bps()
        dev.packets_per_sec = r.pps()

        if op == OP_POLL_REPLY:
            info = parse_poll_reply(data, src_ip)
            if info:
                self._apply_reply(info)
        elif op == OP_DMX:
            pkt = parse_dmx(data)
            if pkt:
                self._apply_dmx(pkt, src_ip)

    def _apply_reply(self, info: dict):
        dev = self.devices.setdefault(info["ip"], Device(ip=info["ip"]))
        for k in ("mac", "short_name", "long_name", "node_report", "style",
                  "input_universes", "output_universes"):
            if info.get(k):
                setattr(dev, k, info[k])
        dev.identified = True
        dev.last_seen = now()

    def _apply_dmx(self, pkt: dict, src_ip: str):
        key = f"{src_ip}:{pkt['universe']}"
        uni = self.universes.setdefault(
            key, Universe(universe=pkt["universe"], source_ip=src_ip))
        t = now()
        frames = self.uni_frames.setdefault(key, deque(maxlen=120))
        frames.append(t)
        while frames and t - frames[0] > WINDOW:
            frames.popleft()
        uni.fps = ((len(frames) - 1) / max(0.25, frames[-1] - frames[0])
                   if len(frames) > 1 else 0.0)
        r = self.uni_rate.setdefault(key, Rate())
        r.add(pkt["length"] + 18)
        uni.bytes_per_sec = r.bps()
        uni.active_channels = pkt["active_channels"]
        uni.last_length = pkt["length"]
        uni.last_sequence = pkt["sequence"]
        uni.last_seen = t

    def merge_lan(self, entries: List[dict]):
        for e in entries:
            d = self.lan.setdefault(e["ip"], LanDevice(ip=e["ip"]))
            d.mac = e.get("mac") or d.mac
            d.vendor = e.get("vendor") or d.vendor
            d.hostname = e.get("hostname") or d.hostname
            d.last_seen = now()

    def prune(self):
        t = now()
        for ip in [i for i, d in self.devices.items() if t - d.last_seen > 600]:
            self.devices.pop(ip); self.dev_rate.pop(ip, None)
        for k in [k for k, u in self.universes.items() if t - u.last_seen > 60]:
            self.universes.pop(k)
            self.uni_rate.pop(k, None)
            self.uni_frames.pop(k, None)

    def snapshot(self) -> dict:
        artnet_ips = set(self.devices)
        return {
            "type": "snapshot",
            "uptime": now() - self.started,
            "local_ips": self.local_ips,
            "global_bps": self.global_rate.bps(),
            "global_pps": self.global_rate.pps(),
            "opcodes": self.opcodes,
            "devices": [d.to_dict() for d in
                        sorted(self.devices.values(), key=lambda d: tuple(map(int, d.ip.split("."))))],
            "lan_devices": [d.to_dict() for d in
                            sorted(self.lan.values(), key=lambda d: tuple(map(int, d.ip.split("."))))
                            if d.ip not in artnet_ips],
            "universes": [u.to_dict() for u in
                          sorted(self.universes.values(), key=lambda u: (u.universe, u.source_ip))],
        }

# --------------------------------------------------------------------------- #
#  UDP listener
# --------------------------------------------------------------------------- #

class ArtNetProtocol(asyncio.DatagramProtocol):
    def __init__(self, engine: Engine):
        self.engine = engine

    def datagram_received(self, data, addr):
        # Ignore our own outgoing ArtPoll echoing back off the broadcast.
        if addr[0] in self.engine.local_ips and identify(data) == OP_POLL:
            return
        self.engine.on_packet(data, addr[0])

    def error_received(self, exc):
        pass


async def open_artnet_socket(engine: Engine) -> asyncio.DatagramTransport:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.bind(("0.0.0.0", ARTNET_PORT))
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: ArtNetProtocol(engine), sock=sock)
    return transport

# --------------------------------------------------------------------------- #
#  LAN discovery (best-effort, no admin rights needed)
# --------------------------------------------------------------------------- #

OUI_VENDORS = {
    "00:50:C2": "Artistic Licence", "00:0E:D3": "ETC", "3C:E1:A1": "ETC",
    "00:1F:C6": "MA Lighting", "00:20:4A": "Avolites",
    "00:1D:A1": "Chauvet Professional", "00:0A:1A": "Robe Lighting",
    "00:0F:3D": "High End Systems",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:15:6D": "Ubiquiti", "24:A4:3C": "Ubiquiti", "78:8A:20": "Ubiquiti", "F0:9F:C2": "Ubiquiti",
    "00:14:38": "Cisco", "00:1A:A1": "Cisco", "F0:9E:63": "Cisco",
    "00:04:A3": "Netgear", "84:1B:5E": "Netgear", "00:09:5B": "Netgear", "00:1F:33": "Netgear",
    "00:18:E7": "D-Link", "00:26:5A": "D-Link", "00:0D:B9": "MikroTik", "4C:5E:0C": "MikroTik",
    "00:1B:63": "Apple", "F4:5C:89": "Apple", "3C:22:FB": "Apple",
    "00:50:56": "VMware vNIC", "00:0C:29": "VMware vNIC", "08:00:27": "VirtualBox vNIC",
    "00:1E:C9": "Dell", "F8:BC:12": "Dell", "00:1B:21": "Intel",
}

_ARP_UNIX = re.compile(r"\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]{11,17})")
_ARP_WIN = re.compile(r"([\d]{1,3}(?:\.[\d]{1,3}){3})\s+([0-9a-fA-F-]{11,17})")


def list_local_networks() -> List[Tuple[str, ipaddress.IPv4Network]]:
    nets = []
    if HAVE_PSUTIL:
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family == socket.AF_INET and a.address and not a.address.startswith("127."):
                    try:
                        nets.append((a.address, ipaddress.IPv4Network(
                            f"{a.address}/{a.netmask or '255.255.255.0'}", strict=False)))
                    except ValueError:
                        pass
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
            nets.append((ip, ipaddress.IPv4Network(f"{ip}/24", strict=False)))
        except OSError:
            pass
        finally:
            s.close()
    return nets


async def ping_sweep(net: ipaddress.IPv4Network, concurrency=48, timeout=0.7):
    hosts = [str(h) for h in net.hosts()][:512]     # cap for huge subnets
    sem = asyncio.Semaphore(concurrency)
    win = platform.system().lower() == "windows"

    async def one(ip):
        async with sem:
            cmd = (["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip] if win
                   else ["ping", "-c", "1", "-W", "1", ip])
            try:
                p = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL)
                await asyncio.wait_for(p.wait(), timeout=timeout + 1.5)
            except (asyncio.TimeoutError, OSError):
                pass

    await asyncio.gather(*(one(h) for h in hosts))


async def read_arp() -> List[Tuple[str, str]]:
    try:
        p = await asyncio.create_subprocess_exec(
            "arp", "-a", stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL)
        out, _ = await p.communicate()
    except (OSError, FileNotFoundError):
        return []
    pat = _ARP_WIN if platform.system().lower() == "windows" else _ARP_UNIX
    found = []
    for line in out.decode(errors="replace").splitlines():
        m = pat.search(line)
        if m:
            mac = m.group(2).replace("-", ":").upper()
            if mac not in ("FF:FF:FF:FF:FF:FF", "00:00:00:00:00:00"):
                found.append((m.group(1), mac))
    return found


async def rdns(ip: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        r = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyaddr, ip), timeout=0.6)
        return r[0]
    except Exception:
        return ""


async def lan_scan(engine: Engine):
    nets = list_local_networks()
    for _, net in nets:
        if net.num_addresses <= 2:
            continue
        await ping_sweep(net)
    entries = []
    in_any_net = lambda ip: any(ipaddress.IPv4Address(ip) in n for _, n in nets)
    for ip, mac in await read_arp():
        try:
            if nets and not in_any_net(ip):
                continue
        except ValueError:
            continue
        entries.append({
            "ip": ip, "mac": mac,
            "vendor": OUI_VENDORS.get(mac[:8], ""),
            "hostname": await rdns(ip),
        })
    engine.merge_lan(entries)

# --------------------------------------------------------------------------- #
#  Web server + background tasks
# --------------------------------------------------------------------------- #

FRONTEND = Path(__file__).parent / "frontend"
engine = Engine()
transport_ref: dict = {}
ARGS = argparse.Namespace(lan_scan=True, poll_interval=5.0)


async def task_artpoll():
    pkt = build_artpoll()
    while True:
        t = transport_ref.get("t")
        if t:
            try:
                t.sendto(pkt, ("255.255.255.255", ARTNET_PORT))
                # Also hit each subnet's directed broadcast - some nodes
                # only answer those.
                for _, net in list_local_networks():
                    t.sendto(pkt, (str(net.broadcast_address), ARTNET_PORT))
            except OSError:
                pass
        await asyncio.sleep(ARGS.poll_interval)


async def task_lan_scan():
    await asyncio.sleep(3)
    while True:
        try:
            await lan_scan(engine)
        except Exception:
            pass
        await asyncio.sleep(60)


async def task_prune():
    while True:
        engine.prune()
        await asyncio.sleep(10)


@asynccontextmanager
async def lifespan(app: FastAPI):
    engine.local_ips = [ip for ip, _ in list_local_networks()]
    transport_ref["t"] = await open_artnet_socket(engine)
    tasks = [asyncio.create_task(task_artpoll()),
             asyncio.create_task(task_prune())]
    if ARGS.lan_scan:
        tasks.append(asyncio.create_task(task_lan_scan()))
    yield
    for t in tasks:
        t.cancel()
    tr = transport_ref.get("t")
    if tr:
        tr.close()


app = FastAPI(title="DMX/Art-Net Network Inspector", lifespan=lifespan)


@app.get("/api/snapshot")
async def api_snapshot():
    return JSONResponse(engine.snapshot())


@app.websocket("/ws")
async def ws_feed(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            await ws.send_text(json.dumps(engine.snapshot()))
            await asyncio.sleep(0.5)
    except (WebSocketDisconnect, ConnectionError, RuntimeError):
        pass


@app.get("/")
async def index():
    return FileResponse(FRONTEND / "index.html")


app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")


def main():
    import uvicorn
    ap = argparse.ArgumentParser(description="DMX/Art-Net Network Inspector")
    ap.add_argument("--port", type=int, default=8058,
                    help="dashboard web port (default 8058)")
    ap.add_argument("--host", default="0.0.0.0",
                    help="dashboard bind address (0.0.0.0 = reachable from "
                         "tablets/other machines on the network)")
    ap.add_argument("--no-lan-scan", action="store_true",
                    help="disable the ping-sweep/ARP scan for non-Art-Net devices")
    ap.add_argument("--poll-interval", type=float, default=5.0,
                    help="seconds between ArtPoll broadcasts (default 5)")
    a = ap.parse_args()
    ARGS.lan_scan = not a.no_lan_scan
    ARGS.poll_interval = a.poll_interval

    local = engine.local_ips or [ip for ip, _ in list_local_networks()]
    print("=" * 62)
    print("  DMX / Art-Net Network Inspector")
    print(f"  Dashboard:  http://localhost:{a.port}")
    for ip in local:
        print(f"              http://{ip}:{a.port}   (from other devices)")
    print(f"  Listening:  UDP {ARTNET_PORT} (Art-Net), passive")
    print("=" * 62)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
