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
* Passively watches for MIDI Time Code (MTC) on the network -> Art-Net
  timecode (ArtTimeCode), ipMIDI multicast and, optionally, RTP-MIDI, with
  a live HH:MM:SS:FF clock per timecode master.
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
OP_TIMECODE = 0x9700
OPCODE_NAMES = {
    0x2000: "ArtPoll", 0x2100: "ArtPollReply", 0x5000: "ArtDmx",
    0x5200: "ArtSync", 0x6000: "ArtAddress", 0x8000: "ArtTodRequest",
    0x8100: "ArtTodData", 0x8200: "ArtTodControl", 0x8300: "ArtRdm",
    0x9700: "ArtTimeCode",
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
#  MIDI Time Code (MTC) over the network - listen-only
# --------------------------------------------------------------------------- #
#  Three ways a show puts timecode on an Ethernet cable, all readable with a
#  plain UDP socket and no admin rights:
#
#    * Art-Net timecode  - ArtTimeCode (OpCode 0x9700) on the port we already
#      listen to. Broadcast, so we always see it.
#    * ipMIDI            - raw MIDI bytes in a multicast datagram on
#      225.0.0.37, one port per bus. Multicast, so we see it after joining
#      the group (a read-only operation).
#    * RTP-MIDI/AppleMIDI - RFC 6295 sessions on UDP 5004/5005. This is
#      *unicast* between the two session partners, so it is only visible on a
#      machine that is itself an endpoint - and there the MIDI software owns
#      the port. Off by default for that reason (--rtp-midi to enable).
#
#  Device names come from AppleMIDI session invitations and from mDNS
#  announcements of _apple-midi._udp, both of which we only ever listen to.

IPMIDI_GROUP = "225.0.0.37"
IPMIDI_BASE_PORT = 21928           # bus 1; bus n = base + (n - 1)
APPLEMIDI_PORTS = (5004, 5005)     # session control / RTP data
MDNS_GROUP, MDNS_PORT = "224.0.0.251", 5353
MIDI_SERVICE = "_apple-midi._udp"

# MTC frame-rate codes, with the nominal integer frame count used for
# timecode arithmetic (29.97 drop-frame counts to 30 too, it just skips
# frame numbers at minute boundaries).
MTC_RATES = {
    0: ("24 fps", 24),
    1: ("25 fps", 25),
    2: ("29.97 fps drop", 30),
    3: ("30 fps", 30),
}

_MIDI_CHANNEL_LEN = {0x8: 2, 0x9: 2, 0xA: 2, 0xB: 2, 0xC: 1, 0xD: 1, 0xE: 2}
_MIDI_SYSTEM_LEN = {0xF1: 1, 0xF2: 2, 0xF3: 1}


def fmt_timecode(tc: Tuple[int, int, int, int]) -> str:
    return "%02d:%02d:%02d:%02d" % tc


def advance_timecode(tc: Tuple[int, int, int, int], frames: int,
                     nominal: int) -> Tuple[int, int, int, int]:
    """tc + n frames, wrapping at 24 h (non-drop arithmetic)."""
    h, m, s, f = tc
    nominal = max(1, nominal)
    total = (((h * 60 + m) * 60) + s) * nominal + f + frames
    f, total = total % nominal, total // nominal
    s, total = total % 60, total // 60
    m, total = total % 60, total // 60
    return (total % 24, m, s, f)


def _valid_tc(h: int, m: int, s: int, f: int, nominal: int) -> bool:
    return h <= 23 and m <= 59 and s <= 59 and f < nominal


def parse_art_timecode(data: bytes) -> Optional[dict]:
    """ArtTimeCode body: filler, filler, frames, secs, mins, hours, type."""
    b = data[10:]
    if len(b) < 9:
        return None
    frames, seconds, minutes, hours = b[4], b[5], b[6], b[7]
    label, nominal = MTC_RATES.get(b[8] & 0x03, ("unknown rate", 30))
    if not _valid_tc(hours, minutes, seconds, frames, nominal):
        return None
    return {"tc": (hours, minutes, seconds, frames), "rate": label,
            "nominal": nominal, "kind": "Art-Net timecode"}


class MidiTimecodeDecoder:
    """Feeds on a raw MIDI byte stream and emits complete timecode readings.

    Handles both ways MTC travels: quarter-frame messages (F1, eight of them
    per two frames) and full-frame SysEx (F0 7F dd 01 01 hh mm ss ff F7),
    which senders use when locating/parking rather than rolling.
    """

    __slots__ = ("_status", "_pending", "_sysex", "_nibbles")

    def __init__(self):
        self._status = 0
        self._pending = 0
        self._sysex: Optional[bytearray] = None
        self._nibbles: List[Optional[int]] = [None] * 8

    def feed(self, data: bytes) -> List[dict]:
        out: List[dict] = []
        for byte in data:
            if byte >= 0xF8:                 # realtime, may interleave anywhere
                continue
            if self._sysex is not None:
                if byte < 0x80:
                    if len(self._sysex) < 24:
                        self._sysex.append(byte)
                    continue
                body = bytes(self._sysex)
                self._sysex = None
                if byte == 0xF7:             # normal end of SysEx
                    hit = self._full_frame(body)
                    if hit:
                        out.append(hit)
                    continue
                # anything else aborts it and is handled as a status byte
            if byte >= 0x80:
                self._status_byte(byte)
            else:
                hit = self._data_byte(byte)
                if hit:
                    out.append(hit)
        return out

    def _status_byte(self, byte: int):
        if byte == 0xF0:
            self._sysex, self._status, self._pending = bytearray(), 0, 0
        elif byte >= 0xF0:
            self._pending = _MIDI_SYSTEM_LEN.get(byte, 0)
            self._status = byte if self._pending else 0   # cancels running status
        else:
            self._status = byte
            self._pending = _MIDI_CHANNEL_LEN.get(byte >> 4, 0)

    def _data_byte(self, byte: int) -> Optional[dict]:
        if self._pending <= 0:
            return None
        if self._status == 0xF1:
            self._status, self._pending = 0, 0
            return self._quarter_frame(byte)
        self._pending -= 1
        if self._pending == 0:
            if self._status < 0xF0:
                # running status: the next data bytes repeat this message
                self._pending = _MIDI_CHANNEL_LEN.get(self._status >> 4, 0)
            else:
                self._status = 0
        return None

    def _quarter_frame(self, value: int) -> Optional[dict]:
        index, nibble = (value >> 4) & 0x07, value & 0x0F
        self._nibbles[index] = nibble
        if index != 7 or any(n is None for n in self._nibbles):
            return None
        n = self._nibbles
        frames = n[0] | (n[1] << 4)
        seconds = n[2] | (n[3] << 4)
        minutes = n[4] | (n[5] << 4)
        hours = n[6] | ((n[7] & 0x01) << 4)
        label, nominal = MTC_RATES[(n[7] >> 1) & 0x03]
        if not _valid_tc(hours, minutes, seconds, frames, nominal):
            return None
        # The eight messages span two frames and carry the time of the first,
        # so a reader displays the value two frames later.
        tc = advance_timecode((hours, minutes, seconds, frames), 2, nominal)
        return {"tc": tc, "rate": label, "nominal": nominal,
                "kind": "MTC quarter-frame"}

    @staticmethod
    def _full_frame(body: bytes) -> Optional[dict]:
        # body is the SysEx between F0 and F7
        if len(body) < 8 or body[0] != 0x7F or body[2:4] != b"\x01\x01":
            return None
        hours, minutes, seconds, frames = body[4] & 0x1F, body[5], body[6], body[7]
        label, nominal = MTC_RATES.get((body[4] >> 5) & 0x03, ("unknown rate", 30))
        if not _valid_tc(hours, minutes, seconds, frames, nominal):
            return None
        return {"tc": (hours, minutes, seconds, frames), "rate": label,
                "nominal": nominal, "kind": "MTC full-frame"}


def _vlq(buf: bytes, i: int) -> int:
    """Skip an RTP-MIDI delta time (variable-length quantity)."""
    for _ in range(4):
        if i >= len(buf):
            return i
        if not buf[i] & 0x80:
            return i + 1
        i += 1
    return i


def rtp_midi_commands(data: bytes) -> Optional[bytes]:
    """Strip the RTP + RTP-MIDI framing and return the bare MIDI messages."""
    if len(data) < 13 or (data[0] & 0xC0) != 0x80 or (data[1] & 0x7F) != 97:
        return None
    off = 12 + (data[0] & 0x0F) * 4                  # CSRC list
    if data[0] & 0x10:                               # header extension
        if off + 4 > len(data):
            return None
        off += 4 + struct.unpack_from(">H", data, off + 2)[0] * 4
    if off >= len(data):
        return None
    header = data[off]
    if header & 0x80:                                # 12-bit length
        if off + 2 > len(data):
            return None
        length, start = ((header & 0x0F) << 8) | data[off + 1], off + 2
    else:
        length, start = header & 0x0F, off + 1
    midi = data[start:start + length]
    if not midi:
        return None

    # The list is [delta] command [delta command]... - Z says whether the
    # first command carries one. Drop the deltas; we only want the messages.
    out, i, first = bytearray(), 0, True
    while i < len(midi):
        if not first or header & 0x20:
            i = _vlq(midi, i)
        first = False
        if i >= len(midi):
            break
        status = midi[i]
        if status == 0xF0:                           # SysEx runs to F7 or end
            end = midi.find(b"\xf7", i)
            end = len(midi) if end < 0 else end + 1
            out += midi[i:end]
            i = end
            continue
        if status >= 0x80:
            size = (_MIDI_SYSTEM_LEN.get(status, 0) if status >= 0xF0
                    else _MIDI_CHANNEL_LEN.get(status >> 4, 0))
            out += midi[i:i + 1 + size]
            i += 1 + size
        else:
            out += midi[i:]                          # running status remainder
            break
    return bytes(out)


def applemidi_session_name(data: bytes) -> Optional[str]:
    """Name out of an AppleMIDI invitation/acceptance (FF FF 'IN'/'OK'/'NO')."""
    if len(data) < 17 or data[:2] != b"\xff\xff" or data[2:4] not in (b"IN", b"OK", b"NO"):
        return None
    return _cstr(data[16:]) or None


def _dns_name(buf: bytes, i: int, depth: int = 0) -> Tuple[str, int]:
    parts: List[str] = []
    while i < len(buf):
        ln = buf[i]
        if ln == 0:
            return ".".join(parts), i + 1
        if ln & 0xC0 == 0xC0:                        # compression pointer
            if i + 1 >= len(buf):
                break
            if depth < 6:
                sub, _ = _dns_name(buf, ((ln & 0x3F) << 8) | buf[i + 1], depth + 1)
                if sub:
                    parts.append(sub)
            return ".".join(parts), i + 2
        i += 1
        parts.append(buf[i:i + ln].decode("utf-8", errors="replace"))
        i += ln
    return ".".join(parts), i


def parse_mdns(data: bytes) -> List[Tuple[str, int, int, int]]:
    """-> [(record name, type, rdata offset, rdata length)]."""
    if len(data) < 12:
        return []
    qd, an, ns, ar = struct.unpack_from(">HHHH", data, 4)
    i = 12
    for _ in range(qd):
        _, i = _dns_name(data, i)
        i += 4
    records = []
    for _ in range(an + ns + ar):
        name, i = _dns_name(data, i)
        if i + 10 > len(data):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", data, i)
        i += 10
        records.append((name, rtype, i, rdlen))
        i += rdlen
    return records


def mdns_midi_sessions(data: bytes) -> List[Tuple[str, int]]:
    """Network-MIDI sessions announced in an mDNS packet -> [(name, port)]."""
    found = []
    for name, rtype, off, rdlen in parse_mdns(data):
        if rtype == 12 and name.lower().startswith(MIDI_SERVICE):        # PTR
            instance, _ = _dns_name(data, off)
            found.append((instance.split("." + MIDI_SERVICE)[0], 0))
        elif rtype == 33 and MIDI_SERVICE in name.lower() and rdlen >= 6:  # SRV
            port = struct.unpack_from(">H", data, off + 4)[0]
            found.append((name.split("." + MIDI_SERVICE)[0], port))
    return [(n, p) for n, p in found if n]


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


@dataclass
class TimecodeSource:
    """One master putting a timecode clock on the network."""
    ip: str
    transport: str                    # Art-Net timecode / ipMIDI bus 1 / RTP-MIDI
    port: int
    name: str = ""
    timecode: str = "--:--:--:--"
    rate: str = ""
    kind: str = ""                    # quarter-frame / full-frame / Art-Net
    updates: int = 0
    updates_per_sec: float = 0.0
    first_seen: float = field(default_factory=now)
    last_seen: float = field(default_factory=now)
    last_change: float = 0.0

    def to_dict(self):
        d = asdict(self)
        t = now()
        d["online"] = (t - self.last_seen) < 5.0
        # Rolling = the clock is actually advancing, not just arriving: a
        # parked deck keeps sending the same frame.
        d["running"] = d["online"] and (t - self.last_change) < 1.0
        return d


@dataclass
class MidiEndpoint:
    """A network-MIDI participant we heard announce itself."""
    ip: str
    name: str = ""
    port: int = 0
    source: str = ""                  # mDNS / AppleMIDI session
    last_seen: float = field(default_factory=now)

    def to_dict(self):
        d = asdict(self)
        d["online"] = (now() - self.last_seen) < 300.0
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
        self.timecode: Dict[str, TimecodeSource] = {}
        self.tc_rate: Dict[str, Rate] = {}
        self.midi_decoders: Dict[str, MidiTimecodeDecoder] = {}
        self.midi_endpoints: Dict[str, MidiEndpoint] = {}
        self.listeners: List[str] = []
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
        elif op == OP_TIMECODE:
            tc = parse_art_timecode(data)
            if tc:
                self.on_timecode(src_ip, "Art-Net timecode", ARTNET_PORT, tc)

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

    # -- timecode ---------------------------------------------------------

    def on_timecode(self, ip: str, transport: str, port: int, reading: dict):
        key = f"{transport}|{ip}"
        src = self.timecode.setdefault(
            key, TimecodeSource(ip=ip, transport=transport, port=port))
        t = now()
        text = fmt_timecode(reading["tc"])
        if text != src.timecode:
            src.last_change = t
        src.timecode = text
        src.rate = reading["rate"]
        src.kind = reading["kind"]
        src.updates += 1
        src.last_seen = t
        r = self.tc_rate.setdefault(key, Rate())
        r.add(1)
        src.updates_per_sec = r.pps()

    def on_midi_stream(self, ip: str, data: bytes, transport: str, port: int):
        """Raw MIDI bytes off the wire (ipMIDI, or an unwrapped RTP-MIDI list)."""
        key = f"{transport}|{ip}"
        decoder = self.midi_decoders.setdefault(key, MidiTimecodeDecoder())
        for reading in decoder.feed(data):
            self.on_timecode(ip, transport, port, reading)

    def note_midi_endpoint(self, ip: str, name: str, port: int, source: str):
        ep = self.midi_endpoints.setdefault(ip, MidiEndpoint(ip=ip))
        if name:
            ep.name = name
        if port:
            ep.port = port
        ep.source = source
        ep.last_seen = now()

    def name_for_ip(self, ip: str) -> str:
        ep = self.midi_endpoints.get(ip)
        if ep and ep.name:
            return ep.name
        dev = self.devices.get(ip)
        if dev and (dev.short_name or dev.long_name):
            return dev.short_name or dev.long_name
        lan = self.lan.get(ip)
        if lan and lan.hostname:
            return lan.hostname
        return ""

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
        for k in [k for k, s in self.timecode.items() if t - s.last_seen > 300]:
            self.timecode.pop(k)
            self.tc_rate.pop(k, None)
            self.midi_decoders.pop(k, None)
        for ip in [i for i, e in self.midi_endpoints.items()
                   if t - e.last_seen > 900]:
            self.midi_endpoints.pop(ip)

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
            "timecode": [self._tc_dict(s) for s in
                         sorted(self.timecode.values(),
                                key=lambda s: (-s.last_seen, s.transport))],
            "midi_endpoints": [e.to_dict() for e in
                               sorted(self.midi_endpoints.values(),
                                      key=lambda e: (e.name.lower(), e.ip))],
            "timecode_listeners": self.listeners,
        }

    def _tc_dict(self, src: TimecodeSource) -> dict:
        # Names can arrive after the timecode does (an ArtPollReply or an
        # mDNS announcement later on), so resolve at send time.
        d = src.to_dict()
        d["name"] = src.name or self.name_for_ip(src.ip)
        return d

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
#  MTC listeners (multicast joins + optional RTP-MIDI ports)
# --------------------------------------------------------------------------- #

class IpMidiProtocol(asyncio.DatagramProtocol):
    def __init__(self, engine: Engine, bus: int, port: int):
        self.engine, self.transport_name, self.port = engine, f"ipMIDI bus {bus}", port

    def datagram_received(self, data, addr):
        self.engine.on_midi_stream(addr[0], data, self.transport_name, self.port)

    def error_received(self, exc):
        pass


class RtpMidiProtocol(asyncio.DatagramProtocol):
    def __init__(self, engine: Engine, port: int):
        self.engine, self.port = engine, port

    def datagram_received(self, data, addr):
        name = applemidi_session_name(data)
        if name:
            self.engine.note_midi_endpoint(addr[0], name, self.port, "AppleMIDI session")
            return
        midi = rtp_midi_commands(data)
        if midi:
            self.engine.on_midi_stream(addr[0], midi, "RTP-MIDI", self.port)

    def error_received(self, exc):
        pass


class MdnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, engine: Engine):
        self.engine = engine

    def datagram_received(self, data, addr):
        for name, port in mdns_midi_sessions(data):
            self.engine.note_midi_endpoint(addr[0], name, port, "mDNS")

    def error_received(self, exc):
        pass


def _udp_socket(port: int, group: Optional[str] = None,
                share: bool = True) -> socket.socket:
    """Bound, non-blocking UDP socket; joins `group` on every interface.

    `share` adds SO_REUSEPORT. That is right for multicast (every joined
    socket gets a copy) but wrong for unicast ports, where the kernel would
    split the packets between us and whatever else has the port open - so
    the RTP-MIDI ports are opened without it and simply fail if taken.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if share and hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    if group:
        # Binding to the group address itself keeps unicast on that port
        # away from us; Windows refuses that bind, so it gets the wildcard.
        bind_ip = "" if platform.system().lower() == "windows" else group
        sock.bind((bind_ip, port))
        for iface in ["0.0.0.0"] + [ip for ip, _ in list_local_networks()]:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                socket.inet_aton(group) + socket.inet_aton(iface))
            except OSError:
                pass            # already a member on that interface, etc.
    else:
        sock.bind(("0.0.0.0", port))
    sock.setblocking(False)
    return sock


async def open_mtc_listeners(engine: Engine) -> List[asyncio.DatagramTransport]:
    loop = asyncio.get_running_loop()
    transports: List[asyncio.DatagramTransport] = []
    engine.listeners.append(f"Art-Net timecode (UDP {ARTNET_PORT})")

    buses = []
    for bus in range(1, ARGS.ipmidi_buses + 1):
        port = IPMIDI_BASE_PORT + bus - 1
        try:
            sock = _udp_socket(port, group=IPMIDI_GROUP)
            t, _ = await loop.create_datagram_endpoint(
                lambda: IpMidiProtocol(engine, bus, port), sock=sock)
            transports.append(t)
            buses.append(bus)
        except OSError as e:
            print(f"  ipMIDI bus {bus}: not listening ({e})")
    if buses:
        engine.listeners.append(
            f"ipMIDI {IPMIDI_GROUP} bus {buses[0]}-{buses[-1]}" if len(buses) > 1
            else f"ipMIDI {IPMIDI_GROUP} bus {buses[0]}")

    if ARGS.mdns:
        try:
            sock = _udp_socket(MDNS_PORT, group=MDNS_GROUP)
            t, _ = await loop.create_datagram_endpoint(
                lambda: MdnsProtocol(engine), sock=sock)
            transports.append(t)
            engine.listeners.append("mDNS network-MIDI announcements")
        except OSError as e:
            print(f"  mDNS: not listening ({e})")

    if ARGS.rtp_midi:
        opened = []
        for port in APPLEMIDI_PORTS:
            try:
                sock = _udp_socket(port, share=False)
                t, _ = await loop.create_datagram_endpoint(
                    lambda: RtpMidiProtocol(engine, port), sock=sock)
                transports.append(t)
                opened.append(str(port))
            except OSError as e:
                print(f"  RTP-MIDI port {port}: not listening ({e})")
        if opened:
            engine.listeners.append("RTP-MIDI (UDP " + "/".join(opened) + ")")
    return transports

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
ARGS = argparse.Namespace(lan_scan=True, poll_interval=5.0,
                          mtc=True, ipmidi_buses=4, mdns=True, rtp_midi=False)


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
    extra_transports = await open_mtc_listeners(engine) if ARGS.mtc else []
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
    for t in extra_transports:
        t.close()


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
    ap.add_argument("--no-mtc", action="store_true",
                    help="disable the timecode (MTC) listeners entirely")
    ap.add_argument("--ipmidi-buses", type=int, default=4, metavar="N",
                    help="listen on ipMIDI buses 1..N (default 4, max 20)")
    ap.add_argument("--no-mdns", action="store_true",
                    help="don't listen for mDNS network-MIDI announcements")
    ap.add_argument("--rtp-midi", action="store_true",
                    help="also listen on the RTP-MIDI/AppleMIDI ports 5004/5005 "
                         "(only useful when this machine is a session endpoint "
                         "and nothing else has those ports open)")
    a = ap.parse_args()
    ARGS.lan_scan = not a.no_lan_scan
    ARGS.poll_interval = a.poll_interval
    ARGS.mtc = not a.no_mtc
    ARGS.ipmidi_buses = max(0, min(20, a.ipmidi_buses))
    ARGS.mdns = not a.no_mdns
    ARGS.rtp_midi = a.rtp_midi

    local = engine.local_ips or [ip for ip, _ in list_local_networks()]
    print("=" * 62)
    print("  DMX / Art-Net Network Inspector")
    print(f"  Dashboard:  http://localhost:{a.port}")
    for ip in local:
        print(f"              http://{ip}:{a.port}   (from other devices)")
    print(f"  Listening:  UDP {ARTNET_PORT} (Art-Net), passive")
    if ARGS.mtc:
        tc_bits = ["Art-Net timecode"]
        if ARGS.ipmidi_buses:
            tc_bits.append(f"ipMIDI {IPMIDI_GROUP} x{ARGS.ipmidi_buses}")
        if ARGS.mdns:
            tc_bits.append("mDNS")
        if ARGS.rtp_midi:
            tc_bits.append("RTP-MIDI 5004/5005")
        print(f"  Timecode:   {', '.join(tc_bits)}, passive")
    print("=" * 62)
    uvicorn.run(app, host=a.host, port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
