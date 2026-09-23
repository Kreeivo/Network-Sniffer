"""
Art-Net + MTC traffic simulator - for testing the Inspector with NO hardware.

Run this in a second terminal while app.py is running and the dashboard
will light up with a fake node ("PIXEL-NODE-1"), three universes of moving
DMX data at ~40 fps, and a timecode clock rolling at 25 fps on two
transports at once:

    * Art-Net timecode (ArtTimeCode) from the same fake node
    * ipMIDI bus 1 quarter-frame MTC (multicast 225.0.0.37:21928)

    python simulator.py                # 25 fps
    python simulator.py --fps 30       # 24, 25, 30 or df (29.97 drop-frame)
    python simulator.py --fps 30 --flag 24   # lie in the rate flag, to see
                                             # the inspector detect the real rate
    python simulator.py --show-control       # also fake a ShowKontrol rig:
                                             # TCNet master, two CDJs + DJM on
                                             # Pro DJ Link, and OSC cues

Everything stays on this machine - Art-Net goes to 127.0.0.1 and the
ipMIDI multicast is sent with TTL 0, which never leaves the host.
Stop it with Ctrl+C.
"""
import argparse
import socket
import struct
import time

ARTNET_ID = b"Art-Net\x00"
OP_POLL_REPLY = 0x2100
OP_DMX = 0x5000
OP_TIMECODE = 0x9700
TARGET = ("127.0.0.1", 6454)
IPMIDI = ("225.0.0.37", 21928)          # bus 1

RATES = {"24": (24.0, 24, 0), "25": (25.0, 25, 1),
         "30": (30.0, 30, 3), "df": (30000 / 1001, 30, 2)}   # real fps, nominal, MTC code
TC_FPS = 25.0                           # real frames per second
TC_NOMINAL = 25                         # frame numbers run 0..TC_NOMINAL-1
TC_RATE_CODE = 1                        # what we put in the rate flag
TC_DROP = False
TC_START = (0, 59, 50, 0)               # roll from 00:59:50:00 so it crosses the hour


def poll_reply(ip, short, long_, style, mac, out_unis=()):
    body = bytearray(207)
    body[0:4] = bytes(int(x) for x in ip.split("."))
    body[4:6] = struct.pack("<H", 6454)
    body[16:16 + len(short)] = short.encode()
    body[34:34 + len(long_)] = long_.encode()
    nr = b"#0001 [0005] Node OK"
    body[98:98 + len(nr)] = nr
    body[162:164] = (len(out_unis)).to_bytes(2, "big")
    for i, u in enumerate(out_unis[:4]):
        body[172 + i] = 0x80
        body[180 + i] = u & 0x0F
    body[190] = style
    body[191:197] = mac
    return ARTNET_ID + struct.pack("<H", OP_POLL_REPLY) + bytes(body)


def dmx(universe, seq):
    levels = bytes(((i * 7 + seq * 3) % 256) for i in range(512))
    body = bytes([0, 14, seq % 256, 0,
                  universe & 0xFF, (universe >> 8) & 0x7F, 2, 0]) + levels
    return ARTNET_ID + struct.pack("<H", OP_DMX) + body


def frames_to_tc(total):
    n = TC_NOMINAL
    if TC_DROP:
        # 29.97 drop-frame: skip frame numbers 0 and 1 at every minute that
        # isn't a multiple of ten (17982 frames per ten minutes).
        d, m = divmod(total, 17982)
        total = total + 18 * d + (0 if m < 2 else 2 * ((m - 2) // 1798))
    f = total % n
    s = (total // n) % 60
    m = (total // (n * 60)) % 60
    h = (total // (n * 3600)) % 24
    return h, m, s, f


def art_timecode(h, m, s, f):
    # ProtVerHi, ProtVerLo, Filler1, Filler2, Frames, Seconds, Minutes, Hours, Type
    return ARTNET_ID + struct.pack("<H", OP_TIMECODE) + bytes(
        [0, 14, 0, 0, f, s, m, h, TC_RATE_CODE])


def mtc_quarter_frames(h, m, s, f):
    """The eight F1 messages that spell out one timecode value."""
    nibbles = [f & 0xF, f >> 4, s & 0xF, s >> 4, m & 0xF, m >> 4,
               h & 0xF, ((h >> 4) & 0x1) | (TC_RATE_CODE << 1)]
    return [bytes([0xF1, (i << 4) | n]) for i, n in enumerate(nibbles)]


# --- show control -----------------------------------------------------------

TCNET_MAGIC = b"TCN"
PDJL_MAGIC = bytes.fromhex("5173707431576d4a4f4c")


def tcnet_header(msg_type, name, node_type, node_id=7):
    return (struct.pack("<H", node_id) + bytes([3, 6]) + TCNET_MAGIC + bytes([msg_type])
            + name.encode()[:8].ljust(8, b"\0") + bytes([1, node_type])
            + struct.pack("<H", 0) + struct.pack("<I", int(time.time() * 1000) & 0xFFFFFFFF))


def tcnet_optin(name, vendor, app, node_type):
    return (tcnet_header(2, name, node_type) + struct.pack("<HHH", 2, 65032, 60) + b"\0\0"
            + vendor.encode()[:16].ljust(16, b"\0") + app.encode()[:16].ljust(16, b"\0")
            + bytes([3, 6, 1, 0]))


def tcnet_time(name, layer_ms, beat):
    pkt = bytearray(154)
    pkt[:24] = tcnet_header(254, name, 2)
    for i, ms in enumerate(layer_ms):
        struct.pack_into("<I", pkt, 24 + i * 4, ms)
        struct.pack_into("<I", pkt, 56 + i * 4, 6 * 60 * 1000)
        pkt[88 + i] = beat if ms else 0
        pkt[96 + i] = 1 if ms else 0          # playing / idle
    pkt[105] = TC_RATE_CODE
    return bytes(pkt)


def pdjl_keepalive(name, number, mac, ip, dev_type):
    pkt = bytearray(0x36)
    pkt[:10] = PDJL_MAGIC
    pkt[0x0A] = 0x06
    pkt[0x0B:0x0B + len(name)] = name.encode()
    pkt[0x1F] = 1
    pkt[0x20:0x22] = b"\x00\x36"
    pkt[0x22] = number
    pkt[0x23:0x29] = mac
    pkt[0x29:0x2D] = bytes(int(x) for x in ip.split("."))
    pkt[0x2D] = 3
    pkt[0x34] = dev_type
    return bytes(pkt)


def pdjl_beat(name, number, bpm, pitch_pct, beat):
    pkt = bytearray(0x60)
    pkt[:10] = PDJL_MAGIC
    pkt[0x0A] = 0x28
    pkt[0x0B:0x0B + len(name)] = name.encode()
    pkt[0x1F] = 1
    pkt[0x21] = number
    pkt[0x22:0x24] = b"\x00\x3c"
    struct.pack_into(">I", pkt, 0x54, int(0x100000 * (1 + pitch_pct / 100.0)))
    struct.pack_into(">H", pkt, 0x5A, int(bpm * 100))
    pkt[0x5C] = beat
    pkt[0x5F] = number
    return bytes(pkt)


def osc(address, *args):
    def pad(b):
        return b + b"\0" * (4 - len(b) % 4)
    tags, body = b",", b""
    for a in args:
        if isinstance(a, int):
            tags += b"i"; body += struct.pack(">i", a)
        elif isinstance(a, float):
            tags += b"f"; body += struct.pack(">f", a)
        else:
            tags += b"s"; body += pad(str(a).encode())
    return pad(address.encode()) + pad(tags) + body


def main():
    global TC_FPS, TC_NOMINAL, TC_RATE_CODE, TC_DROP
    ap = argparse.ArgumentParser(description="Art-Net + MTC simulator")
    ap.add_argument("--fps", choices=sorted(RATES), default="25",
                    help="timecode rate: 24, 25, 30 or df (29.97 drop-frame)")
    ap.add_argument("--flag", choices=sorted(RATES), default=None,
                    help="put a different rate in the MTC rate flag (to test detection)")
    ap.add_argument("--show-control", action="store_true",
                    help="also fake a ShowKontrol rig (TCNet, Pro DJ Link, OSC)")
    a = ap.parse_args()
    TC_FPS, TC_NOMINAL, TC_RATE_CODE = RATES[a.fps]
    TC_DROP = a.fps == "df"
    if a.flag:
        TC_RATE_CODE = RATES[a.flag][2]

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mc.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 0)   # host only
    mc.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)

    node = poll_reply("127.0.0.1", "PIXEL-NODE-1",
                      "Backstage 8-port Art-Net Node", 0x00,
                      bytes([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]),
                      out_unis=(0, 1, 2))
    print("Simulator running - sending fake Art-Net to 127.0.0.1:6454")
    print("and MTC quarter-frames to ipMIDI bus 1 (225.0.0.37:21928, TTL 0).")
    print(f"Open the dashboard: PIXEL-NODE-1 with 3 universes, timecode rolling at "
          f"{a.fps.replace('df', '29.97 drop')} fps"
          + (f" (flagged as {a.flag.replace('df', '29.97 drop')})" if a.flag else "") + ".")
    print("Ctrl+C to stop.")
    def from_ip(last_octet):
        """A sender bound to 127.0.0.N so each fake device has its own address
        (Linux/Windows allow any 127/8 address; elsewhere fall back to default)."""
        so = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            so.bind((f"127.0.0.{last_octet}", 0))
        except OSError:
            pass
        return so

    if a.show_control:
        sk, desk = from_ip(10), from_ip(11)
        cdj1, cdj2, djm = from_ip(21), from_ip(22), from_ip(33)
        print("Show control: TCNet master 'SHOWKTRL' (127.0.0.10) and grandMA3 slave "
              "(127.0.0.11); CDJ-3000 #1/#2 + DJM-900NXS2 on Pro DJ Link "
              "(127.0.0.21/22/33); OSC cues from SHOWKTRL to :7000 - all to 127.0.0.1.")
    seq = 0
    last_reply = 0.0
    sc_last = {"optin": 0.0, "keepalive": 0.0, "beat": 0.0, "osc": 0.0, "time": 0.0}
    sc_beat, sc_cue = 0, 0
    bpm = 128.0
    beat_period = 60.0 / bpm
    h, m, sec, f = TC_START
    tc_frame = ((h * 60 + m) * 60 + sec) * TC_NOMINAL + f
    tc_next = time.time()
    qf_index = 0
    try:
        while True:
            t = time.time()
            if t - last_reply > 4:
                s.sendto(node, TARGET)
                last_reply = t
            for uni in (0, 1, 2):
                s.sendto(dmx(uni, seq), TARGET)
            seq += 1

            # Timecode: one ArtTimeCode per frame, and the MTC quarter-frames
            # spread over the two frames they describe (4 per frame).
            while t >= tc_next:
                tc = frames_to_tc(tc_frame)
                s.sendto(art_timecode(*tc), TARGET)
                if qf_index == 0:
                    qf = mtc_quarter_frames(*tc)
                for msg in qf[qf_index:qf_index + 4]:
                    try:
                        mc.sendto(msg, IPMIDI)
                    except OSError:
                        pass                      # no multicast route - skip
                qf_index = (qf_index + 4) % 8
                tc_frame += 1
                tc_next += 1 / TC_FPS
            if a.show_control:
                lo = ("127.0.0.1", 0)
                if t - sc_last["optin"] > 1.0:
                    sk.sendto(tcnet_optin("SHOWKTRL", "TC Supply", "ShowKontrol", 2), ("127.0.0.1", 60000))
                    desk.sendto(tcnet_optin("LX-DESK", "MA Lighting", "grandMA3", 4), ("127.0.0.1", 60000))
                    sc_last["optin"] = t
                if t - sc_last["keepalive"] > 1.5:
                    for so, name, num, mac, ip, dtype in (
                            (cdj1, "CDJ-3000", 1, b"\xc8\x2b\x96\x00\x00\x01", "127.0.0.21", 1),
                            (cdj2, "CDJ-3000", 2, b"\xc8\x2b\x96\x00\x00\x02", "127.0.0.22", 1),
                            (djm, "DJM-900NXS2", 0x21, b"\xc8\x2b\x96\x00\x00\x21", "127.0.0.33", 2)):
                        so.sendto(pdjl_keepalive(name, num, mac, ip, dtype), ("127.0.0.1", 50000))
                    sc_last["keepalive"] = t
                if t - sc_last["beat"] > beat_period:
                    sc_beat = sc_beat % 4 + 1
                    cdj1.sendto(pdjl_beat("CDJ-3000", 1, bpm, 0.0, sc_beat), ("127.0.0.1", 50001))
                    cdj2.sendto(pdjl_beat("CDJ-3000", 2, 126.0, 1.59, (sc_beat + 1) % 4 + 1), ("127.0.0.1", 50001))
                    sc_last["beat"] = t
                if t - sc_last["time"] > 1 / 30:
                    ms = int((tc_frame / TC_NOMINAL) * 1000)
                    sk.sendto(tcnet_time("SHOWKTRL", [ms, ms - 30000, 0, 0, 0, 0, 0, 0], sc_beat), ("127.0.0.1", 60001))
                    sc_last["time"] = t
                if t - sc_last["osc"] > 2.0:
                    sc_cue += 1
                    sk.sendto(osc("/cmd", f"Go+ Sequence {sc_cue}"), ("127.0.0.1", 7000))
                    sk.sendto(osc("/composition/layers/1/clips/%d/connect" % (sc_cue % 4 + 1), 1), ("127.0.0.1", 7000))
                    sc_last["osc"] = t
            time.sleep(1 / 40)
    except KeyboardInterrupt:
        print("\nSimulator stopped.")


if __name__ == "__main__":
    main()
