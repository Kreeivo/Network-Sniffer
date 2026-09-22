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


def main():
    global TC_FPS, TC_NOMINAL, TC_RATE_CODE, TC_DROP
    ap = argparse.ArgumentParser(description="Art-Net + MTC simulator")
    ap.add_argument("--fps", choices=sorted(RATES), default="25",
                    help="timecode rate: 24, 25, 30 or df (29.97 drop-frame)")
    ap.add_argument("--flag", choices=sorted(RATES), default=None,
                    help="put a different rate in the MTC rate flag (to test detection)")
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
    seq = 0
    last_reply = 0.0
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
            time.sleep(1 / 40)
    except KeyboardInterrupt:
        print("\nSimulator stopped.")


if __name__ == "__main__":
    main()
