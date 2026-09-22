"""
Art-Net traffic simulator - for testing the Inspector with NO hardware.

Run this in a second terminal while app.py is running and the dashboard
will light up with two fake devices ("FOH-CONSOLE" and "PIXEL-NODE-1")
and three universes of moving DMX data at ~40 fps.

    python simulator.py

Everything stays on 127.0.0.1 - nothing is sent onto your real network.
Stop it with Ctrl+C.
"""
import socket
import struct
import time

ARTNET_ID = b"Art-Net\x00"
OP_POLL_REPLY = 0x2100
OP_DMX = 0x5000
TARGET = ("127.0.0.1", 6454)


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


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    node = poll_reply("127.0.0.1", "PIXEL-NODE-1",
                      "Backstage 8-port Art-Net Node", 0x00,
                      bytes([0xAA, 0xBB, 0xCC, 0x01, 0x02, 0x03]),
                      out_unis=(0, 1, 2))
    print("Simulator running - sending fake Art-Net to 127.0.0.1:6454")
    print("Open the dashboard and you should see PIXEL-NODE-1 with 3 universes.")
    print("Ctrl+C to stop.")
    seq = 0
    last_reply = 0.0
    try:
        while True:
            if time.time() - last_reply > 4:
                s.sendto(node, TARGET)
                last_reply = time.time()
            for uni in (0, 1, 2):
                s.sendto(dmx(uni, seq), TARGET)
            seq += 1
            time.sleep(1 / 40)
    except KeyboardInterrupt:
        print("\nSimulator stopped.")


if __name__ == "__main__":
    main()
