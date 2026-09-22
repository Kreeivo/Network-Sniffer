# DMX / Art-Net Network Inspector

A passive, live dashboard for lighting networks. Run it on the lighting
computer and open a browser — it shows every Art-Net device on the network
with its configured name, plus a live feed of how much data is moving and
where it's coming from.

**What you get**

- **Device discovery with real names** — broadcasts ArtPoll and reads the
  ArtPollReply from every node/console, so you see the name each device is
  configured with, its IP, MAC, type (node / controller / media server) and
  which universes it has patched.
- **Live traffic feed** — total network bandwidth with a rolling graph,
  plus per-device and per-universe rates: frame rate (fps), active channel
  count, and kB/s, updated twice a second over a WebSocket.
- **Live network map** — this computer → switch → every device, with lines
  that animate while data is actually flowing on that link.
- **Other LAN devices** — a best-effort ping + ARP scan surfaces
  non-Art-Net gear (show-control PCs, media servers, managed switches)
  with hostname and vendor where available.
- **Show-safe** — passive by design. It never sends DMX, only tiny ArtPoll
  discovery packets (the same thing every console sends) and pings. It
  binds the Art-Net port in shared mode, so it can run on the same machine
  as your console or visualiser software without interfering.

---

## Installation (step by step)

### 1. Install Python

You need Python 3.9 or newer.

- **Windows:** download from https://www.python.org/downloads/ and run the
  installer. **Tick "Add Python to PATH"** on the first screen.
- **macOS:** `brew install python` or the python.org installer.
- **Linux:** usually already installed (`python3 --version` to check).

### 2. Get the files onto the lighting computer

Copy the `dmx-artnet-inspector` folder anywhere, e.g. your Desktop or
`C:\ArtNetInspector`.

### 3. Install the dependencies

Open a terminal (Windows: press Start, type `cmd`, Enter) and run:

```
cd path\to\dmx-artnet-inspector
pip install -r requirements.txt
```

(macOS/Linux: use `pip3` and forward slashes.)

That installs three small libraries: FastAPI + Uvicorn (the web server)
and psutil (to read your network interfaces). No drivers, no admin rights.

### 4. Run it

```
python app.py
```

You'll see:

```
==============================================================
  DMX / Art-Net Network Inspector
  Dashboard:  http://localhost:8058
              http://10.0.0.5:8058   (from other devices)
  Listening:  UDP 6454 (Art-Net), passive
==============================================================
```

### 5. Open the dashboard

Open **http://localhost:8058** in any browser on that machine — or use the
second address from a tablet/laptop on the same network (handy at FOH).

### 6. Windows firewall (first run only)

Windows will pop up a firewall prompt for Python the first time. Tick
**Private networks** and click **Allow access** — that lets the tool
receive Art-Net packets (UDP 6454) and serve the dashboard (TCP 8058).
If you skipped the prompt: Windows Security → Firewall → Allow an app
through firewall → allow Python on private networks.

---

## Try it with no hardware attached

Want to see it working before you plug into the show network? In a second
terminal:

```
python simulator.py
```

A fake node called **PIXEL-NODE-1** appears with three universes of moving
DMX at 40 fps. Everything stays on 127.0.0.1 — nothing touches your real
network. Ctrl+C to stop.

---

## Options

```
python app.py --port 9000        # different dashboard port
python app.py --no-lan-scan     # skip the ping/ARP sweep (Art-Net only)
python app.py --poll-interval 10 # ArtPoll every 10 s instead of 5
```

---

## Reading the dashboard

- **Header** — total bytes/s and packets/s across all Art-Net traffic the
  machine can see, with a rolling 60-second graph.
- **Live network map** — amber-outlined boxes are Art-Net devices; plain
  boxes are other LAN devices; red outline means it has gone quiet. A
  glowing dashed line means data is flowing on that link right now.
- **Art-Net devices** — one card per device. `U0 out` chips are the
  universes that device outputs (to fixtures); `in` chips are inputs. The
  amber left edge means it answered a poll recently; red means offline.
- **DMX universes on the wire** — every universe currently being
  transmitted, who is sending it, at what frame rate (consoles typically
  sit around 30–44 fps), how many of its channels are above zero, and its
  bandwidth.
- **Other devices** — everything else that answered a ping on the subnet.

## Good to know

- **Your switch:** a plain unmanaged switch has no IP address, so no
  software on earth can list it directly — it's invisible at that network
  layer. That's why the map shows it as an implied "switch / LAN" hub.
  A *managed* switch (one with a management web page) will show up in
  "Other devices" via its management IP.
- **Traffic scope:** Art-Net is normally broadcast, so this machine sees
  all of it through a standard switch. Data sent *unicast between two
  other devices* (not through this PC) is invisible to any tool without a
  managed switch's port-mirroring feature — that's physics, not a bug.
- **ShowKontrol / other protocols:** if it speaks Art-Net it'll appear
  with full detail; otherwise it appears in "Other devices" from the LAN
  scan with its hostname.
- **Coexistence:** safe to run next to your console software on the same
  machine — the Art-Net port is opened in shared (reuse) mode.

## Troubleshooting

- **No devices appear:** check this PC has an IP in the same range as your
  nodes (Art-Net gear commonly lives on 2.x.x.x/8 or 10.x.x.x — set a
  static IP on the lighting NIC accordingly), and that the firewall
  allowed Python.
- **Dashboard unreachable from tablet:** allow TCP 8058 through the
  firewall, and make sure the tablet is on the same network.
- **"Address already in use" on start:** something has UDP 6454 open
  exclusively. Close other Art-Net monitor tools and retry (consoles that
  use shared mode are fine).
