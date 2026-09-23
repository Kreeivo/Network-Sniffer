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
- **Timecode (MTC) monitor** — passively listens for MIDI Time Code on the
  network and shows a big rolling HH:MM:SS:FF clock per timecode master,
  with its frame rate, transport and whether it is rolling, parked or
  lost. Covers Art-Net timecode (ArtTimeCode), ipMIDI multicast and,
  optionally, RTP-MIDI/AppleMIDI; network-MIDI sessions announced over
  mDNS are listed by name.
- **Show control visibility (ShowKontrol, TCNet, Pro DJ Link, OSC)** —
  every show-control participant that announces itself, and every stream
  of show-control packets with where it comes *from* and where it goes
  *to*, decoded: TCNet nodes with vendor/app/version and master/slave
  role, the master's running layer times; Pro DJ Link players and mixers
  with BPM, pitch and beat; OSC addresses and arguments.
- **Live network map** — this computer → switch → every device, with lines
  that animate while data is actually flowing on that link — cyan for
  DMX, purple for show control.
- **Other LAN devices** — a best-effort ping + ARP scan surfaces
  non-Art-Net gear (show-control PCs, media servers, managed switches)
  with hostname and vendor where available.
- **Show-safe** — passive by design. It never sends DMX or MIDI, only tiny
  ArtPoll discovery packets (the same thing every console sends) and
  pings. It binds the Art-Net port in shared mode, so it can run on the
  same machine as your console or visualiser software without interfering.

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
DMX at 40 fps; the timecode panel starts rolling at 25 fps from two
transports at once (Art-Net timecode and ipMIDI bus 1); and a fake
ShowKontrol rig — **SHOWKTRL** as the TCNet master with two layers
running, a grandMA3 as a TCNet slave, two CDJ-3000s and a DJM on Pro DJ
Link beating at 128 BPM, and OSC cues — each from its own 127.0.0.x
address, so the show-control panel and the purple lines on the map light
up too.

**To change the timecode frame rate**, open `simulator.py` and edit the
`SETTINGS` block at the very top — `TIMECODE_FPS = "25"` takes `"24"`,
`"25"`, `"30"` or `"df"` (29.97 drop-frame). The same block has
`TIMECODE_FLAG` (make the simulator lie in its rate flag so you can watch
the inspector work out the real rate), `SHOW_CONTROL` and `DJ_BPM`.
Command-line flags override the block for a one-off run:
`python simulator.py --fps 30`, `--flag 24`, `--no-show-control`.
Everything stays
on this machine — the Art-Net goes to 127.0.0.1 and the ipMIDI multicast
is sent with TTL 0, so nothing touches your real network. Ctrl+C to stop.

---

## Options

```
python app.py --port 9000        # different dashboard port
python app.py --no-lan-scan     # skip the ping/ARP sweep (Art-Net only)
python app.py --poll-interval 10 # ArtPoll every 10 s instead of 5
python app.py --preferred-mtc-ip 10.0.0.5   # headline this timecode master (see below)
python app.py --mtc-hold 10      # keep the clock on a master for 10 s after signal loss
python app.py --ipmidi-buses 8   # watch ipMIDI buses 1-8 (default 1-4)
python app.py --rtp-midi         # also listen on RTP-MIDI ports 5004/5005
python app.py --no-mdns          # don't listen for network-MIDI announcements
python app.py --no-mtc           # turn the timecode listeners off entirely
python app.py --osc-ports 8000,9001   # OSC ports to watch (default 7000,7001,8000,9000,53000; 'none' to skip)
python app.py --no-tcnet         # don't listen for TCNet / ShowKontrol
python app.py --no-pro-dj-link   # don't listen for Pioneer Pro DJ Link
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
- **Timecode (MTC) on the network** — the big clock is the master that is
  currently rolling (violet), or the last one heard. Amber means the master
  is still sending but the clock isn't moving (a parked deck or a stopped
  transport); grey means the signal has gone. The table below lists every
  master by transport, so you can see at a glance whether your Art-Net
  timecode and your ipMIDI feed agree. If more than one master is on the
  wire, type the IP of the one you care about into **Preferred master**
  (top right of the panel, or `--preferred-mtc-ip` at launch). It's a
  preference, not a lock: while that IP has signal the big clock follows
  it; if it goes quiet the clock falls back to another source and the
  panel says so in amber ("10.0.0.5 silent — showing 10.0.0.9"); when it
  comes back, the clock returns to it. The settings are shared by every
  open dashboard, so the FOH tablet shows the same choice as the PC.
- **Hold** (next to it, or `--mtc-hold`) is the switch-over delay: the
  clock stays on its current master for that many seconds after the
  signal stops — counting down in red ("signal lost — holding 3 s before
  switching") — before another master may take over. The choice is made
  once, on the server, and is sticky: two masters in lock-step, two
  parked masters, or one device sending timecode on two transports will
  never make the clock flip between them. Without a preference the
  clock only leaves its master when it has been silent for the hold
  time, or has stood still for the hold time while another master is
  rolling.
- **Frame rate is read from the timecode itself**, not from the sender's
  rate flag: 24, 25 and 30 fps are told apart from the frame numbers
  after a couple of seconds of rolling, and 29.97 drop-frame is
  confirmed the first time a minute boundary rolls past (drop-frame
  skips frames 00 and 01 there). Until then the flag's word is shown and
  marked as such. A master whose flag disagrees with its numbers is still
  displayed, at the real rate, with a ⚠ and the flagged value in the
  tooltip — so a console set to 24 fps that is actually chasing 30 fps
  timecode is caught rather than hidden. The rate the clock is running
  at, in frames per wall-clock second, sits next to it while rolling.
- **The digits run at the frame rate**, not at the dashboard's refresh
  rate. The browser gets each master's last frame and its age, then
  advances its own clock at the detected rate between updates, the way a
  hardware timecode display freewheels between reads — so a 25 fps
  master counts 0, 1, 2… on screen rather than jumping a dozen frames
  twice a second. Each update trims the local clock's rate by a few
  percent to absorb any drift instead of stepping it, so a frame is never
  skipped or shown twice; only a real jump (the master locating) re-syncs
  outright. A parked master's digits stand still. "Format" tells you whether a MIDI
  source is sending quarter-frame MTC (rolling) or full-frame messages
  (locate/park). The chips underneath are network-MIDI (RTP-MIDI)
  sessions that have announced themselves over mDNS, by their session
  name — useful for confirming a Mac or a MIDI-over-Ethernet box is on
  the network even before it starts sending timecode.
- **Show control on the network** — the left side lists every
  participant that has announced itself: TCNet nodes (ShowKontrol shows
  up here as a TCNet *Master* with its vendor, app and version; consoles
  and media servers that speak TCNet appear as *Slaves*) with the
  master's layers and their running times, and Pro DJ Link gear (CDJs,
  the DJM, rekordbox) with device number, MAC, and live BPM / pitch /
  beat-in-bar. The right side is the traffic: each row is one stream
  from a source to a destination — *everyone* (broadcast), a multicast
  group, *this computer*, or a specific device — with the protocol,
  message type (or OSC address), rate and the last decoded content. On
  the map, every device that is sending show control right now gets a
  **purple glowing line**, the hub glows purple while anything is being
  broadcast, and a unicast stream between two devices on the map is
  drawn as a direct purple line between them.
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
- **What show-control traffic is visible:** ShowKontrol's own protocol,
  TCNet, is broadcast (OptIn on UDP 60000, the master's Time on 60001),
  and so is Pro DJ Link (keep-alives on 50000, beats on 50001), so this
  machine sees all of it through any switch. TCNet's unicast Data
  packets, and OSC / UDP commands sent point-to-point from ShowKontrol
  to a console, are only visible when they are aimed at this machine or
  at broadcast — that's the same physics as unicast DMX. The OSC ports
  are opened without sharing, so if a console or media server on this PC
  already owns one it is simply skipped (the startup banner says so).
  The "to" address is read straight off each packet on Linux and macOS;
  Windows can't report it, so there the destination reads "this
  computer / broadcast". TCNet layer decoding covers the fields TC Supply
  documents publicly (running time, state, beat, SMPTE mode); anything
  beyond that is shown as raw message types and counts rather than
  guessed at.
- **Which timecode transports are visible:** Art-Net timecode is broadcast
  and ipMIDI is multicast, so this machine sees both through any switch
  with nothing to configure. RTP-MIDI (Apple Network MIDI, most
  MIDI-over-Ethernet boxes) is different: it is a *unicast* session between
  two endpoints, so it can only be observed on a machine that is one of
  those endpoints — and there your MIDI software normally owns the port.
  That's why `--rtp-midi` is off by default; turn it on when this PC is
  the session partner and nothing else has UDP 5004/5005 open. The tool
  never takes those ports in shared mode, so it can't steal MIDI packets
  from your console software. Quarter-frame MTC is displayed two frames
  ahead of the value carried in the messages, as the MIDI spec intends,
  so it lines up with the Art-Net clock.
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
