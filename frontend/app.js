/* Art-Net Inspector dashboard — vanilla JS, no external libraries so it
   works on fully offline show networks. */

"use strict";

const $ = (id) => document.getElementById(id);
const SVG_NS = "http://www.w3.org/2000/svg";

/* ---------------- formatting helpers ---------------- */

function fmtBytes(bps) {
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " MB/s";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " kB/s";
  return Math.round(bps) + " B/s";
}
function fmtUptime(s) {
  s = Math.floor(s);
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  return h > 0 ? `${h}:${String(m).padStart(2, "0")}:${String(sec).padStart(2, "0")}`
               : `${m}:${String(sec).padStart(2, "0")}`;
}
function esc(t) {
  const d = document.createElement("div");
  d.textContent = t == null ? "" : String(t);
  return d.innerHTML;
}

/* ---------------- traffic sparkline ---------------- */

const sparkHistory = [];
function drawSpark() {
  const c = $("spark");
  if (!c) return;
  const ctx = c.getContext("2d");
  const w = c.width, h = c.height;
  ctx.clearRect(0, 0, w, h);
  if (sparkHistory.length < 2) return;
  const max = Math.max(...sparkHistory, 1);
  ctx.beginPath();
  sparkHistory.forEach((v, i) => {
    const x = (i / (sparkHistory.length - 1)) * (w - 8) + 4;
    const y = h - 6 - (v / max) * (h - 14);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.strokeStyle = "#43c6c0";
  ctx.lineWidth = 1.6;
  ctx.stroke();
  // fill under the line
  ctx.lineTo(w - 4, h - 4); ctx.lineTo(4, h - 4); ctx.closePath();
  ctx.fillStyle = "rgba(67,198,192,0.12)";
  ctx.fill();
}

/* ---------------- device cards ---------------- */

function renderDevices(devices) {
  const list = $("device-list");
  $("device-count").textContent =
    devices.length ? `${devices.length} found` : "";
  if (!devices.length) {
    list.innerHTML = `<div class="empty">No Art-Net devices found yet. Polling the network every few seconds — replies appear here automatically.</div>`;
    return;
  }
  list.innerHTML = devices.map((d) => {
    const name = d.short_name || d.long_name || d.ip;
    const cls = !d.online ? "offline" : (d.identified ? "" : "unidentified");
    const styleTxt = d.identified ? esc(d.style) : "unidentified sender";
    const long = d.long_name && d.long_name !== name
      ? `<div class="device-long">${esc(d.long_name)}</div>` : "";
    const chips =
      d.output_universes.map((u) => `<span class="chip out">U${u} out</span>`).join("") +
      d.input_universes.map((u) => `<span class="chip in">U${u} in</span>`).join("");
    const report = d.node_report
      ? `<span title="${esc(d.node_report)}">report: <b>${esc(d.node_report.slice(0, 34))}${d.node_report.length > 34 ? "…" : ""}</b></span>` : "";
    return `
    <div class="device ${cls}">
      <div class="device-top">
        <span class="device-name">${esc(name)}</span>
        <span class="device-style">${styleTxt}</span>
      </div>
      ${long}
      <div class="device-meta">
        <span class="mono"><b>${esc(d.ip)}</b></span>
        ${d.mac ? `<span class="mono">${esc(d.mac)}</span>` : ""}
        <span class="mono device-rate">${fmtBytes(d.bytes_per_sec)} · ${d.packets_per_sec.toFixed(0)} pkt/s</span>
        ${report}
      </div>
      ${chips ? `<div class="uni-chips">${chips}</div>` : ""}
    </div>`;
  }).join("");
}

/* ---------------- universe table ---------------- */

function renderUniverses(unis) {
  const tbody = $("universe-table").querySelector("tbody");
  $("universe-count").textContent = unis.length ? `${unis.length} active` : "";
  if (!unis.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="6">No ArtDmx traffic seen yet. Start output from your console and universes appear here live.</td></tr>`;
    return;
  }
  const maxB = Math.max(...unis.map((u) => u.bytes_per_sec), 1);
  tbody.innerHTML = unis.map((u) => `
    <tr>
      <td class="mono">U${u.universe}</td>
      <td class="mono">${esc(u.source_ip)}</td>
      <td class="mono">${u.fps.toFixed(1)} fps</td>
      <td class="mono">${u.active_channels} / ${u.last_length}</td>
      <td class="mono">
        <span class="bar" style="width:${Math.max(3, (u.bytes_per_sec / maxB) * 90)}px"></span>
        ${fmtBytes(u.bytes_per_sec)}
      </td>
      <td><span class="pill ${u.online ? "" : "off"}"></span></td>
    </tr>`).join("");
}

/* ---------------- timecode (MTC) panel ---------------- */

let tcLeadKey = null;

function tcStateOf(s) {
  if (!s.online) return "off";
  return s.running ? "running" : "holding";
}

function renderTimecode(snap) {
  const sources = snap.timecode || [];
  const hero = document.querySelector(".tc-hero");
  const listeners = snap.timecode_listeners || [];
  $("tc-listeners").textContent = listeners.length
    ? "listening: " + listeners.join(" · ") : "timecode listeners disabled";

  // Headline clock: stick with the master we showed last time while it is
  // still rolling, so two masters in lock-step don't flicker; otherwise the
  // longest-established rolling source, else whoever we heard from last
  // (the list arrives sorted by last_seen).
  const keyOf = (s) => `${s.transport}|${s.ip}`;
  const rolling = sources.filter((s) => s.running);
  let lead = rolling.find((s) => keyOf(s) === tcLeadKey);
  if (!lead) lead = rolling.sort((a, b) => a.first_seen - b.first_seen)[0] || sources[0];
  tcLeadKey = lead ? keyOf(lead) : null;
  hero.classList.remove("running", "holding");
  if (!lead) {
    $("tc-clock").textContent = "--:--:--:--";
    $("tc-source").textContent = "No timecode seen yet";
    $("tc-detail").textContent = "Start your timecode master — Art-Net timecode and ipMIDI appear here automatically.";
    $("tc-state-text").textContent = "no signal";
  } else {
    const state = tcStateOf(lead);
    if (state !== "off") hero.classList.add(state);
    $("tc-clock").textContent = lead.timecode;
    $("tc-source").textContent = lead.name ? `${lead.name}  (${lead.ip})` : lead.ip;
    $("tc-detail").textContent = `${lead.transport} · ${lead.rate} · ${lead.kind}`;
    $("tc-state-text").textContent =
      state === "running" ? "rolling" :
      state === "holding" ? "holding — master is sending but the clock isn't moving" :
      "signal lost";
  }

  const tbody = $("tc-table").querySelector("tbody");
  if (!sources.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="8">No MTC on the wire yet.</td></tr>`;
  } else {
    tbody.innerHTML = sources.map((s) => {
      const state = tcStateOf(s);
      const cls = state === "running" ? "" : state === "holding" ? " hold" : " off";
      return `
      <tr>
        <td>${esc(s.name || "—")}</td>
        <td class="mono">${esc(s.ip)}</td>
        <td>${esc(s.transport)}</td>
        <td class="mono tc-cell${cls}"><b>${esc(s.timecode)}</b></td>
        <td class="mono">${esc(s.rate)}</td>
        <td>${esc(s.kind)}</td>
        <td class="mono">${s.updates_per_sec.toFixed(1)} /s</td>
        <td><span class="pill ${s.online ? "" : "off"}"></span></td>
      </tr>`;
    }).join("");
  }

  const eps = snap.midi_endpoints || [];
  $("midi-endpoints").innerHTML = eps.length
    ? eps.map((e) => `<span class="chip midi ${e.online ? "" : "off"}" title="${esc(e.source)}${e.port ? " · port " + e.port : ""}">${esc(e.name || e.ip)}${e.name ? ` <span class="mono">${esc(e.ip)}</span>` : ""}</span>`).join("")
    : `<span class="hint">none heard yet</span>`;
}

/* ---------------- LAN table ---------------- */

function renderLan(devs) {
  const tbody = $("lan-table").querySelector("tbody");
  if (!devs.length) {
    tbody.innerHTML = `<tr class="empty-row"><td colspan="5">Scanning the subnet… nothing else answered yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = devs.map((d) => `
    <tr>
      <td>${esc(d.hostname || "—")}</td>
      <td class="mono">${esc(d.ip)}</td>
      <td class="mono">${esc(d.mac || "—")}</td>
      <td>${esc(d.vendor || "—")}</td>
      <td><span class="pill ${d.online ? "" : "off"}"></span></td>
    </tr>`).join("");
}

/* ---------------- topology map ---------------- */

function svgEl(tag, attrs, text) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const k in attrs) el.setAttribute(k, attrs[k]);
  if (text != null) el.textContent = text;
  return el;
}

function renderTopology(snap) {
  const svg = $("topo");
  svg.innerHTML = "";
  const known = new Set([...snap.devices, ...snap.lan_devices].map((d) => d.ip));
  const tcOnly = [];
  for (const s of snap.timecode || []) {
    if (!known.has(s.ip)) { known.add(s.ip); tcOnly.push(s); }
  }
  const shownCount = Math.min(9, snap.devices.length + tcOnly.length + snap.lan_devices.length);
  const W = 900, H = Math.max(240, shownCount * 62 + 130);
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);

  // Everything visible on the LAN, Art-Net devices first, then timecode
  // masters heard over MIDI, then the rest of the LAN.
  const nodes = [
    ...snap.devices.map((d) => ({
      label: d.short_name || d.long_name || d.ip,
      sub: d.ip,
      active: d.bytes_per_sec > 1,
      online: d.online,
      artnet: true,
    })),
    ...tcOnly.map((s) => ({
      label: s.name || s.ip,
      sub: `${s.ip} · ${s.transport}`,
      active: s.online,
      online: s.online,
      artnet: false,
      timecode: true,
    })),
    ...snap.lan_devices.map((d) => ({
      label: d.hostname || d.vendor || d.ip,
      sub: d.ip,
      active: false,
      online: d.online,
      artnet: false,
    })),
  ];
  const MAX = 9;
  const extra = nodes.length - MAX;
  const shown = nodes.slice(0, MAX);

  const pcX = 120, hubX = 400, devX = 690;
  const midY = H / 2;

  // This computer
  svg.appendChild(svgEl("rect", { x: pcX - 75, y: midY - 34, width: 150, height: 68, rx: 5, fill: "#22272d", stroke: "#2b3138" }));
  svg.appendChild(svgEl("text", { x: pcX, y: midY - 6, "text-anchor": "middle", class: "topo-label" }, "This computer"));
  svg.appendChild(svgEl("text", { x: pcX, y: midY + 14, "text-anchor": "middle", class: "topo-sub" },
    (snap.local_ips && snap.local_ips[0]) || ""));

  // Switch / LAN hub (implied — an unmanaged switch has no IP to detect)
  svg.appendChild(svgEl("circle", { cx: hubX, cy: midY, r: 26, fill: "#22272d", stroke: "#2b3138", "stroke-width": 1.5 }));
  svg.appendChild(svgEl("text", { x: hubX, y: midY - 34, "text-anchor": "middle", class: "topo-sub" }, "switch / LAN"));

  const anyFlow = snap.global_bps > 5;
  svg.appendChild(svgEl("path", {
    d: `M ${pcX + 75} ${midY} H ${hubX - 26}`,
    class: "topo-link" + (anyFlow ? " flowing" : ""),
  }));

  if (!shown.length) {
    svg.appendChild(svgEl("text", { x: devX, y: midY, "text-anchor": "middle", class: "topo-sub" },
      "listening for devices…"));
    return;
  }

  const gap = Math.min(64, (H - 60) / shown.length);
  const startY = midY - ((shown.length - 1) * gap) / 2;

  shown.forEach((n, i) => {
    const y = startY + i * gap;
    const c1x = hubX + 120;
    svg.appendChild(svgEl("path", {
      d: `M ${hubX + 26} ${midY} C ${c1x} ${midY}, ${c1x} ${y}, ${devX - 78} ${y}`,
      class: "topo-link" + (n.active ? " flowing" : ""),
    }));
    const stroke = !n.online ? "#f26d6d" : (n.artnet ? "#ffb020" : n.timecode ? "#b58cff" : "#2b3138");
    svg.appendChild(svgEl("rect", { x: devX - 78, y: y - 22, width: 200, height: 44, rx: 5, fill: "#22272d", stroke, "stroke-width": (n.artnet || n.timecode) ? 1.6 : 1 }));
    const label = n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label;
    svg.appendChild(svgEl("text", { x: devX - 66, y: y - 2, class: "topo-label" }, label));
    svg.appendChild(svgEl("text", { x: devX - 66, y: y + 15, class: "topo-sub" }, n.sub));
  });

  if (extra > 0) {
    svg.appendChild(svgEl("text", { x: devX + 20, y: startY + shown.length * gap, class: "topo-sub" },
      `+ ${extra} more below`));
  }
}

/* ---------------- websocket live feed ---------------- */

let ws = null;
function connect() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    $("conn-led").classList.add("on");
    $("conn-text").textContent = "live";
  };
  ws.onclose = () => {
    $("conn-led").classList.remove("on");
    $("conn-text").textContent = "reconnecting…";
    setTimeout(connect, 1500);
  };
  ws.onerror = () => ws.close();

  ws.onmessage = (ev) => {
    let snap;
    try { snap = JSON.parse(ev.data); } catch { return; }
    if (snap.type !== "snapshot") return;

    $("stat-bps").textContent = fmtBytes(snap.global_bps);
    $("stat-pps").textContent = Math.round(snap.global_pps);
    $("stat-uptime").textContent = fmtUptime(snap.uptime);

    sparkHistory.push(snap.global_bps);
    if (sparkHistory.length > 120) sparkHistory.shift();
    drawSpark();

    renderDevices(snap.devices);
    renderUniverses(snap.universes);
    renderTimecode(snap);
    renderLan(snap.lan_devices);
    renderTopology(snap);
  };
}
connect();
