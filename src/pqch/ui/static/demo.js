/* The stage. One document from /api/demo, drawn beat by beat with d3; every number on screen is
   that document's. Keys: → ← 1–8 F S N L ↑ ↓ ?. Nothing here decides anything: the scan is the
   page's own /scan, the narration is one timed model call per row, the proof is the ledger's. */
(function () {
  "use strict";
  const stage = document.getElementById("stage");
  const beats = Array.from(document.querySelectorAll(".beat"));
  const names = beats.map(b => b.dataset.beat);
  let D = null, at = 0, t0 = null, clockTimer = null;
  const done = new Set();
  const fmt = n => (n == null ? "—" : Number(n).toLocaleString("en-US"));
  const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]));
  const sel = id => document.getElementById(id);

  // ───────── load, navigate, keys ─────────
  // a script error on stage says so in the corner instead of leaving a beat blank
  const sayError = msg => { const b = document.getElementById("stage-errors"); if (!b) return; b.hidden = false; const d = document.createElement("div"); d.textContent = msg; b.appendChild(d); while (b.children.length > 4) b.removeChild(b.firstChild); };
  window.addEventListener("error", e => sayError(`${e.message} (${(e.filename || "").split("/").pop()}:${e.lineno})`));
  window.addEventListener("unhandledrejection", e => sayError(`unhandled: ${e.reason && e.reason.message || e.reason}`));
  const SNAP = !!window.__SNAP;   // a still: no transitions, simulations settled before the first paint
  if (SNAP) { const st = document.createElement("style"); st.textContent = ".beat, .setup div, .bignums div, .layer, .host, .term .ln, .chain .ev, .arch .band, .arch .box, .arch .tape div, .proof .step, .pipeline .pstage, .mv, .ch-dot, .ch-ent, .ch-link { animation: none !important; transition: none !important; } .setup div, .bignums div, .layer, .host, .term .ln, .chain .ev, .arch .band, .arch .tape div { opacity: 1 !important; transform: none !important; } .beat { display: none; }"; document.head.appendChild(st); document.body.classList.add("fullscreen"); }
  const T = ms => (SNAP ? 0 : ms);     // every delay and duration passes through here
  // a static copy (the public demo): nothing is fetched from an app; what the stage would fetch is in the document
  const STATIC = !!window.__STATIC, BASE = window.__BASE || "/";
  const ST = () => (D && D.static) || {};
  window.addEventListener("error", e => { const d = document.createElement("pre"); d.className = "jserr"; d.textContent = `page error: ${e.message} (${(e.filename || "").split("/").pop()}:${e.lineno})`; document.body.appendChild(d); });
  (window.__DEMO ? Promise.resolve(window.__DEMO) : fetch("/api/demo").then(r => r.json())).then(d => {
    D = d;
    const l = sel("stage-loading"); if (l) l.remove();
    buildBar();
    const h = location.hash.replace("#", "");
    go(Math.max(0, names.indexOf(h)));
  }).catch(e => { const l = sel("stage-loading"); if (l) l.textContent = "Could not read /api/demo: " + e; });

  sel("btn-next").addEventListener("click", ev => { ev.preventDefault(); go(at + 1); });
  sel("btn-back").addEventListener("click", ev => { ev.preventDefault(); go(at - 1); });
  function go(n) {
    if (n > 0) sel("keys").hidden = true;
    at = Math.max(0, Math.min(beats.length - 1, n));
    beats.forEach((b, k) => b.classList.toggle("on", k === at));
    if (!t0 && at > 0) startClock();
    for (let k = 0; k < at; k++) done.add(k);
    updateBar();
    history.replaceState(null, "", "#" + names[at]);
    render(names[at]);
  }
  document.addEventListener("keydown", ev => {
    if (ev.target && /input|textarea/i.test(ev.target.tagName)) return;
    const k = ev.key;
    if (k === "ArrowRight" || k === " " || k === "PageDown") { ev.preventDefault(); go(at + 1); }
    else if (k === "ArrowLeft" || k === "PageUp") { ev.preventDefault(); go(at - 1); }
    else if (/^[1-8]$/.test(k)) go(Number(k) - 1);
    else if (k === "f" || k === "F") fullscreen();
    else if (k === "s" || k === "S") startScan();
    else if (k === "n" || k === "N") narrateNext();
    else if (k === "a" || k === "A") askNext();
    else if (k === "l" || k === "L") approveLive();
    else if (k === "ArrowUp" || k === "ArrowDown") { if (names[at] === "cbom") { ev.preventDefault(); walk(k === "ArrowDown" ? 1 : -1); } }
    else if (k === "?") { const b = sel("keys"); b.hidden = !b.hidden; }
    else if (k === "Escape") { const b = sel("keys"); b.hidden = true; }
  });
  function fullscreen() {
    const b = document.body;
    if (!document.fullscreenElement) { (document.documentElement.requestFullscreen || function () {}).call(document.documentElement); b.classList.add("fullscreen"); }
    else { (document.exitFullscreen || function () {}).call(document); b.classList.remove("fullscreen"); }
    setTimeout(() => render(names[at], true), 350);
  }
  document.addEventListener("fullscreenchange", () => { if (!document.fullscreenElement) document.body.classList.remove("fullscreen"); });

  function buildBar() {
    const bar = sel("beatbar"); bar.innerHTML = "";
    beats.forEach((b, k) => {
      const a = document.createElement("a"); a.href = "#" + b.dataset.beat; a.title = b.dataset.beat;
      a.innerHTML = `<span>${k + 1} ${esc(b.dataset.beat)}</span>`;
      a.addEventListener("click", ev => { ev.preventDefault(); go(k); });
      bar.appendChild(a);
    });
    const c = document.createElement("span"); c.className = "clock"; c.id = "clock"; c.textContent = "0:00 / 8:00"; bar.appendChild(c);
  }
  function updateBar() {
    Array.from(sel("beatbar").querySelectorAll("a")).forEach((a, k) => { a.classList.toggle("on", k === at); a.classList.toggle("done", done.has(k) && k !== at); });
  }
  function startClock() {
    t0 = Date.now();
    clockTimer = setInterval(() => {
      const s = Math.floor((Date.now() - t0) / 1000), c = sel("clock");
      if (!c) return;
      c.textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")} / 8:00`;
      c.classList.toggle("over", s > 480);
    }, 1000);
  }

  // ───────── renderers ─────────
  const drawn = {};
  function render(name, again) {
    if (!D) return;
    if (drawn[name] && !again) return;
    drawn[name] = true;
    ({why, arch, scan, plan, cbom, change, ask, record: closing})[name]();
  }

  // gauges: three arcs for the answer-key score
  function gauges(el, score) {
    el.innerHTML = "";
    const w = (score && score.columns && score.columns.workbench) || null;
    if (!w) { el.innerHTML = `<p class="foot">No scored run yet: run the scan.</p>`; return; }
    const items = [
      {lab: "on the wire", num: w.wire.covered, of: w.wire.of, sub: `${w.wire.false_positives || 0} false positives`},
      {lab: "in the files", num: w.host.covered, of: w.host.of, sub: `${w.host.false_positives || 0} false positives`},
      {lab: "posture", num: w.posture ? w.posture.correct : null, of: w.posture ? w.posture.total : null, sub: "listeners judged right"},
    ];
    items.forEach((it, k) => {
      const g = document.createElement("div"); g.className = "gauge";
      g.innerHTML = `<svg viewBox="0 0 220 130" role="img" aria-label="${esc(it.lab)}: ${it.num == null ? "not measured" : esc(String(it.num)) + " of " + esc(String(it.of))}"></svg><div class="num">0<small> of ${fmt(it.of)}</small></div><div class="lab">${esc(it.lab)}</div><div class="sub">${esc(it.sub)}</div>`;
      el.appendChild(g);
      const svg = d3.select(g).select("svg");
      const arc = d3.arc().innerRadius(78).outerRadius(96).startAngle(-Math.PI / 2);
      svg.append("path").attr("transform", "translate(110,118)").attr("d", arc({endAngle: Math.PI / 2})).attr("fill", "rgba(255,255,255,.08)");
      const p = svg.append("path").attr("transform", "translate(110,118)").attr("fill", "#00a3cc");
      const num = g.querySelector(".num");
      const frac = it.of ? (it.num || 0) / it.of : 0;
      if (SNAP) { p.attr("d", arc({endAngle: -Math.PI / 2 + Math.PI * frac})); num.innerHTML = `${it.num || 0}<small> of ${fmt(it.of)}</small>`; return; }
      p.transition().delay(T(300 + k * 250)).duration(T(1400)).ease(d3.easeCubicOut)
        .attrTween("d", () => t => arc({endAngle: -Math.PI / 2 + Math.PI * frac * t}))
        .tween("num", () => t => { num.innerHTML = `${Math.round((it.num || 0) * t)}<small> of ${fmt(it.of)}</small>`; });
    });
  }

  // a canvas sized to its box, crisp on any display
  function canvas(id) {
    const cv = sel(id), r = cv.getBoundingClientRect(), dpr = Math.min(2, window.devicePixelRatio || 1);
    cv.width = Math.round(r.width * dpr); cv.height = Math.round(r.height * dpr);
    const ctx = cv.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return {cv, ctx, W: r.width, H: r.height};
  }
  const C = {accent: "#00a3cc", red: "#e2543f", green: "#35d07f", fg: "#e8edf3", dim: "#8a97a8", nv: "#76b900"};
  function roundRect(ctx, x, y, w, h, r) { ctx.beginPath(); ctx.moveTo(x + r, y); ctx.arcTo(x + w, y, x + w, y + h, r); ctx.arcTo(x + w, y + h, x, y + h, r); ctx.arcTo(x, y + h, x, y, r); ctx.arcTo(x, y, x + w, y, r); ctx.closePath(); }

  // why a standalone box: the GB10 inside a sealed perimeter, its six jobs around it
  const CAPS = [
    ["scan the network", "Scanners in containers probe every listener on the wire, from this box.", "in"],
    ["read hosts whole", "A server's files, firmware and management controller, read as one estate.", "in"],
    ["build the CBOM", "Every component and dependency, projected from evidence on a signed ledger.", "out"],
    ["analyze with a local model", STATIC ? "A model the owner runs narrates, drafts and answers; it never decides a finding." : "Nemotron on this GPU narrates, drafts and answers; it never decides a finding.", "out"],
    ["compute the plan", "What comes first, by rules, from the owner's own facts.", "out"],
    ["prove each change", "Approved by a person, applied by the runner, verified by re-scan; the models, the data and the record never leave the box.", "out"],
  ];
  let heroAnim = null, storyTimers = [];
  function why() {
    storyTimers.forEach(clearTimeout); storyTimers = [];
    story(SNAP ? Number(new URLSearchParams(location.search).get("mv") || 3) : 0);
    hero();
  }
  // the story: the gap, the chain, the plan — the same dots, organized, top to bottom
  function story(stopAt) {
    const svg = d3.select("#story-svg"), bb = svg.node().getBoundingClientRect(), W = Math.round(bb.width) || 900, H = Math.round(bb.height) || 760;
    svg.attr("viewBox", `0 0 ${W} ${H}`).selectAll("*").remove();
    const c = (D.cbom || {}).counts || {}, sheet = (D.estate && D.estate.sheet) || [], P = D.plan || {}, rank = (P.ranking || []).map(r => r.service);
    const N = new Map(D.cbom.nodes.map(n => [n.id, n])), out = new Map();
    D.cbom.links.forEach(l => (out.get(l.source) || out.set(l.source, []).get(l.source)).push(l.target));
    // who owns what: the first service, in ranking order, that reaches a component
    const owner = new Map();
    rank.forEach(s => { const seen = new Set(); let fr = ["svc:" + s];
      for (let d = 0; d < 3; d++) { const nx = []; fr.forEach(x => (out.get(x) || []).forEach(y => { if (!seen.has(y)) { seen.add(y); nx.push(y); } })); fr = nx; }
      seen.forEach(id => { if (!owner.has(id)) owner.set(id, s); }); });
    const colOf = n => n.kind === "listener" || n.kind === "image" ? 2 : (n.kind === "related-crypto-material" && n.layer === "host") ? 4 : 3;
    const comps = D.cbom.nodes.filter(n => n.kind !== "service").map(n => ({...n, svc: owner.get(n.id) || null, col: colOf(n)}));
    const bands = {A: [0, H * 0.26], B: [H * 0.28, H * 0.62], C: [H * 0.64, H]};
    const lanes = rank.slice(0, 8), T0 = stopAt ? 0 : 1;
    const band = (k, y, label) => { svg.append("line").attr("class", "band-line").attr("x1", 0).attr("x2", W).attr("y1", y - 6).attr("y2", y - 6);
      return svg.append("text").attr("class", "band-k").attr("id", "bk-" + k).attr("x", 0).attr("y", y + 8).text(label); };
    // ── band A: the owner's sheet, and the spatter of what is actually there
    const [a0] = bands.A; band("A", a0 + 6, "1 · the starting point: one row per system, no link between rows, no date, over an estate that keeps changing");
    const rows = sheet.length ? sheet : d3.range(6).map(i => ({system: `row ${i + 1}`, says: ""})), rh = Math.min(22, (bands.A[1] - a0 - 56) / rows.length), sw = Math.min(470, W * 0.40);
    svg.append("text").attr("class", "col-k").attr("x", 0).attr("y", a0 + 30).text("the owner's spreadsheet");
    const scols = [["system", 0, d => d.system], ["owner", .36, d => d.owner || ""], ["crypto", .62, d => (d.says || "").slice(0, 26)]];
    const hg = svg.append("g").attr("transform", `translate(0,${a0 + 44})`);
    scols.forEach(([k, f]) => hg.append("text").attr("class", "col-k").attr("x", 2 + sw * f).attr("y", 8).text(k));
    hg.append("line").attr("x1", 0).attr("x2", sw).attr("y1", 13).attr("y2", 13).attr("stroke", "rgba(196,207,221,.35)");
    const rg = svg.append("g").selectAll("g").data(rows).join("g").attr("class", "sheet-row").attr("transform", (d, i) => `translate(0,${a0 + 58 + i * rh})`);
    rg.append("line").attr("x1", 0).attr("x2", sw).attr("y1", rh - 3).attr("y2", rh - 3);
    scols.forEach(([k, f, v], j) => rg.append("text").attr("class", j ? "says" : null).attr("x", 2 + sw * f).attr("y", 13).style("font-size", j ? "11px" : "11.5px").text(v));
    svg.append("text").attr("class", "col-k").attr("x", sw + 40).attr("y", a0 + 30).text("what is actually there, and keeps changing");
    const rnd = d3.randomLcg(5), x0 = sw + 44;
    comps.forEach(d => { d.ax = x0 + rnd() * (W - x0 - 10); d.ay = a0 + 38 + rnd() * (bands.A[1] - a0 - 54); });
    const aLab = svg.append("text").attr("class", "mark").attr("x", W - 4).attr("y", bands.A[1] - 4).attr("text-anchor", "end").attr("opacity", 0)
      .text(`${fmt(c.components)} components · ${fmt(c.quantum_vulnerable)} quantum-vulnerable · none a row, none linked, none dated`);
    // ── band B: the chain
    const [b0, b1] = bands.B; band("B", b0 + 6, "2 · the CBOM: every component tied to its service, with its dependencies recorded");
    const cols = [["services", 0.07], ["listeners and images", 0.33], ["assets", 0.62], ["files", 0.9]];
    cols.forEach(([k, f]) => svg.append("text").attr("class", "col-k").attr("x", W * f).attr("y", b0 + 34).attr("text-anchor", "middle").text(k));
    const sy = i => b0 + 50 + (i + 0.5) * (b1 - b0 - 58) / lanes.length;
    const svcs = lanes.map((s, i) => ({id: "svc:" + s, name: s, x: W * 0.07, y: sy(i)}));
    [2, 3, 4].forEach(col => { const mine = comps.filter(d => d.col === col).sort((p, q) => (lanes.indexOf(p.svc) - lanes.indexOf(q.svc)) || (q.qv - p.qv));
      const f = cols[col - 1][1], n = mine.length; mine.forEach((d, i) => { d.bx = W * f + (col === 2 ? 0 : (i % 5 - 2) * 11); d.by = b0 + 46 + (i + 0.5) * (b1 - b0 - 54) / Math.max(1, n); }); });
    const byId = new Map(comps.map(d => [d.id, d])); svcs.forEach(s => byId.set(s.id, {bx: s.x, by: s.y}));
    const links = D.cbom.links.map(l => ({s: byId.get(l.source), t: byId.get(l.target), svc: N.get(l.source) && N.get(l.source).kind === "service"})).filter(l => l.s && l.t && l.s.bx != null);
    const lg = svg.append("g"); const lk = lg.selectAll("path").data(links).join("path").attr("class", d => "chain-link" + (d.svc ? "" : " thin"))
      .attr("d", d => { const m = (d.s.bx + d.t.bx) / 2; return `M${d.s.bx},${d.s.by} C${m},${d.s.by} ${m},${d.t.by} ${d.t.bx},${d.t.by}`; }).attr("opacity", 0);
    const sg = svg.append("g").selectAll("g").data(svcs).join("g").attr("transform", d => `translate(${d.x},${d.y})`).attr("opacity", 0);
    sg.append("circle").attr("r", 6).attr("class", "node-service"); sg.append("text").attr("class", "node-label svc").attr("x", 10).attr("y", 4).text(d => d.name);
    const lis = comps.filter(d => d.kind === "listener"); const ll = svg.append("g").selectAll("text").data(lis).join("text").attr("class", "node-label").attr("x", d => d.bx + 8).attr("y", d => d.by + 3.5)
      .text(d => (d.name || "").replace(/172\.16\.106\./, ".")).attr("opacity", 0);
    const bLab = svg.append("text").attr("class", "mark").attr("x", W - 4).attr("y", b1 - 2).attr("text-anchor", "end").attr("opacity", 0).text(`${fmt(c.links)} dependencies, each from evidence on the ledger`);
    // ── band C: the plan
    const [c0, c1] = bands.C; band("C", c0 + 6, "3 · the plan: rules order the same components into steps, from the record; the local model drafts each change and explains it");
    const L = 118, laneH = (c1 - c0 - 46) / lanes.length, top = c0 + 36, waves = ["now", "2030", "2031"], wx = w => L + (W - L - 20) * ({now: 0.16, "2030": 0.5, "2031": 0.84}[w] || 0.5);
    waves.forEach(w => svg.append("text").attr("class", "col-k").attr("x", wx(w)).attr("y", c0 + 30).attr("text-anchor", "middle").text(w === "now" ? "now" : "by " + w));
    const order = (P.order || []).filter(s => s.service && lanes.includes(s.service)).map(s => ({...s}));
    lanes.forEach((s, i) => { const y = top + i * laneH; svg.append("line").attr("class", "band-line").attr("x1", L - 8).attr("x2", W - 10).attr("y1", y + laneH - 2).attr("y2", y + laneH - 2);
      svg.append("text").attr("class", "node-label svc").attr("x", 0).attr("y", y + laneH / 2 + 4).style("font-size", "11.5px").text(`${i + 1} · ${s}`);
      waves.forEach(w => { const here = order.filter(x => x.service === s && x.wave === w); here.forEach((x, k) => { x.x = wx(w) + (k - (here.length - 1) / 2) * 118; x.y = y + laneH / 2; }); }); });
    const stepById = new Map(order.map(s => [s.id, s]));
    const word = s => ({replace: "replace", enable: "offer hybrid", require: "require hybrid", reissue: "reissue (ML-DSA)", tls13: "TLS 1.3", ca: "new root", retire: "retire"})[s.kind] || s.kind;
    const perSvc = new Map(); comps.forEach(d => { const li = lanes.indexOf(d.svc); if (li < 0) { d.cx2 = L + 10 + rnd() * (W - L - 40); d.cy2 = c1 - 8; d.none = true; return; }
      const room = Math.min(120, wx("now") - 54 - L - 20); d.cx2 = L + 8 + rnd() * room; d.cy2 = top + li * laneH + 5 + rnd() * (laneH - 12); d.none = !order.some(x => x.service === d.svc); });
    const boxes = svg.append("g").selectAll("g").data(order).join("g").attr("transform", d => `translate(${d.x},${d.y})`).attr("opacity", 0);
    boxes.append("rect").attr("x", -54).attr("y", -10).attr("width", 108).attr("height", 20).attr("rx", 3).attr("fill", "rgba(12,17,23,.9)")
      .attr("stroke", d => d.state === "ready" ? "#00a3cc" : "rgba(196,207,221,.45)").attr("stroke-width", 1.2).attr("stroke-dasharray", d => d.state === "ready" ? null : "3 3");
    boxes.append("text").attr("class", "mark").attr("text-anchor", "middle").attr("y", 4).style("font-size", "10px").text(d => word(d));
    lanes.forEach((s, i) => { if (!order.some(x => x.service === s)) svg.append("text").attr("class", "mark dim").attr("id", "none-" + i).attr("x", W - 10).attr("y", top + i * laneH + laneH / 2 + 4).attr("text-anchor", "end").attr("fill", "#35d07f").attr("opacity", 0).text("nothing open · every item met"); });
    const deps = order.flatMap(s => (s.depends_on || []).map(d => stepById.get(d)).filter(Boolean).map(from => ({from, to: s})));
    const dp = svg.append("g").selectAll("path").data(deps).join("path").attr("fill", "none").attr("stroke", "rgba(0,163,204,.7)").attr("stroke-width", 1.2)
      .attr("d", d => { const x0 = d.from.x + 54, x1 = d.to.x - 54, m = (x0 + x1) / 2; return `M${x0},${d.from.y} C${m},${d.from.y} ${m},${d.to.y} ${x1},${d.to.y}`; });
    const cLab = svg.append("text").attr("class", "mark").attr("x", W - 4).attr("y", c1 - 2).attr("text-anchor", "end").attr("opacity", 0)
      .text(`${(P.order || []).length} steps in three waves · ${deps.length} dependencies · ordered by rules, drafted and explained by the local model`);
    // ── the dots, drawn last so they ride above the lines
    const ghostA = svg.append("g").selectAll("circle").data(comps).join("circle").attr("r", 2.2).attr("fill", d => d.qv ? "#e2543f" : "rgba(196,207,221,.7)").attr("cx", d => d.ax).attr("cy", d => d.ay).attr("opacity", 0);
    const ghostB = svg.append("g").selectAll("circle").data(comps).join("circle").attr("r", 2.2).attr("fill", d => d.qv ? "#e2543f" : "rgba(196,207,221,.7)").attr("cx", d => d.bx).attr("cy", d => d.by).attr("opacity", 0);
    const dots = svg.append("g").selectAll("circle").data(comps).join("circle").attr("r", 2.4).attr("fill", d => d.qv ? "#e2543f" : d.pq ? "#35d07f" : "rgba(196,207,221,.55)")
      .attr("cx", d => d.ax).attr("cy", d => d.ay).attr("opacity", 0);
    const bandOn = k => ["A", "B", "C"].forEach(x => svg.select("#bk-" + x).classed("on", x === k));
    const say = html => { sel("story-p").innerHTML = html; };
    const sayA = `An inventory of systems is not an inventory of cryptography. Each row stands alone: nothing says what depends on what, or when it last changed, while the estate under it keeps moving. <em>The wire and the files hold ${fmt(c.components)} components, ${fmt(c.quantum_vulnerable)} of them quantum-vulnerable.</em>`;
    const sayB = `The CBOM is the same components with their dependencies: which service runs which listener, what each negotiates, which file each key sits in. <em>Every link from evidence on a signed ledger, so a model can be asked about it and checked against it.</em>`;
    const sayC = `Organized, they are a plan: each component to its service, each service to a lane, each lane to the steps that move it, in the order the dependencies allow. <em>${(P.order || []).length} steps: rules put them in order from the record, so the order is the same every run; the local model ${STATIC ? "in the lab" : "on this box"} drafts each change and explains the plan in the owner's words.</em>`;
    if (stopAt) {   // a still: the state after band A, B or C
      dots.attr("opacity", .9); aLab.attr("opacity", 1); bandOn("A"); say(sayA);
      if (stopAt >= 2) { ghostA.attr("opacity", .22); dots.attr("cx", d => d.bx).attr("cy", d => d.by); lk.attr("opacity", 1); sg.attr("opacity", 1); ll.attr("opacity", 1); bLab.attr("opacity", 1); bandOn("B"); say(sayB); }
      if (stopAt >= 3) { ghostB.attr("opacity", .22); dots.attr("cx", d => d.cx2).attr("cy", d => d.cy2).attr("opacity", .85); lk.attr("opacity", .25); boxes.attr("opacity", 1); svg.selectAll("[id^=none-]").attr("opacity", 1); cLab.attr("opacity", 1); bandOn("C"); say(sayC); }
      return;
    }
    // live: A at once, B after 6 s, C after 13 s; the earlier bands stay, so the page reads top to bottom
    bandOn("A"); say(sayA);
    dots.transition().delay((d, i) => 400 + i * 5).duration(500).attr("opacity", .9);
    aLab.transition().delay(2200).attr("opacity", 1);
    storyTimers.push(setTimeout(() => { if (names[at] !== "why") return; bandOn("B"); say(sayB);
      sg.transition().duration(500).attr("opacity", 1); ghostA.transition().delay(600).duration(800).attr("opacity", .22);
      dots.transition().delay((d, i) => i * 4).duration(1200).ease(d3.easeCubicInOut).attr("cx", d => d.bx).attr("cy", d => d.by);
      lk.attr("stroke-dasharray", function () { const l = this.getTotalLength(); return `${l} ${l}`; }).attr("stroke-dashoffset", function () { return this.getTotalLength(); }).attr("opacity", 1)
        .transition().delay((d, i) => 1300 + i * 6).duration(600).attr("stroke-dashoffset", 0).on("end", function () { d3.select(this).attr("stroke-dasharray", null); });
      ll.transition().delay(1400).duration(500).attr("opacity", 1); bLab.transition().delay(3200).attr("opacity", 1); }, 6000));
    storyTimers.push(setTimeout(() => { if (names[at] !== "why") return; bandOn("C"); say(sayC);
      lk.transition().duration(800).attr("opacity", .25); ghostB.transition().delay(600).duration(800).attr("opacity", .22);
      dots.transition().delay((d, i) => i * 4).duration(1300).ease(d3.easeCubicInOut).attr("cx", d => d.cx2).attr("cy", d => d.cy2).attr("opacity", .85);
      boxes.transition().delay(2300).duration(500).attr("opacity", 1); svg.selectAll("[id^=none-]").transition().delay(2300).attr("opacity", 1);
      dp.attr("stroke-dasharray", function () { const l = this.getTotalLength(); return `${l} ${l}`; }).attr("stroke-dashoffset", function () { return this.getTotalLength(); })
        .transition().delay((d, i) => 2900 + i * 120).duration(700).attr("stroke-dashoffset", 0);
      cLab.transition().delay(4200).attr("opacity", 1); }, 13000));
  }

  // the figure: the GB10 inside a sealed perimeter, its six jobs around it
  function hero() {
    if (heroAnim) cancelAnimationFrame(heroAnim);
    const {ctx, W, H} = canvas("hero-canvas");
    const cx = W * 0.5, cy = H * 0.52, RX = Math.min(W * 0.36, 430), RY = Math.min(H * 0.5 - 64, RX * 0.74), bw = 304, bh = 122;
    const sats = CAPS.map((cap, i) => { const a = -Math.PI / 2 + i * Math.PI * 2 / CAPS.length; return {cap, a, x: cx + Math.cos(a) * RX, y: cy + Math.sin(a) * RY, lit: SNAP ? 1 : 0}; });
    let typed = "", typedFor = -1, cycleAt = 0, cycleT = 0;
    const parts = []; for (let i = 0; i < 260; i++) parts.push({s: i % CAPS.length, t: Math.random(), v: 0.15 + Math.random() * 0.2, o: (Math.random() - 0.5) * 18});
    const orbit = d3.range(40).map(i => ({a: Math.random() * Math.PI * 2, v: 0.25 + Math.random() * 0.2}));
    const t0 = performance.now(); const NC = CAPS.length; let litUpTo = SNAP ? NC : 0, last = t0;
    const caption = sel("hero-caption");
    const frame = now => {
      if (now - last < 30 && !SNAP) { heroAnim = requestAnimationFrame(frame); return; }
      const dt = Math.min(0.05, (now - last) / 1000); last = now;
      const el = (now - t0) / 1000;
      if (!SNAP) litUpTo = Math.min(NC, Math.floor(el / 2.6) + 1);
      const sealed = litUpTo >= NC;
      ctx.clearRect(0, 0, W, H);
      ctx.save(); ctx.translate(cx, cy);
      ctx.setLineDash([14, 10]); ctx.lineDashOffset = SNAP ? 0 : -el * 18; ctx.lineWidth = sealed ? 2.5 : 1.5; ctx.strokeStyle = sealed ? `rgba(0,163,204,${0.6 + 0.3 * Math.sin(el * 3)})` : "rgba(0,163,204,.45)";
      ctx.beginPath(); ctx.ellipse(0, 0, RX + 46, RY + 44, 0, 0, Math.PI * 2); ctx.stroke();
      ctx.setLineDash([]); ctx.strokeStyle = "rgba(0,163,204,.12)"; ctx.beginPath(); ctx.ellipse(0, 0, RX + 58, RY + 56, 0, 0, Math.PI * 2); ctx.stroke(); ctx.restore();
      if (sealed) orbit.forEach(o => { o.a += o.v * dt * (SNAP ? 0 : 1); ctx.fillStyle = "rgba(0,163,204,.85)"; ctx.beginPath(); ctx.arc(cx + Math.cos(o.a) * (RX + 46), cy + Math.sin(o.a) * (RY + 44), 1.8, 0, Math.PI * 2); ctx.fill(); });
      ctx.font = "600 10px JetBrains Mono, monospace"; ctx.fillStyle = "rgba(0,163,204,.85)"; ctx.textAlign = "center";
      ctx.fillText(sealed ? "AIR-GAPPED  ·  NOTHING LEAVES THE BOX" : "ONE DESKTOP BOX", cx, cy - RY - 62);
      // after the sweep, the caption cycles through the eight jobs, and the one being told pulses
      if (sealed && !SNAP) { cycleT += dt; if (cycleT > 5.5) { cycleT = 0; cycleAt = (cycleAt + 1) % NC; } }
      const focus = sealed ? cycleAt : Math.max(0, Math.min(NC - 1, litUpTo - 1));
      sats.forEach((s, i) => {
        const on = i < litUpTo; s.lit += ((on ? 1 : 0) - s.lit) * Math.min(1, dt * 4);
        if (s.cap[2] === "ring") return;
        ctx.strokeStyle = `rgba(0,163,204,${0.08 + 0.3 * s.lit})`; ctx.lineWidth = 1; ctx.beginPath(); ctx.moveTo(cx, cy); ctx.lineTo(s.x, s.y); ctx.stroke();
      });
      parts.forEach(p => {
        const s = sats[p.s]; if (s.lit < 0.2) return;
        p.t += p.v * dt * (SNAP ? 0 : 1); if (p.t > 1) p.t -= 1;
        const dir = s.cap[2] === "in" ? p.t : 1 - p.t;
        const x = s.x + (cx - s.x) * dir, y = s.y + (cy - s.y) * dir, nx = -(cy - s.y), ny = (cx - s.x), L = Math.hypot(nx, ny) || 1;
        ctx.fillStyle = s.cap[2] === "in" ? `rgba(0,163,204,${0.9 * s.lit})` : `rgba(53,208,127,${0.9 * s.lit})`;
        ctx.beginPath(); ctx.arc(x + nx / L * p.o * 0.3, y + ny / L * p.o * 0.3, 1.8, 0, Math.PI * 2); ctx.fill();
      });
      sats.forEach((s, i) => {
        const pulse = i === focus ? 1 + 0.12 * Math.sin(el * 4) : 1;
        ctx.beginPath(); ctx.arc(s.x, s.y, 22 * pulse, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(0,163,204,${0.08 + 0.3 * s.lit + (i === focus ? 0.2 : 0)})`; ctx.fill();
        ctx.lineWidth = i === focus ? 2.5 : 1.5; ctx.strokeStyle = `rgba(0,163,204,${0.35 + 0.65 * s.lit})`; ctx.stroke();
        if (s.lit > 0.5) { ctx.lineWidth = i === focus ? 10 : 7; ctx.strokeStyle = `rgba(0,163,204,${0.14 * s.lit})`; ctx.stroke(); ctx.lineWidth = i === focus ? 2.5 : 1.5; }
        ctx.fillStyle = `rgba(232,237,243,${0.45 + 0.55 * s.lit})`; ctx.font = `${s.lit > 0.5 ? 600 : 500} 13px Inter, sans-serif`;
        ctx.textAlign = "center"; ctx.fillText(s.cap[0], s.x, s.y + (s.y < cy ? -32 : 42));
      });
      ctx.save(); for (let k = 3; k >= 1; k--) { roundRect(ctx, cx - bw / 2 - k * 6, cy - bh / 2 - k * 6, bw + k * 12, bh + k * 12, 6 + k * 3); ctx.fillStyle = `rgba(0,163,204,${0.05 * (4 - k)})`; ctx.fill(); }
      roundRect(ctx, cx - bw / 2, cy - bh / 2, bw, bh, 6); ctx.fillStyle = "#0e1620"; ctx.fill(); ctx.restore();
      roundRect(ctx, cx - bw / 2, cy - bh / 2, bw, bh, 6); ctx.lineWidth = 2; ctx.strokeStyle = C.accent; ctx.stroke();
      ctx.textAlign = "center"; ctx.fillStyle = C.fg; ctx.font = "500 19px EB Garamond, serif"; ctx.fillText("Dell Pro Max GB10", cx, cy - 24);
      ctx.fillStyle = C.dim; ctx.font = "400 11px Inter, sans-serif"; ctx.fillText("Grace CPU · Blackwell GPU · 128 GB unified memory", cx, cy - 4);
      ctx.fillStyle = C.nv; ctx.font = "600 10px JetBrains Mono, monospace"; ctx.fillText("NEMOTRON · NeMo RETRIEVER · CUDA 13", cx, cy + 18);
      ctx.fillStyle = C.accent; ctx.fillText("SIGNED LEDGERS · REPLAYABLE RECORDINGS", cx, cy + 36);
      const cur = sats[focus];
      if (SNAP) caption.innerHTML = `<b>${esc(cur.cap[0])}</b> — ${esc(cur.cap[1])}`;
      else { if (typedFor !== focus) { typedFor = focus; typed = ""; } if (typed.length < cur.cap[1].length) typed = cur.cap[1].slice(0, typed.length + 1);
        caption.innerHTML = `<b>${esc(cur.cap[0])}</b> — ${esc(typed)}<span class="cur"></span>`; }
      if (names[at] === "why" && !SNAP && !document.hidden) heroAnim = requestAnimationFrame(frame);
    };
    frame(performance.now());
  }

  // the architecture: five layers, one box
  let archTimers = [];
  function arch() {
    archTimers.forEach(clearTimeout); archTimers = [];
    const E = D.engine || {}, T = E.tiers || {}, live = E.live || {}, c = (D.cbom || {}).counts || {}, sc = D.scan || {};
    const fastHw = (T.fast || {}).hardware || "", embedHw = (T.embed || {}).hardware || "";
    const ver = (s, re) => { const m = (s || "").match(re); return m ? m[0] : ""; };
    const box = (b, s, o) => `<div class="box ${o && o.live ? "live" : ""}" data-k="${o && o.k || ""}"><b>${esc(b)}${o && o.nv ? '<span class="nv">NVIDIA</span>' : ""}${o && o.live ? '<span class="lv">LIVE</span>' : ""}</b>${s ? `<span>${s}</span>` : ""}</div>`;
    const bands = [
      ["L5 · Outputs", "what leaves the ledger as a projection, and the people's part", "rgba(53,208,127,.6)", "rgba(53,208,127,.05)", [
        box("CBOM", `${fmt(c.components)} components · ${fmt(c.quantum_vulnerable)} quantum-vulnerable · CycloneDX 1.6`, {k: "cbom"}),
        box("Plan", `${fmt(((D.plan || {}).order || []).length)} steps, ordered by rules from the memo's criteria`, {k: "plan"}),
        box("Changes proved on the wire", `${((D.change || {}).changes || []).filter(x => x.landed).length} landed · approved by a person · verified twice`, {k: "changes"}),
        box("Ask the CBOM", "answers from retrieved entries, every citation checked", {k: "ask"}), box("This stage", STATIC ? `every number from the recorded runs (${esc(D.hardware)})` : "every number read live", {k: "stage"})]],
      ["L4 · Workbench", "three services and two runners, each with one job; scanners as containers", "rgba(0,163,204,.6)", "rgba(0,163,204,.05)", [
        box("app", "FastAPI, server-rendered, the only public leg", {k: "app"}), box("runner", "holds the Docker socket; starts every scanner as a container, by digest", {k: "runner"}),
        box("signer", "ML-DSA-65 checkpoints; the key where nothing else reads it", {k: "signer"}), box("system runner", "reads this box's listeners, files and firmware", {k: "sysrunner"}),
        box("inference seam", "tiers fast · deliberate · embed; a role moves to a model only by measurement", {k: "seam"}),
        box("scanners", (D.scanners || []).map(s => `<code>${esc(s.tool)} ${esc(s.version || "")}</code>`).join(" "), {k: "scanners"})]],
      ["L3 · Models", "served on the GPU, NVFP4 weights, offline", "rgba(118,185,0,.6)", "rgba(118,185,0,.05)", [
        box("Nemotron 3.5 Lightning 30B-A3B", `${esc(ver(fastHw, /NVFP4[^,)]*/) || "NVFP4")} · tiers fast and deliberate · reasoning on or off per role`, {nv: 1, k: "llm"}),
        box("vLLM", `${esc(ver(fastHw, /vLLM [0-9.]+/) || "vLLM")} on the Blackwell GPU · OpenAI-compatible · ${esc(ver(fastHw, /0\.[0-9]+ share/) || "")}`, {k: "vllm"}),
        box("NeMo Retriever embed NIM", `${esc(ver(embedHw, /llama-nemotron-embed[^ )]*( [0-9.]+)?/) || "llama-nemotron-embed-1b-v2")} · retrieval for Ask`, {nv: 1, k: "embed"}),
        box("The index", "a cosine over the CBOM's entries, in the app; then two hops up its dependencies, by rule", {k: "index"}),
        live.models ? box("the engine, now", `serving <code>${esc(live.models.join(", "))}</code> · ${fmt(live.ms)} ms round trip`, {live: 1, k: "engine"}) : ""]],
      ["L2 · Platform", "containers with the GPU through CDI; a read-only registry; nothing fetched", "rgba(196,207,221,.5)", "rgba(196,207,221,.04)", [
        box("Ubuntu 24.04 aarch64", "kernel 7.0 nvidia", {k: "os"}), box("CUDA 13", "", {nv: 1, k: "cuda"}), box("NVIDIA Container Toolkit", "CDI: <code>nvidia.com/gpu=all</code>", {nv: 1, k: "cdi"}),
        box("Docker Engine 29", "every scanner and service a container", {k: "docker"}), box("Image registry on the box", "<code>127.0.0.1:15000</code>, read-only, images by digest", {k: "registry"})]],
      ["L1 · Hardware", "one desktop box; the same stack scales without changing shape", "rgba(229,163,58,.6)", "rgba(229,163,58,.05)", [
        box("Dell Pro Max GB10", "Grace: 20 Arm cores · 128 GB unified memory · ConnectX-7", {k: "gb10"}), box("Blackwell GPU", "NVFP4 tensor cores · shares the unified memory", {nv: 1, k: "gpu"}),
        box("GB10 → two GB10s → GB300 → PowerEdge XE → AI factory", "the scale story", {k: "scale"})]],
    ];
    const el = sel("arch"); el.innerHTML = "";
    bands.forEach(([h, sub, bc, bb, boxes], k) => {
      const d = document.createElement("div"); d.className = "band"; d.style.setProperty("--bc", bc); d.style.setProperty("--bb", bb);
      d.innerHTML = `<h3>${esc(h)}<small>${esc(sub)}</small></h3><div class="boxes">${boxes.join("")}</div>`;
      el.appendChild(d);
      if (SNAP) d.classList.add("in"); else archTimers.push(setTimeout(() => d.classList.add("in"), 200 + (bands.length - k) * 320));
    });
    // the substrate stands beside every layer: whatever any of them does becomes an event here first
    const sub = document.createElement("div"); sub.className = "band substrate";
    sub.innerHTML = `<h3>The event substrate<small>one signed JSONL ledger per run, beside every layer: the authoritative record, not a log</small></h3><div class="boxes">` +
      box("Hash-chained events", `${fmt(sc.events)} on the latest scan · every finding, assessment, approval, verdict`, {k: "events"}) + box("Checkpoints signed with ML-DSA-65", "by the signer, key id on every page", {k: "ckpt"}) +
      box("Projections", "the CBOM, the plan, every page: rebuilt from the events, never edited", {k: "proj"}) + box("Replayable", "a recording replays into a new signed run on any box", {k: "replay"}) +
      `</div><div class="tape" id="tape"><div class="tape-k">the ledger, as it is written</div></div>`;
    el.appendChild(sub); if (SNAP) sub.classList.add("in"); else archTimers.push(setTimeout(() => sub.classList.add("in"), 200));
    const cap = document.createElement("div"); cap.className = "jcap"; cap.id = "jcap";
    const svg = d3.select(el).append("svg").attr("class", "journey");
    // three journeys through the layers, each a real path through the stack; the stops are the boxes above
    const J = [
      ["A scan: from the runner to the CBOM", [["runner", "The runner starts a scanner."], ["registry", "Its image comes by digest from the box's own registry; nothing is fetched."], ["docker", "It runs as a container on the target network."],
        ["scanners", "The scanner probes a listener on the wire."], ["events", "The finding is appended, hash-chained to the one before.", 1], ["signer", "The signer checkpoints the chain."],
        ["ckpt", "An ML-DSA-65 signature, key id on every page.", 1], ["proj", "The CBOM is rebuilt from the events."], ["cbom", "The CBOM says what the wire said."]]],
      ["A question: from Ask to the GPU and back", [["ask", "A question, in the owner's words."], ["seam", "The seam picks the tier; which model serves it is config, not code."], ["embed", "The embed NIM turns the question into a vector."],
        ["index", "The nearest CBOM entries come back, and the chain above each, by rule."], ["vllm", "The fast tier answers from them, thinking off, citing them."], ["gpu", "NVFP4 weights on the Blackwell GPU, in unified memory."],
        ["engine", "The answer comes back through the one seam."], ["ask", "Every citation is checked against the entries the model was shown."], ["events", "The answer and its check go on the ledger.", 1]]],
      ["A change: approved by a person, proved on the wire", [["plan", "A step is drafted; a person reads it."], ["changes", "They approve it, in their name."], ["events", "The approval is an event before anything moves.", 1],
        ["runner", "The runner applies the change."], ["scanners", "Then it probes twice: new-only succeeds, old-only is refused."], ["events", "The verdict is an event; a model never decides it.", 1],
        ["ckpt", "Signed."], ["plan", "The plan turns the step done, because the wire said so."]]],
      ["A host read whole", [["sysrunner", "The system runner reads this box: listeners, files, firmware, the management controller."], ["os", "Under /host, read-only."],
        ["events", "Each key, certificate and cipher becomes an event.", 1], ["signer", "Checkpointed by its own signer."], ["ckpt", "Key id on every page.", 1], ["proj", "The host's page is a projection."], ["stage", "This stage reads it live."]]],
      ["A replay on another box", [["replay", "A recording from one box."], ["runner", "It replays into the runner here."], ["events", "A new run, a new chain, the same findings.", 1],
        ["signer", "Signed by this box's key."], ["ckpt", "Verified end to end.", 1], ["proj", "The CBOM rebuilt."], ["cbom", "The same CBOM, provably."]]],
    ];
    // the activities, as buttons: the stage cycles through them; a click starts one from the top
    const btns = document.createElement("div"); btns.className = "jbtns";
    J.forEach(([title], j) => { const b = document.createElement("button"); b.type = "button"; b.textContent = title.split(":")[0].replace(/ on another box| read whole/, m => m); b.title = title;
      b.addEventListener("click", ev => { ev.preventDefault(); archTimers.forEach(clearTimeout); archTimers = []; svg.selectAll("*").interrupt(); run(j); }); btns.appendChild(b); });
    const acts = sel("arch-acts"); acts.innerHTML = ""; acts.appendChild(btns); acts.appendChild(cap);
    const pos = node => { let x = 0, y = 0, n = node; while (n && n !== el) { x += n.offsetLeft; y += n.offsetTop; n = n.offsetParent; } return {x: x + node.offsetWidth / 2, y: y + node.offsetHeight / 2}; };
    const boxOf = k => el.querySelector(`.box[data-k="${k}"]`);
    const chain = ((D.record || {}).chain || []).slice(-40); let ci = 0;
    const tape = sel("tape"), tapeLine = note => { const e = chain.length ? chain[ci++ % chain.length] : null; const d = document.createElement("div");
      d.innerHTML = e ? `<b>${esc(e.type)}</b> · ${esc(e.actor || "")} · seq ${fmt(e.seq)} · ${esc((e.hash || "").slice(0, 8))} ← ${esc((e.prev || "").slice(0, 8))}` : `<b>event</b> · ${esc(note)}`;
      tape.appendChild(d); while (tape.children.length > 7) tape.removeChild(tape.children[1]); };
    const legPath = (a, b) => `M${a.x},${a.y} C${a.x},${(a.y + b.y) / 2} ${b.x},${(a.y + b.y) / 2} ${b.x},${b.y}`;
    const clearHot = () => el.querySelectorAll(".box.hot").forEach(x => x.classList.remove("hot"));
    const run = j => {
      if (names[at] !== "arch") return;
      const [title, stops] = J[j % J.length]; clearHot(); svg.selectAll("*").remove();
      Array.from(btns.children).forEach((b, k) => b.classList.toggle("on", k === j % J.length));
      const pts = stops.map(([k]) => boxOf(k)).map(n => n ? pos(n) : null);
      sel("jcap").textContent = "";
      const dot = svg.append("circle").attr("class", "pulse").attr("r", 5).attr("cx", pts[0] ? pts[0].x : 0).attr("cy", pts[0] ? pts[0].y : 0);
      const leg = i => {
        if (names[at] !== "arch") return;
        const [k, note, ev] = stops[i], n = boxOf(k); if (n) n.classList.add("hot");
        sel("jcap").textContent = note; if (ev) tapeLine(note);
        if (i + 1 >= stops.length) { archTimers.push(setTimeout(() => run(j + 1), 2600)); return; }
        const a = pts[i], b = pts[i + 1]; if (!a || !b) { archTimers.push(setTimeout(() => leg(i + 1), 100)); return; }
        svg.selectAll("path.leg").transition().duration(700).style("opacity", .16);
        const path = svg.append("path").attr("class", "leg").attr("d", legPath(a, b)); const L = path.node().getTotalLength();
        path.attr("stroke-dasharray", `${L} ${L}`).attr("stroke-dashoffset", L).transition().duration(650).ease(d3.easeCubicInOut).attr("stroke-dashoffset", 0);
        dot.transition().duration(650).ease(d3.easeCubicInOut).attrTween("transform", () => tt => { const p = path.node().getPointAtLength(tt * L); return `translate(${p.x - a.x},${p.y - a.y})`; })
          .on("end", () => { dot.attr("transform", null).attr("cx", b.x).attr("cy", b.y); archTimers.push(setTimeout(() => leg(i + 1), 900)); });
      };
      leg(0);
    };
    if (SNAP) {   // a still: the first journey drawn whole
      const [title, stops] = J[0]; const pts = stops.map(([k]) => boxOf(k)).map(n => n ? pos(n) : null);
      stops.forEach(([k, note, ev]) => { const n = boxOf(k); if (n) n.classList.add("hot"); if (ev) tapeLine(note); });
      for (let i = 0; i + 1 < pts.length; i++) if (pts[i] && pts[i + 1]) svg.append("path").attr("class", "leg").attr("d", legPath(pts[i], pts[i + 1]));
      const last = pts[pts.length - 1]; if (last) svg.append("circle").attr("class", "pulse").attr("r", 5).attr("cx", last.x).attr("cy", last.y);
      sel("jcap").textContent = stops[stops.length - 1][1]; btns.children[0].classList.add("on");
    } else archTimers.push(setTimeout(() => run(0), 200 + (bands.length + 1) * 320 + 700));
  }

  // the estate map: services and their listeners
  function estateMap(svg, data, opts) {
    const node = svg.node(), bb = node.getBoundingClientRect(), W = Math.round(bb.width) || node.clientWidth || 1200, H = Math.round(bb.height) || node.clientHeight || 600;
    svg.attr("viewBox", `0 0 ${W} ${H}`).selectAll("*").remove();
    const nodes = data.nodes.map(n => ({...n})), links = data.links.map(l => ({...l}));
    const byId = new Map(nodes.map(n => [n.id, n]));
    const g = svg.append("g");
    const link = g.append("g").selectAll("line").data(links).join("line").attr("class", "edge");
    const nd = g.append("g").selectAll("g").data(nodes).join("g");
    nd.filter(d => d.kind === "service").append("circle").attr("r", 34).attr("class", "node-service");
    nd.filter(d => d.kind === "listener").append("circle").attr("r", 9).attr("class", d => "node-listener" + (d.qv ? " vuln" : ""));
    nd.filter(d => d.kind === "service").append("text").attr("class", "label-service").attr("text-anchor", "middle").attr("dy", 5).text(d => d.name);
    nd.filter(d => d.kind === "service").append("text").attr("class", "label-mission").attr("text-anchor", "middle").attr("dy", 52).text(d => d.mission || "");
    nd.filter(d => d.kind === "listener").append("text").attr("class", "label-listener").attr("text-anchor", "middle").attr("dy", -14).text(d => (d.name || "").replace(/^(TLS|SSH|POSTGRES|Postgres)\s*/i, m => m.trim().toUpperCase() + " ").replace(/172\.16\.106\./, ".") );
    const sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id(d => d.id).distance(l => 96))
      .force("charge", d3.forceManyBody().strength(d => d.kind === "service" ? -700 : -120))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .force("x", d3.forceX(W / 2).strength(.035)).force("y", d3.forceY(H / 2).strength(.06))
      .force("collide", d3.forceCollide(d => d.kind === "service" ? 72 : 24))
      .on("tick", () => {
        nodes.forEach(d => { const m = d.kind === "service" ? 70 : 24; d.x = Math.max(m, Math.min(W - m, d.x)); d.y = Math.max(m + 10, Math.min(H - m - 40, d.y)); });
        link.attr("x1", d => d.source.x).attr("y1", d => d.source.y).attr("x2", d => d.target.x).attr("y2", d => d.target.y);
        nd.attr("transform", d => `translate(${d.x},${d.y})`);
      });
    if (SNAP) { sim.stop(); for (let i = 0; i < 300; i++) sim.tick(); sim.on("tick")(); nd.filter(d => d.kind === "service").select("circle").classed("lit", true); }
    else alive(sim, nd);
    if (opts && opts.sweep && !SNAP) {
      // light the services one by one once the layout has settled
      setTimeout(() => nd.filter(d => d.kind === "service").each(function (d, k) {
        setTimeout(() => d3.select(this).select("circle").classed("lit", true), 400 + k * 180);
      }), 1500);
    }
    return {nodes, byId, nd, link, sim};
  }

  // a simulation that never settles: a faint drift keeps it alive, and a node can be dragged
  function alive(sim, nd) {
    sim.alphaDecay(0.02).velocityDecay(0.35);
    const drift = () => { if (!document.hidden) sim.alphaTarget(0.035).restart(); setTimeout(() => sim.alphaTarget(0.008), 900); };
    const timer = setInterval(drift, 4200);
    sim.on("end", () => sim.alphaTarget(0.01).restart());
    nd.call(d3.drag()
      .on("start", (ev, d) => { if (!ev.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
      .on("drag", (ev, d) => { d.fx = ev.x; d.fy = ev.y; })
      .on("end", (ev, d) => { if (!ev.active) sim.alphaTarget(0.01); d.fx = null; d.fy = null; }));
    nd.on("mouseenter", function () { d3.select(this).select("circle").classed("lit", true); }).on("mouseleave", function () { d3.select(this).select("circle").classed("lit", false); });
    return timer;
  }

  // the scan, along its chain: service → listener → what it accepts; each job lights the piece it touched
  let scanTimer = null, CH = null, chainHold = null;
  function scan() {
    const svg = d3.select("#chain-svg"), node = svg.node(), bb = node.getBoundingClientRect(), W = Math.round(bb.width) || 1100, H = Math.round(bb.height) || 640;
    svg.attr("viewBox", `0 0 ${W} ${H}`).selectAll("*").remove(); scanPanel(SNAP ? "done" : "replay");
    const cb = D.cbom || {nodes: [], links: []}, N = new Map(cb.nodes.map(n => [n.id, n])), out = new Map();
    cb.links.forEach(l => (out.get(l.source) || out.set(l.source, []).get(l.source)).push(l.target));
    const svcs = cb.nodes.filter(n => n.kind === "service").sort((p, q) => p.name.localeCompare(q.name)).map(s => ({...s, listeners: [], image: null}));
    svcs.forEach(s => (out.get(s.id) || []).forEach(id => { const n = N.get(id); if (!n) return; if (n.kind === "listener") s.listeners.push(n.id); if (n.kind === "image") s.image = n.id; }));
    const lis = []; svcs.forEach(s => s.listeners.forEach(id => lis.push({...N.get(id), svc: s.id})));
    const accepts = new Map();   // entry id → {node, from: [listener ids]}
    lis.forEach(l => (out.get(l.id) || []).forEach(id => { const n = N.get(id); if (!n || !["algorithm", "protocol", "certificate"].includes(n.kind)) return;
      const key = `${n.kind}:${n.name}`; const e = accepts.get(key) || accepts.set(key, {...n, id: key, from: []}).get(key); if (!e.from.includes(l.id)) e.from.push(l.id); }));
    const kindOrder = {protocol: 0, algorithm: 1, certificate: 2};
    const ents = Array.from(accepts.values()).sort((p, q) => (kindOrder[p.kind] - kindOrder[q.kind]) || (q.from.length - p.from.length) || p.name.localeCompare(q.name));
    const X = [W * 0.03, W * 0.36, W * 0.70], top = 34, bot = H - 66;
    const spread = (arr, pad) => arr.forEach((d, i) => { d.y = arr.length === 1 ? (top + bot) / 2 : top + pad + (bot - top - 2 * pad) * i / (arr.length - 1); });
    spread(svcs, 40); spread(lis, 30); spread(ents, 4);
    svcs.forEach(s => s.x = X[0]); lis.forEach(l => l.x = X[1]); ents.forEach(e => e.x = X[2]);
    const L = new Map(lis.map(l => [l.id, l])), S = new Map(svcs.map(s => [s.id, s])), Ent = new Map(ents.map(e => [e.id, e]));
    const curve = (a, b) => { const m = (a.x + b.x) / 2; return `M${a.x},${a.y} C${m},${a.y} ${m},${b.y} ${b.x},${b.y}`; };
    const col = n => n.qv ? "#e2543f" : n.pq ? "#35d07f" : "rgba(196,207,221,.7)";
    const heads = [["service", X[0]], ["listener", X[1]], ["what it accepts or chose", X[2]]];
    heads.forEach(([k, x]) => svg.append("text").attr("class", "col-k").attr("x", x - 6).attr("y", 14).text(k));
    const g1 = svg.append("g"), g2 = svg.append("g");
    const sl = g1.selectAll("path").data(lis).join("path").attr("class", "ch-link sl").attr("d", d => curve(S.get(d.svc), d));
    const le = []; ents.forEach(e => e.from.forEach(f => le.push({l: f, e: e.id, svc: (L.get(f) || {}).svc})));
    const el2 = g2.selectAll("path").data(le).join("path").attr("class", "ch-link le").attr("d", d => curve(L.get(d.l), Ent.get(d.e))).attr("stroke", d => col(Ent.get(d.e)));
    const gs = svg.append("g").selectAll("g").data(svcs).join("g").attr("class", "ch-svc").attr("transform", d => `translate(${d.x},${d.y})`).style("cursor", "pointer");
    gs.append("circle").attr("r", 7).attr("class", "ch-dot"); gs.append("text").attr("class", "ch-name").attr("x", 13).attr("y", 4).text(d => d.name);
    gs.append("text").attr("class", "ch-sub").attr("x", 13).attr("y", 18).text(d => d.mission || "");
    gs.append("text").attr("class", "ch-img").attr("x", 13).attr("y", 31).attr("opacity", 0).text("");
    const gl = svg.append("g").selectAll("g").data(lis).join("g").attr("class", "ch-lis").attr("transform", d => `translate(${d.x},${d.y})`).style("cursor", "pointer");
    gl.append("circle").attr("r", 5.5).attr("class", "ch-dot"); gl.append("text").attr("class", "ch-mono").attr("x", 11).attr("y", 4)
      .text(d => `${(d.name || "").split(" ")[1] || d.name} · ${(d.protocol || "").toLowerCase()}`);
    const ge = svg.append("g").selectAll("g").data(ents).join("g").attr("class", "ch-ent").attr("transform", d => `translate(${d.x},${d.y})`);
    ge.append("circle").attr("r", 3.6).attr("fill", d => col(d)).attr("class", "ch-dot"); ge.append("text").attr("class", "ch-mono small").attr("x", 9).attr("y", 3.5).attr("fill", d => col(d)).text(d => d.name);
    svg.append("text").attr("class", "mark dim").attr("x", W - 12).attr("y", H - 10).attr("text-anchor", "end").text(`${ents.filter(e => e.qv).length} quantum-vulnerable · ${ents.filter(e => e.pq).length} post-quantum · ${ents.length} entries on ${lis.length} listeners`);
    CH = {svg, svcs, lis, ents, S, L, Ent, gs, gl, ge, sl, el2};
    // hover isolates a service's or a listener's chain; click holds it
    const iso = (svcId, lId) => { svg.classed("iso", !!(svcId || lId));
      sl.classed("on", d => svcId ? d.svc === svcId : lId ? d.id === lId : false);
      el2.classed("on", d => svcId ? d.svc === svcId : lId ? d.l === lId : false);
      const onE = new Set(le.filter(d => svcId ? d.svc === svcId : lId ? d.l === lId : false).map(d => d.e)), onL = new Set(lis.filter(d => svcId ? d.svc === svcId : lId ? d.id === lId : false).map(d => d.id));
      gs.classed("on", d => svcId ? d.id === svcId : lId ? d.id === (L.get(lId) || {}).svc : false); gl.classed("on", d => onL.has(d.id)); ge.classed("on", d => onE.has(d.id)); };
    gs.on("mouseenter", (ev, d) => { if (!chainHold) iso(d.id, null); }).on("mouseleave", () => { if (!chainHold) iso(null, null); })
      .on("click", (ev, d) => { chainHold = chainHold && chainHold.svc === d.id ? null : {svc: d.id}; chainHold ? iso(d.id, null) : iso(null, null); });
    gl.on("mouseenter", (ev, d) => { if (!chainHold) iso(null, d.id); }).on("mouseleave", () => { if (!chainHold) iso(null, null); })
      .on("click", (ev, d) => { chainHold = chainHold && chainHold.l === d.id ? null : {l: d.id}; chainHold ? iso(null, d.id) : iso(null, null); });
    chainHold = null;
    if (SNAP) { if (D.scan) { D.scan.jobs.forEach((j, k) => { line(j); counters(k + 1, d3.sum(D.scan.jobs.slice(0, k + 1), x => x.findings || 0), D.scan.jobs.length); }); doneLine(D.scan.jobs.length, d3.sum(D.scan.jobs, x => x.findings || 0)); } return; }
    if (STATIC) { if (D.scan && D.scan.jobs.length) replay(D.scan.jobs); return; }
    fetch("/api/scan").then(r => r.json()).then(s => {
      if (s.running) poll();
      else if (D.scan && D.scan.jobs.length) replay(D.scan.jobs);
    }).catch(() => { if (D.scan) replay(D.scan.jobs); });
  }
  // a job lands: its listener and what it accepts light up, or its image is marked read
  function probe(j) {
    if (!CH) return;
    const t = j.target || {};
    if (t.host) { const id = `listener:${t.host}:${t.port}`; if (!CH.L.has(id)) return;
      CH.gl.filter(d => d.id === id).classed("lit", true).select("circle").attr("r", 9).transition().duration(T(500)).attr("r", 5.5);
      CH.sl.filter(d => d.id === id).classed("lit", true); CH.el2.filter(d => d.l === id).classed("lit", true);
      const es = new Set(CH.ents.filter(e => e.from.includes(id)).map(e => e.id)); CH.ge.filter(d => es.has(d.id)).classed("lit", true);
      return; }
    const name = (t.image || "").split("/").pop().split("@")[0], s = CH.svcs.find(x => x.name === name); if (!s) return;
    const g = CH.gs.filter(d => d.id === s.id); g.classed("lit", true);
    s.read = s.read || {}; s.read[/theia/.test(j.profile || "") ? "image" : "files"] = true;
    g.select(".ch-img").text([s.read.files && "files read", s.read.image && "image read"].filter(Boolean).join(" · ")).attr("opacity", 1);
  }
  function scanPanel(state, live) {
    const el = sel("hosts-scan"), sc = D.scan || {}, S = (D.score || {}).columns || {}, jobs = sc.jobs || [];
    const cols = ["baseline-cbomkit", "baseline-scanners", "workbench"].filter(k => S[k]);
    const bar = (a, b, good) => `<div class="sbar"><i style="width:${b ? Math.round(100 * a / b) : 0}%" class="${good ? "good" : ""}"></i></div>`;
    const row = (label, get, of) => `<div class="srow"><span>${label}</span>${cols.map(k => { const [a, b, bad] = get(S[k]); return `<div class="scell${k === "workbench" ? " wb" : ""}"><b>${a}</b>${of && b ? ` of ${b}` : ""}${bad ? ` <em>${bad} false</em>` : ""}${bar(a, b, k === "workbench")}</div>`; }).join("")}</div>`;
    const status = state === "running" ? `<div class="sstat run"><span class="cursor"></span> scanning live · ${fmt(live && live.jobs || 0)} jobs so far · ${fmt(live && live.findings || 0)} findings</div>`
      : state === "replay" ? `<div class="sstat">replaying the latest scan · ${fmt(jobs.length)} jobs · ${fmt(d3.sum(jobs, j => j.findings || 0))} findings · ${fmt(sc.events)} events on the ledger</div>`
      : `<div class="sstat done">done · ${fmt(jobs.length)} jobs · ${fmt(d3.sum(jobs, j => j.findings || 0))} findings · ${fmt(sc.events)} events on the ledger, signed · run ${esc(String(sc.run || "").slice(0, 10))}</div>`;
    el.innerHTML = status + (cols.length ? `<div class="score"><div class="sk">The scan, scored against the answer key<small>what was planted in the mini-agency, and what each approach found</small></div>` +
      `<div class="srow head"><span></span>${cols.map(k => `<div class="scell${k === "workbench" ? " wb" : ""}">${esc({"baseline-cbomkit": "cbomkit-theia alone", "baseline-scanners": "all scanners, no rules"}[k] || S[k].label)}</div>`).join("")}</div>` +
      row("planted on the wire", c => [c.wire.covered, c.wire.of, c.wire.false_positives], true) + row("planted in the files", c => [c.host.covered, c.host.of, c.host.false_positives], true) +
      row("posture verdicts", c => c.posture ? [c.posture.correct, c.posture.total, 0] : ["—", 0, 0], true) + row("components in the CBOM", c => [fmt(c.components), 0, 0], false) +
      `<div class="snote"><p><b>cbomkit-theia</b> is IBM's open-source CBOM reader for images and files; it does not touch the wire.</p><p><b>All scanners</b> is testssl.sh, ssh-audit, openssl s_client, the OpenSSH client and cbomkit-theia, their findings unioned.</p>` +
      `<p><b>The workbench</b> runs those same scanners and adds its own file reader, its rules and the record: the delta is in the files and the verdicts. On the wire the two misses are the same two, keyed as out of reach from outside.</p></div></div>` : "");
  }
  function hostsPanel() {
    const el = sel("hosts-scan"), hosts = Array.isArray(D.hosts) ? D.hosts : [];
    el.innerHTML = "";
    hosts.forEach((h, k) => {
      const f = h.files || {}, fw = h.firmware || {}, d = document.createElement("div"); d.className = "host" + (h.this_machine ? " me" : "");
      d.innerHTML = `<h4>${esc(h.name)}${h.this_machine ? "<small>this box, read whole</small>" : h.recorded ? "<small>replayed from a recording</small>" : "<small>read whole</small>"}</h4>` +
        `<p><b>${fmt(h.findings)}</b> findings · ${(h.jobs || []).length} jobs${h.jobs && h.jobs.length ? ` in ${fmt(d3.sum(h.jobs, j => j.ms || 0))} ms` : ""}</p>` +
        (f.read != null ? `<p>${fmt(f.read)} files read as uid ${f.as_uid}${f.unreadable ? `, <b>${f.unreadable}</b> unreadable` : ", nothing unreadable"}${f.trust_store ? ` · ${fmt(f.trust_store)} CA certificates trusted` : ""}</p>` : "") +
        (fw.model ? `<p>${esc(fw.vendor || "")} ${esc(fw.model)}${fw.bios ? ` · ${esc(fw.bios)}` : ""} · Secure Boot <b>${fw.secure_boot === true ? "on" : fw.secure_boot === false ? "off" : "unknown"}</b>${fw.tpm ? ` · ${esc(fw.tpm)}` : ""}</p>` : "") +
        (h.controller && h.controller.model ? `<p>controller ${esc(h.controller.model)} ${esc(h.controller.firmware || "")} <span class="m">Redfish, GET only</span></p>` : "") +
        `<p class="m">${(h.parts || []).join(" · ")}</p>`;
      el.appendChild(d); setTimeout(() => d.classList.add("in"), T(600 + k * 500));
    });
  }
  function counters(jobs, findings, of) {
    sel("counters-scan").innerHTML = `<div>${fmt(jobs)}<small>jobs${of ? " of " + of : ""}</small></div><div>${fmt(findings)}<small>findings</small></div>`;
  }
  function targetName(t) {
    t = t || {};
    if (t.host) return `${t.host}:${t.port}`;
    if (t.image) return (t.image.split("/").pop() || "").split("@")[0];
    return t.system || t.controller || "";
  }
  function doneLine(jobs, findings) {
    const term = sel("term-scan"); const cur = term.querySelector(".cursor"); if (cur) cur.parentElement.remove();
    const d = document.createElement("div"); d.className = "ln done"; d.innerHTML = `<span class="ok">done</span>  ${fmt(jobs)} jobs · ${fmt(findings)} findings · checkpoint signed`; term.appendChild(d);
    while (term.scrollHeight > term.clientHeight && term.children.length > 2) term.removeChild(term.firstChild);
  }
  function line(j) {
    const term = sel("term-scan");
    const cur = term.querySelector(".cursor"); if (cur) cur.remove();
    const st = j.status === "ok" ? `<span class="ok">ok</span>` : `<span class="err">${esc(j.status)}</span>`;
    const d = document.createElement("div"); d.className = "ln";
    d.innerHTML = `${esc((j.profile || "").padEnd(22))}${esc(targetName(j.target).padEnd(22))}${st} ${String(fmt(j.ms)).padStart(7)} ms  <span class="n">${fmt(j.findings)}</span>`;
    term.appendChild(d);
    d.insertAdjacentHTML("afterend", `<div class="ln"><span class="cursor"></span></div>`);
    while (term.scrollHeight > term.clientHeight && term.children.length > 2) term.removeChild(term.firstChild);
    probe(j);
  }
  function replay(jobs) {
    let k = 0, findings = 0;
    const step = () => {
      if (k >= jobs.length) { doneLine(jobs.length, findings); scanPanel("done"); return; }
      const j = jobs[k++]; findings += j.findings || 0; line(j); counters(k, findings, jobs.length);
      scanTimer = setTimeout(step, 420);
    };
    step();
  }
  function startScan() {
    if (names[at] !== "scan") go(names.indexOf("scan"));
    if (scanTimer) { clearTimeout(scanTimer); scanTimer = null; }
    if (STATIC) { sel("term-scan").innerHTML = `<div class="ln">$ replaying run ${esc(String((D.scan || {}).run || "").slice(0, 10))} from its ledger · recorded on ${esc(D.hardware)}<span class="cursor"></span></div>`;
      if (CH) { CH.svg.selectAll(".lit").classed("lit", false); CH.gs.select(".ch-img").text("").attr("opacity", 0); CH.svcs.forEach(s => { s.read = null; }); }
      scanPanel("replay"); if (D.scan) replay(D.scan.jobs); return; }
    fetch("/scan?host=live", {method: "POST", headers: {"Origin": location.origin}}).then(() => {
      sel("term-scan").innerHTML = `<div class="ln">$ pqch scan --live · started ${new Date().toISOString()}<span class="cursor"></span></div>`;
      if (CH) { CH.svg.selectAll(".lit").classed("lit", false); CH.gs.select(".ch-img").text("").attr("opacity", 0); CH.svcs.forEach(s => { s.read = null; }); }
      scanPanel("running"); poll();
    }).catch(e => { sel("term-scan").innerHTML += `<div class="ln"><span class="err">could not start a scan: ${esc(e)}</span></div>`; });
  }
  function poll() {
    let seen = 0, findings = 0;
    const tick = () => fetch("/api/scan").then(r => r.json()).then(s => {
      const lines = s.lines || [];
      for (; seen < lines.length; seen++) { const j = lines[seen]; findings += j.findings || 0; line(j); }
      counters(seen, findings, 0); if (s.running) scanPanel("running", {jobs: seen, findings});
      if (s.running) scanTimer = setTimeout(tick, 700);
      else fetch("/api/demo").then(r => r.json()).then(d => { D = d; Object.keys(drawn).forEach(k => { if (k !== "scan") delete drawn[k]; }); doneLine(seen, findings); scanPanel("done"); });
    }).catch(() => { scanTimer = setTimeout(tick, 1500); });
    tick();
  }

  // what comes first: the ranking as bars to the year the data must stay secret
  let narrateAt = 0;
  let planLoaded = false;
  function plan() {
    // the plan page's own figure ("The plan, drawn"): lanes per service, left to right in time, a line per
    // dependency; plan.js draws every figure.planmap at load, so it is loaded only once the beat is on screen
    sel("narration-first").innerHTML = STATIC ? `<span class="who">narration · recorded ${esc((ST().recorded_at || "").slice(0, 10))} · ${esc(((ST().narration || []).find(n => n.model) || {}).model || "no narration recorded")} · <i>press N</i></span>`
      : `<span class="who">narration · nemotron-3.5-lightning on this box · <i>press N</i></span>`;
    narrateAt = 0; clearTimeout(walkTimer);
    const fig = document.querySelector("figure.stage-plan"); if (!fig) return;
    if (fig.querySelector("svg")) { walkTimer = setTimeout(walkPlan, 400); return; }   // drawn already
    // plan.js draws every figure.planmap when it loads; load it once the beat is on screen, and again if a load failed
    // (a request lost while the app restarts) or the figure came up empty
    if (planLoaded) { document.querySelectorAll('script[src*="plan.js"]').forEach(s => s.remove()); }
    planLoaded = true;
    const s = document.createElement("script"); s.src = BASE + "static/plan.js?v=" + ((document.querySelector('script[src*="demo.js"]') || {src: ""}).src.split("v=")[1] || "") + "&t=" + Date.now();
    s.onload = () => { if (!fig.querySelector("svg")) { planLoaded = false; fig.innerHTML = `<p class="foot">The plan's figure did not draw; press 5 to try again.</p>`; return; } animatePlan(); };
    s.onerror = () => { planLoaded = false; fig.innerHTML = `<p class="foot">Could not load the plan's figure; press 5 to try again.</p>`; };
    document.body.appendChild(s);
    // a request that hangs (the app restarting under it) is given six seconds, then tried again, three times
    clearTimeout(planRetry); planRetry = setTimeout(() => { if (fig.querySelector("svg")) return; s.remove(); planLoaded = false; planTries++;
      if (planTries < 3) { if (names[at] === "plan") plan(); } else fig.innerHTML = `<p class="foot">The plan's figure did not arrive after three tries; reload the page.</p>`; }, 6000);
  }
  let planRetry = null, planTries = 0;
  let walkTimer = null;
  function laneBox(service) {   // the lane's band, as plan.js stamped it on the lane's label
    const fig = document.querySelector("figure.stage-plan"); if (!fig) return null;
    const lab = Array.from(fig.querySelectorAll("text[data-lane]")).find(e => e.getAttribute("data-lane") === service); if (!lab) return null;
    const svg = lab.ownerSVGElement, vb = svg.viewBox && svg.viewBox.baseVal;
    return {svg, y: +lab.getAttribute("data-y0"), h: +lab.getAttribute("data-y1") - +lab.getAttribute("data-y0"), w: (vb && vb.width) || +svg.getAttribute("width") || svg.getBoundingClientRect().width};
  }
  function laneLight(service) {
    const b = service && laneBox(service), fig = document.querySelector("figure.stage-plan"); if (!fig) return;
    let hl = fig.querySelector("rect.lane-hl");
    if (!b) { if (hl) hl.setAttribute("opacity", 0); return; }
    if (!hl) { hl = document.createElementNS("http://www.w3.org/2000/svg", "rect"); hl.setAttribute("class", "lane-hl"); b.svg.appendChild(hl); }
    hl.setAttribute("x", 0); hl.setAttribute("y", b.y); hl.setAttribute("width", b.w); hl.setAttribute("height", b.h); hl.setAttribute("opacity", 1);
  }
  const reason = r => `<span class="who">row ${r.rank} · ${esc(r.service)} · by the rules · <i>${esc((r.criteria || []).join(" · ") || "not prioritized")}</i></span>` +
    `<span class="said">${esc(r.mission || "")}${r.sensitive_through ? `: its data must stay secret until ${r.sensitive_through}` : ""}${r.open && r.open.length ? `; open: ${esc(r.open.join(", "))}` : "; nothing open"}${r.blocked && r.blocked.length ? `; waiting on ${esc(r.blocked.join(", "))}` : ""}.</span>`;
  function walkPlan() {
    clearTimeout(walkTimer); const rows = (D.plan && D.plan.ranking) || []; if (!rows.length) return;
    let k = 0; const step = () => { if (names[at] !== "plan" || narrateAt > 0) return; const r = rows[k % rows.length]; laneLight(r.service); sel("narration-first").innerHTML = reason({...r, rank: k % rows.length + 1}); k++; walkTimer = setTimeout(step, 3200); };
    step();
  }
  function animatePlan() {
    const fig = document.querySelector("figure.stage-plan svg"); if (!fig) return;
    if (SNAP) { const r = ((D.plan || {}).ranking || [])[0]; if (r) { laneLight(r.service); sel("narration-first").innerHTML = reason({...r, rank: 1}); } return; }
    walkTimer = setTimeout(walkPlan, 3000);
    const items = Array.from(fig.querySelectorAll("rect, text, path, line, circle"));
    const xOf = el => { try { const b = el.getBBox(); return b.x + (el.tagName === "path" ? 0 : b.width / 2); } catch (e) { return 0; } };
    const minX = d3.min(items, xOf) || 0, maxX = d3.max(items, xOf) || 1;
    items.forEach(el => {
      const delay = 150 + ((xOf(el) - minX) / Math.max(1, maxX - minX)) * 2600;
      if (el.tagName === "path" || el.tagName === "line") {
        let L = 0; try { L = el.getTotalLength ? el.getTotalLength() : 0; } catch (e) {}
        if (L > 0) { el.style.strokeDasharray = `${L} ${L}`; el.style.strokeDashoffset = L; el.style.transition = `stroke-dashoffset 900ms ease-out ${delay}ms`; requestAnimationFrame(() => { el.style.strokeDashoffset = 0; }); return; }
      }
      el.style.opacity = 0; el.style.transition = `opacity 500ms ease-out ${delay}ms`;
      requestAnimationFrame(() => { el.style.opacity = 1; });
    });
  }
  function narrateNext() {
    if (names[at] !== "plan") go(names.indexOf("plan"));
    const rows = (D.plan && D.plan.ranking) || [];
    if (!rows.length) return;
    const r = rows[narrateAt % rows.length]; const k = narrateAt; narrateAt++; clearTimeout(walkTimer); laneLight(r.service);
    const box = sel("narration-first");
    box.innerHTML = `<span class="who">row ${k % rows.length + 1} · ${esc(r.service)} · asking the model…</span>`;
    const row = {rank: k + 1, service: r.service, mission: r.mission, why: (r.criteria || []).join(", "), secret_until: r.sensitive_through,
                 kex: (r.kex_now || []).join("/"), blocked: (r.blocked || []).join(", ") || "nothing", title: r.step && r.step.title};
    if (STATIC) {   // the line recorded for this row, labelled as recorded
      const a = (ST().narration || [])[k % rows.length];
      if (!a || a.error || !a.text) { box.innerHTML = `<span class="who">row ${k % rows.length + 1} · no narration recorded for this row</span>`; return; }
      box.innerHTML = `<span class="who">row ${k % rows.length + 1} · ${esc(a.model)} · <i>recorded ${esc((ST().recorded_at || "").slice(0, 10))} · ${fmt(a.ms)} ms · ${fmt(a.tokens)} tokens · ${esc(((a.hardware || "").split(";")[0]).replace(/\([^)]*$/, m => m + ")"))}</i></span><span class="said"></span>`;
      const said = box.querySelector(".said"); let i = 0; const txt = a.text;
      (function type() { said.textContent = txt.slice(0, ++i); if (i < txt.length) setTimeout(type, 18); })();
      return;
    }
    const t = Date.now();
    const ac = new AbortController(), killer = setTimeout(() => ac.abort(), 25000);
    fetch("/api/demo/narrate", {method: "POST", headers: {"Content-Type": "application/json", "Origin": location.origin}, body: JSON.stringify({kind: "plan", row}), signal: ac.signal})
      .then(x => x.text().then(s => { clearTimeout(killer); if (!x.ok) throw new Error(`the app answered ${x.status}`); try { return JSON.parse(s); } catch (e) { throw new Error("an empty or cut-off answer from the app"); } })).then(a => {
        if (a.error) { box.innerHTML = `<span class="who">row ${k + 1} · the model did not answer · <i>${esc(a.error)}</i></span>`; return; }
        box.innerHTML = `<span class="who">row ${k + 1} · ${esc(a.model)} · <i>${fmt(a.ms)} ms · ${fmt(a.tokens)} tokens · ${esc(((a.hardware || "").split(";")[0]).replace(/\([^)]*$/, m => m + ")"))}</i></span><span class="said"></span>`;
        const said = box.querySelector(".said"); let i = 0; const txt = a.text || "";
        (function type() { said.textContent = txt.slice(0, ++i); if (i < txt.length) setTimeout(type, 18); })();
      }).catch(e => { box.innerHTML = `<span class="who">row ${k % rows.length + 1} · no answer · <i>${esc(e.name === "AbortError" ? "the model did not answer in 25 s" : e.message || e)}</i></span>`; });
  }

  // inside the CBOM: the wire layer as a flow — service → listener → algorithm → what the rules said —
  // with particles streaming along every dependency; ↑/↓ follows one service's flow
  let F = null, walkAt = -1, flowAnim = null;
  function flowData() {
    const N = new Map(D.cbom.nodes.map(n => [n.id, n])), out = new Map();
    D.cbom.links.forEach(l => (out.get(l.source) || out.set(l.source, []).get(l.source)).push(l.target));
    const verdictOf = a => a.pq ? "post-quantum" : a.qv ? "quantum-vulnerable" : "not at risk";
    const algKey = a => `${a.name} · ${a.primitive || ""}`;
    const svcs = D.cbom.nodes.filter(n => n.kind === "service"), lis = [], algs = new Map(), links = [];
    const verd = {"quantum-vulnerable": {id: "v:qv", name: "quantum-vulnerable", cls: "qv", w: 0}, "post-quantum": {id: "v:pq", name: "post-quantum", cls: "pq", w: 0}, "not at risk": {id: "v:ok", name: "not at risk today", cls: "ok", w: 0}};
    svcs.forEach(s => (out.get(s.id) || []).forEach(lid => {
      const L = N.get(lid); if (!L || L.kind !== "listener") return;
      const myAlgs = (out.get(lid) || []).map(x => N.get(x)).filter(x => x && x.kind === "algorithm");
      lis.push({id: lid, name: (L.name || "").replace(/172\.16\.106\./, "."), svc: s.id, w: Math.max(1, myAlgs.length), qv: L.qv});
      links.push({s: s.id, t: lid, w: Math.max(1, myAlgs.length), cls: myAlgs.some(a => a.qv && !a.pq) ? "qv" : myAlgs.some(a => a.pq) ? "pq" : "ok"});
      myAlgs.forEach(a => {
        const k = algKey(a); const v = verdictOf(a);
        const A = algs.get(k) || algs.set(k, {id: "a:" + k, name: a.name, primitive: a.primitive, cls: verd[v].cls, w: 0, verdict: v}).get(k);
        A.w += 1; links.push({s: lid, t: A.id, w: 1, cls: A.cls});
      });
    }));
    const a2v = new Map();
    algs.forEach(A => { verd[A.verdict].w += A.w; a2v.set(A.id, A.verdict); links.push({s: A.id, t: verd[A.verdict].id, w: A.w, cls: A.cls}); });
    const cols = [
      {title: "services", items: svcs.map(s => ({id: s.id, name: s.name, w: Math.max(1, lis.filter(l => l.svc === s.id).reduce((x, l) => x + l.w, 0)), cls: "svc", mission: s.mission}))},
      {title: "listeners on the wire", items: lis},
      {title: "algorithms negotiated", items: Array.from(algs.values()).sort((x, y) => (x.cls > y.cls ? -1 : x.cls < y.cls ? 1 : y.w - x.w))},
      {title: "what the rules said", items: Object.values(verd).filter(v => v.w)},
    ];
    return {cols, links};
  }
  function cbom() {
    if (flowAnim) { cancelAnimationFrame(flowAnim); flowAnim = null; }
    const svg = d3.select("#graph-cbom"), node = svg.node(), bb = node.getBoundingClientRect(), W = Math.round(bb.width) || 1200, H = Math.round(bb.height) || 700;
    svg.attr("viewBox", `0 0 ${W} ${H}`).selectAll("*").remove();
    const {cols, links} = flowData();
    const left = 40, right = 176, top = 44, bottom = 24, colW = 18, gap = 10;
    const xs = cols.map((c, k) => left + k * ((W - left - right - colW) / (cols.length - 1)));
    const pos = new Map();
    cols.forEach((c, k) => {
      const total = d3.sum(c.items, d => d.w), free = H - top - bottom - gap * (c.items.length - 1), sc = free / Math.max(1, total);
      let y = top;
      c.items.forEach(d => { const h = Math.max(4, d.w * sc); pos.set(d.id, {x: xs[k], y, h, d, col: k, inY: y, outY: y}); y += h + gap; });
    });
    const g = svg.append("g");
    cols.forEach((c, k) => g.append("text").attr("class", "flow-head").attr("x", xs[k]).attr("y", 22).attr("text-anchor", "start").text(`${c.items.length} ${c.title}`));
    // link geometry: a ribbon from the source's running out-edge to the target's running in-edge
    const scaleW = d3.scaleLinear().domain([0, d3.max(Object.values(Object.fromEntries(pos)).map(p => p.d.w)) || 1]).range([0, 1]);
    const ribbons = links.map(l => {
      const s = pos.get(l.s), tt = pos.get(l.t); if (!s || !tt) return null;
      const sh = s.h * (l.w / s.d.w), th = tt.h * (l.w / tt.d.w);
      const y0 = s.outY + sh / 2, y1 = tt.inY + th / 2; s.outY += sh; tt.inY += th;
      const x0 = s.x + colW, x1 = tt.x, mx = (x0 + x1) / 2;
      return {...l, path: `M${x0},${y0} C${mx},${y0} ${mx},${y1} ${x1},${y1}`, width: Math.max(1.5, Math.min(sh, th)), x0, x1};
    }).filter(Boolean);
    const linkSel = g.append("g").selectAll("path").data(ribbons).join("path").attr("class", d => `flow-link ${d.cls}`).attr("d", d => d.path).attr("stroke-width", d => d.width)
      .attr("stroke-dasharray", function () { const L = this.getTotalLength(); return `${L} ${L}`; }).attr("stroke-dashoffset", function () { return this.getTotalLength(); });
    linkSel.transition().delay((d, k) => T(200 + k * 12)).duration(T(900)).ease(d3.easeCubicOut).attr("stroke-dashoffset", 0).on("end", function () { d3.select(this).attr("stroke-dasharray", null); });
    const nodes = Array.from(pos.values());
    const nd = g.append("g").selectAll("g").data(nodes).join("g").attr("transform", d => `translate(${d.x},${d.y})`);
    nd.append("rect").attr("class", d => `flow-node ${d.d.cls}`).attr("width", colW).attr("height", d => d.h).attr("rx", 2);
    nd.append("text").attr("class", d => `flow-label ${d.col === cols.length - 1 ? "big" : ""}`).attr("x", colW + 8).attr("y", d => d.h / 2 + 5).attr("text-anchor", "start")
      .text(d => d.col === 2 ? `${d.d.name}${d.d.primitive ? " · " + d.d.primitive : ""} ×${d.d.w}` : d.col === 3 ? `${d.d.name} · ${d.d.w}` : d.d.name);
    nd.append("title").text(d => d.d.mission || d.d.name);
    // particles
    const parts = [];
    ribbons.forEach((r, k) => { const n = Math.max(1, Math.min(4, Math.round(r.w / 2.5))); for (let i = 0; i < n; i++) parts.push({r, at: Math.random(), speed: 0.08 + Math.random() * 0.07, el: null, k}); });
    const pathEls = linkSel.nodes();
    // each ribbon sampled once; the frame loop interpolates instead of asking the browser for a point per dot per frame
    const NS = 40, samples = pathEls.map(el => { const L = el.getTotalLength(); return d3.range(NS + 1).map(i => { const q = el.getPointAtLength(L * i / NS); return [q.x, q.y]; }); });
    const cv = sel("dots-cbom"), dpr = Math.min(2, window.devicePixelRatio || 1); cv.width = Math.round(W * dpr); cv.height = Math.round(H * dpr);
    const ctx = cv.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const COL = {qv: "255,122,102", pq: "95,240,160", ok: "196,207,221"};
    parts.forEach(d => { d.r_ = 1.8 + Math.min(2.2, d.r.w * 0.3); d.dim = false; });
    let last = performance.now();
    const frame = now => {
      if (now - last < 40 && !SNAP) { flowAnim = requestAnimationFrame(frame); return; }   // 25 frames a second is plenty for dots
      const dt = Math.min(0.08, (now - last) / 1000); last = now;
      ctx.clearRect(0, 0, W, H);
      parts.forEach(d => {
        d.at += d.speed * dt; if (d.at > 1) d.at -= 1;
        const s = samples[d.k]; if (!s) return;
        const f = d.at * NS, i = Math.min(NS - 1, Math.floor(f)), u = f - i, a = s[i], b = s[i + 1];
        ctx.beginPath(); ctx.arc(a[0] + (b[0] - a[0]) * u, a[1] + (b[1] - a[1]) * u, d.r_, 0, Math.PI * 2);
        ctx.fillStyle = `rgba(${COL[d.r.cls] || COL.ok},${d.dim ? .08 : .6})`; ctx.fill();
      });
      if (names[at] === "cbom" && !document.hidden) flowAnim = requestAnimationFrame(frame); else flowAnim = null;
    };
    if (SNAP) { linkSel.attr("stroke-dasharray", null).attr("stroke-dashoffset", 0); frame(performance.now() + 16); }
    else flowAnim = requestAnimationFrame(frame);
    F = {cols, ribbons, linkSel, nd, parts, svcs: cols[0].items};
    nd.filter(d => d.col === 0).on("mouseenter", (ev, d) => focus(d.d.id)).on("mouseleave", () => focus(null));
    nd.filter(d => d.col === 1 || d.col === 2).on("mouseenter", (ev, d) => showEntry(d.d.id)).style("cursor", "help");
    walkAt = -1; legendCbom(null);
    loadCbomDoc().then(() => { if (names[at] === "cbom" && !entryShown) showEntry(F.svcs.length ? F.svcs[0].id : null); });
  }
  // the entry itself: the component as the CBOM holds it, one at a time from the app, cached by bom-ref
  const ENTRIES = new Map(); let entryWanted = null, entryShown = false;
  function loadCbomDoc() { return Promise.resolve(true); }
  const tintJson = s => esc(s).replace(/("(?:[^"\\]|\\.)*")(\s*:)?/g, (m, q, c) => c ? `<i class="k">${q}</i>${c}` : `<i class="s">${q}</i>`).replace(/\b(true|false|null|-?\d+(?:\.\d+)?)\b(?![^<]*<\/i>)/g, `<i class="n">$1</i>`);
  function showEntry(id) {
    const el = sel("entry-cbom"); if (!el) return; entryWanted = id;
    if (!id) { el.innerHTML = `<div class="ek">the entry<small>hover a service, a listener or an algorithm to see its entry as the CBOM holds it</small></div>`; return; }
    const draw = e => {
      if (entryWanted !== id) return;
      if (!e || e.error) { el.innerHTML = `<div class="ek">the entry<small>${esc(e && e.error || "not in the CBOM")} · ${esc(id)}</small></div>`; return; }
      entryShown = true;
      const c = e.component, dep = e.depends_on || [], props = Object.fromEntries((c.properties || []).map(p => [p.name, p.value]));
      const meta = `${esc(e.bom.format || "CycloneDX")} ${esc(e.bom.spec || "")} · ${fmt(e.bom.components)} components · serial …${esc(String(e.bom.serial || "").slice(-12))}`;
      el.innerHTML = `<div class="ek">the entry, as the record holds it<small>${meta}</small></div>` +
        `<div class="eh"><b>${esc(c.name)}</b> <span>${esc(c.type)}${props["pqch:asset-type"] ? " · " + esc(props["pqch:asset-type"]) : ""}${props["pqch:layer"] ? " · " + esc(props["pqch:layer"]) + " layer" : ""}</span>` +
        `<code>${esc(c["bom-ref"])}</code>${dep.length ? `<em>depends on ${dep.length} ${dep.length === 1 ? "entry" : "entries"}</em>` : ""}` +
        `${props["pqch:evidence"] ? (ev => `<em>evidence: ${ev.length === 1 ? "ledger event " + esc(ev[0]) : ev.length + " ledger events, " + esc(ev[0]) + " first"}</em>`)(String(props["pqch:evidence"]).split(",")) : ""}</div>` +
        `<pre>${tintJson(JSON.stringify(c, null, 2))}</pre>`;
    };
    if (ENTRIES.has(id)) { draw(ENTRIES.get(id)); return; }
    if (STATIC) { draw((ST().entries || {})[id] || {error: "not in the CBOM"}); return; }
    el.innerHTML = `<div class="ek">the entry<small>reading ${esc(id)}…</small></div>`;
    fetch(`/api/demo/entry?ref=${encodeURIComponent(id)}`).then(r => r.json().then(j => r.ok ? j : {error: j.detail || `the app answered ${r.status}`}))
      .then(e => { ENTRIES.set(id, e); draw(e); }).catch(err => draw({error: String(err)}));
  }
  function focus(svcId) {
    if (!F) return;
    if (!svcId) { F.linkSel.classed("dim", false).classed("lit", false); F.nd.classed("dim", false); F.parts.forEach(p => { p.dim = false; }); return; }
    const keep = new Set([svcId]); let frontier = [svcId];
    for (let i = 0; i < 3; i++) { const next = []; F.ribbons.forEach(r => { if (frontier.includes(r.s) && !keep.has(r.t)) { keep.add(r.t); next.push(r.t); } }); frontier = next; }
    F.linkSel.classed("dim", r => !(keep.has(r.s) && keep.has(r.t))).classed("lit", r => keep.has(r.s) && keep.has(r.t));
    F.nd.classed("dim", d => !keep.has(d.d.id));
    F.parts.forEach(p => { p.dim = !(keep.has(p.r.s) && keep.has(p.r.t)); });
    showEntry(svcId);
    const algs = F.cols[2].items.filter(a => keep.has(a.id)), s = F.cols[0].items.find(x => x.id === svcId);
    legendCbom({name: s ? s.name : svcId, listeners: F.cols[1].items.filter(l => keep.has(l.id)).length, assets: algs.length,
                qv: algs.filter(a => a.cls === "qv").length, pq: algs.filter(a => a.cls === "pq").length});
  }
  function legendCbom(chain) {
    const c = D.cbom.counts;
    let s = `<span><i style="background:#e2543f"></i>quantum-vulnerable</span><span><i style="background:#35d07f"></i>post-quantum</span><span><i style="background:rgba(196,207,221,.5)"></i>not at risk today (hashes, symmetric)</span>` +
      `<span>the wire layer of <b>${c.components}</b> components and <b>${c.links}</b> dependencies; <b>${c.quantum_vulnerable}</b> quantum-vulnerable in all, including the files</span>`;
    if (chain) s += `<span>· <b>${esc(chain.name)}</b>: ${chain.listeners} listener${chain.listeners === 1 ? "" : "s"} → ${chain.assets} algorithms, <b style="color:#e2543f">${chain.qv} quantum-vulnerable</b>${chain.pq ? `, <b style="color:#35d07f">${chain.pq} post-quantum</b>` : ""}</span>`;
    sel("legend-cbom").innerHTML = s;
  }
  function walk(dir) {
    if (!F || !F.svcs.length) return;
    walkAt = (walkAt + dir + F.svcs.length) % F.svcs.length;
    focus(F.svcs[walkAt].id);
  }

  // the stack, from the silicon up
  function stack() {
    const E = D.engine || {}, T = E.tiers || {}, live = E.live || {};
    const ver = (s, re) => { const m = (s || "").match(re); return m ? m[0] : null; };
    const fastHw = (T.fast || {}).hardware || "", embedHw = (T.embed || {}).hardware || "";
    const li = (a, b, m, lv) => `<li>${esc(a)}${b ? ` <code>${esc(b)}</code>` : ""}${m ? ` <span class="m">${esc(m)}</span>` : ""}${lv ? `<span class="live">live</span>` : ""}</li>`;
    const hosts = Array.isArray(D.hosts) ? D.hosts : [];
    const sc = D.scan || {}, c = (D.cbom || {}).counts || {}, P = D.plan || {}, ch = (D.change || {}).changes || [];
    const layers = [
      ["Hardware", "stated from the spec sheet; the labels below are measured", [li(stage.dataset.spec), li("recorded on every event as", D.hardware)]],
      ["Runtime", "containers with the GPU through CDI; nothing leaves the box", [li("Docker Engine", "CDI nvidia.com/gpu=all"), li("vLLM", ver(fastHw, /vLLM [0-9.]+/) || "vLLM"), li("NVFP4 weights", ver(fastHw, /NVFP4[^,)]*/) || ""),
          li("NeMo Retriever embed NIM", ver(embedHw, /NIM [^)]*/) || ""), li("a read-only image registry on the box", "127.0.0.1:15000")]],
      ["Models, by role", "a role moves to a model only by measurement (spike S3)", Object.entries(T).map(([k, t]) => li(`${k} tier`, t.model, (t.hardware || "").split(";")[1] ? (t.hardware || "").split(";")[1].replace(/\)$/, "").trim() : ""))
          .concat(live.models ? [li("the engine says it serves", live.models.join(", "), `${fmt(live.ms)} ms round trip`, true)] : [])],
      ["The workbench", "three services and two runners, each with one job", [li("app", "FastAPI, server-rendered, the only public leg"), li("runner", "holds the Docker socket; starts every scanner as a container"),
          li("signer", "ML-DSA-65 checkpoints, key where nothing else reads it"), li("system runner", "reads this box's files and firmware"), li("scanners", (D.scanners || []).map(s => `${s.tool} ${s.version || ""}`.trim()).join(" · "))]],
      ["Estates", "the planted one with an answer key; real servers read whole", [li("mini-agency", `${c.services} services · ${c.listeners} listeners`, "scored against the answer key")]
          .concat(hosts.map(h => li(h.name, (h.addresses || []).join(", "), `${fmt(h.findings)} findings · ${(h.parts || []).join(", ")}${h.this_machine ? " · this machine" : ""}${h.recorded ? " · replayed from a recording" : ""}`)))],
      ["What comes out", "the ledger is the record; the CBOM and the plan are projections of it", [li("ledger", `${fmt(sc.events)} events`, "hash-chained, checkpointed, signed"), li("CBOM", `${fmt(c.components)} components`, `${fmt(c.quantum_vulnerable)} quantum-vulnerable · ${fmt(c.post_quantum)} post-quantum`),
          li("plan", `${fmt((P.order || []).length)} steps`, `${fmt((P.order || []).filter(s => s.status === "landed").length)} landed`), li("changes proved on the wire", `${ch.filter(x => x.landed).length}`, "approved by a person, verified by probes, twice")]],
    ];
    const el = sel("layers-stack"); el.innerHTML = "";
    layers.reverse().forEach(([h, sub, items], k) => {
      const d = document.createElement("div"); d.className = "layer";
      d.innerHTML = `<h3>${esc(h)}<small>${esc(sub)}</small></h3><ul>${items.join("")}</ul>`;
      el.appendChild(d);
      if (SNAP) d.classList.add("in"); else setTimeout(() => d.classList.add("in"), 250 + (layers.length - k) * 260);
    });
  }

  // one change, proved: the ledger's own sequence, with its own timings
  let proofTimers = [];
  function change(live) {
    proofTimers.forEach(clearTimeout); proofTimers = [];
    const el = sel("proof-change"), ch = ((D.change || {}).changes || []);
    const pick = live || ch.find(x => x.landed && x.drafted) || ch.find(x => x.landed && x.intent === "require") || ch.find(x => x.landed) || ch[0];
    if (!pick) { el.innerHTML = `<p class="foot">No change run yet: propose from the policy on the Changes page.</p>`; return; }
    // in a copy the tier map is today's, not the one the draft was made under; the ledger names the role only
    const roleModel = STATIC ? `the ${(pick.drafted || {}).role || "drafting"} role's model` : (() => { const E = D.engine || {}, r = (E.roles || {})[(pick.drafted || {}).role] || {}; const tr = (E.tiers || {})[r.tier] || {}; return tr.model ? `${tr.model}${r.reasoning ? ", reasoning on" : ""}` : "a model on this box"; })();
    sel("change-title").textContent = `${pick.service} · ${pick.intent} the hybrid key exchange${pick.landed ? "" : " · in progress"}`;
    const S = pick.steps, t = s => s && s.at ? Date.parse(s.at) : null;
    const approved = S.find(s => s.what === "approved"), applied = S.find(s => s.what === "applied"), verdicts = S.filter(s => s.what === "verdict"), recreated = S.find(s => s.what === "recreated");
    const v1 = verdicts[0], v2 = verdicts[1];
    const probe = (v, name) => v && (v.probes || []).find(p => p.name === name);
    const reh = S.find(s => s.what === "rehearsed");
    const cards = [
      [pick.drafted ? "the draft" : "proposed", pick.drafted ? `<p><b>a config edit, nothing applied</b></p><p class="m">the step came from the rules; the edit was written from ${pick.drafted.findings} findings on the ledger by ${esc(roleModel.replace(", reasoning on", ""))} ${STATIC ? "in the lab" : "on this box"} · the policy file only</p>` :
        `<p>${esc(pick.service)} <span class="m">${esc(pick.address || "")}</span></p><p>intent <b>${esc(pick.intent)}</b></p><p class="m">rule ${esc(pick.rule || "")}</p>`],
      ...(reh ? [["rehearsed on a copy", `<p class="big">${esc((reh.verdict && reh.verdict.status) || reh.verdict || "")}</p><p class="m">a twin at ${esc(reh.twin || "")}, probed before anyone could approve</p>`]] : []),
      ["approved", approved ? `<p>by <b>${esc(approved.by)}</b></p><p class="m">${esc(approved.how || "")}</p>` : `<p class="m">waiting for a person</p>`],
      ["applied", applied ? `<p class="big">${fmt(applied.ms)} ms</p><p class="m">by the runner, config rendered from the policy</p>` : ""],
      ["probes", v1 ? `<p>offer only the hybrid group<br><b class="${probe(v1, "positive") && probe(v1, "positive").result}">${esc((probe(v1, "positive") || {}).result || "")}</b> <span class="m">${esc((probe(v1, "positive") || {}).negotiated || "")}</span></p>` +
          `<p>offer only classical groups<br><b class="${probe(v1, "negative") && probe(v1, "negative").result}">${esc((probe(v1, "negative") || {}).result || "")}</b> <span class="m">${esc((probe(v1, "negative") || {}).negotiated || "")}</span></p>` : ""],
      ["verdict", v1 ? `<p class="big">${esc(v1.status)}</p><p class="m">meets intent: ${v1.meets_intent}${v1.also_accepts && v1.also_accepts.length ? " · also accepts " + esc(v1.also_accepts.join(", ")) : ""}</p>` : ""],
      ["recreated", recreated ? `<p class="big">${fmt(recreated.ms)} ms</p><p class="m">the service restarted from its image</p>` : ""],
      ["proved again", v2 ? `<p class="big">${esc(v2.status)}</p><p class="m">durable: <b>${v2.durable}</b></p>` : ""],
    ];
    const setting = l => l.slice(1).trim().replace(/;$/, "").replace(/'/g, "");
    const lines = (pick.diff || "").split("\n").filter(l => /^[+-]/.test(l) && !/^(\+\+\+|---)/.test(l) && !/^[+-]\s*#/.test(l) && l.length > 1);
    const after = lines.filter(l => l[0] === "+").map(setting), before = lines.filter(l => l[0] === "-").map(setting);
    const file = ((pick.diff || "").match(/^\+\+\+ (.+)$/m) || [])[1] || "the policy's file";
    const kv = s => { const m = s.match(/^([\w.]+)\s*=?\s*(.*)$/); return m ? [m[1].replace(/_/g, " "), m[2]] : [s, ""]; };
    const afterKV = Object.fromEntries(after.map(kv));
    // what the listener accepts, before (from the scan) and after (from the settings written, and the probes)
    const B = pick.before || {}, pillK = n => `<i class="pill ${n.qv ? "qv" : "pq"}">${esc(n.name)}</i>`, pillP = n => `<i class="pill ok">${esc(n)}</i>`;
    const groupsAfter = (afterKV["ssl groups"] || afterKV["ssl ecdh curve"] || "").split(/[:,\s]+/).filter(Boolean);
    const pmin = afterKV["ssl min protocol version"], pmax = afterKV["ssl max protocol version"];
    const protosAfter = pmin && pmax ? (pmin === pmax ? [pmin] : [pmin, pmax]) : (afterKV["ssl protocols"] || "").split(/\s+/).filter(Boolean);
    const neg = probe(v1, "positive") && probe(v1, "positive").negotiated;
    const kexAfter = groupsAfter.length ? groupsAfter.map(g => ({name: g, qv: !/MLKEM|sntrup|ML-KEM/i.test(g)})) : neg ? [{name: neg, qv: false}] : [];
    const row = (label, b, a) => `<div class="arow"><span class="k">${label}</span><div class="pills">${b.length ? b : `<span class="m">—</span>`}</div><span class="arr">→</span><div class="pills">${a.length ? a : `<span class="m">unchanged</span>`}</div></div>`;
    const accepts = (B.kex || protosAfter.length) ? `<div class="accepts"><div class="ahead"><span></span><span>before, from the scan</span><span></span><span>after, as written and probed</span></div>` +
      row("key exchange", (B.kex || []).map(pillK).join(""), kexAfter.map(pillK).join("")) +
      row("protocol", (B.protocols || []).map(n => pillP(n.replace(/^TLS /, "TLS "))).join(""), protosAfter.map(v => pillP(v.replace(/^TLSv/, "TLS "))).join("")) + `</div>` : "";
    const settings = `<div class="settings"><span class="k">the lines written to ${esc(file)}</span>` +
      after.map(s => { const [k, v] = kv(s); const long = v.length > 48; return `<p class="add" title="${esc(v)}"><b>${esc(k)}</b> ${esc(long ? v.slice(0, 44) + "…" : v)}</p>`; }).join("") +
      (before.length ? `<span class="k">replaced</span>` + before.map(s => `<p class="del">${esc(s)}</p>`).join("") : "") + `</div>`;
    const edit = `<div class="edit"><h4>the edit, as applied<small>rendered from the policy into the service's config; its own file is not touched</small></h4>${accepts}${settings}</div>`;
    el.innerHTML = `<div class="steps">${cards.map(([h, b]) => `<div class="step"><h4>${esc(h)}</h4>${b}</div>`).join("")}</div>` +
      `<div class="proof-lower">${edit}<div class="wire" id="proof-wire"></div></div>` +
      `<div class="verdict" id="proof-verdict"></div><div class="elapsed" id="proof-elapsed"></div>`;
    const wire = wireDiagram(sel("proof-wire"), pick, v1, v2, applied, recreated);
    const steps = Array.from(el.querySelectorAll(".step"));
    // which wire stage and which lower panel each card brings in
    const names_ = cards.map(([h]) => h), wireFor = {"the draft": "before", "proposed": "before", "rehearsed on a copy": "twin", "probes": "real", "proved again": "again"};
    const editEl = el.querySelector(".edit"); if (editEl && !SNAP) editEl.style.opacity = 0;
    const times = [t(S.find(s => s.what === "proposed")), ...(reh ? [t(reh)] : []), t(approved), t(applied), probe(v1, "positive") ? Date.parse(probe(v1, "positive").at || v1.at) : t(v1), t(v1), t(recreated), t(v2)];
    const base = times.find(x => x != null) || 0, span = Math.max(1, (times.filter(x => x != null).pop() || base) - base);
    const scale = SNAP ? 0 : Math.min(1, 18000 / span);
    if (SNAP) { steps.forEach(s => s.classList.add("on")); if (pick.drafted && steps[0]) steps[0].classList.add("model"); if (v2) sel("proof-verdict").innerHTML = `<b>${esc(v2.status)}</b> · proved on the wire, twice <small>a model drafted the edit; the probes judged it</small>`; return; }
    const start = Date.now();
    times.forEach((tm, k) => {
      const delay = SNAP ? 0 : (tm == null ? 400 + k * 500 : Math.max(400 + k * 350, (tm - base) * scale + 400));
      proofTimers.push(setTimeout(() => {
        if (steps[k]) steps[k].classList.add("on");
        if (steps[k] && pick.drafted && k === 0) steps[k].classList.add("model");
        if (wireFor[names_[k]]) wire.show(wireFor[names_[k]]);
        if (names_[k] === "applied" && editEl) { editEl.style.transition = "opacity .5s"; editEl.style.opacity = 1; }
        const ap = t(approved) || base;
        sel("proof-elapsed").textContent = tm != null && tm >= ap ? `replayed from the ledger with its own timings · ${((tm - ap) / 1000).toFixed(1)} s after the approval` + (SNAP ? "" : ` · shown at ${scale < 1 ? "×" + (1 / scale).toFixed(1) + " speed" : "real speed"}`) : "replayed from the ledger with its own timings";
        if (k === steps.length - 1 && v2) sel("proof-verdict").innerHTML = `<b>${esc(v2.status)}</b> · proved on the wire, twice <small>a model drafted the edit; the probes judged it</small>`;
      }, delay));
    });
  }
  // the probes, drawn: a client offering only the hybrid group, a client offering only classical groups,
  // each against the deployed listener, before and after it was recreated; the ledger's own results
  function wireDiagram(el, pick, v1, v2, applied, recreated) {
    // four stages, each a group revealed when its card lights (change() calls show(name)); a still shows all
    const W = Math.max(520, el.clientWidth || 700), GAP = 92, H = 40 + 4 * GAP + 28;
    const reh = (pick.steps || []).find(s => s.what === "rehearsed"), rv = reh && reh.verdict && reh.verdict.probes ? {...reh.verdict, probes: reh.verdict.probes.map(q => ({...q, negotiated: q.negotiated === "None" ? null : q.negotiated, ms: q.started_at && q.ended_at ? Date.parse(q.ended_at) - Date.parse(q.started_at) : null}))} : null;
    const probe = (v, name) => v && (v.probes || []).find(p => p.name === name) || {};
    const rows = [["offer only X25519MLKEM768", "positive"], ["offer only classical groups", "negative"]];
    const svg = d3.select(el).html("").append("svg").attr("viewBox", `0 0 ${W} ${H}`).attr("class", "wire-svg");
    const cx = 236, lx = W - 330, B = pick.before;
    svg.append("text").attr("class", "wire-small").attr("x", 0).attr("y", 12).text("Two clients against the listener: one offering only the hybrid group, one offering only classical groups. Met when the first is accepted and the second refused.");
    const hadHybrid = B && (B.kex || []).some(k => !k.qv), classical = B ? (B.kex || []).filter(k => k.qv).map(k => k.name) : [];
    const blocks = [
      ["before", `1 · before the change · the real listener, from the scan · ${B ? esc(B.posture || "") + (hadHybrid && classical.length ? ": hybrid enabled, not enforced" : "") : "no record"}`, null,
        B ? [[hadHybrid ? "accepted" : "refused", hadHybrid ? "the hybrid group was offered" : "no hybrid group offered"], [classical.length ? "accepted" : "refused", classical.join(", ")]] : null, true, `${pick.service} ${pick.address || ""}`],
      ["twin", "2 · rehearsed on a twin · the edit applied to a copy and probed before approval", rv, null, false, `twin ${reh && reh.twin || ""}`],
      ["real", "3 · the real change · the edit applied to the listener and probed", v1, null, false, `${pick.service} ${pick.address || ""}`],
      ["again", "4 · the same two probes after the service restarted from its image", v2, null, false, `${pick.service} ${pick.address || ""}`],
    ];
    const groups = {};
    blocks.forEach(([key, label, v, pre, isBefore, under], k) => {
      const y0 = 42 + k * GAP, g = svg.append("g").attr("opacity", SNAP ? 1 : 0); groups[key] = {g, items: []};
      const status = v && v.status ? " · " + v.status : "", durable = v && v.durable === true ? " · durable" : "";
      g.append("text").attr("class", "wire-head" + (isBefore ? " before" : "")).attr("x", 0).attr("y", y0 - 14).text(`${label}${status}${durable}${!v && !isBefore ? " · not run" : ""}`);
      rows.forEach(([what, name], i) => {
        const y = y0 + i * 34;
        let result, detail, ms = null;
        if (isBefore) { if (!pre) return; result = pre[i][0]; detail = pre[i][1]; }
        else { const pr = probe(v, name); result = pr.result; detail = pr.negotiated || ""; ms = pr.ms; }
        const ok = result === "accepted", wrong = isBefore && i === 1 && ok;
        g.append("text").attr("class", "wire-client").attr("x", cx - 8).attr("y", y + 4).attr("text-anchor", "end").text(what);
        const line = g.append("line").attr("class", `wire-line ${ok ? "ok" : "no"}${wrong ? " wrong" : ""}`).attr("x1", cx).attr("y1", y).attr("x2", lx - 2).attr("y2", y);
        const res = g.append("text").attr("class", `wire-result ${ok ? "ok" : "no"}${wrong ? " wrong" : ""}`).attr("x", lx + 14).attr("y", y + 4)
          .text(result ? `${result}${detail ? " · " + detail : ""}${ms != null ? " · " + ms + " ms" : ""}${wrong ? " · not enforced" : ""}` : "—");
        groups[key].items.push({line, res, i});
      });
      // the listener: a bracket both lines meet, with its node at the middle
      g.append("line").attr("class", "wire-bracket").attr("x1", lx).attr("y1", y0 - 4).attr("x2", lx).attr("y2", y0 + 38);
      g.append("circle").attr("class", "wire-node").attr("cx", lx).attr("cy", y0 + 17).attr("r", 7);
      g.append("circle").attr("class", "wire-node-core").attr("cx", lx).attr("cy", y0 + 17).attr("r", 2.5);
      g.append("text").attr("class", "wire-small").attr("x", lx).attr("y", y0 + 50).attr("text-anchor", "middle").text(under);
    });
    svg.append("text").attr("class", "wire-small").attr("x", 0).attr("y", H - 6)
      .text(`openssl s_client 3.5 and testssl.sh 3.2.4 in containers · applied in ${fmt(applied && applied.ms)} ms · recreated in ${fmt(recreated && recreated.ms)} ms · raw outputs hashed on the ledger`);
    return {show(key) { const G = groups[key]; if (!G || SNAP) return; G.g.transition().duration(300).attr("opacity", 1);
      G.items.forEach(({line, res, i}) => { const L = (lx - 2) - cx; line.attr("stroke-dasharray", `${L} ${L}`).attr("stroke-dashoffset", L).transition().delay(200 + i * 450).duration(650).attr("stroke-dashoffset", 0).on("end", function () { d3.select(this).attr("stroke-dasharray", null); });
        res.attr("opacity", 0).transition().delay(800 + i * 450).attr("opacity", 1); }); }};
  }
  function approveLive() {
    if (STATIC) { if (names[at] !== "change") go(names.indexOf("change")); sel("change-title").textContent = "Approving needs the running workbench; this copy replays the recorded change from its ledger."; return; }
    const ch = ((D.change || {}).changes || []), open = ch.find(x => x.open), run = (D.change || {}).run;
    if (!open || !run) { sel("change-title").textContent = "No open change to approve: propose from the policy first (the Changes page)."; return; }
    if (names[at] !== "change") go(names.indexOf("change"));
    sel("change-title").textContent = `${open.service} · approving as ${stage.dataset.operator} · the runner applies, probes, recreates, probes again…`;
    fetch(`/changes/${run}/${open.change_id}/approve`, {method: "POST", headers: {"Origin": location.origin}}).then(() => {
      const tick = () => fetch("/api/demo").then(r => r.json()).then(d => {
        D = d; const c = ((D.change || {}).changes || []).find(x => x.change_id === open.change_id);
        change(c);
        if (!(c && c.landed)) proofTimers.push(setTimeout(tick, 3000));
      });
      tick();
    });
  }

  // ask the CBOM: one question, live, with every citation checked
  const ASK = ["Which listeners are still limited to TLS 1.2?", "Which SSH listener still offers the 1024-bit Diffie-Hellman group?",
               "Does any service present an ML-DSA certificate, and which?", "Which listeners already negotiate a hybrid post-quantum key exchange?"];
  let askAt = 0, askTimer = null;
  function ask() {
    if (SNAP) {
      sel("ask-q").textContent = ASK[0];
      sel("ask-box").innerHTML = `<div class="pipeline done"><div class="pstage on"><b>1 · retrieve</b><span>12 entries shown to the model</span></div><div class="pstage on"><b>2 · reason</b><span>nemotron-3.5-lightning, reasoning on, 5,111 completion tokens, 37,663 ms</span></div><div class="pstage on"><b>3 · check</b><span>6 of 6 citations on the ledger</span></div></div>` +
        `<div class="ask-grid"><div><div class="answer">The listeners still limited to TLS 1.2 are <code>listener:172.16.106.32:8443</code> and <code>listener:172.16.106.31:5671</code>; both have the TLS 1.3 item open with a 2030 deadline. All other listeners negotiate TLS 1.3.</div><div class="verdict ok">Every citation and component passes the rule.</div><div class="cites"><span class="ok">01M6KW2M0ZPQ18E1SZ26G53FRQ ✓ on the ledger</span><span class="ok">01M6KW2M173YQXMAP0R6SRBCSJ ✓ on the ledger</span></div><div class="who">a still: the shape of an answer, not a live one</div></div>` +
        `<div class="shown"><b>what the model was shown</b><span>listener TLS 172.16.106.32:8443 <i>0.36</i></span><span>listener TLS 172.16.106.10:443 <i>0.35</i></span><span>listener TLS 172.16.106.31:5671 <i>0.34</i></span><span>svc:legacy-app <i>0.31</i></span><span>svc:queue <i>0.30</i></span></div></div>` +
        `<div class="qlist">${ASK.map((x, i) => `<span class="${i === 0 ? "on" : ""}">${esc(x)}</span>`).join("")}</div>`;
      return;
    }
    askRun(ASK[askAt % ASK.length]);
  }
  function askNext() { if (names[at] !== "ask") go(names.indexOf("ask")); askAt++; askRun(ASK[askAt % ASK.length]); }
  let askAbort = null;
  function askRun(q) {
    if (askTimer) clearInterval(askTimer);
    if (askAbort) { askAbort.abort(); askAbort = null; }   // a click or A while a question is out: that one is dropped
    const box = sel("ask-box"), run = (D.scan || {}).run, t0 = Date.now();
    sel("ask-q").textContent = q;
    const E = D.engine || {}, Tm = E.tiers || {}, emb = (Tm.embed || {}).model || "the embed NIM", mdl = (Tm[((E.roles || {})["ask-cbom"] || {}).tier || "deliberate"] || {}).model || "the model";
    box.innerHTML = `<div class="pipeline">` +
      `<div class="pstage on" id="st-retrieve"><b>1 · retrieve</b><span>${esc(emb)}: the entries nearest the question, from the CBOM</span></div>` +
      `<div class="pstage" id="st-reason"><b>2 · reason</b><span>${esc(mdl)}${STATIC ? ", recorded" : ` on the Blackwell GPU, thinking ${((E.roles || {})["ask-cbom"] || {}).reasoning ? "on" : "off, by measurement"}`}</span></div>` +
      `<div class="pstage" id="st-check"><b>3 · check</b><span>every cited event looked up on the ledger; an absent one fails the answer</span></div></div>` +
      `<div class="thinking"><span class="t">0.0 s</span>${STATIC ? `an answer recorded ${esc((ST().ask_recorded_at || "").slice(0, 10))}, its citations checked when this copy was built` : "on this box, nothing leaves it"}</div>` +
      `<div class="qlist">${ASK.map((x, i) => `<span class="${x === q ? "on" : ""}">${esc(x)}</span>`).join("")}</div>`;
    wireChips(box);
    askTimer = setInterval(() => { const s = box.querySelector(".t"); if (!s) return; const e = (Date.now() - t0) / 1000; s.textContent = e.toFixed(1) + " s"; if (e > 2.5) { const r = sel("st-reason"); if (r) r.classList.add("on"); } }, 100);
    const ac = new AbortController(), killer = setTimeout(() => ac.abort(), 12000); askAbort = ac;
    const askUrl = STATIC ? ((ST().ask || {})[q] ? BASE + ST().ask[q] : null) : `/ask?run=${encodeURIComponent(run || "")}&q=${encodeURIComponent(q)}`;
    (askUrl ? fetch(askUrl, {signal: ac.signal}) : Promise.reject(new Error("no answer was recorded for this question"))).then(r => { clearTimeout(killer); if (!r.ok) throw new Error(`the app answered ${r.status}`); return r.text(); }).then(html => {
      clearInterval(askTimer);
      const doc = new DOMParser().parseFromString(html, "text/html");
      const ans = doc.querySelector("p.answer"), notes = Array.from(doc.querySelectorAll("p.note")).map(n => n.textContent.trim());
      const verdict = notes.find(n => /passes the rule|fails the rule|No events cited|do not answer/.test(n)) || "";
      const model = notes.find(n => /completion tokens/.test(n)) || "";
      const cites = Array.from(doc.querySelectorAll("table tbody tr")).map(tr => { const td = tr.querySelectorAll("td"); return {ev: (td[0] ? td[0].textContent : "").trim().slice(0, 26), ok: /passes/.test(tr.textContent)}; }).filter(c => c.ev);
      const na = Array.from(doc.querySelectorAll("p, div")).map(x => x.textContent.trim()).find(x => /^Not answered/.test(x));
      const good = /passes the rule/.test(verdict);
      const shownH = Array.from(doc.querySelectorAll("h3")).find(h => /What the model was shown/.test(h.textContent));
      const shown = shownH && shownH.nextElementSibling ? Array.from(shownH.nextElementSibling.querySelectorAll("li")).map(li => { const a = li.querySelector("a"), s = li.querySelector("small"); return {name: a ? a.textContent.trim() : "", score: s ? (s.textContent.match(/score ([0-9.]+)/) || [])[1] : null}; }).filter(x => x.name) : [];
      box.innerHTML = `<div class="pipeline done"><div class="pstage on"><b>1 · retrieve</b><span>${shown.length} entries shown to the model</span></div><div class="pstage on"><b>2 · reason</b><span>${esc(model.replace(/\. Retrieval:.*$/, "").replace(/^.*?\(aarch64[^)]*\),? ?/, ""))}</span></div><div class="pstage on ${good ? "" : "bad"}"><b>3 · check</b><span>${cites.filter(c => c.ok).length} of ${cites.length} citations on the ledger</span></div></div>` +
        `<div class="ask-grid"><div>` +
        (ans ? `<div class="answer">${esc(ans.textContent.trim()).replace(/(listener:[^\s,)]+|svc:[a-z-]+|0[0-9A-Z]{25})/g, "<code>$1</code>")}</div>` : `<div class="answer">${esc(na || "No answer.")}</div>`) +
        `<div class="verdict ${good ? "ok" : "bad"}">${esc(verdict || (na ? "Not answered." : ""))}</div>` +
        (cites.length ? `<div class="cites">${cites.map(c => `<span class="${c.ok ? "ok" : "bad"}">${esc(c.ev)} ${c.ok ? "✓ on the ledger" : "✗"}</span>`).join("")}</div>` : "") +
        `<div class="who">answered in ${((Date.now() - t0) / 1000).toFixed(1)} s · ${esc(model.replace(/\. Retrieval:.*$/, ""))}</div></div>` +
        `<div class="shown"><b>what the model was shown</b>${shown.map(x => `<span>${esc(x.name)}${x.score ? ` <i>${x.score}</i>` : ""}</span>`).join("")}</div></div>` +
        `<div class="qlist">${ASK.map(x => `<span class="${x === q ? "on" : ""}">${esc(x)}</span>`).join("")}</div>`;
      wireChips(box);
    }).catch(e => { if (e.name === "AbortError" && ac !== askAbort) return;   // dropped on purpose for a newer question
      clearInterval(askTimer); clearTimeout(killer);
      box.innerHTML = `<div class="pipeline"><div class="pstage on bad"><b>no answer</b><span>${esc(e.name === "AbortError" ? "nothing came back in 12 s; the app or the engine did not reply. Press A or click a question to ask again." : (e.message || String(e)))}</span></div></div>` +
        `<div class="qlist">${ASK.map(x => `<span class="${x === q ? "on" : ""}">${esc(x)}</span>`).join("")}</div>`; wireChips(box); });
  }
  function wireChips(box) {
    box.querySelectorAll(".qlist span").forEach(s => { s.style.cursor = "pointer"; s.title = "ask this one now"; s.addEventListener("click", () => { askAt = ASK.indexOf(s.textContent); askRun(s.textContent); }); });
  }

  // the closing beat: the stack and the record together
  function closing() { try { record(); } catch (e) { sel("verify-record").textContent = "record not drawn: " + e; } }

  // the record: the chain scrolling, the verification, and where this scales
  function record() {
    const R = D.record || {}, el = sel("chain-record"); el.innerHTML = "";
    const chain = R.chain || [], first = chain[0];
    // one event as the file holds it, trimmed to the fields that make the chain
    if (first) { const line = document.createElement("div"); line.className = "ev-line";
      line.innerHTML = `<span class="k">one event, as written to the JSONL file (payload left out)</span><code>{"schema":"pqch.event/1","seq":${first.seq},"ts":"${esc(first.ts || "")}","type":"${esc(first.type || "")}","actor":{"kind":"${esc(first.actor || "")}"},"prev":"${esc(first.prev)}…","hash":"${esc(first.hash)}…"}</code>`;
      el.appendChild(line); }
    chain.forEach((e, k) => {
      const d = document.createElement("div"); d.className = "ev"; d.style.animationDelay = `${T(k * 45)}ms`;
      d.innerHTML = `<span class="p">${String(e.seq).padStart(4)}</span>  <span class="h">${esc(e.hash)}</span> ← <span class="p">${esc(e.prev)}</span>  <span class="t">${esc(e.type)}</span>  <span class="p">${esc((e.ts || "").replace("T", " ").slice(0, 19))} · ${esc(e.actor || "")}</span>`;
      el.appendChild(d);
    });
    const v = R.verify || {}, cv = ((D.change || {}).record || {}).verify || {};
    // the history of changes, in order, from the change run's own ledger
    const ch = ((D.change || {}).changes || []), hhmm = s => s && s.at ? s.at.replace("T", " ").slice(11, 19) : "";
    const hist = ch.filter(c => c.steps && c.steps.length).map(c => { const S = c.steps, w = n => S.find(s => s.what === n), vs = S.filter(s => s.what === "verdict");
      const met = v => v.meets_intent === true || v.status === "enforced" || (c.intent === "enable" && v.status === "enabled-not-enforced");
      const parts = [w("proposed") ? `proposed ${hhmm(w("proposed"))}` : "", w("rehearsed") ? `rehearsed on a twin: ${esc((w("rehearsed").verdict || {}).status || "")}` : "", w("approved") ? `approved by <b>${esc(w("approved").by)}</b> ${hhmm(w("approved"))}` : "<i>not approved</i>",
        w("applied") ? `applied in ${fmt(w("applied").ms)} ms` : "", vs[0] ? `<b class="${met(vs[0]) ? "ok" : "no"}">${esc(vs[0].status)}</b>` : "", w("recreated") ? "recreated" : "", vs[1] ? `<b class="${met(vs[1]) ? "ok" : "no"}">${esc(vs[1].status)}</b>${vs[1].durable === true ? ", durable" : ""}` : ""].filter(Boolean);
      return `<li><span class="svc">${esc(c.service)} · ${esc(c.intent)}</span>${parts.join(" → ")}</li>`; }).join("");
    sel("verify-record").innerHTML =
      `<div class="big">${v.ok ? "<b>Chain intact, every event signed</b>" : "<b class='no'>Verification failed</b>"}</div>` +
      `<p><b>${fmt(v.events)}</b> events on the scan's ledger · ${fmt(v.checkpoints)} checkpoint${v.checkpoints === 1 ? "" : "s"} · signed through event ${fmt(v.signed_through)} · ${fmt(v.unsigned_after)} unsigned after` +
      (cv.events ? ` · <b>${fmt(cv.events)}</b> on the change run's · ${fmt(cv.checkpoints)} checkpoints · ${cv.ok ? "intact" : "<b class='no'>failed</b>"}` : "") + `</p>` +
      `<p class="m">ML-DSA-65 · key id <code>${esc(v.key_id || "")}</code></p>` +
      `<div class="facts">` +
      `<div><i>JSONL</i><b>An append-only file per run</b>one line per event, in order: findings, assessments, approvals, verdicts, model calls; nothing is edited or deleted</div>` +
      `<div><i>hash chain</i><b>Each event carries the hash of the one before</b>change a byte anywhere and every hash after it breaks, so the file is tamper-evident, not merely logged</div>` +
      `<div><i>ML-DSA-65</i><b>Checkpoints signed with a post-quantum key</b>by a signer that alone holds the key; the key id is on every page, and the record is verified live each time it is shown</div>` +
      `<div><i>projection</i><b>The CBOM, the plan and every page are rebuilt from the events</b>so the estate can be shown as of any event, and a recording replays into a new signed run on any box</div>` +
      `</div>` +
      (hist ? `<div class="hist"><span class="k">the history of changes, in order, from the ledger</span><ul>${hist}</ul></div>` : "");
    const tiers = [["one GB10", "this demo: one estate, scanned, planned and changed on a desktop box"], ["two GB10s", "linked over ConnectX-7: the 120B model with long context across both"],
      ["Pro Max GB300", "the larger model resident, more estates in parallel"], ["PowerEdge XE", "many estates and many investigators at once; one queue today"], ["an AI factory", "the agency's whole estate, continuously"]];
    sel("scale-record").innerHTML = (STATIC ? `<p class="m">This copy's runs were recorded on <b>${esc(D.hardware)}</b>; the stack drawn is the kit as it runs on one GB10.</p>` : "") + `<div class="k">The same stack scales without changing shape</div><div class="tiers">${tiers.map(([n, d], i) => `<div class="tier${i === 0 ? " here" : ""}"><b>${esc(n)}</b><span>${esc(d)}</span></div>${i < tiers.length - 1 ? '<span class="arr">→</span>' : ""}`).join("")}</div>` +
      `<p class="m">What does not change: the containers by digest, the one inference seam, the ledger and its signatures. What changes: which model serves each tier, and how many estates run at once. Only the first tier is measured; the rest is the same images on more hardware, to be measured as it is reached.</p>`;
  }
})();
