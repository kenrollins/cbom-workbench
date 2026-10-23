// The plan, drawn: one lane per service in priority order, plus the certificate authority and the
// estate-wide work; columns are the waves (now, by 2030, by 2031), and within a wave a step sits right
// of what it waits for. Lines are dependencies. The shared dependencies sit above the lanes; hovering
// one lights every step it touches. A click shows the step: why, what it waits for and unblocks, the
// CBOM fields it was computed from, and where it is resolved. Drawn from planning.build.
(function () {
  if (typeof d3 === "undefined") return;
  var css = getComputedStyle(document.documentElement);
  var T = function (n) { return css.getPropertyValue(n).trim(); };
  var C = { fg: T("--fg"), fg2: T("--fg2"), dim: T("--dim"), faint: T("--faint"), line: T("--line"), line2: T("--line2"),
            card: T("--card"), bg: T("--bg"), good: T("--good"), warn: T("--warn"), bad: T("--bad"), accent: T("--accent"),
            gov: T("--gov"), ast: T("--ast"), risk: T("--risk"), outc: T("--outc") };
  var MONO = T("--mono");
  var KIND = { replace: "replace", tls13: "TLS 1.3", enable: "offer hybrid", require: "require hybrid", ca: "new ML-DSA root",
               reissue: "reissue (ML-DSA)", retire: "retire unserved", clients: "upgrade clients", scope: "add to scope", cert: "replace cert" };
  var DEPC = { "certificate-authority": C.gov, "library-build": C.ast, "shared-key": C.outc, "client-trust-anchor": C.risk, "client-vlan": C.gov };
  function esc(s) { return String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }

  function draw(fig) {
    var P = JSON.parse(fig.dataset.plan);
    var steps = [], byId = {};
    P.waves.forEach(function (w) { w.steps.forEach(function (s) { s.wave = w.id; steps.push(s); byId[s.id] = s; }); });
    // Lanes: the CA and estate-wide work, then services by rank.
    var lanes = P.lanes ? P.lanes.slice() : [];
    if (!P.lanes && steps.some(function (s) { return s.kind === "ca"; })) lanes.push({ id: "@ca", label: "internal CA", sub: "one root, many leaves" });
    if (!P.lanes) P.ranking.forEach(function (r, i) {
      lanes.push({ id: r.service, label: r.service, sub: (i + 1) + " · " + (r.prioritized ? "secret until " + (r.sensitive_through || "?") : "not prioritized"),
                   prioritized: r.prioritized });
    });
    if (!P.lanes && steps.some(function (s) { return s.kind === "retire"; })) lanes.push({ id: "@estate", label: "whole estate", sub: "files nothing serves" });
    var laneOf = function (s) { return s.kind === "ca" ? "@ca" : (s.service || "@estate"); };
    // Slot within a wave: right of every step it waits for in the same wave.
    var depth = {};
    function slot(s) {
      if (depth[s.id] != null) return depth[s.id];
      depth[s.id] = 0;
      var d = 0;
      s.depends_on.forEach(function (x) { var p = byId[x]; if (p && p.wave === s.wave) d = Math.max(d, slot(p) + 1); });
      return (depth[s.id] = d);
    }
    steps.forEach(slot);
    var WAVES = P.waves.map(function (w) { return w.id; });
    var slots = {}; WAVES.forEach(function (w) { slots[w] = 1 + d3.max(steps.filter(function (s) { return s.wave === w; }), function (s) { return depth[s.id]; }); });

    var wrap = d3.select(fig).classed("drawn", true);
    var W = Math.max(fig.clientWidth - 320, 760), LABEL = 150, LH = 42, NH = 26;
    var slotW = (W - LABEL - 10) / d3.sum(WAVES, function (w) { return slots[w]; });
    var NW = Math.min(118, slotW - 10);

    var waveX = {}, acc = LABEL;
    WAVES.forEach(function (w) { waveX[w] = acc; acc += slots[w] * slotW; });
    var svg = wrap.append("svg").attr("role", "img").attr("aria-label", "the migration plan");
    // Shared dependencies, as chips above the lanes.
    var chips = svg.append("g");
    var cx = LABEL, cy = 8;
    P.dependencies.forEach(function (d) {
      var g = chips.append("g").style("cursor", "pointer");
      var label = ({ "certificate-authority": "CA: ", "library-build": "one build: ", "shared-key": "one key: ", "client-trust-anchor": "clients' CA: ", "client-vlan": "" })[d.kind]
        + d.name.split(",")[0].replace("CN=", "");
      var t = g.append("text").attr("x", 10).attr("y", 20).attr("font-size", 11.5).attr("fill", DEPC[d.kind] || C.fg2).text(label);
      var w = t.node().getComputedTextLength() + 28;
      if (cx + w > W) { cx = LABEL; cy += 52; }
      g.attr("transform", "translate(" + cx + "," + cy + ")");
      g.insert("rect", "text").attr("width", w).attr("height", 30).attr("fill", C.bg).attr("stroke", DEPC[d.kind] || C.line2);
      g.append("text").attr("x", 10).attr("y", 44).attr("font-size", 9.5).attr("fill", C.dim)
        .text(d.services.length > 2 ? d.services.length + " " + (P.lanes ? "hosts" : "services") : d.services.join(" · "));
      g.on("mouseenter", function () { light(d); }).on("mouseleave", function () { light(null); }).on("click", function () { showDep(d); });
      cx += w + 12;
    });

    // The lanes start below the chips as drawn.
    var TOP = cy + 52 + 46;
    var H = TOP + lanes.length * LH + 16;
    svg.attr("viewBox", [0, 0, W, H]);
    var panel = wrap.append("div").attr("class", "estate-panel");
    var laneY = {}; lanes.forEach(function (l, i) { laneY[l.id] = TOP + i * LH + LH / 2; });
    steps.forEach(function (s) { s.x = waveX[s.wave] + depth[s.id] * slotW + (slotW - NW) / 2; s.y = laneY[laneOf(s)] - NH / 2; });

    // Wave bands and headings.
    var labels = P.wave_labels || { now: "now", "2030": "by 2030", "2031": "by 2031" };
    WAVES.forEach(function (w, i) {
      svg.append("rect").attr("x", waveX[w]).attr("y", TOP - 22).attr("width", slots[w] * slotW).attr("height", H - TOP + 14)
        .attr("fill", i % 2 ? "none" : C.card).attr("opacity", .55);
      svg.append("text").attr("x", waveX[w] + 8).attr("y", TOP - 8).attr("fill", C.dim).attr("font-size", 10.5).attr("font-family", MONO)
        .attr("letter-spacing", ".08em").text(labels[w].toUpperCase());
    });
    // Lanes.
    lanes.forEach(function (l) {
      svg.append("line").attr("x1", 0).attr("x2", W).attr("y1", laneY[l.id] + LH / 2).attr("y2", laneY[l.id] + LH / 2).attr("stroke", C.line);
      svg.append("text").attr("x", 4).attr("y", laneY[l.id] - 2).attr("fill", l.id.charAt(0) === "@" ? C.dim : C.fg).attr("font-size", 12.5)
        .attr("font-weight", 600).text(l.label);
      svg.append("text").attr("x", 4).attr("y", laneY[l.id] + 12).attr("fill", C.dim).attr("font-size", 10).text(l.sub);
      if (!steps.some(function (s) { return laneOf(s) === l.id; })) {
        svg.append("text").attr("x", LABEL + 8).attr("y", laneY[l.id] + 4).attr("fill", C.good).attr("font-size", 11)
          .text("nothing open: every migration item met");
      }
    });
    var curve = function (a, b) {
      var x1 = a.x + NW, y1 = a.y + NH / 2, x2 = b.x, y2 = b.y + NH / 2, m = (x1 + x2) / 2;
      if (x2 < x1 + 6) { x1 = a.x + NW / 2; y1 = a.y + (y2 > y1 ? NH : 0); x2 = b.x + NW / 2; y2 = b.y + (y2 > y1 ? 0 : NH); return "M" + x1 + "," + y1 + "L" + x2 + "," + y2; }
      return "M" + x1 + "," + y1 + "C" + m + "," + y1 + " " + m + "," + y2 + " " + x2 + "," + y2;
    };
    svg.append("defs").append("marker").attr("id", "arr").attr("viewBox", "0 0 8 8").attr("refX", 7).attr("refY", 4).attr("markerWidth", 7)
      .attr("markerHeight", 7).attr("orient", "auto").append("path").attr("d", "M0,0L8,4L0,8z").attr("fill", C.dim);
    var links = [];
    steps.forEach(function (s) { s.depends_on.forEach(function (x) { if (byId[x]) links.push({ a: byId[x], b: s }); }); });
    var path = svg.append("g").selectAll("path").data(links).join("path").attr("fill", "none").attr("stroke", C.dim).attr("stroke-width", 1.3)
      .attr("marker-end", "url(#arr)").attr("d", function (l) { return curve(l.a, l.b); });

    var freed = P.freed || [];
    var fill = function (s) { return s.assumed ? C.warn : (s.state === "done" ? C.good : (s.state === "ready" ? C.accent : C.line2)); };
    var node = svg.append("g").selectAll("g").data(steps).join("g").attr("transform", function (s) { return "translate(" + s.x + "," + s.y + ")"; })
      .style("cursor", "pointer").on("click", function (ev, s) { show(s); });
    node.append("rect").attr("width", NW).attr("height", NH).attr("rx", 3)
      .attr("fill", function (s) { return s.assumed ? C.warn : (s.state === "done" ? C.good : C.bg); })
      .attr("fill-opacity", function (s) { return s.state === "done" ? .25 : 1; })
      .attr("filter", function (s) { return freed.indexOf(s.id) >= 0 ? "drop-shadow(0 0 6px " + C.accent + ")" : null; })
      .attr("stroke", fill).attr("stroke-width", 1.6).attr("stroke-dasharray", function (s) { return s.state === "waiting" ? "4 3" : null; });
    node.append("text").attr("x", NW / 2).attr("y", 17).attr("text-anchor", "middle").attr("font-size", 11)
      .attr("fill", function (s) { return s.state === "waiting" ? C.dim : C.fg; }).text(function (s) { return KIND[s.kind] || s.kind; });
    node.append("title").text(function (s) { return s.title; });

    function touches(d, s) {
      if (s.touch) return s.touch.indexOf(d.id) >= 0;
      if (d.kind === "certificate-authority") return s.kind === "ca" || (s.kind === "reissue" && d.services.indexOf(s.service) >= 0) || (s.kind === "replace" && d.services.indexOf(s.service) >= 0);
      if (d.kind === "library-build") return (s.kind === "enable" || s.kind === "require") && d.services.indexOf(s.service) >= 0;
      return s.kind === "reissue" && d.services.indexOf(s.service) >= 0;
    }
    function light(d) {
      node.attr("opacity", function (s) { return !d || touches(d, s) ? 1 : .18; });
      path.attr("opacity", function (l) { return !d || (touches(d, l.a) && touches(d, l.b)) ? 1 : .1; });
    }
    function row(k, v) { return v == null || v === "" ? "" : "<div class=\"k\">" + k + "</div><div class=\"v\">" + v + "</div>"; }
    // What-if, in the browser: take steps as done, recompute what is freed and what is closer, and
    // show it — on the map, in a panel and in the table. The assumption lives in the address
    // (#assume=…), so a what-if can be shared; nothing is sent anywhere. Works on a static page.
    var base = {}, d0 = {};
    steps.forEach(function (s) { base[s.id] = s.state === "done" && !s.assumed; if (base[s.id]) d0[s.id] = 1; });
    var waits = function (s, done) { return s.depends_on.some(function (x) { return byId[x] && !done[x]; }); };
    var before = {}; steps.forEach(function (s) { if (!base[s.id] && waits(s, d0)) before[s.id] = 1; });
    var assumed = [];
    function settle() {
      var done = {}; steps.forEach(function (s) { if (base[s.id] || assumed.indexOf(s.id) >= 0) done[s.id] = 1; });
      steps.forEach(function (s) {
        s.assumed = assumed.indexOf(s.id) >= 0;
        s.state = done[s.id] ? "done" : (waits(s, done) ? "waiting" : "ready");
      });
      var freedNow = steps.filter(function (s) { return before[s.id] && s.state === "ready"; }).map(function (s) { return s.id; });
      var reach = {}, frontier = assumed.concat(freedNow);
      while (frontier.length) {
        var nxt = [];
        steps.forEach(function (t) {
          if (!reach[t.id] && assumed.indexOf(t.id) < 0 && freedNow.indexOf(t.id) < 0 &&
              t.depends_on.some(function (x) { return frontier.indexOf(x) >= 0; })) { reach[t.id] = 1; nxt.push(t.id); }
        });
        frontier = nxt;
      }
      var closer = steps.filter(function (s) { return reach[s.id] && s.state === "waiting"; });
      return { freed: freedNow, closer: closer };
    }
    function restyle(res) {
      node.select("rect").attr("fill", function (s) { return s.assumed ? C.warn : (s.state === "done" ? C.good : C.bg); })
        .attr("fill-opacity", function (s) { return s.state === "done" ? .25 : 1; })
        .attr("filter", function (s) { return res.freed.indexOf(s.id) >= 0 ? "drop-shadow(0 0 6px " + C.accent + ")" : null; })
        .attr("stroke", fill).attr("stroke-dasharray", function (s) { return s.state === "waiting" ? "4 3" : null; });
      node.select("text").attr("fill", function (s) { return s.state === "waiting" ? C.dim : C.fg; });
      document.querySelectorAll("table.steps tr[data-step]").forEach(function (tr) {
        var id = tr.dataset.step, st = byId[id];
        tr.classList.toggle("assumed", assumed.indexOf(id) >= 0);
        tr.classList.toggle("freed", res.freed.indexOf(id) >= 0);
        var cell = tr.querySelector("td.state"); if (cell && st) cell.textContent = st.state;
      });
    }
    function titleOf(id) { return byId[id] ? byId[id].title : id; }
    function renderPanel(res) {
      var box = document.getElementById("whatif-live"); if (!box) return;
      var old = document.getElementById("whatif"); if (old) old.hidden = true;
      if (!assumed.length) { box.hidden = true; box.innerHTML = ""; return; }
      var li = function (s, extra) { return "<li><strong>" + esc(s.title) + "</strong>" + (s.due ? " <span class=\"dim\">— due " + esc(s.due) + "</span>" : "") + "<br>" + extra + "</li>"; };
      var h = "<div class=\"head\"><strong>What if</strong> " + assumed.map(function (a) { return "<em>" + esc(titleOf(a)) + "</em>"; }).join(" and ")
        + (assumed.length > 1 ? " were" : " was") + " done? <a href=\"#\" data-clear=\"1\">clear the what-if</a></div>"
        + "<p class=\"sum\">" + (res.freed.length ? "<strong>" + res.freed.length + "</strong> step" + (res.freed.length !== 1 ? "s" : "") + " could start at once" : "No other step could start on this alone")
        + (res.closer.length ? ", and <strong>" + res.closer.length + "</strong> more would be one step closer" : "") + ". Nothing is changed or recorded.</p>";
      if (res.freed.length) h += "<h4>Free to start</h4><ul class=\"wi\">" + res.freed.map(function (id) { var s = byId[id];
        return li(s, "<span class=\"small\">" + esc(s.why) + "</span>" + (s.entries.length ? " <span class=\"dim small\">· moves " + s.entries.length + " CBOM entr" + (s.entries.length !== 1 ? "ies" : "y") + "</span>" : "")
          + (s.unblocks.length ? "<br><span class=\"dim small\">then unblocks: " + s.unblocks.map(function (u) { return esc(titleOf(u)); }).join("; ") + "</span>" : "")); }).join("") + "</ul>";
      if (res.closer.length) h += "<h4>Closer, but still waiting</h4><ul class=\"wi\">" + res.closer.map(function (s) {
        return li(s, "<span class=\"small\">still waits for: " + s.depends_on.filter(function (x) { return byId[x] && byId[x].state !== "done"; }).map(function (x) { return esc(titleOf(x)); }).join("; ") + "</span>"); }).join("") + "</ul>";
      h += "<h4>Taken as done</h4><ul class=\"wi\">" + assumed.map(function (a) { var s = byId[a]; return s ? "<li><strong>" + esc(s.title) + "</strong> <span class=\"dim small\">— " + esc(s.why) + "</span></li>" : ""; }).join("") + "</ul>"
        + "<p class=\"dim small\">On the map: amber is assumed done, a glow is freed. Click another step's \"What if this were done?\" to add it.</p>";
      box.innerHTML = h; box.hidden = false;
    }
    function apply(scroll) {
      var res = settle(); restyle(res); renderPanel(res);
      history.replaceState(null, "", location.pathname + location.search + (assumed.length ? "#assume=" + encodeURIComponent(assumed.join(",")) : ""));
      if (scroll && assumed.length) document.getElementById("whatif-live").scrollIntoView({ behavior: "smooth", block: "start" });
    }
    document.addEventListener("click", function (ev) {
      var a = ev.target.closest && ev.target.closest("a[data-whatif], a[data-clear]");
      if (!a) return;
      ev.preventDefault();
      if (a.dataset.clear) { assumed = []; } else if (assumed.indexOf(a.dataset.whatif) < 0) { assumed.push(a.dataset.whatif); }
      apply(true);
    });
    function show(s) {
      var st = { done: "<span class=\"good\">done</span>", ready: "ready to start", waiting: "<span class=\"dim\">waiting on another step</span>" }[s.state];
      var h = "<div class=\"kind\">" + esc(KIND[s.kind] || s.kind) + "</div><div class=\"name\">" + esc(s.title) + "</div>"
        + row("state", st + (s.done ? " — change <code>" + esc(s.done.change_id) + "</code> landed " + esc((s.done.ts || "").slice(0, 10)) : ""))
        + row("due", s.due ? esc(s.due) : "no deadline") + row("why", esc(s.why))
        + (s.external ? row("outside the agency", esc(s.external)) : "")
        + row("waits for", s.depends_on.map(function (x) { return byId[x] ? esc(byId[x].title) : esc(x); }).join("<br>") || "nothing")
        + row("unblocks", s.unblocks.map(function (x) { return byId[x] ? esc(byId[x].title) : esc(x); }).join("<br>") || "—")
        + row("CBOM entries it moves", s.entries.length ? s.entries.length + " — <a href=\"/cbom-workbench/cbom\">see them on the chain</a>" : "—")
        + row("computed from", "<ul class=\"fields\">" + s.fields.map(function (f) { return "<li>" + esc(f) + "</li>"; }).join("") + "</ul>")
        + (s.resolve ? row("resolve", "<a href=\"" + esc(s.resolve) + "\">" + esc(s.resolve_label || "resolve") + " →</a>") : "")
        + (s.state !== "done" ? row("what if", "<a href=\"#\" data-whatif=\"" + esc(s.id) + "\">What if this were done? →</a> The plan is recomputed with it taken as done; nothing is changed or recorded.") : "")
        + (s.assumed ? row("what if", "<span class=\"warn-text\">taken as done for this what-if</span>") : "");
      panel.html(h);
      node.select("rect").attr("stroke-width", function (n) { return n === s ? 3 : 1.6; });
    }
    function showDep(d) {
      panel.html("<div class=\"kind\">" + esc(d.kind.replace(/-/g, " ")) + "</div><div class=\"name\">" + esc(d.name.split(",")[0].replace("CN=", "")) + "</div>"
        + row("what", esc(d.what)) + row("so", esc(d.consequence)) + row("services", esc(d.services.join(", ")))
        + row("CBOM entries", d.entries.length ? String(d.entries.length) : "from the runtime's own list"));
    }
    var fromHash = (location.hash.match(/assume=([^&]+)/) || [])[1];
    assumed = fromHash ? decodeURIComponent(fromHash).split(",").filter(function (a) { return byId[a]; }) : (P.assumed || []).slice();
    if (assumed.length) apply(false);
    panel.html("<div class=\"kind\">the plan</div><div class=\"name\">" + steps.length + " steps over " + (lanes.length) + " lanes</div>"
      + row("how to read it", "Left to right in time; a line means the step on the right waits for the one on the left. Solid outline: ready to start. Dashed: waiting. Green: done. Hover a shared dependency above to see what it ties together; click a step for its reasons."));
  }

  document.querySelectorAll("figure.planmap[data-plan]").forEach(function (fig) {
    try { draw(fig); } catch (e) { fig.textContent = "figure not drawn: " + e; }
  });
})();
