// The lab estate, drawn from one capture run (view.capture_view). Vendored D3; no network.
// Three figures: the radial estate with bundled edges, the hours against the internet, the
// capability matrix; and the outside world as bars. Every number is from the ledger's events.
(function () {
  if (typeof d3 === "undefined") return;
  var css = getComputedStyle(document.documentElement);
  var T = function (n) { return css.getPropertyValue(n).trim(); };
  var C = { fg: T("--fg"), fg2: T("--fg2"), dim: T("--dim"), faint: T("--faint"), line: T("--line"), line2: T("--line2"), card: T("--card"),
            good: T("--good"), bad: T("--bad"), warn: T("--warn"), accent: T("--accent"), classical: T("--classical"), bg: T("--bg") };
  var MONO = T("--mono"), SERIF = T("--serif");
  var CAP = { hybrid: C.good, "classical-1.3": C.warn, legacy: C.bad };
  var POST = { pq: C.good, mixed: C.warn, classical: C.classical };
  var esc = function (s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]; }); };
  var fmt = d3.format(","), pct = function (a, b) { return b ? Math.round(100 * a / b) + "%" : "—"; };
  function fit(sel, width) {
    sel.each(function () {
      var t = d3.select(this), s = t.text();
      while (s.length > 1 && this.getComputedTextLength() > width) { s = s.slice(0, -2); t.text(s + "…"); }
    });
  }

  // ---------------------------------------------------------------- the radial estate
  function radial(fig) {
    var D = JSON.parse(fig.dataset.lab);
    var W = 760, H = 760, R0 = Math.min(W, H) / 2 - 118;
    var wrap = d3.select(fig).classed("drawn", true);
    var svg = wrap.append("svg").attr("viewBox", [-W / 2, -H / 2, W, H]).attr("role", "img").attr("aria-label", "the lab estate, every handshake");
    var panel = wrap.append("div").attr("class", "estate-panel");

    // The hierarchy: root → inside (VLAN → devices and listeners) · outside (names). Leaves sit on the ring.
    var byVlan = {};
    D.clients.forEach(function (c) { (byVlan[c.vlan == null ? "?" : c.vlan] = byVlan[c.vlan == null ? "?" : c.vlan] || []).push({ id: "c:" + c.host, kind: "client", label: c.host, d: c, n: c.handshakes }); });
    D.servers.forEach(function (s) { (byVlan[s.vlan == null ? "?" : s.vlan] = byVlan[s.vlan == null ? "?" : s.vlan] || []).push({ id: "l:" + s.host + ":" + s.port, kind: "listener", label: s.host + ":" + s.port, d: s, n: s.handshakes }); });
    var inside = Object.keys(byVlan).sort(function (a, b) { return (+a || 9999) - (+b || 9999); }).map(function (v) {
      return { id: "vlan:" + v, label: "VLAN " + v, children: byVlan[v].sort(function (a, b) { return a.kind === b.kind ? b.n - a.n : (a.kind === "listener" ? -1 : 1); }) };
    });
    var named = {}; D.outside.forEach(function (o) { named[o.domain] = true; });
    var other = { domain: "other names", handshakes: 0, hybrid: 0, classical: 0, servers: 0 };
    var outside = D.outside.map(function (o) { return { id: "d:" + o.domain, kind: "domain", label: o.domain, d: o, n: o.handshakes }; });
    D.edges.forEach(function (e) { if (e.kind === "domain" && !named[e.target]) { other.handshakes += e.n; other.hybrid += e.hybrid; other.classical += e.n - e.hybrid; } });
    outside.push({ id: "d:other names", kind: "domain", label: "other names", d: other, n: other.handshakes });
    var root = d3.hierarchy({ id: "root", children: [{ id: "inside", label: "inside the house", children: inside }, { id: "outside", label: "the outside world", children: outside }] });
    d3.cluster().size([360, R0])(root);
    var leaves = root.leaves(), byId = {}; leaves.forEach(function (l) { byId[l.data.id] = l; });

    // Edges along the hierarchy, bundled: client → (vlan → inside → root → outside → name), or → listener.
    var line = d3.lineRadial().curve(d3.curveBundle.beta(.86)).radius(function (d) { return d.y; }).angle(function (d) { return d.x * Math.PI / 180; });
    var edges = D.edges.map(function (e) {
      var a = byId["c:" + e.client], b = byId[e.kind === "listener" ? "l:" + e.target : ("d:" + (named[e.target] ? e.target : "other names"))];
      if (!a || !b) return null;
      var cls = e.refused > 0 ? "refused" : (e.hybrid > 0 ? "hybrid" : "classical");
      return { a: a, b: b, e: e, cls: cls, path: a.path(b) };
    }).filter(Boolean);
    var EC = { hybrid: C.good, refused: C.bad, classical: C.classical };
    var w = d3.scaleSqrt().domain([1, d3.max(edges, function (d) { return d.e.n; }) || 1]).range([.5, 5]);
    var g = svg.append("g");
    // Arcs for the VLANs and the two halves.
    var arc = d3.arc();
    root.children.forEach(function (half) {
      var ls = half.leaves(), a0 = d3.min(ls, function (l) { return l.x; }), a1 = d3.max(ls, function (l) { return l.x; });
      g.append("path").attr("d", arc({ innerRadius: R0 + 86, outerRadius: R0 + 88, startAngle: (a0 - 1) * Math.PI / 180, endAngle: (a1 + 1) * Math.PI / 180 })).attr("fill", C.line2);
    });
    inside.forEach(function (v) {
      var node = root.children[0].children.find(function (n) { return n.data.id === v.id; });
      var ls = node.leaves(), a0 = d3.min(ls, function (l) { return l.x; }), a1 = d3.max(ls, function (l) { return l.x; });
      g.append("path").attr("d", arc({ innerRadius: R0 + 6, outerRadius: R0 + 9, startAngle: (a0 - .6) * Math.PI / 180, endAngle: (a1 + .6) * Math.PI / 180 })).attr("fill", C.accent).attr("fill-opacity", .7);
      var mid = (a0 + a1) / 2, rr = R0 + 100;
      g.append("text").attr("transform", "rotate(" + (mid - 90) + ") translate(" + rr + ",0) rotate(" + (mid < 180 ? 0 : 180) + ")")
        .attr("text-anchor", mid < 180 ? "start" : "end").attr("fill", C.accent).attr("font-family", MONO).attr("font-size", 10.5).attr("letter-spacing", ".08em").text(v.label);
    });
    var links = g.append("g").attr("fill", "none").selectAll("path").data(edges).join("path")
      .attr("d", function (d) { return line(d.path); }).attr("stroke", function (d) { return EC[d.cls]; })
      .attr("stroke-width", function (d) { return w(d.e.n); }).attr("stroke-opacity", function (d) { return d.cls === "classical" ? .22 : .5; })
      .attr("mix-blend-mode", "screen");
    var nodes = g.append("g").selectAll("g").data(leaves).join("g")
      .attr("transform", function (d) { return "rotate(" + (d.x - 90) + ") translate(" + d.y + ",0)"; }).style("cursor", "pointer");
    nodes.append("circle").attr("r", function (d) { return d.data.kind === "listener" ? 5 : 3.5; })
      .attr("fill", function (d) { return d.data.kind === "client" ? (CAP[(d.data.d.capability || {}).capability] || C.dim) : d.data.kind === "listener" ? (POST[(d.data.d.posture || {}).posture] || C.dim) : C.bg; })
      .attr("stroke", function (d) { return d.data.kind === "domain" ? (d.data.d.hybrid > d.data.d.classical ? C.good : C.classical) : C.bg; }).attr("stroke-width", 1.5);
    nodes.append("text").attr("dy", "0.32em").attr("x", function (d) { return d.x < 180 ? 9 : -9; }).attr("text-anchor", function (d) { return d.x < 180 ? "start" : "end"; })
      .attr("transform", function (d) { return d.x >= 180 ? "rotate(180)" : null; }).attr("fill", function (d) { return d.data.kind === "listener" ? C.fg : C.fg2; })
      .attr("font-size", function (d) { return d.data.kind === "listener" ? 10.5 : 9.5; }).attr("font-family", MONO).attr("font-weight", function (d) { return d.data.kind === "listener" ? 600 : 400; })
      .text(function (d) { return d.data.label; }).each(function (d) { if (d.data.kind !== "listener") fit(d3.select(this), 82); });
    svg.append("text").attr("x", -W / 2 + 10).attr("y", -H / 2 + 22).attr("fill", C.fg).attr("font-size", 13).attr("font-weight", 600).text(fmt(edges.length) + " client–server pairs, " + fmt(d3.sum(edges, function (d) { return d.e.n; })) + " handshakes");
    var leg = svg.append("g").attr("transform", "translate(" + (-W / 2 + 10) + "," + (H / 2 - 54) + ")");
    [["hybrid negotiated", C.good], ["hybrid offered, server chose classical", C.bad], ["classical only", C.classical]].forEach(function (l, i) {
      leg.append("line").attr("x1", 0).attr("x2", 22).attr("y1", i * 16).attr("y2", i * 16).attr("stroke", l[1]).attr("stroke-width", 2.5);
      leg.append("text").attr("x", 28).attr("y", i * 16 + 4).attr("fill", C.dim).attr("font-size", 10.5).text(l[0]);
    });

    var held = null;
    function row(k, v) { return "<div class=\"k\">" + k + "</div><div class=\"v\">" + v + "</div>"; }
    function describe(d) {
      var h = "<div class=\"kind\">" + d.data.kind + "</div><div class=\"name\">" + esc(d.data.label) + "</div>";
      var x = d.data.d;
      if (d.data.kind === "client") {
        var cap = x.capability || {};
        h += row("VLAN", x.vlan == null ? "untagged" : x.vlan) + row("handshakes", fmt(x.handshakes))
          + row("capability", "<span style=\"color:" + (CAP[cap.capability] || C.dim) + "\">" + esc(cap.capability || "?") + "</span>")
          + row("offers", x.offers.map(function (o) { return (o.hybrid ? "<span class=\"good\">" : "<span>") + esc(o.name) + "</span> ×" + o.n; }).join(", "))
          + row("versions", x.versions.map(function (v) { return esc(v.name) + " ×" + v.n; }).join(", "))
          + row("rule", "<code>capability/observed/1</code> event <code>" + esc(cap.event || "") + "</code>");
      } else if (d.data.kind === "listener") {
        var p = x.posture || {};
        h += row("VLAN", x.vlan == null ? "untagged" : x.vlan) + (x.sni ? row("name", esc(x.sni)) : "") + row("handshakes", fmt(x.handshakes))
          + row("posture", "<span style=\"color:" + (POST[p.posture] || C.dim) + "\">" + esc(p.posture || "?") + "</span>")
          + row("chose", x.chosen.map(function (o) { return (o.hybrid ? "<span class=\"good\">" : "<span>") + esc(o.name) + "</span> ×" + o.n; }).join(", "))
          + row("clients offered hybrid", fmt(p.hybrid_offered || 0)) + row("refused", p.hybrid_refused ? "<span class=\"bad\">" + fmt(p.hybrid_refused) + "</span>" : "0")
          + row("rule", "<code>posture/observed/1</code> event <code>" + esc(p.event || "") + "</code>");
      } else {
        h += row("handshakes", fmt(x.handshakes)) + row("hybrid", fmt(x.hybrid) + " (" + pct(x.hybrid, x.hybrid + x.classical) + ")") + row("classical", fmt(x.classical)) + (x.servers ? row("addresses", x.servers) : "");
      }
      var mine = edges.filter(function (e) { return e.a === d || e.b === d; });
      h += row("pairs", mine.length + " · " + fmt(d3.sum(mine, function (e) { return e.e.n; })) + " handshakes");
      return h;
    }
    function focus(d) {
      links.attr("stroke-opacity", function (e) { return d == null ? (e.cls === "classical" ? .22 : .5) : (e.a === d || e.b === d ? .95 : .04); })
        .attr("stroke-width", function (e) { return d != null && (e.a === d || e.b === d) ? Math.max(1.2, w(e.e.n)) : w(e.e.n); });
      nodes.attr("opacity", function (n) { if (d == null) return 1; if (n === d) return 1; return edges.some(function (e) { return (e.a === d && e.b === n) || (e.b === d && e.a === n); }) ? 1 : .25; });
      panel.html(d == null ? home() : describe(d));
    }
    function home() {
      var refused = edges.filter(function (e) { return e.cls === "refused"; });
      return "<div class=\"kind\">the estate</div><div class=\"name\">" + D.clients.length + " devices, " + D.servers.length + " listeners inside; " + D.outside.length + " names outside</div>"
        + row("pairs negotiating hybrid", edges.filter(function (e) { return e.cls === "hybrid"; }).length)
        + row("pairs where hybrid was offered and refused", "<span class=\"bad\">" + refused.length + "</span>, " + fmt(d3.sum(refused, function (e) { return e.e.refused; })) + " handshakes")
        + row("pairs classical only", edges.filter(function (e) { return e.cls === "classical"; }).length)
        + row("how to read it", "Hover a point to isolate its pairs; click to hold it. Listeners inside the house are the larger points; a point's colour is the rule's verdict on it.")
        + row("colour", "<span style=\"color:" + C.good + "\">hybrid</span> · <span style=\"color:" + C.warn + "\">TLS 1.3, no hybrid</span> · <span style=\"color:" + C.bad + "\">no TLS 1.3</span> · listeners: <span style=\"color:" + C.good + "\">pq</span> / <span style=\"color:" + C.warn + "\">mixed</span> / <span style=\"color:" + C.classical + "\">classical</span>");
    }
    nodes.on("mouseenter", function (ev, d) { if (!held) focus(d); }).on("mouseleave", function () { if (!held) focus(null); })
      .on("click", function (ev, d) { held = held === d ? null : d; focus(held); ev.stopPropagation(); });
    svg.on("click", function () { held = null; focus(null); });
    focus(null);
  }

  // ---------------------------------------------------------------- the hours
  function hours(fig) {
    var H0 = JSON.parse(fig.dataset.hours), V = JSON.parse(fig.dataset.vlans);
    if (!H0.length) { fig.textContent = "no hourly tallies on this run"; return; }
    var parse = d3.utcParse("%Y-%m-%dT%H:%M:%S.%LZ");
    H0.forEach(function (h) { h.t0 = parse(h.t); h.t1 = parse(h.end); });
    var W = 920, PW = 440, PH = 170, SM = 100, cols = 4, vl = V.filter(function (v) { return v.vlan; });
    var rows = Math.ceil(vl.length / cols), H = 50 + PH + 40 + rows * (SM + 44) + 10;
    var svg = d3.select(fig).append("svg").attr("viewBox", [0, 0, W, H]).attr("role", "img").attr("aria-label", "hybrid share by hour");
    var x = d3.scaleUtc().domain([d3.min(H0, function (h) { return h.t0; }), d3.max(H0, function (h) { return h.t1; })]);
    var share = function (s, k) { return s.handshakes ? s[k] / s.handshakes : null; };
    function panel(gx, gy, pw, ph, title, get, small) {
      var g = svg.append("g").attr("transform", "translate(" + gx + "," + gy + ")");
      var xs = x.copy().range([34, pw - 8]), ys = d3.scaleLinear().domain([0, 1]).range([ph - 20, 10]);
      var pts = H0.map(function (h) { var s = get(h); return { t: new Date((h.t0 - 0 + (h.t1 - 0)) / 2), neg: s ? share(s, "hybrid") : null, off: s ? share(s, "hybrid_offered") : null, n: s ? s.handshakes : 0 }; });
      var area = d3.area().defined(function (d) { return d.neg != null && d.off != null; }).x(function (d) { return xs(d.t); }).y0(function (d) { return ys(d.neg); }).y1(function (d) { return ys(Math.max(d.neg, d.off)); }).curve(d3.curveMonotoneX);
      g.append("path").datum(pts).attr("d", area).attr("fill", C.bad).attr("fill-opacity", .18);
      var ln = function (k, col, dash) {
        g.append("path").datum(pts).attr("fill", "none").attr("stroke", col).attr("stroke-width", 1.8).attr("stroke-dasharray", dash || null)
          .attr("d", d3.line().defined(function (d) { return d[k] != null; }).x(function (d) { return xs(d.t); }).y(function (d) { return ys(d[k]); }).curve(d3.curveMonotoneX));
      };
      ln("off", C.dim, "4,3"); ln("neg", C.good);
      // handshake volume, faint, along the bottom
      var vol = d3.scaleLinear().domain([0, d3.max(pts, function (d) { return d.n; }) || 1]).range([0, 18]);
      g.append("g").selectAll("rect").data(pts).join("rect").attr("x", function (d) { return xs(d.t) - 2; }).attr("width", 4).attr("y", function (d) { return ph - 20 - vol(d.n); }).attr("height", function (d) { return vol(d.n); }).attr("fill", C.faint).attr("fill-opacity", .5);
      var ax = g.append("g").attr("transform", "translate(0," + (ph - 20) + ")").call(d3.axisBottom(xs).ticks(small ? 3 : 6).tickFormat(d3.utcFormat("%H:%M")).tickSize(3));
      ax.selectAll("text").attr("fill", C.dim).attr("font-family", MONO).attr("font-size", 9.5); ax.selectAll("line, path").attr("stroke", C.line2);
      var ay = g.append("g").attr("transform", "translate(34,0)").call(d3.axisLeft(ys).ticks(small ? 2 : 4).tickFormat(d3.format(".0%")).tickSize(3));
      ay.selectAll("text").attr("fill", C.dim).attr("font-family", MONO).attr("font-size", 9.5); ay.selectAll("line, path").attr("stroke", C.line2);
      var last = pts.filter(function (d) { return d.neg != null; }).slice(-1)[0];
      var now = last ? "now " + Math.round(100 * last.neg) + "% negotiated, " + Math.round(100 * last.off) + "% offered" : "";
      var tt = g.append("text").attr("x", 0).attr("y", small ? -14 : 0).attr("fill", C.fg).attr("font-size", small ? 11 : 12.5).attr("font-weight", 600).text(title);
      if (small) g.append("text").attr("x", 0).attr("y", -2).attr("fill", C.dim).attr("font-size", 9.5).attr("font-family", MONO).text(now);
      else tt.append("tspan").attr("fill", C.dim).attr("font-weight", 400).text("  " + now);
    }
    panel(0, 28, PW, PH, "to the outside world", function (h) { return h.outside; });
    panel(W - PW, 28, PW, PH, "inside the house", function (h) { return h.inside; });
    var leg = svg.append("g").attr("transform", "translate(0," + (28 + PH + 8) + ")");
    [["negotiated a hybrid group", C.good, null], ["a hybrid group was offered", C.dim, "4,3"]].forEach(function (l, i) {
      leg.append("line").attr("x1", i * 230).attr("x2", i * 230 + 22).attr("y1", 6).attr("y2", 6).attr("stroke", l[1]).attr("stroke-width", 2).attr("stroke-dasharray", l[2]);
      leg.append("text").attr("x", i * 230 + 28).attr("y", 10).attr("fill", C.dim).attr("font-size", 10.5).text(l[0]);
    });
    leg.append("rect").attr("x", 470).attr("y", 0).attr("width", 22).attr("height", 12).attr("fill", C.bad).attr("fill-opacity", .25);
    leg.append("text").attr("x", 498).attr("y", 10).attr("fill", C.dim).attr("font-size", 10.5).text("offered and refused · bars: handshakes per hour");
    var sw = (W - (cols - 1) * 16) / cols;
    vl.forEach(function (v, i) {
      var r = Math.floor(i / cols), c = i % cols;
      panel(c * (sw + 16), 28 + PH + 58 + r * (SM + 44), sw, SM, "VLAN " + v.vlan + " · " + v.clients + (v.clients === 1 ? " client" : " clients"), function (h) { return (h.by_vlan || {})[String(v.vlan)]; }, true);
    });
  }

  // ---------------------------------------------------------------- the capability matrix
  function matrix(fig) {
    var CL = JSON.parse(fig.dataset.clients), G = JSON.parse(fig.dataset.groups);
    var hybridOf = {}; CL.forEach(function (c) { c.offers.forEach(function (o) { hybridOf[o.name] = o.hybrid; }); });
    var W = 920, RH = 15, L = 150, colw = 26, GAP = 14, VERS = ["TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"];
    var groups = d3.groups(CL, function (c) { return c.vlan == null ? "untagged" : "VLAN " + c.vlan; });
    var H = 70 + d3.sum(groups, function (g) { return g[1].length * RH + 26; });
    var svg = d3.select(fig).append("svg").attr("viewBox", [0, 0, W, H]).attr("role", "img").attr("aria-label", "who can offer what");
    var xg = function (i) { return L + i * colw; }, xv = function (i) { return L + G.length * colw + GAP + i * colw; }, xc = L + G.length * colw + GAP + VERS.length * colw + GAP, xn = xc + 110;
    // column heads, rotated
    var head = svg.append("g").attr("transform", "translate(0,58)");
    G.forEach(function (g, i) {
      head.append("text").attr("transform", "translate(" + (xg(i) + 4) + ",0) rotate(-55)").attr("fill", hybridOf[g] ? C.good : C.fg2).attr("font-size", 10).attr("font-family", MONO).attr("font-weight", hybridOf[g] ? 600 : 400).text(g);
    });
    VERS.forEach(function (v, i) { head.append("text").attr("transform", "translate(" + (xv(i) + 4) + ",0) rotate(-55)").attr("fill", C.fg2).attr("font-size", 10).attr("font-family", MONO).text(v); });
    head.append("text").attr("x", xc).attr("y", 0).attr("fill", C.dim).attr("font-size", 10).attr("font-family", MONO).attr("letter-spacing", ".08em").text("RULE");
    head.append("text").attr("x", xn).attr("y", 0).attr("fill", C.dim).attr("font-size", 10).attr("font-family", MONO).attr("letter-spacing", ".08em").text("HANDSHAKES");
    var y = 72;
    groups.forEach(function (grp) {
      svg.append("text").attr("x", 0).attr("y", y + 4).attr("fill", C.accent).attr("font-family", MONO).attr("font-size", 10.5).attr("letter-spacing", ".08em").text(grp[0].toUpperCase());
      svg.append("line").attr("x1", 0).attr("x2", W).attr("y1", y + 10).attr("y2", y + 10).attr("stroke", C.line);
      y += 20;
      grp[1].sort(function (a, b) { var o = { hybrid: 0, "classical-1.3": 1, legacy: 2 }; var ca = (a.capability || {}).capability, cb = (b.capability || {}).capability; return (o[ca] - o[cb]) || (b.handshakes - a.handshakes); });
      grp[1].forEach(function (c) {
        var r = svg.append("g").attr("transform", "translate(0," + y + ")");
        var cap = (c.capability || {}).capability;
        r.append("rect").attr("x", 0).attr("y", -RH / 2).attr("width", W).attr("height", RH).attr("fill", "transparent").attr("class", "mrow");
        r.append("text").attr("x", 0).attr("y", 4).attr("fill", C.fg2).attr("font-size", 10.5).attr("font-family", MONO).text(c.host);
        var off = {}; c.offers.forEach(function (o) { off[o.name] = o; });
        G.forEach(function (g, i) {
          var o = off[g]; if (!o) return;
          var first = o.first > 0 && o.first >= c.handshakes / 2;
          r.append("circle").attr("cx", xg(i) + 8).attr("cy", 0).attr("r", first ? 5 : 4).attr("fill", first ? (o.hybrid ? C.good : C.fg2) : "none").attr("stroke", o.hybrid ? C.good : C.fg2).attr("stroke-width", 1.4)
            .append("title").text(c.host + " offered " + g + " on " + o.n + " of " + c.handshakes + " handshakes; first choice on " + o.first);
        });
        var vs = {}; c.versions.forEach(function (v) { vs[v.name] = v.n; });
        VERS.forEach(function (v, i) { if (vs[v]) r.append("rect").attr("x", xv(i) + 3).attr("y", -5).attr("width", 10).attr("height", 10).attr("fill", v === "TLS 1.3" ? C.fg2 : C.faint); });
        r.append("text").attr("x", xc).attr("y", 4).attr("fill", CAP[cap] || C.dim).attr("font-size", 10.5).attr("font-family", MONO).text(cap || "?");
        r.append("text").attr("x", xn).attr("y", 4).attr("fill", C.dim).attr("font-size", 10.5).attr("font-family", MONO).text(fmt(c.handshakes));
        y += RH;
      });
      y += 6;
    });
    svg.selectAll("rect.mrow").on("mouseenter", function () { d3.select(this).attr("fill", C.line); }).on("mouseleave", function () { d3.select(this).attr("fill", "transparent"); });
  }

  // ---------------------------------------------------------------- the outside world
  function outside(fig) {
    var O = JSON.parse(fig.dataset.outside);
    var W = 920, RH = 18, L = 190, H = 30 + O.length * RH;
    var svg = d3.select(fig).append("svg").attr("viewBox", [0, 0, W, H]).attr("role", "img").attr("aria-label", "the outside world by name");
    var x = d3.scaleLinear().domain([0, d3.max(O, function (o) { return o.hybrid + o.classical; }) || 1]).range([L, W - 120]);
    var g = svg.append("g").selectAll("g").data(O).join("g").attr("transform", function (d, i) { return "translate(0," + (20 + i * RH) + ")"; });
    g.append("text").attr("x", L - 8).attr("y", 4).attr("text-anchor", "end").attr("fill", C.fg2).attr("font-size", 10.5).attr("font-family", MONO).text(function (d) { return d.domain; }).call(fit, L - 12);
    g.append("rect").attr("x", L).attr("y", -6).attr("height", 12).attr("width", function (d) { return x(d.hybrid) - L; }).attr("fill", C.good);
    g.append("rect").attr("x", function (d) { return x(d.hybrid); }).attr("y", -6).attr("height", 12).attr("width", function (d) { return x(d.hybrid + d.classical) - x(d.hybrid); }).attr("fill", C.classical).attr("fill-opacity", .6);
    g.append("text").attr("x", function (d) { return x(d.hybrid + d.classical) + 6; }).attr("y", 4).attr("fill", C.dim).attr("font-size", 10).attr("font-family", MONO)
      .text(function (d) { return fmt(d.hybrid + d.classical) + " · " + pct(d.hybrid, d.hybrid + d.classical) + " hybrid"; });
    svg.append("text").attr("x", L).attr("y", 8).attr("fill", C.dim).attr("font-size", 10).text("handshakes with a key exchange; green: hybrid negotiated, grey: classical");
  }

  var run = function (sel, fn) { document.querySelectorAll(sel).forEach(function (fig) { try { fn(fig); } catch (e) { fig.textContent = "figure not drawn: " + e; console.error(e); } }); };
  run("figure.radial[data-lab]", radial);
  run("figure.hours[data-hours]", hours);
  run("figure.matrix[data-clients]", matrix);
  run("figure.outside[data-outside]", outside);
})();
