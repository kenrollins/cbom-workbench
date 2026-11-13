// Figures drawn from the ledger's own events. Vendored D3; no network. Each figure reads the JSON
// on its element and draws an SVG; the words and groups come from the events, never from here.
(function () {
  if (typeof d3 === "undefined") return;
  var css = getComputedStyle(document.documentElement);
  var T = function (n) { return css.getPropertyValue(n).trim(); };
  var C = { fg: T("--fg"), fg2: T("--fg2"), dim: T("--dim"), faint: T("--faint"), line: T("--line"), line2: T("--line2"),
            good: T("--good"), bad: T("--bad"), warn: T("--warn"), accent: T("--accent"), classical: T("--classical"), bg: T("--bg"), card: T("--card") };
  var MONO = T("--mono"), SERIF = T("--serif");
  var PQ = /MLKEM|ML-KEM|sntrup/i;
  var isPQ = function (g) { return PQ.test(g); };

  // Text that fits: truncate with an ellipsis to a width.
  function fit(sel, width) {
    sel.each(function () {
      var t = d3.select(this), s = t.text();
      while (s.length > 1 && this.getComputedTextLength() > width) { s = s.slice(0, -2); t.text(s + "…"); }
    });
  }
  // Text that wraps: greedy by measured width, at most `max` lines.
  function wrap(sel, width, lineHeight, max) {
    sel.each(function () {
      var t = d3.select(this), words = t.text().split(/\s+/), line = [], n = 0, y = +t.attr("y");
      var tspan = t.text(null).append("tspan").attr("x", t.attr("x")).attr("y", y);
      for (var i = 0; i < words.length; i++) {
        line.push(words[i]); tspan.text(line.join(" "));
        if (tspan.node().getComputedTextLength() > width && line.length > 1) {
          line.pop(); tspan.text(line.join(" ")); line = [words[i]]; n++;
          if (n >= max) { fit(tspan, width); return; }
          tspan = t.append("tspan").attr("x", t.attr("x")).attr("y", y + n * lineHeight).text(words[i]);
        }
      }
    });
  }

  // The paired probes. Two clients, each one handshake, at one listener; the witness enumerates what the
  // listener accepts. From a verdict.issued event and the check fixed in its change.proposed event.
  function probes(fig) {
    var v = JSON.parse(fig.dataset.verdict), check = JSON.parse(fig.dataset.check);
    var W = 920, H = 312, L = 20, CW = 340, LX = 596, LW = W - LX - 20, CH = 92;
    var svg = d3.select(fig).append("svg").attr("viewBox", [0, 0, W, H]).attr("role", "img").attr("aria-label", "paired probes: " + v.status);
    var byName = {}; v.probes.forEach(function (p) { byName[p.name] = p; });
    var pos = byName.positive || {}, neg = byName.negative || {}, wit = byName.witness || {};
    var must = check.must_accept || [], refuse = check.must_refuse || [], accepted = wit.accepted_groups || [];
    var kindOf = function (gs) { return gs.length && gs.every(isPQ) ? "post-quantum" : (gs.length && !gs.some(isPQ) ? "classical" : "mixed"); };
    var colour = function (g) { return must.indexOf(g) >= 0 ? C.good : C.bad; };

    var rows = [
      { y: 28, title: "a client offering only " + (must.length === 1 ? must[0] : must.length + " " + kindOf(must) + " groups"),
        sub: (must.length === 1 ? kindOf(must) : must.join(" ")) + " · TLS 1.3 only", p: pos, want: "accepted" },
      { y: 136, title: "a client offering only " + kindOf(refuse) + " groups, any TLS version",
        sub: refuse.length + " groups · " + refuse.join(" "), p: neg, want: "refused" }
    ];
    var okColour = function (d) { return d.p.result === d.want ? C.good : (d.p.result === "error" || !d.p.result ? C.warn : C.bad); };
    var g = svg.selectAll("g.client").data(rows).join("g").attr("class", "client").attr("transform", function (d) { return "translate(" + L + "," + d.y + ")"; });
    g.append("rect").attr("width", CW).attr("height", CH).attr("fill", C.bg).attr("stroke", C.line);
    g.append("rect").attr("width", 3).attr("height", CH).attr("fill", okColour);
    g.append("text").attr("x", 16).attr("y", 26).attr("fill", C.fg).attr("font-size", 13.5).attr("font-weight", 600).text(function (d) { return d.title; }).call(wrap, CW - 32, 17, 2);
    g.append("text").attr("x", 16).attr("y", 62).attr("fill", C.dim).attr("font-size", 11.5).attr("font-family", MONO).text(function (d) { return d.sub; }).call(fit, CW - 32);
    g.append("text").attr("x", 16).attr("y", 80).attr("fill", C.faint).attr("font-size", 11).attr("font-family", MONO)
      .text(function (d) { return (d.p.tool || "probe") + (d.p.started_at ? " · " + d.p.started_at.slice(11, 19) + "Z" : ""); }).call(fit, CW - 32);

    // The handshake: drawn from the card to the listener; an arrowhead where it was accepted, a wall where refused.
    var yMid = CH / 2, x0 = CW, xWall = LX - L - 56;
    var xEnd = function (d) { return d.p.result === "accepted" ? LX - L - 10 : xWall - 14; };
    var line = g.append("line").attr("x1", x0).attr("y1", yMid).attr("x2", xEnd).attr("y2", yMid)
      .attr("stroke", okColour).attr("stroke-width", 3).attr("stroke-linecap", "round");
    line.each(function () { var n = this.getTotalLength(); d3.select(this).attr("stroke-dasharray", n).attr("stroke-dashoffset", n)
      .transition().delay(function (d, i) { return 300 + i * 700; }).duration(800).ease(d3.easeCubicOut).attr("stroke-dashoffset", 0); });
    var end = g.append("g").attr("transform", function (d) { return "translate(" + xEnd(d) + "," + yMid + ")"; }).attr("opacity", 0);
    end.transition().delay(function (d, i) { return 1100 + i * 700; }).duration(250).attr("opacity", 1);
    end.each(function (d) {
      var m = d3.select(this), c = okColour(d);
      if (d.p.result === "accepted") m.append("path").attr("d", "M-12,-7 L0,0 L-12,7").attr("fill", "none").attr("stroke", c).attr("stroke-width", 3).attr("stroke-linejoin", "round");
      else if (d.p.result === "refused") m.append("rect").attr("x", 12).attr("y", -22).attr("width", 5).attr("height", 44).attr("fill", c);
      else m.append("text").attr("y", 5).attr("fill", C.warn).attr("font-size", 14).attr("font-family", MONO).text("?");
    });
    // The result, in the ledger's word, set above the line at the listener's end.
    g.append("text").attr("x", function (d) { return xEnd(d) - (d.p.result === "accepted" ? 16 : 6); }).attr("y", yMid - 10).attr("text-anchor", "end")
      .attr("fill", okColour).attr("font-size", 12).attr("font-family", MONO).attr("font-weight", 600).attr("opacity", 0)
      .text(function (d) {
        var r = d.p.result || "no result", neg = d.p.negotiated ? " " + d.p.negotiated : "";
        if (!d.p.result || d.p.result === "error") return r;
        return r + neg + (r === d.want ? " · as required" : " · should be " + d.want);
      })
      .transition().delay(function (d, i) { return 1100 + i * 700; }).duration(250).attr("opacity", 1);

    // The listener: what it is, what it served, and what the witness found it accepting.
    var LH = rows[1].y + CH - rows[0].y;
    var l = svg.append("g").attr("transform", "translate(" + LX + "," + rows[0].y + ")");
    l.append("rect").attr("width", LW).attr("height", LH).attr("fill", C.bg).attr("stroke", C.line2);
    l.append("text").attr("x", 16).attr("y", 28).attr("fill", C.fg).attr("font-size", 15).attr("font-weight", 600).text(check.target.sni || check.target.host).call(fit, LW - 40);
    l.append("text").attr("x", 16).attr("y", 47).attr("fill", C.dim).attr("font-size", 11.5).attr("font-family", MONO)
      .text(v.binding.address + " · container " + (v.binding.container_id || "").slice(0, 12)).call(fit, LW - 40);
    l.append("text").attr("x", 16).attr("y", 64).attr("fill", C.dim).attr("font-size", 11.5).attr("font-family", MONO)
      .text("certificate " + (v.binding.cert_fingerprint || "").slice(0, 16) + (v.binding.cert_fingerprint ? "…" : "none")).call(fit, LW - 32);
    l.append("line").attr("x1", 16).attr("x2", LW - 16).attr("y1", 78).attr("y2", 78).attr("stroke", C.line);
    l.append("text").attr("x", 16).attr("y", 98).attr("fill", C.dim).attr("font-size", 10.5).attr("letter-spacing", ".1em").text("ACCEPTS, BY THE WITNESS");
    // Chips flow left to right and wrap.
    var cx = 16, cy = 108, chips = l.append("g");
    accepted.forEach(function (d, i) {
      var w = Math.min(d.length * 7.2 + 16, LW - 32);
      if (cx + w > LW - 16) { cx = 16; cy += 24; }
      var c = chips.append("g").attr("transform", "translate(" + cx + "," + cy + ")").attr("opacity", 0);
      c.append("rect").attr("width", w).attr("height", 18).attr("fill", colour(d)).attr("fill-opacity", .14).attr("stroke", colour(d));
      c.append("text").attr("x", 8).attr("y", 13).attr("font-size", 11.5).attr("font-family", MONO).attr("fill", colour(d)).text(d).call(fit, w - 12);
      c.transition().delay(1800 + i * 120).duration(250).attr("opacity", 1);
      cx += w + 8;
    });
    if (!accepted.length) l.append("text").attr("x", 16).attr("y", 122).attr("fill", C.dim).attr("font-size", 12).text(wit.result === "error" ? "the witness did not run" : "nothing enumerated");
    l.append("text").attr("x", 16).attr("y", LH - 14).attr("fill", C.faint).attr("font-size", 11).attr("font-family", MONO)
      .text((wit.tool || "witness") + (wit.tool_version ? " " + wit.tool_version : "") + " · one handshake per group").call(fit, LW - 32);

    // The verdict, in the ledger's word, and what it means.
    var meaning = { "enforced": "the groups the policy names are accepted; every other kind is refused",
                    "enabled-not-enforced": "the new groups are accepted, and so are the old: a client that does not offer the new ones is unprotected",
                    "not-landed": "the groups the policy names are refused: the change did not take",
                    "inconclusive": "a probe failed, or reached the wrong container: nothing is claimed" }[v.status] || "";
    var vc = { "enforced": C.good, "enabled-not-enforced": C.warn, "not-landed": C.bad }[v.status] || C.warn;
    var cap = svg.append("g").attr("transform", "translate(" + L + "," + (H - 24) + ")").attr("opacity", 0);
    cap.append("rect").attr("x", 0).attr("y", -24).attr("width", 4).attr("height", 32).attr("fill", vc);
    var word = cap.append("text").attr("x", 16).attr("y", -2).attr("fill", vc).attr("font-family", SERIF).attr("font-weight", 700).attr("font-size", 24).text(v.status);
    cap.append("text").attr("x", 16 + word.node().getComputedTextLength() + 16).attr("y", -3).attr("fill", C.dim).attr("font-size", 12.5).text(meaning).call(fit, W - 60 - word.node().getComputedTextLength());
    cap.transition().delay(2300).duration(400).attr("opacity", 1);
  }

  // The ledger as a strip of time: the change's events on one track, the signer's signatures on
  // another, each placed by its own clock, and time-to-change read off between them.
  function timeline(fig) {
    var ev = JSON.parse(fig.dataset.timeline), t = JSON.parse(fig.dataset.intervals);
    var mine = ev.filter(function (e) { return e.type !== "checkpoint.signed" && e.type !== "run.closed" && e.type !== "run.started"
      && (!e.change_id || e.change_id === t.change_id) && !e.target_override; });
    var cps = ev.filter(function (e) { return e.type === "checkpoint.signed" && e.signed_at; });
    var all = mine.map(function (e) { return e.ts; }).concat(cps.map(function (e) { return e.signed_at; }));
    var parse = d3.utcParse("%Y-%m-%dT%H:%M:%S.%LZ"), t0 = d3.min(all, parse), t1 = d3.max(all, parse);
    var W = 920, H = 240, L = 24, R = 24, x = d3.scaleUtc().domain([t0, t1]);
    var svg = d3.select(fig).append("svg").attr("viewBox", [0, 0, W, H]).attr("role", "img").attr("aria-label", "the change on the ledger's timeline");
    var short = { "policy.changed": "policy", "change.proposed": "proposed", "approval.granted": "approved", "approval.denied": "denied",
                  "change.applied": "applied", "verdict.issued": "verdict", "service.recreated": "recreated" };
    var kind = { "policy.changed": C.accent, "approval.granted": C.accent, "change.applied": C.fg2, "service.recreated": C.fg2, "change.proposed": C.dim,
                 "verdict.issued": C.good };

    // Ticks that sit within a few pixels of each other share one label, so nothing overprints.
    function clusters(items, at, name) {
      var out = [], sorted = items.slice().sort(function (a, b) { return x(parse(at(a))) - x(parse(at(b))); });
      sorted.forEach(function (d) {
        var px = x(parse(at(d))), last = out[out.length - 1];
        if (last && px - last.x1 < 64) { last.items.push(d); last.x1 = px; } else out.push({ x0: px, x1: px, items: [d] });
      });
      out.forEach(function (c) { c.x = (c.x0 + c.x1) / 2; c.label = c.items.map(name).join(" · "); });
      return out;
    }
    var y1 = 92, y2 = 160, left = L + 118;
    function band(y, a, b, colour, label, value) {
      var g = svg.append("g");
      if (a && b) g.append("rect").attr("x", x(parse(a))).attr("y", y - 11).attr("width", Math.max(2, x(parse(b)) - x(parse(a)))).attr("height", 22).attr("fill", colour).attr("fill-opacity", .10);
      g.append("text").attr("x", L).attr("y", y - 6).attr("fill", C.dim).attr("font-size", 10.5).attr("font-family", MONO).attr("letter-spacing", ".08em").text(label);
      g.append("text").attr("x", L).attr("y", y + 14).attr("fill", colour).attr("font-family", SERIF).attr("font-weight", 700).attr("font-size", 17).text(value).call(fit, left - L - 12);
    }
    var sec = function (ms) { return ms == null ? "" : (ms / 1000).toFixed(1) + " s"; };
    x.range([left, W - R]);
    band(y1, t.policy_ts, t.verdict_ts, C.accent, "LEDGER'S CLOCK", sec(t.policy_to_verdict_ms));
    var before = cps.filter(function (c) { return t.policy_ts && c.seq < mine[0].seq; }).map(function (c) { return c.signed_at; }).sort().pop();
    var over = cps.filter(function (c) { return t.verdict_ts && parse(c.signed_at) >= parse(t.verdict_ts); }).map(function (c) { return c.signed_at; }).sort()[0];
    band(y2, before || t.signer_policy_ts, over || t.signer_verdict_ts, C.good, "SIGNER'S CLOCK",
         t.signer_policy_to_verdict_max_ms != null ? "≤ " + sec(t.signer_policy_to_verdict_max_ms) : sec(t.signer_policy_to_verdict_ms));

    // Track 1: the events, by the harness's stamps.
    var c1 = clusters(mine, function (d) { return d.ts; }, function (d) { return short[d.type] || d.type; });
    var e1 = svg.append("g").selectAll("g").data(c1).join("g").attr("transform", function (d) { return "translate(" + d.x + "," + y1 + ")"; });
    e1.selectAll("line").data(function (d) { return d.items; }).join("line")
      .attr("x1", function (d, i, n) { return x(parse(d.ts)) - x(parse(n[0].__data__.ts)) - (n.length > 1 ? (x(parse(n[n.length - 1].__data__.ts)) - x(parse(n[0].__data__.ts))) / 2 : 0); })
      .attr("x2", function (d, i, n) { return x(parse(d.ts)) - x(parse(n[0].__data__.ts)) - (n.length > 1 ? (x(parse(n[n.length - 1].__data__.ts)) - x(parse(n[0].__data__.ts))) / 2 : 0); })
      .attr("y1", -14).attr("y2", 14).attr("stroke", function (d) { return kind[d.type] || C.dim; }).attr("stroke-width", 2.5);
    e1.append("text").attr("y", -22).attr("text-anchor", function (d) { return d.x < left + 80 ? "start" : (d.x > W - R - 80 ? "end" : "middle"); })
      .attr("fill", C.fg2).attr("font-size", 11).attr("font-family", MONO).text(function (d) { return d.label; });
    // Track 2: the signatures, by the signer's own time.
    var c2 = clusters(cps, function (d) { return d.signed_at; }, function (d) { return "#" + d.through_seq; });
    var e2 = svg.append("g").selectAll("g").data(c2).join("g").attr("transform", function (d) { return "translate(" + d.x + "," + y2 + ")"; });
    e2.append("path").attr("d", "M-5,-12 L0,-16 L5,-12 M0,-16 L0,16").attr("fill", "none").attr("stroke", C.good).attr("stroke-width", 2);
    e2.append("text").attr("y", 30).attr("text-anchor", function (d) { return d.x < left + 80 ? "start" : (d.x > W - R - 80 ? "end" : "middle"); })
      .attr("fill", C.dim).attr("font-size", 10).attr("font-family", MONO).text(function (d) { return (d.items.length > 1 ? "signatures " : "signature ") + d.label; });
    // The axis.
    var ax = svg.append("g").attr("transform", "translate(0," + (H - 26) + ")").call(d3.axisBottom(x).ticks(6).tickFormat(d3.utcFormat("%H:%M:%S")).tickSize(4));
    ax.selectAll("text").attr("fill", C.dim).attr("font-family", MONO).attr("font-size", 10.5);
    ax.selectAll("line, path").attr("stroke", C.line2);
    svg.append("text").attr("x", L).attr("y", 20).attr("fill", C.fg).attr("font-size", 13).attr("font-weight", 600)
      .text("The change on the ledger: " + mine.length + " events, " + cps.length + " signatures");
    svg.append("text").attr("x", L).attr("y", 38).attr("fill", C.dim).attr("font-size", 11.5)
      .text("Events are placed by the harness's stamp, signatures by the signer's own time. The signer's reading runs from the last signature before the policy event to the first over the last verdict.")
      .call(wrap, W - L - R, 15, 2);
  }

  // The clock: the dated federal requirements on one axis, today marked, the unpublished minimum
  // elements of a CBOM singled out. Dates and sources come from the page's data, cited in the BRIEF.
  function clock(fig) {
    var items = JSON.parse(fig.dataset.clock).slice().sort(function (a, b) { return a.date < b.date ? -1 : 1; });
    var parse = d3.utcParse("%Y-%m-%d"), today = new Date();
    var W = 920, L = 24, R = 24, LANE = 20;
    // Piecewise: the year that holds every date due now gets 40% of the width, the decade after it
    // the rest, with a break drawn between. On one even scale the near dates sat on top of each other.
    var BREAK = parse("2027-07-01"), SPLIT = L + (W - L - R) * 0.40;
    var x = d3.scaleUtc().domain([parse("2026-06-01"), BREAK, parse("2036-01-01")]).range([L, SPLIT, W - R]);
    var svg = d3.select(fig).append("svg").attr("role", "img").attr("aria-label", "the dates federal policy sets");
    // Each label takes the lowest lane where it overprints no other label, no other date's leader line
    // runs through it, and its own leader line runs through no label below it. A label that would run
    // off the right edge is set to the left of its date.
    var meas = svg.append("text").attr("font-size", 11).attr("visibility", "hidden"), placed = [];
    // Latest first: each label then sits above every later date its text spans — a staircase in which
    // no line runs through a label. Placed earliest first, a near-term cluster corners itself.
    items.slice().reverse().forEach(function (d) {
      var px = x(parse(d.date));
      meas.attr("font-weight", d.key ? 600 : 400).text(d.date.slice(0, 7) + "  " + d.label);
      var w = meas.node().getComputedTextLength(), end = px + 4 + w > W - R;
      var x0 = end ? px - 4 - w : px + 4, x1 = x0 + w, GAP = 10;
      // Conflicts at lane k: an overprinted label counts most, a line through a label less.
      var cost = function (k) {
        return d3.sum(placed, function (o) {
          var overlap = o.lane === k && !(x1 + GAP < o.x0 || x0 - GAP > o.x1);
          var crossesMe = o.lane > k && o.px >= x0 - GAP && o.px <= x1 + GAP;     // its line through my label
          var crossesIt = k > o.lane && px >= o.x0 - GAP && px <= o.x1 + GAP;     // my line through its label
          return (overlap ? 100 : 0) + (crossesMe ? 1 : 0) + (crossesIt ? 1 : 0);
        });
      };
      // The lowest clean lane, if one exists within a bounded number; else the least conflicted.
      var k = 0, best = 0, MAXL = items.length + 1;
      while (k < MAXL && cost(k) > 0) k++;
      if (k === MAXL) { for (var j = 1; j < MAXL; j++) if (cost(j) < cost(best)) best = j; k = best; }
      d.lane = k; d.end = end; d.px = px; d.x0 = x0; d.x1 = x1;
      placed.push(d);
    });
    meas.remove();
    var lanesN = d3.max(placed, function (d) { return d.lane; }) + 1;
    var y = 64 + lanesN * LANE, H = y + 72;
    svg.attr("viewBox", [0, 0, W, H]);
    svg.append("text").attr("x", L).attr("y", 20).attr("fill", C.fg).attr("font-size", 13).attr("font-weight", 600).text("The clock this runs against");
    svg.append("text").attr("x", W - R).attr("y", 20).attr("text-anchor", "end").attr("fill", C.dim).attr("font-size", 11).attr("font-family", MONO)
      .text("today " + d3.utcFormat("%Y-%m-%d")(today));
    var near = ["2026-07-01", "2026-10-01", "2027-01-01", "2027-04-01"].map(parse);
    var far = d3.range(2028, 2037).map(function (yr) { return parse(yr + "-01-01"); });
    var ax = svg.append("g").attr("transform", "translate(0," + y + ")")
      .call(d3.axisBottom(x).tickValues(near.concat(far)).tickSize(4)
        .tickFormat(function (d) { return d < BREAK ? d3.utcFormat("%b %Y")(d) : d3.utcFormat("%Y")(d); }));
    ax.selectAll("text").attr("fill", C.dim).attr("font-family", MONO).attr("font-size", 10.5).attr("dy", "1.4em");
    ax.selectAll("line, path").attr("stroke", C.line2);
    // The break: two slashes on the axis, and a word for each side.
    var bx = x(BREAK);
    svg.append("rect").attr("x", bx - 5).attr("y", y - 4).attr("width", 10).attr("height", 8).attr("fill", C.card);
    [-3, 3].forEach(function (o) { svg.append("line").attr("x1", bx + o - 3).attr("x2", bx + o + 3).attr("y1", y + 5).attr("y2", y - 5).attr("stroke", C.dim); });
    svg.append("text").attr("x", (L + bx) / 2).attr("y", y + 34).attr("text-anchor", "middle").attr("fill", C.faint).attr("font-size", 10).attr("font-family", MONO).text("the next year, month by month");
    svg.append("text").attr("x", (bx + W - R) / 2).attr("y", y + 34).attr("text-anchor", "middle").attr("fill", C.faint).attr("font-size", 10).attr("font-family", MONO).text("the decade after, year by year");
    // Today, and the span from today to the minimum elements.
    var key = items.filter(function (d) { return d.key; })[0];
    if (key) svg.append("rect").attr("x", x(today)).attr("y", y - 26).attr("width", Math.max(0, x(parse(key.date)) - x(today))).attr("height", 26)
      .attr("fill", C.accent).attr("fill-opacity", .12);
    svg.append("line").attr("x1", x(today)).attr("x2", x(today)).attr("y1", y - 30).attr("y2", y + 4).attr("stroke", C.fg2).attr("stroke-dasharray", "3,3");
    var g = svg.append("g").selectAll("g").data(items).join("g").attr("transform", function (d) { return "translate(" + d.px + ",0)"; });
    var top = function (d) { return y - 30 - d.lane * LANE; };
    g.append("line").attr("y1", top).attr("y2", y).attr("stroke", function (d) { return d.key ? C.accent : C.line2; }).attr("stroke-width", function (d) { return d.key ? 2 : 1; });
    g.append("circle").attr("cy", y).attr("r", function (d) { return d.key ? 5 : 3.5; }).attr("fill", function (d) { return d.key ? C.accent : C.bg; }).attr("stroke", function (d) { return d.key ? C.accent : C.fg2; }).attr("stroke-width", 1.5);
    g.append("text").attr("y", function (d) { return top(d) - 4; }).attr("text-anchor", function (d) { return d.end ? "end" : "start"; }).attr("dx", function (d) { return d.end ? -4 : 4; })
      .attr("fill", function (d) { return d.key ? C.accent : C.fg2; }).attr("font-size", 11).attr("font-weight", function (d) { return d.key ? 600 : 400; })
      .text(function (d) { return d.date.slice(0, 7) + "  " + d.label; });
    svg.append("text").attr("x", L).attr("y", H - 8).attr("fill", C.dim).attr("font-size", 11)
      .text("Each date is cited in the repository's facts table; the shaded span is the time left before a federal CBOM has a published minimum.")
      .call(wrap, W - L - R, 14, 1);
  }

  document.querySelectorAll("figure.clock[data-clock]").forEach(function (fig) {
    try { clock(fig); } catch (e) { fig.textContent = "figure not drawn: " + e; }
  });
  document.querySelectorAll("figure.probes[data-verdict]").forEach(function (fig) {
    try { probes(fig); } catch (e) { fig.textContent = "figure not drawn: " + e; }
  });
  document.querySelectorAll("figure.timeline[data-timeline]").forEach(function (fig) {
    try { timeline(fig); } catch (e) { fig.textContent = "figure not drawn: " + e; }
  });
})();

// The estate map, in columns that follow the CBOM's own dependency chain: the rows the sheet names, the
// services with evidence, their listeners and images, the assets each listener negotiates or serves, and
// the files those assets come from. One service is in focus at a time and its chain is drawn to the end;
// the rest stay at the services' column. A panel shows what the ledger holds for the chosen node.
// Drawn from view.estate_graph; no layout is simulated, so every node is where its column says.
(function () {
  if (typeof d3 === "undefined") return;
  var css = getComputedStyle(document.documentElement);
  var T = function (n) { return css.getPropertyValue(n).trim(); };
  var C = { fg: T("--fg"), fg2: T("--fg2"), dim: T("--dim"), faint: T("--faint"), line: T("--line"), line2: T("--line2"), card: T("--card"),
            good: T("--good"), bad: T("--bad"), warn: T("--warn"), accent: T("--accent"), classical: T("--classical"), bg: T("--bg") };
  var MONO = T("--mono");
  var POSTURE = { pq: C.good, mixed: C.warn, classical: C.classical };
  var COLS5 = [["sheet", "the spreadsheet"], ["service", "services"], ["mid", "listeners and images"], ["asset", "assets"], ["file", "files"]];

  function estate(fig) {
    var G = JSON.parse(fig.dataset.graph);
    // A graph may name its own columns (the lab's: subnet, host, listeners, entries); else the estate's five.
    var COLS = G.columns || COLS5;
    var byId = {}; G.nodes.forEach(function (n) { byId[n.id] = n; n.children = []; n.parents = []; });
    G.edges.forEach(function (e) { byId[e.from].children.push(e); byId[e.to].parents.push(e); });
    var kids = function (n, kinds) { return n.children.map(function (e) { return byId[e.to]; }).filter(function (c) { return !kinds || kinds.indexOf(c.kind) >= 0; }); };
    var sheet = G.nodes.filter(function (n) { return n.kind === "sheet"; });
    var services = G.nodes.filter(function (n) { return n.kind === "service"; });
    // Services in the sheet's order first, then the ones the sheet never knew.
    var rank = function (s) { var i = sheet.findIndex(function (r) { return r.children.some(function (e) { return e.to === s.id; }); }); return i < 0 ? 99 : i; };
    services.sort(function (a, b) { return rank(a) - rank(b) || a.label.localeCompare(b.label); });
    sheet.sort(function (a, b) { return (a.evidence ? 0 : 1) - (b.evidence ? 0 : 1); });
    var focus = services[0], selected = null;

    var W = fig.clientWidth ? fig.clientWidth - 300 : 860;
    if (W < 520) W = Math.max(fig.clientWidth || 360, 360);
    var wrap = d3.select(fig).classed("drawn", true);
    var svg = wrap.append("svg").attr("role", "img").attr("aria-label", "the estate, by the CBOM's dependency chain");
    var panel = wrap.append("div").attr("class", "estate-panel");
    // Column widths weighted by what their labels need; x of each column is the sum of those before it.
    var PAD = 14, RH = 24, TOP = 40, WEIGHT = COLS.length === 5 ? [1, .85, 1.3, .8, 1.35] : [.9, 1, .8, 1.3], SUM = WEIGHT.reduce(function (a, b) { return a + b; });
    var colX = WEIGHT.map(function (w, i) { return PAD + WEIGHT.slice(0, i).reduce(function (a, b) { return a + b; }, 0) * (W - PAD * 2) / SUM; });
    var colWidth = function (i) { return WEIGHT[i] * (W - PAD * 2) / SUM; };
    // An image's files no asset points to, grouped by directory when there are more than three: a base
    // image's package-signing keys are real files, but forty of them say one thing.
    var groups = {};
    function imageFiles(img, taken) {
      var loose = kids(img, ["file"]).filter(function (f) { return taken.indexOf(f) < 0; }), byDir = {};
      loose.forEach(function (f) { var d = f.label.replace(/[^/]*$/, ""); (byDir[d] = byDir[d] || []).push(f); });
      var out = [];
      Object.keys(byDir).sort().forEach(function (d) {
        if (byDir[d].length <= 3) { out = out.concat(byDir[d]); return; }
        var id = "group:" + img.id + ":" + d;
        var gnode = groups[id] = groups[id] || { id: id, kind: "group", label: d + " ×" + byDir[d].length, dir: d, files: byDir[d], children: [], parents: [], image: img.image };
        byId[id] = gnode; out.push(gnode);
      });
      return out;
    }

    function colour(n) {
      if (n.kind === "service" || n.kind === "listener") return POSTURE[n.posture] || C.line2;
      if (n.kind === "asset") return n.pq ? C.good : (n.role === "key-establishment" ? C.classical : C.fg2);
      if (n.kind === "file" || n.kind === "group") return n.in_use === false ? C.faint : C.fg2;
      if (n.kind === "sheet") return n.evidence ? C.dim : C.bad;
      return C.line2;
    }
    function fitText(sel, width) {
      sel.each(function () { var t = d3.select(this), s = t.text(); while (s.length > 3 && this.getComputedTextLength() > width) { s = s.slice(0, -2); t.text(s + "…"); } });
    }

    function layout() {
      var mid = [], assets = [], files = [];
      services.forEach(function (s) { kids(s, ["listener", "image"]).forEach(function (c) { c.owner = s; mid.push(c); }); });
      kids(focus, ["listener"]).forEach(function (l) { kids(l, ["asset"]).forEach(function (a) { if (assets.indexOf(a) < 0) assets.push(a); }); });
      assets.forEach(function (a) { kids(a, ["file"]).forEach(function (f) { if (files.indexOf(f) < 0) files.push(f); }); });
      var links = files.slice();
      kids(focus, ["image"]).forEach(function (i) { imageFiles(i, links).forEach(function (f) { if (files.indexOf(f) < 0) { files.push(f); f.img = i; } }); });
      var cols = [sheet, services, mid, assets, files].slice(0, COLS.length);
      var H = TOP + Math.max.apply(null, cols.map(function (c) { return c.length; })) * RH + 20;
      cols.forEach(function (c, i) {
        var y0 = TOP + (H - TOP - 20 - c.length * RH) / 2;
        c.forEach(function (n, j) { n.x = colX[i] + 8; n.y = y0 + j * RH + RH / 2; n.col = i; });
      });
      return { cols: cols, H: H };
    }

    function render() {
      var L = layout(), shown = [].concat.apply([], L.cols), on = {};
      shown.forEach(function (n) { on[n.id] = true; });
      svg.attr("viewBox", [0, 0, W, L.H]).attr("height", L.H);
      svg.selectAll("*").remove();
      svg.selectAll("text.head").data(COLS).join("text").attr("class", "head").attr("x", function (d, i) { return colX[i]; }).attr("y", 18)
        .attr("fill", C.dim).attr("font-size", 10.5).attr("font-family", MONO).attr("letter-spacing", ".08em").text(function (d) { return d[1].toUpperCase(); });
      var inFocus = function (n) { return n === focus || n.owner === focus || n.col >= 3 || (n.kind === "sheet" && n.children.some(function (e) { return e.to === focus.id; })); };
      var links = G.edges.filter(function (e) { var a = byId[e.from], b = byId[e.to]; return on[a.id] && on[b.id] && b.col === a.col + 1 || (on[a.id] && on[b.id] && a.kind === "image" && b.kind === "file"); });
      shown.forEach(function (n) { if (n.kind === "group" && n.img) links.push({ from: n.img.id, to: n.id, kind: "holds" }); });
      svg.append("g").selectAll("path").data(links).join("path").attr("fill", "none")
        .attr("d", function (e) { var a = byId[e.from], b = byId[e.to]; var x1 = a.x + 6, x2 = b.x - 6, m = (x1 + x2) / 2;
          return "M" + x1 + "," + a.y + "C" + m + "," + a.y + " " + m + "," + b.y + " " + x2 + "," + b.y; })
        .attr("stroke", function (e) { var a = byId[e.from], b = byId[e.to]; return inFocus(a) && inFocus(b) ? C.accent : C.line2; })
        .attr("stroke-opacity", function (e) { var a = byId[e.from], b = byId[e.to]; return inFocus(a) && inFocus(b) ? .55 : .45; })
        .attr("stroke-dasharray", function (e) { return e.kind === "is" ? "3 4" : null; });
      var g = svg.append("g").selectAll("g").data(shown).join("g").attr("transform", function (n) { return "translate(" + n.x + "," + n.y + ")"; })
        .style("cursor", "pointer").attr("opacity", function (n) { return inFocus(n) ? 1 : .5; })
        .on("click", function (ev, n) {
          var s = n.kind === "service" ? n : (n.owner || (n.kind === "sheet" && n.children.length ? byId[n.children[0].to] : null));
          if (s && s !== focus) { focus = s; render(); }
          select(n);
        });
      g.append("circle").attr("r", function (n) { return n.kind === "service" ? 7 : 5; })
        .attr("fill", function (n) { return n.kind === "sheet" && !n.evidence ? "none" : colour(n); })
        .attr("fill-opacity", function (n) { return n.kind === "service" || n.kind === "listener" ? .35 : .9; })
        .attr("stroke", colour).attr("stroke-width", function (n) { return n === selected ? 3 : 1.6; })
        .attr("stroke-dasharray", function (n) { return (n.kind === "sheet" && !n.evidence) || n.in_use === false ? "2 2" : null; });
      g.append("text").attr("x", 11).attr("y", 4).attr("font-size", function (n) { return n.kind === "service" ? 13 : 11.5; })
        .attr("font-weight", function (n) { return n === focus ? 700 : (n.kind === "service" ? 600 : 400); })
        .attr("font-family", function (n) { return n.kind === "sheet" || n.kind === "service" ? null : MONO; })
        .attr("fill", function (n) { return n.kind === "sheet" && !n.evidence ? C.bad : (n.kind === "asset" ? colour(n) : C.fg2); })
        .text(function (n) { return n.kind === "image" ? "image " + n.label : n.label; }).each(function (n) { fitText(d3.select(this), colWidth(n.col) - 32); });
      g.append("title").text(function (n) { return n.label; });
    }

    function row(k, v) { return v == null || v === "" ? "" : "<div class=\"k\">" + k + "</div><div class=\"v\">" + v + "</div>"; }
    function esc(s) { return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;"); }
    function select(d) {
      selected = d;
      var h = "<div class=\"kind\">" + (d.host ? "host" : (d.subnet ? "subnet" : d.kind)) + "</div><div class=\"name\">" + esc(d.label) + "</div>";
      if (d.kind === "sheet" && d.subnet) h += row("hosts", d.children.length + " with a listener in this CBOM");
      else if (d.kind === "sheet") h += row("the sheet says", esc(d.says)) + row("owner", esc(d.owner)) + row("evidence", d.evidence ? "yes: a scanned service" : "<span class=\"bad\">none — nothing in the slice answers to this row</span>");
      if (d.kind === "service" && d.host) h += row("posture", d.posture ? "<span style=\"color:" + (POSTURE[d.posture] || C.dim) + "\">" + d.posture + "</span> — its best listener" : "none stated")
        + row("listeners", d.children.length + " in this CBOM") + row("owner's facts", "none supplied: no owner has said what this host is for");
      else if (d.kind === "service") {
        h += row("posture", d.posture ? "<span style=\"color:" + (POSTURE[d.posture] || C.dim) + "\">" + d.posture + "</span>" : "none stated") + row("holds", d.children.length + " listeners and images")
          + row("joined by evidence", d.linked ? "yes — the runner found a container of this service at the listener's address" : "<span class=\"bad\">no — named by the scope only</span>");
        var f = d.facts || {};
        if (Object.keys(f).length) h += row("mission function <span class=\"tag supplied\">supplied</span>", esc(f["mission-function"] || "")) + row("data lifetime", f["data-lifetime"] != null ? esc(f["data-lifetime"]) + " years" : "") + row("high-value asset", f["high-value-asset"] === true ? "yes" : (f["high-value-asset"] === false ? "no" : ""));
        else h += row("owner's facts", "none supplied");
      }
      if (d.kind === "listener") h += row("address", esc(d.address)) + row("posture", d.posture || "none") + row("bound to scope", d.bound === false ? "<span class=\"bad\">no</span>" : "yes")
        + (d.reading ? row("the entries say", esc(d.reading)) : "") + (d.scan ? row("scanned by", esc(d.scan.tool) + ", " + (d.scan.ms / 1000).toFixed(1) + " s, " + esc(d.scan.status)) : "") + row("assets", d.children.length + " on this listener");
      if (d.kind === "image") h += row("image", esc(d.image)) + row("files", d.children.length + " with cryptographic material");
      if (d.kind === "asset") h += row("CycloneDX type", esc(d.asset_type)) + row("role", esc(d.role)) + row("post-quantum", d.pq ? "<span class=\"good\">yes</span>" : "no")
        + row("parameters", "<code>" + esc(JSON.stringify(d.parameters)) + "</code>") + row("seen by", esc(d.tool)) + row("observed", esc(d.observed_at))
        + row("raw output", "<code>" + esc(d.raw) + "</code> sha256 <code>" + esc((d.raw_sha256 || "").slice(0, 16)) + "…</code>") + row("ledger event", "<code>" + esc(d.event) + "</code>")
        + (d.children.length ? row("served from", d.children.map(function (e) { return "<code>" + esc(byId[e.to].label) + "</code>"; }).join(", ")) : "")
        + row("in the CBOM", "a <code>cryptographic-asset</code> component; <a href=\"/cbom-workbench/site/notes/01-what-is-a-cbom/\">what these fields are</a>");
      if (d.kind === "group") h += row("in image", esc(d.image)) + row("holds", d.files.length + " files with cryptographic material that no listener serves")
        + row("files", d.files.map(function (f) { return "<code>" + esc(f.label.slice(d.dir.length)) + "</code>"; }).join(", "));
      if (d.kind === "file") h += row("in image", esc(d.image)) + row("holds", esc(d.asset_type) + " " + esc(d.name)) + row("in use", d.in_use === false ? "<span class=\"dim\">no — " + esc(d.basis || "") + "</span>" : (d.in_use ? "yes — " + esc(d.basis || "") : "not judged"))
        + (d.parameters ? row("parameters", "<code>" + esc(JSON.stringify(d.parameters)) + "</code>") : "") + (d.event ? row("ledger event", "<code>" + esc(d.event) + "</code>") : "");
      panel.html(h);
      svg.selectAll("circle").attr("stroke-width", function (n) { return n === d ? 3 : 1.6; });
    }

    if (G.intro) panel.html("<div class=\"kind\">the CBOM</div><div class=\"name\">" + esc(G.intro.split(";")[0]) + "</div>" + row("how to read it", esc(G.intro.split(";").slice(1).join(";").trim())));
    else panel.html("<div class=\"kind\">the estate</div><div class=\"name\">" + G.nodes.filter(function (n) { return n.kind === "service"; }).length + " services with evidence, " +
      G.nodes.filter(function (n) { return n.kind === "sheet" && !n.evidence; }).length + " rows of the sheet with none</div>" +
      row("run", "<code>" + esc(G.run) + "</code>") + row("how to read it", "Left to right is the CBOM's dependency chain: a row of the sheet, the service it is, the service's listeners and images, the assets each listener negotiates or serves, and the files they come from. Click a service to follow its chain; click anything for the evidence behind it.") +
      row("colour", "<span style=\"color:" + C.good + "\">post-quantum</span> · <span style=\"color:" + C.warn + "\">mixed</span> · <span style=\"color:" + C.classical + "\">classical</span> · <span class=\"bad\">no evidence</span> · dashed: not in use"));
    render();
  }

  document.querySelectorAll("figure.estate[data-graph]").forEach(function (fig) {
    try { estate(fig); } catch (e) { fig.textContent = "figure not drawn: " + e; }
  });
})();
