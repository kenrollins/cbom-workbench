// While a scan runs, poll its progress and reload when it finishes. Vendored.
(function () {
  var el = document.getElementById("progress");
  if (!el || el.dataset.running !== "true") return;
  function row(l) {
    var t = l.target.host ? l.target.host + ":" + l.target.port : l.target.image.split("@")[0];
    return "<tr><td>" + l.profile + "</td><td>" + t + "</td><td>" + l.status +
      (l.replayed ? ' <span class="tag replay">replayed</span>' : "") + '</td><td class="num">' +
      (l.duration_ms / 1000).toFixed(1) + ' s</td><td class="num">' + l.findings + "</td></tr>";
  }
  function poll() {
    fetch("/api/scan").then(function (r) { return r.json(); }).then(function (s) {
      var body = el.querySelector("tbody");
      if (body) body.innerHTML = s.lines.map(row).join("");
      if (s.running) { setTimeout(poll, 1500); } else { window.location.reload(); }
    }).catch(function () { setTimeout(poll, 3000); });
  }
  setTimeout(poll, 1500);
})();
