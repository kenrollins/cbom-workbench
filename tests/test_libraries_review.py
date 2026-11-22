"""link/library/1 after the 2026-11 review: an image that serves two services links both."""

import json

from pqch import scope as scope_mod
from pqch.assessor import libraries
from pqch.run import Run
from pqch.scout.normalize import normalize

IMAGE = "pqch-agency/web"


def test_every_service_an_image_serves_is_linked_and_the_library_is_counted_once(tmp_path):
    scope = {"schema": "pqch.scope/1", "id": "01M40W6W873YWJMWPKGMK3YBMM", "estate": "colocated", "owned": True,
             "authorized_by": None, "images": [IMAGE + "@sha256:" + "b" * 64], "sources": [], "reach": {"kind": "local"},
             "endpoints": [{"host": "172.16.106.10", "port": 443, "transport": "tcp", "protocol": "tls", "service": "web-a"},
                           {"host": "172.16.106.11", "port": 443, "transport": "tcp", "protocol": "tls", "service": "web-b"}]}
    run = Run.start(tmp_path / "var", scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="t")
    rule = {"kind": "rule", "id": "test"}
    run.ledger.append("sbom.observed", rule, {"image": IMAGE, "crypto_libraries": [
        {"name": "libssl3", "version": "3.5", "purl": "pkg:apk/alpine/libssl3@3.5"}]})
    for svc in ("web-a", "web-b"):
        run.ledger.append("link.asserted", rule, {"from": {"kind": "image", "image": IMAGE + "@sha256:" + "b" * 64},
                                                  "to": {"kind": "service", "name": svc}, "kind": "runs"})
    for host in ("172.16.106.10", "172.16.106.11"):
        job = {"tool": "testssl.sh", "version": "x", "image_digest": "sha256:" + "c" * 64, "profile": "tls-targeted",
               "target": {"host": host, "port": 443}, "ended_at": "2026-10-03T12:00:00.000Z", "raw": "var/raw/x.json",
               "raw_sha256": "d" * 64}
        for f in normalize(json.dumps([{"id": "FS_ECDHE_curves", "finding": "X25519"}]).encode(), job):
            run.ledger.append("finding.observed", rule, f)
    counts = libraries.link(run)
    assert counts == {"library_links": 2, "libraries": 1, "libraries_in_use": 1}
    links = [e["payload"] for e in run.ledger.events() if e["payload"].get("rule_id") == libraries.RULE]
    assert sorted(p["basis"].split("what ")[1].split("'s listener")[0] for p in links) == ["web-a", "web-b"]
