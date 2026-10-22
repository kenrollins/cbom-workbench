import json

from pqch.scout.imported import _asset, place, run_import

from .conftest import SCOPE


def test_an_occurrence_is_placed_only_where_the_workbench_can_find_it_again():
    kw = {"scope": SCOPE, "image": None, "image_digest": None, "repo": None, "commit": None}
    assert place("172.16.106.10:443", {}, **kw) == ("wire", {"kind": "endpoint", "host": "172.16.106.10", "port": 443,
                                                             "protocol": "tls", "sni": "portal.agency.test"})
    assert place("203.0.113.9:443", {}, **kw) is None                       # not in the scope
    assert place("/etc/ssl/a.crt", {}, **kw) is None                         # a file, but in which image?
    assert place("/etc/ssl/a.crt", {}, **{**kw, "image": "pqch-agency/portal", "image_digest": "sha256:" + "a" * 64})[0] == "host"
    assert place("app/x.rb", {"line": 7}, **{**kw, "repo": "r", "commit": "c"}) == (
        "code", {"kind": "call-site", "repo": "r", "commit": "c", "path": "app/x.rb", "line": 7})


def test_names_are_read_the_workbench_way():
    alg = {"type": "cryptographic-asset", "name": "X25519MLKEM768", "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "kem"}}}
    assert _asset(alg, {})[:3] == ("algorithm", "key-establishment", "X25519MLKEM768")
    assert _asset({"type": "library", "name": "openssl"}, {}) is None


def test_an_import_places_scores_and_records_what_it_could_not_place(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"tools": {"components": [{"name": "acme-scan", "version": "9"}]}},
           "components": [
               {"type": "cryptographic-asset", "bom-ref": "a", "name": "X25519", "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "key-agree"}},
                "evidence": {"occurrences": [{"location": "172.16.106.10:443"}]}},
               {"type": "cryptographic-asset", "bom-ref": "b", "name": "AES-128-GCM", "cryptoProperties": {"assetType": "algorithm"}}]}
    p = tmp_path / "acme.cdx.json"
    p.write_text(json.dumps(doc))
    (tmp_path / "var" / "runs").mkdir(parents=True)
    run, s = run_import(tmp_path / "var", [(p, None)], SCOPE)
    assert s["tool"] == "acme-scan" and s["findings"] == 1 and s["by_layer"] == {"wire": 1}
    assert s["unplaced_names"] == ["algorithm AES-128-GCM"]
    types = [e["type"] for e in run.ledger.events()]
    assert types.count("finding.observed") == 1 and "import.completed" in types and types[-1] == "run.closed"
