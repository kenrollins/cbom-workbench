import importlib
import warnings

from pqch.assessor import load_policy, structure
from pqch.pipeline import write_cboms, write_score


def test_page_renders_a_run(slice_run, monkeypatch):
    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    write_cboms(slice_run)
    write_score(slice_run, __import__("pathlib").Path("eval/answer-keys/mini-agency-m0.yaml"))
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
    html = c.get("/walkthrough").text
    for text in ("The spreadsheet", "static", "Scan", "posture classical", "posture mixed",
                 "/etc/ssl/legacy/portal-2019.crt", "in-use/not-served/1", "Workbench", "consistent", "closed without a checkpoint"):
        assert text in html, text
    import re
    assert not re.search(r'(src|href)="https://[^"]*\.(js|css|woff2?)"', html)  # no external assets
    assert c.get(f"/runs/{slice_run.id}/workbench.cdx.json").status_code == 200
    assert c.get(f"/runs/{slice_run.id}/..%2Fscope.json").status_code == 404
    assert c.get("/walkthrough?run=../../etc").status_code == 404
    # A ledger that does not verify is reported, and nothing is rendered from it.
    lines = slice_run.ledger.path.read_text().splitlines()
    slice_run.ledger.path.write_text("\n".join(lines[:3] + lines[4:]) + "\n")
    html = c.get("/walkthrough").text
    assert "does not verify" in html and "posture mixed" not in html


def test_overview_draws_nists_frame_for_both_estates(slice_run, monkeypatch):
    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    write_cboms(slice_run)
    write_score(slice_run, __import__("pathlib").Path("eval/answer-keys/mini-agency-m0.yaml"))
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
    html = c.get("/").text
    # NIST's figure, credited, with its own labels; the estate's live counts inside it.
    for text in ("NIST CSWP 39-upd1", "doi.org/10.6028/NIST.CSWP.39-upd1", "NIST has not reviewed this page",
                 "Governance", "Information Repository", "Risk Analysis Prioritization Engine", "Mitigation", "Migration",
                 "Zero-Trust", "verifier — no model", f"Latest run <code>{slice_run.id}</code>"):
        assert text in html, text
    # The lab estate renders with no capture at all, and says what it does not reach.
    lab = c.get("/?estate=lab").text
    assert "no capture yet" in lab and "applies nothing to an estate it did not build" in lab
    assert c.get("/?estate=elsewhere").status_code == 404


def test_house_cbom_merges_both_layers_by_fingerprint():
    from pqch.cbom import house

    def comp(fp, name, subject, params, tool, ev, atype="algorithm", role="key-establishment"):
        import json
        return {"type": "cryptographic-asset", "bom-ref": "fp:" + fp, "name": name, "cryptoProperties": {"assetType": atype},
                "properties": [{"name": "pqch:fingerprint", "value": fp}, {"name": "pqch:subject", "value": json.dumps(subject)},
                               {"name": "pqch:role", "value": role}, {"name": "pqch:parameters", "value": json.dumps(params)},
                               {"name": "pqch:tools", "value": tool}, {"name": "pqch:evidence", "value": ev}]}
    ln = {"host": "10.9.9.9", "kind": "endpoint", "port": 443, "protocol": "tls"}
    scan = {"components": [comp("a", "X25519", ln, {}, "testssl.sh", "E1"), comp("b", "X25519MLKEM768", ln, {}, "testssl.sh", "E2")]}
    import pqch.cbom.house as h
    orig = h.project
    h.project = lambda ev: {"components": [comp("a", "X25519", ln, {"inside": True, "chosen": 40, "clients_offered_hybrid": 0}, "zeek", "E3"),
                                           comp("z", "X25519", {"host": "1.2.3.4", "kind": "endpoint", "port": 443}, {"inside": False, "chosen": 9}, "zeek", "E4")]}
    try:
        out = house.build([{}], scan)
    finally:
        h.project = orig
    # The outside entry is left out; the shared one is one entry with both tools and both events.
    assert out["entries"] == 2 and out["both"] == 1 and out["scan_only"] == 1 and out["capture_only"] == 0
    merged = next(c for c in out["doc"]["components"] if c["name"] == "X25519")
    props = [(p["name"], p["value"]) for p in merged["properties"]]
    assert ("pqch:tools", "testssl.sh, zeek") in props and ("pqch:evidence", "E1") in props and ("pqch:evidence", "E3") in props
    assert out["listeners"][0]["reading"] == "accepts a hybrid group, never chosen: no client offered one"


def test_the_plan_pages_render(slice_run, monkeypatch):
    # Every page template must compile and render, with or without a plan to show.
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
    for url in ("/plan", "/plan?estate=lab", "/plan?assume=replace:queue", "/resolve", "/imports", "/packages"):
        assert c.get(url).status_code == 200, url


def test_public_mode_leaves_no_way_into_the_lab(slice_run, monkeypatch):
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.setenv("PQCH_PUBLIC", "1")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
    for url in ("/lab", "/lab/house.cdx.json", "/?estate=lab", "/plan?estate=lab"):
        assert c.get(url).status_code == 404, url
    for url in ("/", "/walkthrough", "/plan", "/cbom", "/resolve"):
        html = c.get(url).text
        assert 'href="/lab"' not in html and "estate=lab" not in html.replace("estate=lab|", ""), url
        assert "<form" not in html or url == "/cbom", url
    monkeypatch.delenv("PQCH_PUBLIC")
    importlib.reload(ui)
