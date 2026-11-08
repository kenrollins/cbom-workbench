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
    monkeypatch.setenv("PQCH_TRUSTED_PROXIES", "testclient")      # the lab estate answers a signed-on viewer only
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app, headers={"X-Forwarded-User": "ken"})
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
    monkeypatch.setenv("PQCH_TRUSTED_PROXIES", "testclient")      # the lab estate answers a signed-on viewer only
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app, headers={"X-Forwarded-User": "ken"})
    for url in ("/agency", "/plan", "/plan?estate=lab", "/plan?assume=replace:queue", "/resolve", "/imports", "/packages"):
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
    # Only the pages the public copy renders are held to this (ADR-0006): the rest are never published.
    import importlib.util as ilu
    spec = ilu.spec_from_file_location("build_public", "tools/build_public.py")
    bp = ilu.module_from_spec(spec)
    spec.loader.exec_module(bp)
    assert set(bp.PUBLIC_PAGES) == {"/demo", "/cbom", "/about"} and bp.PUBLIC_PAGES["/demo"] == "index.html"
    for url in [*bp.PUBLIC_PAGES, "/ask"]:
        html = c.get(url).text
        assert 'href="/lab"' not in html and "estate=lab" not in html.replace("estate=lab|", ""), url
        assert "<form" not in html or url in ("/cbom", "/ask"), url
        for dropped in ("/walkthrough", "/agency", "/plan", "/packages", "/imports", "/resolve", "/hosts"):
            assert f'href="{dropped}"' not in html, (url, dropped)
    monkeypatch.delenv("PQCH_PUBLIC")
    importlib.reload(ui)


def test_the_test_agency_matches_its_files():
    # The page is read from the estate's files; every service in compose has a description, and the
    # answer key's items all land on a service.
    from pathlib import Path

    from pqch.ui import estate

    e = estate.build(Path("agency"), Path("agency/answer-key.yaml"))
    assert len(e["services"]) == 8 and e["listeners"] == 9
    assert sum(s["counts"]["present"] for s in e["services"]) == e["totals"]["present"]
    assert sum(s["counts"]["decoy"] for s in e["services"]) == e["totals"]["decoy"]
    assert sum(s["counts"]["out-of-reach"] for s in e["services"]) == e["totals"]["out-of-reach"]


def test_ask_in_a_static_copy_shows_recorded_answers_checked_again(slice_run, monkeypatch):
    import json

    from pqch import ask

    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    write_cboms(slice_run)
    real = next(iter(slice_run.ledger.events()))["id"]
    q = ask.EXAMPLES[0]
    shown = [{"ref": "listener/x", "kind": "listener", "label": "x", "score": 0.9, "events": [real], "text": "x"}]
    # The recording claims every citation passed; the page must decide that again from the ledger.
    reply = {"answer": "the bastion", "components": ["listener/x"], "citations": [real, "01M00000000000000000000000"],
             "not_in_passages": False}
    p = ask.recording_path(slice_run.var, slice_run.id)
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"run": slice_run.id, "recorded_at": "2026-11-05T19:30:00Z", "answers": {q: {
        "question": q, "shown": shown, "reply": reply, "check": {"ok": True, "citations": [], "components": []},
        "model": "m", "tier": "fast", "hardware": "h", "latency_ms": 1, "reasoning": True, "finish_reason": "stop",
        "completion_tokens": 9, "embed_model": "e", "embed_hardware": "h"}}}))
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.setenv("PQCH_DEMO_MODE", "snapshot")
    monkeypatch.delenv("PQCH_INFERENCE_CONFIG", raising=False)     # no model to call, and none is looked for
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
    page = c.get("/ask").text
    assert "asked once, on 2026-11-05" in page and "disabled" in page and q in page
    html = c.get("/ask", params={"q": q}).text
    assert "Recorded 2026-11-05" in html and "the bastion" in html
    assert html.count('class="ok">passes') == 1 and html.count('class="bad">fails') == 1
    assert "only the example questions" in c.get("/ask", params={"q": "anything else"}).text


def test_the_static_stage_carries_the_test_agency_only_and_calls_nothing(slice_run, monkeypatch):
    import json
    import re

    from pqch.ui import demo

    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    write_cboms(slice_run)
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.setenv("PQCH_PUBLIC", "1")
    monkeypatch.setenv("PQCH_HARDWARE", "the box the app runs on")    # not what the copy may claim
    monkeypatch.delenv("PQCH_INFERENCE_CONFIG", raising=False)
    # a server read whole lives beside the test agency in a deployment; the copy must not carry it
    monkeypatch.setattr("pqch.systems.hosts", lambda var: [{"name": "a-lab-server", "run": "x", "addresses": ["10.9.9.9"]}])
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
    html = c.get("/demo").text
    doc = json.loads(re.search(r"window.__DEMO = (.*?);( window.__STATIC)", html, re.S).group(1).replace("<\\/", "</"))
    assert doc["hosts"] == [] and doc["this_host"] is None and "a-lab-server" not in html and "10.9.9.9" not in html
    assert doc["hardware"] == demo.ledger_hardware(slice_run) or doc["hardware"] == "unlabelled"
    assert "the box the app runs on" not in html
    assert doc["static"]["entries"] and all(e["run"] == slice_run.id for e in doc["static"]["entries"].values())
    assert "window.__STATIC = true" in html and "A recorded copy of the stage" in html
    assert doc["engine"]["live"] is None                                  # no engine was asked anything
    assert c.get("/api/demo").status_code == 404 and c.post("/api/demo/narrate", json={}).status_code == 404
    assert 'href="/demo"' in c.get("/about").text                          # the tab is in the public header
