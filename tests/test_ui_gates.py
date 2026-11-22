"""Who the pages answer, and what they will not show: the lab gate by a run's scope, the journal behind the
sign-on, the host names the page is served under, identity in its two modes, approvals under ADR-0008,
and nothing drawn from a ledger that does not verify or from a stored file in place of the ledger."""

import importlib
import json
import re
import time
import warnings
from pathlib import Path

import pytest

from pqch.assessor import load_policy, structure
from pqch.pipeline import write_cboms

from .conftest import SCOPE
from .test_copy import M0_KEY, copy_scope

KEN = {"X-Forwarded-User": "ken"}
ENV = ("PQCH_TRUSTED_PROXIES", "PQCH_OPERATOR", "PQCH_PUBLIC", "PQCH_ALLOWED_HOSTS", "PQCH_APPROVER_GROUP",
       "PQCH_SEPARATION_OF_DUTIES", "PQCH_SITE_DIR", "PQCH_PREVIEW_DIR", "PQCH_INFERENCE_CONFIG", "PQCH_DEMO_MODE",
       "PQCH_SIGNER_SOCKET", "PQCH_ESTATE_READERS")


def app_with(monkeypatch, var, **env):
    """The app module reloaded under a deployment's settings, and a client whose peer is `testclient`."""
    for k in ENV:
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PQCH_VAR", str(var))
    for k, v in env.items():
        monkeypatch.setenv(k, str(v))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        return ui, TestClient(ui.app)


def _copy_import(var: Path):
    """Another tool's CBOM of the copy, imported under the copy's scope: a run of kind `import`."""
    from pqch.scout.imported import run_import

    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"tools": {"components": [{"name": "a-sensor", "version": "3.6"}]}},
           "components": [{"type": "cryptographic-asset", "bom-ref": "a", "name": "X25519",
                           "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "key-agree"}},
                           "evidence": {"occurrences": [{"location": "10.20.30.102:443"}]}}]}
    p = var.parent / "sensor.cdx.json"
    p.write_text(json.dumps(doc))
    (var / "runs").mkdir(parents=True, exist_ok=True)
    run, _ = run_import(var, [(p, None)], copy_scope(), key_path=M0_KEY)
    own, _ = run_import(var, [(p, None)], SCOPE, key_path=M0_KEY)       # the same document under the estate's own scope
    return run, own


# ───────── the lab gate decides by scope, in every route ─────────

def test_an_import_under_a_copy_scope_is_the_labs_in_every_route(tmp_path, monkeypatch):
    var = tmp_path / "var"
    lab, own = _copy_import(var)
    assert next(iter(lab.ledger.events()))["payload"]["kind"] == "import"
    routes = [f"/cbom?run={lab.id}", f"/runs/{lab.id}/ledger.jsonl", f"/estate/cbom.json?runs={lab.id}",
              f"/runs/{lab.id}/projection/agency-inventory.csv", f"/ask?run={lab.id}", f"/walkthrough?run={lab.id}",
              f"/packages?run={lab.id}", f"/resolve?change={lab.id}", f"/runs/{lab.id}/register.json"]

    # A peer on the application's own network, with or without a typed header: not there.
    _, c = app_with(monkeypatch, var, PQCH_TRUSTED_PROXIES="10.20.33.3")
    for path in routes:
        for h in ({}, KEN):
            r = c.get(path, headers=h)
            assert r.status_code == 404 and "10.20.30." not in r.text, path
    page = c.get("/imports", headers=KEN).text
    assert lab.id not in page and "10.20.30." not in page and own.id in page      # the estate's own import is public

    # Through the front door, signed on: the lab's viewer sees it, labelled as a copy.
    _, c = app_with(monkeypatch, var, PQCH_TRUSTED_PROXIES="testclient")
    assert c.get(f"/cbom?run={lab.id}").status_code == 404
    assert c.get(f"/cbom?run={lab.id}", headers=KEN).status_code == 200
    assert c.get(f"/runs/{lab.id}/ledger.jsonl", headers=KEN).status_code == 200
    page = c.get("/imports", headers=KEN).text
    assert lab.id in page and "A document of a <strong>copy</strong> of mini-agency" in page
    assert "no scan of that copy is on this deployment" in page
    assert lab.id not in c.get("/imports").text

    # Public mode never serves it at all, whoever asks.
    _, c = app_with(monkeypatch, var, PQCH_PUBLIC="1", PQCH_TRUSTED_PROXIES="testclient")
    for path in routes:
        assert c.get(path, headers=KEN).status_code == 404, path
    assert lab.id not in c.get("/imports", headers=KEN).text


def test_lab_is_decided_from_the_first_event_by_kind_or_scope(tmp_path, monkeypatch):
    ui, _ = app_with(monkeypatch, tmp_path)
    ev = lambda kind, **scope: {"payload": {"kind": kind, "scope": scope}}      # noqa: E731
    assert not ui.is_lab(ev("scan", estate="colocated"))
    assert not ui.is_lab(ev("import", estate="colocated"))
    assert not ui.is_lab(ev("scan-code", estate="external"))           # a public repository at a pinned commit
    assert ui.is_lab(ev("import", estate="external"))
    assert ui.is_lab(ev("import", estate="colocated", copy={"of": "x"}))
    assert ui.is_lab(ev("investigate", estate="external", copy={"of": "x"}))
    assert ui.is_lab(ev("package", estate="external"))
    assert all(ui.is_lab(ev(k, estate="colocated")) for k in ui.LAB_KINDS)
    assert ui.is_lab(None) and ui.is_lab({"payload": "not an object"})  # unreadable: closed


def test_the_lab_links_are_shown_only_to_a_viewer_the_lab_answers(tmp_path, monkeypatch):
    from .test_lab_gate import _capture
    _capture(tmp_path)
    _, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient")
    assert 'href="/lab"' not in c.get("/").text and "/?estate=lab" not in c.get("/").text
    assert 'href="/lab"' in c.get("/", headers=KEN).text
    assert 'href="/lab"' not in c.get("/about").text and 'href="/lab"' in c.get("/about", headers=KEN).text


def _stage_run(slice_run):
    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    write_cboms(slice_run)
    return slice_run


def test_the_stage_document_carries_scanned_servers_and_the_engine_address_only_for_a_lab_viewer(slice_run, tmp_path, monkeypatch):
    _stage_run(slice_run)
    cfg = tmp_path / "inference.yaml"
    cfg.write_text(json.dumps({"schema": "pqch.inference/1", "profile": "t", "tiers": {
        "fast": {"base_url": "http://10.99.0.7:8014/v1", "api_key_env": "K", "model": "m", "hardware": "box", "engine": "vllm"}}}))
    host = {"name": "a-lab-server", "run": "01LABSYSTEMRUN000000000000", "addresses": ["10.9.9.9"]}
    monkeypatch.setattr("pqch.systems.hosts", lambda var: [host])
    probed = []
    import requests
    monkeypatch.setattr(requests, "get", lambda *a, **k: probed.append(a) or (_ for _ in ()).throw(OSError("down")))

    _, c = app_with(monkeypatch, slice_run.var, PQCH_TRUSTED_PROXIES="testclient", PQCH_INFERENCE_CONFIG=cfg)
    for path in ("/api/demo", "/demo?inline_data=1", "/demo?snap=1"):
        r = c.get(path)
        assert r.status_code == 200, path
        for secret in ("a-lab-server", "10.9.9.9", "01LABSYSTEMRUN", "10.99.0.7"):
            assert secret not in r.text, (path, secret)
    doc = c.get("/api/demo").json()
    assert doc["hosts"] == [] and doc["this_host"] is None and doc["cbom"]["nodes"]
    assert doc["engine"]["tiers"]["fast"] == {"model": "m", "hardware": "box", "engine": "vllm", "reasoning_model": None}
    assert probed == []                                   # and the engine was not called for this viewer
    signed = c.get("/api/demo", headers=KEN).json()
    assert signed["hosts"][0]["name"] == "a-lab-server" and signed["engine"]["tiers"]["fast"]["base_url"].startswith("http://10.99")
    assert len(probed) == 1


@pytest.mark.parametrize("env", [{}, {"PQCH_PUBLIC": "1"}])
def test_the_inlined_stage_document_cannot_close_its_script_block(slice_run, monkeypatch, env):
    _stage_run(slice_run)
    ui, c = app_with(monkeypatch, slice_run.var, **env)
    evil = "CN=</script><script>alert(1)</script><!-- &  "
    doc = {"hardware": "h", "cbom": {"nodes": [{"id": "x", "name": evil}], "links": [], "counts": {}}}
    monkeypatch.setattr(ui._demo, "payload", lambda *a, **k: dict(doc))
    monkeypatch.setattr(ui._demo, "still_block", lambda var: {"ask": None})
    for path in ("/demo?inline_data=1", "/demo?snap=1") if not env else ("/demo",):
        html = c.get(path).text
        assert "</script><script>alert(1)" not in html and "<!--" not in html.split("window.__DEMO = ", 1)[1].split("</script>", 1)[0]
        raw = html.split("window.__DEMO = ", 1)[1].split("</script>", 1)[0]
        raw = re.sub(r";( window\.__\w+ = [^;]+;)*\s*$", "", raw)
        assert json.loads(raw)["cbom"]["nodes"][0]["name"] == evil      # the browser reads back the same text


@pytest.mark.parametrize("env", [{}, {"PQCH_PUBLIC": "1"}])
def test_the_stage_is_stepped_by_the_presenter_and_reveals_nothing_on_a_timer(slice_run, monkeypatch, env):
    """The stage's beats move on the presenter's key, in the app and in the static copy alike: each beat that
    has more than one thing to show has a heading for its "step k of n", the keys say how stepping works,
    and the script has one stepper that every such beat registers with, and none of the loops that used to
    play a beat by themselves."""
    _stage_run(slice_run)
    _, c = app_with(monkeypatch, slice_run.var, **env)
    html = c.get("/demo").text
    for beat in ("why", "arch", "scan", "plan", "change"):
        section = re.search(rf'<section class="beat" data-beat="{beat}".*?</section>', html, re.S).group(0)
        assert re.search(r"<h[12][ >]", section), beat                    # where the step count is written
    keys = re.search(r'<div class="keys" id="keys" hidden>(.*?)</div>', html, re.S).group(1)
    assert "the next step, then the next beat" in keys and "back a step" in keys and "leaves the beat at once" in keys
    assert 'id="btn-next"' in html and 'id="btn-back"' in html and 'id="beatbar"' in html
    js = Path("src/pqch/ui/static/demo.js").read_text()
    for beat in ("why", "arch", "scan", "plan", "change"):
        assert f'stepper("{beat}", ' in js, beat
    assert js.count("function stepper(") == 1 and "beatStep[names[at]]" in js
    for gone in ("changeStep", "storyTimers", "walkPlan", "walkTimer", "function replay(", "run(j + 1)"):
        assert gone not in js, gone
    # what a timer may still do: the clock, a layout's drift, a typed-out line, one journey's dot, a scan
    # running now; what none may do is move the stage on: change the beat, show a step, start a journey
    waits = re.findall(r"set(?:Timeout|Interval)\([^;]{0,80}", js)
    assert len(waits) > 5 and not [w for w in waits if re.search(r"\bgo\(|\.show\(|\brun\(|stepper\(", w)]


# ───────── the journal and the preview are behind the sign-on ─────────

def test_the_journal_site_the_preview_and_its_question_box_answer_only_a_signed_on_viewer(tmp_path, monkeypatch):
    site, prev = tmp_path / "site", tmp_path / "preview"
    for d in (site / "lessons" / "23-lab-only", site / "search", prev):
        d.mkdir(parents=True)
    (site / "lessons" / "23-lab-only" / "index.html").write_text("<p>the mirror port is on switch 10.20.33.2</p>")
    (site / "search" / "search_index.json").write_text('{"docs": []}')
    (prev / "index.html").write_text("<p>preview</p>")
    paths = ["/site/lessons/23-lab-only/", "/site/search/search_index.json", "/preview/", "/notes/ask"]

    _, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="10.20.33.3", PQCH_SITE_DIR=site, PQCH_PREVIEW_DIR=prev)
    for p in paths:
        assert c.get(p).status_code == 404 and c.get(p, headers=KEN).status_code == 404, p
        assert "10.20.33.2" not in c.get(p, headers=KEN).text
    _, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient", PQCH_SITE_DIR=site, PQCH_PREVIEW_DIR=prev)
    for p in paths:
        assert c.get(p).status_code == 404, p
        assert c.get(p, headers=KEN).status_code == 200, p
    # The kit: one box, the operator at its loopback, no header at all.
    _, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient", PQCH_OPERATOR="the operator",
                    PQCH_ALLOWED_HOSTS="testserver", PQCH_SITE_DIR=site, PQCH_PREVIEW_DIR=prev)
    assert c.get(paths[0]).status_code == 200
    # No front door configured at all: nobody is signed on, so nobody is shown the journal.
    _, c = app_with(monkeypatch, tmp_path, PQCH_SITE_DIR=site, PQCH_PREVIEW_DIR=prev)
    assert c.get(paths[0], headers=KEN).status_code == 404
    _, c = app_with(monkeypatch, tmp_path, PQCH_PUBLIC="1", PQCH_TRUSTED_PROXIES="testclient", PQCH_SITE_DIR=site)
    assert c.get(paths[0], headers=KEN).status_code == 404 and c.get("/notes/ask", headers=KEN).status_code == 404


# ───────── host names, origin, and identity in its two modes ─────────

def test_a_request_under_another_host_name_is_refused_on_every_route(tmp_path, monkeypatch):
    # Console mode with no list given: the loopback names, and nothing else. A rebound name is same-origin
    # to the browser (Origin equals Host), which is exactly why Host is checked against a list.
    ui, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient", PQCH_OPERATOR="the operator")
    assert ui.ALLOWED_HOSTS == {"127.0.0.1", "localhost", "::1"}
    rebound = {"host": "rebound.attacker.example:8080", "origin": "http://rebound.attacker.example:8080"}
    assert c.get("/agency", headers=rebound).status_code == 400
    assert c.post("/changes/propose", headers=rebound, follow_redirects=False).status_code == 400
    assert c.post("/changes/ABC/DEF/approve", headers=rebound, follow_redirects=False).status_code == 400
    for host in ("127.0.0.1:8080", "localhost:8080", "localhost", "[::1]:8080"):
        assert c.get("/agency", headers={"host": host}).status_code == 200, host
    assert c.get("/healthz", headers={"host": "evil.example"}).status_code == 400            # nothing is exempt
    # A deployment's own list: the door's name.
    ui, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient", PQCH_ALLOWED_HOSTS="pqc.lab.example, testserver")
    assert c.get("/agency", headers={"host": "pqc.lab.example"}).status_code == 200
    assert c.get("/agency", headers={"host": "10.20.33.106:8080"}).status_code == 400
    # With no list and no console mode nothing is refused by name (the door's cookie is bound to its name).
    ui, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient")
    assert ui.ALLOWED_HOSTS == set() and c.get("/agency", headers={"host": "anything.example"}).status_code == 200


def test_a_post_the_browser_calls_cross_site_is_refused(tmp_path, monkeypatch):
    _, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient", PQCH_ALLOWED_HOSTS="testserver")
    assert c.post("/scan", headers={**KEN, "sec-fetch-site": "cross-site"}, follow_redirects=False).status_code == 403
    assert c.post("/scan", headers={**KEN, "sec-fetch-site": "same-site"}, follow_redirects=False).status_code == 403
    assert c.post("/scan", headers={**KEN, "origin": "http://evil.example"}, follow_redirects=False).status_code == 403


def test_in_console_mode_the_operator_is_the_setting_and_no_header_is_read(tmp_path, monkeypatch):
    ui, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient", PQCH_OPERATOR="the operator",
                     PQCH_ALLOWED_HOSTS="testserver", PQCH_APPROVER_GROUP="approvers")
    seen = {}

    @ui.app.get("/_who")
    def _who(request: ui.Request):
        seen.update(who=ui.identity(request), groups=ui.groups_of(request))
        return {}
    c.get("/_who", headers={"X-Forwarded-User": "alice", "X-Forwarded-Groups": "approvers"})
    assert seen == {"who": "the operator", "groups": []}
    assert "Approve as alice" not in c.get("/resolve", headers={"X-Forwarded-User": "alice"}).text
    # Front-door mode: the header is the identity, and only from the door.
    ui, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient")

    @ui.app.get("/_who")
    def _who2(request: ui.Request):
        seen.update(who=ui.identity(request), groups=ui.groups_of(request))
        return {}
    c.get("/_who", headers={"X-Forwarded-User": "alice", "X-Forwarded-Groups": "approvers; staff"})
    assert seen == {"who": "alice", "groups": ["approvers", "staff"]}


# ───────── approvals (ADR-0008) ─────────

@pytest.fixture
def proposed(tmp_path):
    from pqch.migrator import propose

    from .test_apply import POLICY, ScopeClient
    from .test_checkpoints import PySigner

    var = tmp_path / "var"
    (var / "runs").mkdir(parents=True)
    agency = tmp_path / "agency"
    (agency / "generated" / "portal").mkdir(parents=True)
    (agency / "generated" / "portal" / "tls.conf").write_text("ssl_ecdh_curve X25519:prime256v1;\n")
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    signer = PySigner(tmp_path / "s", var / "runs")
    signer.ensure_key()
    run, props = propose(var, ScopeClient(SCOPE), pol, agency, by="ken", authenticated_by="test")
    return var, run, props[0]["payload"]["change_id"], signer


def _approvals(run):
    return [e for e in run.ledger.events() if e["type"].startswith("approval.")]


def _settle(ui):
    for _ in range(200):
        if not ui.change_state.snapshot()["running"]:
            return ui.change_state.snapshot()
        time.sleep(0.02)
    raise AssertionError("the change thread did not finish")


def test_under_separation_a_self_approval_is_refused_at_the_page_and_never_recorded(proposed, monkeypatch):
    var, run, cid, signer = proposed
    ui, c = app_with(monkeypatch, var, PQCH_TRUSTED_PROXIES="testclient", PQCH_SEPARATION_OF_DUTIES="1",
                     PQCH_APPROVER_GROUP="approvers")
    monkeypatch.setattr("pqch.pipeline.signer_from_env", lambda: signer)
    ken = {**KEN, "X-Forwarded-Groups": "approvers"}
    page = c.get("/resolve", headers=ken).text
    assert "Approve as ken" not in page and "ken asked for this change" in page
    r = c.post(f"/changes/{run.id}/{cid}/approve", headers=ken, follow_redirects=False)
    assert r.status_code == 403 and "another person approves" in r.json()["detail"]
    assert _approvals(run) == []
    # Someone not in the group: refused, nothing recorded.
    r = c.post(f"/changes/{run.id}/{cid}/approve", headers={"X-Forwarded-User": "bob", "X-Forwarded-Groups": "staff"}, follow_redirects=False)
    assert r.status_code == 403 and _approvals(run) == []
    # Another person, in the group: recorded once, with the role and the groups it rested on; not applied here.
    ada = {"X-Forwarded-User": "ada", "X-Forwarded-Groups": "approvers,staff"}
    assert "Approve as ada" in c.get("/resolve", headers=ada).text
    assert c.post(f"/changes/{run.id}/{cid}/approve", headers=ada, follow_redirects=False).status_code == 303
    assert _settle(ui)["error"] is None
    (a,) = _approvals(run)
    assert a["payload"]["by"] == "ada" and a["payload"]["role"] == "approver" and a["payload"]["groups"] == ["approvers", "staff"]
    # One decision a change: a second approval is refused, so the first on the ledger is the only one.
    eve = {"X-Forwarded-User": "eve", "X-Forwarded-Groups": "approvers"}
    assert c.post(f"/changes/{run.id}/{cid}/approve", headers=eve, follow_redirects=False).status_code == 409
    assert len(_approvals(run)) == 1


def test_with_separation_on_and_no_approver_group_nobody_is_stamped_approver(proposed, monkeypatch):
    var, run, cid, signer = proposed
    _, c = app_with(monkeypatch, var, PQCH_TRUSTED_PROXIES="testclient", PQCH_SEPARATION_OF_DUTIES="1")
    monkeypatch.setattr("pqch.pipeline.signer_from_env", lambda: signer)
    ada = {"X-Forwarded-User": "ada", "X-Forwarded-Groups": "approvers"}
    r = c.post(f"/changes/{run.id}/{cid}/approve", headers=ada, follow_redirects=False)
    assert r.status_code == 403 and "PQCH_APPROVER_GROUP" in r.json()["detail"]
    assert _approvals(run) == []
    page = c.get("/resolve", headers=ada).text
    assert "Approve as ada" not in page and "names no approver group" in page


def test_without_a_group_or_separation_an_approval_carries_no_role(proposed, monkeypatch):
    var, run, cid, signer = proposed
    ui, c = app_with(monkeypatch, var, PQCH_TRUSTED_PROXIES="testclient")
    monkeypatch.setattr("pqch.pipeline.signer_from_env", lambda: signer)
    applied = []
    monkeypatch.setattr("pqch.migrator.execute", lambda *a, **k: applied.append(a))
    assert c.post(f"/changes/{run.id}/{cid}/approve", headers=KEN, follow_redirects=False).status_code == 303
    assert _settle(ui)["error"] is None
    (a,) = _approvals(run)
    assert "role" not in a["payload"] and "groups" not in a["payload"] and len(applied) == 1   # the single owner's loop, as before
    assert c.post(f"/changes/{run.id}/NOSUCHCHANGE/approve", headers=KEN, follow_redirects=False).status_code == 404


def test_a_reset_needs_the_approver_where_the_deployment_names_one(tmp_path, monkeypatch):
    ui, c = app_with(monkeypatch, tmp_path, PQCH_TRUSTED_PROXIES="testclient", PQCH_APPROVER_GROUP="approvers")
    started = []
    monkeypatch.setattr(ui, "_start_change", lambda fn: started.append(fn))
    assert c.post("/estate/reset", headers={**KEN, "X-Forwarded-Groups": "staff"}, follow_redirects=False).status_code == 403
    assert started == []
    assert c.post("/estate/reset", headers={**KEN, "X-Forwarded-Groups": "approvers"}, follow_redirects=False).status_code == 303
    assert len(started) == 1


# ───────── nothing from a ledger that does not verify; the CBOM from the ledger, not the file ─────────

def _tamper(run):
    """One event's payload altered in place, its recorded hash left as it was."""
    lines = run.ledger.path.read_text().splitlines()
    k = min(5, len(lines) - 1)
    e = json.loads(lines[k])
    e["payload"]["altered"] = True
    lines[k] = json.dumps(e)
    run.ledger.path.write_text("\n".join(lines) + "\n")


def test_the_stage_and_the_projection_download_draw_nothing_from_a_ledger_that_does_not_verify(slice_run, monkeypatch):
    _stage_run(slice_run)
    _, c = app_with(monkeypatch, slice_run.var)
    ok = c.get("/api/demo").json()
    assert ok["cbom"]["counts"]["components"] > 0 and "error" not in ok
    # No signer is reachable here: the record says it was checked against nothing outside the run directory.
    assert ok["record"]["verify"]["anchored"] is False and "no outside record" in ok["record"]["verify"]["source"]
    assert c.get(f"/runs/{slice_run.id}/projection/agency-inventory.csv").status_code == 200
    _tamper(slice_run)
    doc = c.get("/api/demo").json()
    assert "does not verify" in doc["error"] and doc["record"]["verify"]["ok"] is False
    assert not ({"cbom", "estate", "score", "plan", "policy"} & set(doc))
    assert c.get(f"/runs/{slice_run.id}/projection/agency-inventory.csv").status_code == 409
    assert c.get("/api/demo/entry", params={"ref": "x"}).status_code == 404
    assert c.get("/demo?inline_data=1").status_code == 200


def test_a_change_run_that_does_not_verify_contributes_no_steps(proposed, monkeypatch):
    var, run, _cid, _signer = proposed
    from pqch.ui import demo
    doc = demo.payload(var, [], snapshots_dir=Path("policy/snapshots"), hardware="h", inference_config=None, this_host=None)
    assert doc["change"]["changes"] and "error" not in doc["change"]
    _tamper(run)
    doc = demo.payload(var, [], snapshots_dir=Path("policy/snapshots"), hardware="h", inference_config=None, this_host=None)
    assert doc["change"]["changes"] == [] and "Nothing is drawn" in doc["change"]["error"]


def test_the_entry_panel_and_the_house_read_the_ledger_not_the_stored_cbom_file(slice_run, monkeypatch):
    _stage_run(slice_run)
    ui, c = app_with(monkeypatch, slice_run.var)
    ref = c.get("/api/demo").json()["cbom"]["nodes"][0]["id"]
    stale = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"bom-ref": "edited-by-hand", "name": "x"}], "dependencies": []}
    (slice_run.dir / "workbench.cdx.json").write_text(json.dumps(stale))
    r = c.get("/api/demo/entry", params={"ref": ref})
    assert r.status_code == 200 and r.json()["bom"]["components"] > 1
    assert c.get("/api/demo/entry", params={"ref": "edited-by-hand"}).status_code == 404
    from pqch.ui import demo
    assert "edited-by-hand" not in demo.static_block(slice_run.var, slice_run)["entries"]
    # The house (the lab's merged CBOM) is built from the scan's projection too.
    seen = {}
    monkeypatch.setattr("pqch.cbom.house.build", lambda cap, bom: seen.update(bom=bom) or None)
    ui._house_cached(None, slice_run)
    assert seen["bom"] and all(comp["bom-ref"] != "edited-by-hand" for comp in seen["bom"]["components"])


def test_a_run_with_an_empty_ledger_is_a_404_not_a_500(slice_run, monkeypatch):
    _stage_run(slice_run)
    empty = slice_run.var / "runs" / "01EMPTYLEDGER0000000000000"
    empty.mkdir()
    (empty / "ledger.jsonl").write_text("")
    _, c = app_with(monkeypatch, slice_run.var, PQCH_TRUSTED_PROXIES="testclient")
    assert c.get("/cbom?run=01EMPTYLEDGER0000000000000").status_code == 404           # unreadable: closed to anyone else
    assert c.get("/cbom?run=01EMPTYLEDGER0000000000000", headers=KEN).status_code in (200, 404)   # no CBOM to show; not a 500
    assert c.get("/walkthrough?run=01EMPTYLEDGER0000000000000", headers=KEN).status_code == 200   # shows the latest scan instead


# ───────── routes that hold a worker or call a model ─────────

def test_routes_that_wait_or_call_a_model_need_the_sign_on_where_there_is_a_front_door(slice_run, monkeypatch):
    _stage_run(slice_run)
    ui, c = app_with(monkeypatch, slice_run.var, PQCH_TRUSTED_PROXIES="testclient")
    called = []
    monkeypatch.setattr(ui._demo, "narrate", lambda kind, row: called.append((kind, row)) or {"text": "x"})
    assert c.get("/api/demo/slow?s=0").status_code == 403 and c.get("/api/demo/slow?s=0", headers=KEN).status_code == 200
    assert c.post("/api/demo/narrate", json={"row": {}}).status_code == 403 and called == []
    assert c.post("/api/demo/narrate", json={"row": {"service": "api"}}, headers=KEN).json() == {"text": "x"}
    assert c.post("/api/demo/narrate", json=["not", "an", "object"], headers=KEN).status_code == 422   # not a 500
    assert c.post("/api/demo/narrate", json={"row": "nope"}, headers=KEN).status_code == 200 and called[-1] == ("plan", {})
    assert c.get("/ask", params={"q": "anything"}).status_code == 403
    assert c.get("/ask").status_code == 200                                # the page itself calls nothing
    import inspect
    assert inspect.iscoroutinefunction(ui.demo_slow) and not inspect.iscoroutinefunction(ui.demo_narrate)
    _, c = app_with(monkeypatch, slice_run.var, PQCH_PUBLIC="1")
    assert c.get("/api/demo/slow?s=0").status_code == 404


def test_the_page_never_shows_an_exceptions_own_text_for_a_failed_question(slice_run, tmp_path, monkeypatch):
    _stage_run(slice_run)
    cfg = tmp_path / "inference.yaml"
    tier = {"base_url": "http://10.99.0.7:8014/v1", "api_key_env": "K", "model": "m", "hardware": "box", "engine": "vllm"}
    cfg.write_text(json.dumps({"schema": "pqch.inference/1", "profile": "t", "tiers": {"fast": tier, "embed": tier},
                               "roles": {"ask-cbom": {"tier": "fast"}}}))
    _, c = app_with(monkeypatch, slice_run.var, PQCH_INFERENCE_CONFIG=cfg)

    def boom(*a, **k):
        raise RuntimeError("503 from http://10.99.0.7:8014/v1/embeddings")
    monkeypatch.setattr("pqch.ask.Index", boom)
    html = c.get("/ask", params={"q": "anything"}).text
    assert "Not answered." in html and "RuntimeError" in html and "10.99.0.7" not in html
