"""The lab's pages answer only to a signed-on viewer through the front door, and the portal's
VLAN-level summary names no address."""

import importlib
import json
import re
import warnings

from pqch.scout import capture
from pqch.ui import lab_summary

from .test_capture import SCOPE, make_logs

ADDRESS = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|[a-z0-9-]+\.(com|net|org|test|dev|arpa|gov)\b", re.I)


def _capture(tmp_path):
    cap = tmp_path / "capture"
    cap.mkdir()
    make_logs(cap)
    run, _ = capture.ingest(tmp_path, SCOPE, cap, hardware="test")
    return run


def _client(monkeypatch, var, *, trusted="", readers=""):
    monkeypatch.setenv("PQCH_VAR", str(var))
    monkeypatch.setenv("PQCH_TRUSTED_PROXIES", trusted)
    monkeypatch.setenv("PQCH_ESTATE_READERS", readers)
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    monkeypatch.delenv("PQCH_PUBLIC", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        return TestClient(ui.app)


def test_lab_pages_need_the_front_door_and_a_sign_on(tmp_path, monkeypatch):
    run = _capture(tmp_path)
    ken = {"X-Forwarded-User": "ken"}
    lab = ["/lab", "/lab/house.cdx.json", "/lab/estate.json", "/?estate=lab", "/plan?estate=lab",
           f"/cbom?run={run.id}", f"/runs/{run.id}/ledger.jsonl",
           # every page that takes a run id refuses a lab run by id, and does not say it exists
           f"/walkthrough?run={run.id}", f"/walkthrough?change={run.id}", f"/packages?run={run.id}", f"/resolve?change={run.id}"]

    # A peer that is not the front door: 404 with or without the header, the lab unacknowledged.
    c = _client(monkeypatch, tmp_path, trusted="10.20.33.3")
    for path in lab:
        assert c.get(path).status_code == 404, path
        assert c.get(path, headers=ken).status_code == 404, path
    assert c.get("/agency").status_code == 200                       # the mini-agency is untouched

    # The front door (the test client's peer is "testclient"): the header decides.
    c = _client(monkeypatch, tmp_path, trusted="testclient")
    for path in lab:
        assert c.get(path).status_code == 404, path
    for path in lab:
        assert c.get(path, headers=ken).status_code == 200, path
    # A run directory whose ledger cannot be read is treated as the lab's: it fails closed to anyone else.
    (tmp_path / "runs" / "01BROKENLEDGER00000000000X").mkdir(parents=True)
    (tmp_path / "runs" / "01BROKENLEDGER00000000000X" / "ledger.jsonl").write_text("not json\n")
    c = _client(monkeypatch, tmp_path, trusted="10.20.33.3")
    assert c.get("/runs/01BROKENLEDGER00000000000X/ledger.jsonl", headers=ken).status_code == 404
    assert c.get("/walkthrough?run=01BROKENLEDGER00000000000X").status_code == 404


def test_a_scan_starts_only_from_the_page_by_a_signed_on_viewer(tmp_path, monkeypatch):
    # Where a front door is configured, a request without its sign-on cannot start a scan, and a form
    # posted from another site cannot either; the public snapshot has no scan at all.
    c = _client(monkeypatch, tmp_path, trusted="testclient")
    assert c.post("/scan", follow_redirects=False).status_code == 403
    assert c.post("/scan", headers={"X-Forwarded-User": "ken", "origin": "https://elsewhere.example", "host": "demo.test"},
                  follow_redirects=False).status_code == 403
    monkeypatch.setenv("PQCH_PUBLIC", "1")
    import importlib
    import warnings

    import pqch.ui.app as ui
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        importlib.reload(ui)
        from fastapi.testclient import TestClient
        assert TestClient(ui.app).post("/scan", follow_redirects=False).status_code == 404


def test_estate_summary_is_for_the_portal_and_names_no_address(tmp_path, monkeypatch):
    run = _capture(tmp_path)
    # The portal's address may read the summary and nothing else of the lab.
    c = _client(monkeypatch, tmp_path, trusted="10.20.33.3", readers="testclient")
    assert c.get("/lab").status_code == 404
    r = c.get("/lab/estate.json")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] and body["run_id"] == run.id
    assert body["handshakes"] == 3 and body["clients_inside"] == 2 and body["outside_names"] == 1
    assert body["listeners_inside"] == {"tls": 2, "ssh": 1, "pq": 1, "mixed": 0, "classical": 1}
    assert body["inside"]["negotiated_pct"] == 50.0 and body["outside"]["negotiated_pct"] == 0.0
    assert [v["vlan"] for v in body["vlans"]] == [10, 28]
    assert not ADDRESS.search(json.dumps(body)), ADDRESS.search(json.dumps(body)).group(0)

    # VLAN names come from the deployment's file; unnamed ones keep their number.
    names = tmp_path / "vlans.json"
    names.write_text(json.dumps({"10": "Core"}))
    s = lab_summary.build(tmp_path, run, None, names=lab_summary.vlan_names(str(names)))
    assert [v["name"] for v in s["vlans"]] == ["Core", "VLAN 28"]
    assert s["vlans"][0]["note"] == "one listener refuses hybrid though 100% of its clients offer it"
    assert s["history"] and s["history"][-1]["closed_at"] == s["closed_at"]
    assert s["certificates"] == {"count": 0, "soonest_expiry": None, "soonest_days": None} and s["scan"] is None
