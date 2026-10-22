"""The change section: diff, approval with who and how, verdicts, both intervals; approving needs sign-on."""

import importlib
import warnings

from pqch.migrator import approve, propose

from .test_apply import POLICY, ScopeClient
from .conftest import SCOPE
from .test_checkpoints import PySigner


def test_change_section_and_approval_gate(tmp_path, monkeypatch):
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
    cid = props[0]["payload"]["change_id"]
    monkeypatch.setenv("PQCH_VAR", str(var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    ken = {"X-Forwarded-User": "ken"}

    def client(trusted):
        monkeypatch.setenv("PQCH_TRUSTED_PROXIES", trusted)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from fastapi.testclient import TestClient

            import pqch.ui.app as ui
            importlib.reload(ui)
            return TestClient(ui.app)

    # A peer that is not the front door: its sign-on header is a string anyone can type.
    c = client("10.20.33.3")
    html = c.get("/resolve", headers=ken).text
    assert "+ssl_ecdh_curve X25519MLKEM768;" in html and "Waiting for approval" in html
    assert "Approve as" not in html
    assert c.post(f"/changes/{run.id}/{cid}/approve", headers=ken, follow_redirects=False).status_code == 403
    assert c.post("/changes/propose", headers=ken, follow_redirects=False).status_code == 403
    assert not any(e["type"].startswith("approval") for e in run.ledger.events())

    # The front door itself (the test client's peer address is "testclient").
    c = client("testclient")
    assert "Approve as" not in c.get("/resolve").text                      # no header, no identity
    assert "Approve as ken" in c.get("/resolve", headers=ken).text
    r = c.post(f"/changes/{run.id}/{cid}/approve", headers={**ken, "Origin": "https://evil.example"},
               follow_redirects=False)
    assert r.status_code == 403                                      # a form posted from another site

    approve(run, cid, by="ken", authenticated_by="lab front door", signer=signer)
    verdict = {"change_id": cid, "status": "enforced", "meets_intent": True, "durable": "untested",
               "hardware": "test", "probes": [], "binding": {"address": "172.16.106.10:443"},
               "after_event": props[0]["id"], "reasons": []}
    run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"}, verdict)
    html = c.get("/resolve").text
    assert "approval.granted by <strong>ken</strong>" in html
    assert "has no time-to-change" in html and "Policy change to last verdict" not in html   # not yet repeated
    run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"}, {**verdict, "durable": True})
    html = c.get("/resolve").text
    # A verdict that names no runner job cannot be checked against the runner's record, so the
    # page gives the elapsed time and does not call it a time-to-change (M0B review F-55).
    assert "Policy change to last verdict" not in html and "Not checked against the runner" in html
    assert "on test" in html and "run open" in html
