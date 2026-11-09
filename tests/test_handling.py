"""FR-08 and FR-13 as settings: the marking on pages, documents and the register; retention on the
record; the rules of engagement required by the runner."""

import importlib
import json
import warnings
from datetime import UTC, datetime, timedelta

from pqch import retention
from pqch import scope as scope_mod
from pqch.pipeline import write_cboms


def test_the_marking_is_on_every_page_document_and_register_row(slice_run, monkeypatch):
    from pqch import planning
    from .test_register import assessed

    monkeypatch.setenv("PQCH_MARKING", "CUI")
    assessed(slice_run)
    write_cboms(slice_run)
    bom = json.loads((slice_run.dir / "workbench.cdx.json").read_text())
    assert {"name": "pqch:marking", "value": "CUI"} in bom["metadata"]["properties"]
    reg = planning.register(planning.build(slice_run.var, slice_run), list(slice_run.ledger.events()))
    assert reg["marking"] == "CUI" and reg["columns"][-1] == "marking" and all(r[-1] == "CUI" for r in reg["rows"])
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
        for path in ("/", "/cbom", "/plan", "/about"):
            html = c.get(path).text
            assert '<div class="marking" role="note" aria-label="marking">CUI</div>' in html, path
    monkeypatch.delenv("PQCH_MARKING")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        importlib.reload(ui)
        assert 'class="marking"' not in TestClient(ui.app).get("/about").text


def test_retention_destroys_old_artefacts_on_the_record_and_keeps_the_ledger(slice_run):
    from .test_register import assessed

    assessed(slice_run)
    var = slice_run.var
    before = sorted(p.name for p in slice_run.dir.iterdir())
    assert "workbench.cdx.json" in before and (var / "raw" / "job0.json").exists()
    # Not old enough: nothing happens, and a dry run says so.
    assert retention.apply(var, days=30, by="ken", basis="test") == {"dry_run": False, "runs": [], "destroyed": 0}
    future = datetime.now(UTC) + timedelta(days=400)
    dry = retention.apply(var, days=365, by="ken", basis="test", dry_run=True, now=future)
    assert dry["dry_run"] and dry["runs"][0]["run"] == slice_run.id and (var / "raw" / "job0.json").exists()
    done = retention.apply(var, days=365, by="ken", basis="the deployment keeps a year", now=future)
    assert done["destroyed"] > 0 and not (var / "raw" / "job0.json").exists()
    assert sorted(p.name for p in slice_run.dir.iterdir()) == ["ledger.jsonl"]
    from pqch.run import Run

    rrun = Run(var, done["run"])
    evs = list(rrun.ledger.events())
    assert evs[0]["payload"]["kind"] == "retention"
    d = next(e for e in evs if e["type"] == "artefact.destroyed")
    assert d["actor"] == {"kind": "human", "id": "ken"} and d["payload"]["run"] == slice_run.id and d["payload"]["kept"] == ["ledger.jsonl"]
    assert "var/raw/job0.json" in d["payload"]["destroyed"] and d["payload"]["basis"] == "the deployment keeps a year"
    # The retention run itself is never a candidate; the scan's ledger still verifies.
    from pqch.ledger import verify

    assert verify(list(slice_run.ledger.events())).ok
    assert retention.candidates(var, days=0, now=future + timedelta(days=1)) == []


def test_the_rules_of_engagement_are_required_only_by_setting():
    auth = {"system_id": "S-1", "person": "owner", "role": "system owner", "valid_from": "2026-01-01", "valid_until": "2027-01-01"}
    scope = {"authorization": auth}
    now = datetime(2026, 6, 1, tzinfo=UTC)
    assert scope_mod.authorization_refusal(scope, now=now) is None
    why = scope_mod.authorization_refusal(scope, now=now, require_roe=True)
    assert why and "rules-of-engagement" in why
    scope["authorization"]["rules_of_engagement_sha256"] = "a" * 64
    assert scope_mod.authorization_refusal(scope, now=now, require_roe=True) is None


def test_the_page_refuses_an_approver_outside_the_group_and_records_the_groups(monkeypatch):
    monkeypatch.setenv("PQCH_TRUSTED_PROXIES", "testclient")
    monkeypatch.setenv("PQCH_APPROVER_GROUP", "pqc-approvers")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        from starlette.requests import Request

        def req(headers):
            scope = {"type": "http", "method": "POST", "path": "/x", "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()],
                     "client": ("testclient", 1), "scheme": "http", "server": ("testserver", 80), "query_string": b""}
            return Request(scope)
        assert ui.groups_of(req({"X-Forwarded-Groups": "staff, pqc-approvers"})) == ["pqc-approvers", "staff"]
        import pytest
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as e:
            ui._approver(req({"X-Forwarded-User": "bob", "X-Forwarded-Groups": "staff", "Origin": "http://testserver", "Host": "testserver"}))
        assert e.value.status_code == 403 and "pqc-approvers" in e.value.detail
        who, groups = ui._approver(req({"X-Forwarded-User": "alice", "X-Forwarded-Groups": "pqc-approvers", "Origin": "http://testserver", "Host": "testserver"}))
        assert who == "alice" and groups == ["pqc-approvers"]
        assert TestClient(ui.app).get("/about").status_code == 200
