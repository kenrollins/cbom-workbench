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


def test_a_run_records_the_hosts_time_source_when_it_starts(tmp_path):
    from pqch import clock, scope as scope_mod
    from pqch.run import Run

    ts = clock.time_source()
    assert ts["source"] in ("adjtimex", "unavailable") and ts["synchronized"] in (True, False, None)
    scope = {"schema": "pqch.scope/1", "id": "01M40W6W873YWJMWPKGMK3YBMN", "estate": "external", "owned": False,
             "authorized_by": "owner", "endpoints": [{"host": "10.0.0.5", "port": 443, "transport": "tcp", "protocol": "tls"}],
             "images": [], "sources": [], "reach": {"kind": "local"}}
    run = Run.start(tmp_path / "var", scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="tls-targeted", kind="scan-external")
    started = next(iter(run.ledger.events()))["payload"]
    assert started["clock"]["source"] == ts["source"] and "synchronized" in started["clock"]


def test_the_access_log_is_one_json_line_per_request_with_who_and_whether_it_was_a_download(tmp_path, monkeypatch):
    import importlib
    import json
    import warnings

    log = tmp_path / "access.jsonl"
    monkeypatch.setenv("PQCH_VAR", str(tmp_path / "var"))
    monkeypatch.setenv("PQCH_TRUSTED_PROXIES", "testclient")
    monkeypatch.setenv("PQCH_ACCESS_LOG", str(log))
    monkeypatch.setenv("PQCH_MARKING", "CUI")
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    monkeypatch.delenv("PQCH_PUBLIC", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app, headers={"X-Forwarded-User": "ken"}, raise_server_exceptions=False)
        c.get("/about")
        c.get("/estate/cbom.json")
        TestClient(ui.app, raise_server_exceptions=False).get("/about")
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r["path"] for r in rows] == ["/about", "/estate/cbom.json", "/about"]
    assert all(r["schema"] == "pqch.access/1" and r["method"] == "GET" and r["marking"] == "CUI" and r["ms"] >= 0 for r in rows)
    assert (rows[0]["who"], rows[0]["download"], rows[0]["status"]) == ("ken", False, 200)
    assert rows[1]["download"] is True and rows[2]["who"] is None
    monkeypatch.delenv("PQCH_ACCESS_LOG")
    monkeypatch.delenv("PQCH_MARKING")
    importlib.reload(ui)


def test_a_plan_row_is_narrated_from_facts_whose_labels_say_what_they_are():
    from pqch.ui import demo

    done = demo.narration_facts({"rank": 3, "service": "pq-gateway", "mission": "inter-agency data exchange", "why": "high-impact",
                                 "secret_until": 2051, "kex": "pq", "blocked": "nothing", "title": None})
    assert done["key_exchange_today"] == "already post-quantum only" and done["next_step"] == "none: every migration item is already met"
    assert done["waits_on_its_supplier_for"] == "nothing" and done["its_data_must_stay_secret_until_year"] == 2051
    assert done["ranked_by_the_memo_for"] == "a high-impact system"
    row = demo.narration_facts({"rank": 8, "service": "bastion", "mission": "administrative access", "why": "", "secret_until": 2027,
                                "kex": "mixed", "blocked": "signature", "title": "Require the hybrid group on bastion"})
    assert row["waits_on_its_supplier_for"] == "signature" and row["next_step"] == "Require the hybrid group on bastion"
    assert row["ranked_by_the_memo_for"].startswith("nothing") and "classical still accepted" in row["key_exchange_today"]
    assert not {"blocked", "secret_until", "kex", "title", "why"} & set(row)      # the short keys never reach the model
