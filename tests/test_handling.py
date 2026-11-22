"""FR-08 and FR-13 as settings: the marking on pages, documents and the register; retention on the
record; the rules of engagement required by the runner."""

import importlib
import json
import warnings
from datetime import UTC, datetime, timedelta

import pytest

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
    assert retention.apply(var, days=30, by="ken", basis="test") == {"dry_run": False, "runs": [], "destroyed": 0, "skipped": []}
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
    assert d["actor"] == {"kind": "human", "id": "ken"} and d["payload"]["run"] == slice_run.id
    assert d["payload"]["kept"] == ["ledger.jsonl", "ledger.pub"]
    assert "var/raw/job0.json" in d["payload"]["destroyed"] and d["payload"]["basis"] == "the deployment keeps a year"
    # The intent went on the record before anything was deleted, and the result answers it.
    intent = evs[evs.index(d) - 1]
    assert intent["type"] == "destruction.intended" and d["inputs"] == [intent["id"]] and d["payload"]["intent"] == intent["id"]
    assert set(d["payload"]["destroyed"]) == set(intent["payload"]["paths"])
    assert evs[-1]["type"] == "run.closed" and verify_chain(evs)
    # The retention run itself is never a candidate; the scan's ledger still verifies.
    from pqch.ledger import verify

    assert verify(list(slice_run.ledger.events())).ok
    assert retention.candidates(var, days=0, now=future + timedelta(days=1)) == []


def verify_chain(events) -> bool:
    from pqch.ledger import verify

    return verify(events).ok


def _run_citing(var, refs, *, ts=None, kind="scan"):
    """A small run whose one event after the start cites raw files by ref."""
    from pqch.common import hash_object, ulid
    from pqch.run import Run

    scope = {"schema": "pqch.scope/1", "id": ulid(), "estate": "colocated", "owned": True, "authorized_by": None,
             "endpoints": [], "images": [], "sources": [], "reach": {"kind": "local"}}
    run = Run(var, ulid())
    run.ledger.append("run.started", {"kind": "runner", "id": "t"},
                      {"run": run.id, "scope": scope, "scope_hash": hash_object(scope), "profile": "t", "schemas": [],
                       "kind": kind}, ts=ts)
    run.ledger.append("key.committed", {"kind": "human", "id": "t"}, {"n": 1},
                      evidence=[{"ref": r, "sha256": "1" * 64} for r in refs])
    return run


OLD = "2026-01-05T00:00:00.000Z"


def test_retention_keeps_raw_output_a_younger_run_still_cites(tmp_path):
    var = tmp_path
    (var / "raw").mkdir()
    for n in ("shared.txt", "own.txt", "attested.txt"):
        (var / "raw" / n).write_text(n)
    old = _run_citing(var, ["var/raw/shared.txt", "var/raw/own.txt", "var/raw/attested.txt"], ts=OLD)
    # The younger run names the same file by another spelling: paths are compared, not strings.
    _run_citing(var, ["var/raw/./shared.txt"])
    _run_citing(var, ["var/raw/attested.txt"], ts=OLD, kind="attestation")      # a kind retention never touches
    done = retention.apply(var, days=30, by="ken", basis="test")
    assert (var / "raw" / "shared.txt").exists() and (var / "raw" / "attested.txt").exists()
    assert not (var / "raw" / "own.txt").exists() and done["destroyed"] == 1
    from pqch.run import Run

    d = next(e["payload"] for e in Run(var, done["run"]).ledger.events() if e["type"] == "artefact.destroyed")
    assert d["run"] == old.id and d["destroyed"] == ["var/raw/own.txt"]
    assert d["kept_cited"] == ["var/raw/attested.txt", "var/raw/shared.txt"]


def test_retention_never_follows_a_ref_out_of_var_raw(tmp_path):
    var = tmp_path
    (var / "raw").mkdir()
    (var / "raw" / "own.txt").write_text("x")
    (var / "victim").mkdir()
    (var / "victim" / "keep.txt").write_text("x")
    (tmp_path / "outside.txt").write_text("x")
    (var / "raw" / "link").symlink_to(tmp_path / "outside.txt")
    young = _run_citing(var, [])
    old = _run_citing(var, ["var/raw/own.txt", "var/raw/../victim/keep.txt", "var/raw/link",
                            f"var/raw/../runs/{young.id}/ledger.jsonl"], ts=OLD)
    assert verify_chain(list(old.ledger.events()))      # such a ledger verifies: the schema does not stop it
    done = retention.apply(var, days=30, by="ken", basis="test")
    assert young.ledger.path.exists() and (var / "victim" / "keep.txt").exists() and (tmp_path / "outside.txt").exists()
    assert not (var / "raw" / "own.txt").exists() and done["destroyed"] == 1
    assert sorted(done["runs"][0]["refused"]) == sorted(
        ["var/raw/../victim/keep.txt", "var/raw/link", f"var/raw/../runs/{young.id}/ledger.jsonl"])
    from pqch.run import Run

    d = next(e["payload"] for e in Run(var, done["run"]).ledger.events() if e["type"] == "artefact.destroyed")
    assert d["destroyed"] == ["var/raw/own.txt"] and len(d["refused"]) == 3


def test_retention_skips_and_reports_a_run_it_cannot_trust_and_goes_on(tmp_path):
    var = tmp_path
    (var / "raw").mkdir()
    for n in ("a.txt", "b.txt", "c.txt"):
        (var / "raw" / n).write_text(n)
    good = _run_citing(var, ["var/raw/a.txt"], ts=OLD)
    broken = _run_citing(var, ["var/raw/b.txt"], ts=OLD)
    broken.ledger.path.write_text(broken.ledger.path.read_text().replace('"n":1', '"n":2'))     # an edit: the hash fails
    timeless = _run_citing(var, ["var/raw/c.txt"], ts=OLD)
    lines = timeless.ledger.path.read_text().splitlines()
    timeless.ledger.path.write_text("\n".join([lines[0].replace('"ts":', '"t_s":'), *lines[1:]]) + "\n")
    done = retention.apply(var, days=30, by="ken", basis="test")
    assert [c["run"] for c in done["runs"]] == [good.id] and not (var / "raw" / "a.txt").exists()
    assert (var / "raw" / "b.txt").exists() and (var / "raw" / "c.txt").exists()
    why = {s["run"]: s["why"] for s in done["skipped"]}
    assert "does not verify" in why[broken.id] and "no time" in why[timeless.id]


def test_a_retained_signed_ledger_still_verifies_from_the_files_left_beside_it(slice_run, tmp_path):
    from pqch.ledger.checkpoints import verify_signed

    from .test_checkpoints import PySigner

    signer = PySigner(tmp_path / "signer", slice_run.var / "runs")
    signer.ensure_key()
    slice_run.close(signer)
    (slice_run.dir / "workbench.cdx.json").write_text("{}")
    future = datetime.now(UTC) + timedelta(days=400)
    done = retention.apply(slice_run.var, days=365, by="ken", basis="test", signer=signer, now=future)
    assert done["destroyed"] > 0
    assert sorted(p.name for p in slice_run.dir.iterdir()) == ["ledger.jsonl", "ledger.pub"]
    res = verify_signed(list(slice_run.ledger.events()), (slice_run.dir / "ledger.pub").read_bytes())
    assert res.ok and res.checkpoints == 1, res.error


def test_a_retention_pass_cut_short_leaves_its_intent_and_the_next_pass_records_what_went(tmp_path, monkeypatch):
    from pqch.ledger import Ledger
    from pqch.run import Run

    var = tmp_path
    (var / "raw").mkdir()
    (var / "raw" / "a.txt").write_text("a")
    old = _run_citing(var, ["var/raw/a.txt"], ts=OLD)
    real = Ledger.append

    def failing(self, type, *a, **kw):
        if type == "artefact.destroyed":
            raise OSError("No space left on device")
        return real(self, type, *a, **kw)

    monkeypatch.setattr(Ledger, "append", failing)
    with pytest.raises(OSError):
        retention.apply(var, days=30, by="ken", basis="test")
    monkeypatch.setattr(Ledger, "append", real)
    assert not (var / "raw" / "a.txt").exists()
    first = Run.latest(var, "retention")
    evs = list(first.ledger.events())
    # The file is gone and the record says who meant to destroy it, and the run did not stay open.
    assert [e["type"] for e in evs] == ["run.started", "destruction.intended", "run.closed"]
    assert evs[1]["payload"]["paths"] == ["var/raw/a.txt"] and evs[1]["actor"]["id"] == "ken"
    owed = retention.unreconciled(var)
    assert [o["intent"] for o in owed] == [evs[1]["id"]]
    done = retention.apply(var, days=30, by="ken", basis="test")
    assert done["reconciled"] == 1 and done["runs"] == []
    d = next(e["payload"] for e in Run(var, done["run"]).ledger.events() if e["type"] == "artefact.destroyed")
    assert d["run"] == old.id and d["destroyed"] == ["var/raw/a.txt"] and d["reconciled"] and d["intent_run"] == first.id
    assert retention.unreconciled(var) == []
    assert retention.apply(var, days=30, by="ken", basis="test")["destroyed"] == 0


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
                                 "secret_until": 2051, "kex": "pq-only", "blocked": "nothing", "title": None})
    assert done["key_exchange_today"].startswith("a post-quantum hybrid group only") and done["next_step"] == "none: every migration item is already met"
    assert done["waits_on_its_supplier_for"] == "nothing" and done["its_data_must_stay_secret_until_year"] == 2051
    assert done["ranked_by_the_memo_for"] == "a high-impact system"
    row = demo.narration_facts({"rank": 8, "service": "bastion", "mission": "administrative access", "why": "", "secret_until": 2027,
                                "kex": "both", "blocked": "signature", "title": "Require the hybrid group on bastion"})
    assert row["waits_on_its_supplier_for"] == "signature" and row["next_step"] == "Require the hybrid group on bastion"
    assert row["ranked_by_the_memo_for"].startswith("nothing") and "classical still accepted" in row["key_exchange_today"]
    assert not {"blocked", "secret_until", "kex", "title", "why"} & set(row)      # the short keys never reach the model
