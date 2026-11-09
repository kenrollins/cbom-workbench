"""M10 item 6: what no tool could see is a queue on the ledger, closed by evidence a person brings;
coverage per asset class is counted from it."""

import importlib
import warnings

import pytest

from pqch import attest
from pqch.assessor import chains, gaps, load_policy, structure
from pqch.run import Run

from .test_attest import EXAMPLE, system_run


def prepared(run: Run) -> Run:
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(run)
    chains.supply(run, "agency/context.yaml", author="owner")
    from pqch.assessor import managed
    from datetime import date

    managed.assess(run, pack_path="policy/packs/m-26-15.yaml", families_path="policy/algorithm-families.yaml",
                   capabilities_path=None, cmvp_path=None, as_of=date(2026, 10, 20))
    return run


def test_the_slices_gaps_are_the_key_the_reader_could_not_open_and_nothing_invented(slice_run):
    prepared(slice_run)
    counts = gaps.record(slice_run)
    slice_run.close()
    events = list(slice_run.ledger.events())
    rec = [e for e in events if e["type"] == "gap.recorded"]
    assert counts["gaps"] == len(rec) and counts["gaps_by_kind"] == {"algorithm-unidentified": 1}
    g = rec[0]["payload"]
    assert g["asset_class"] == "entries" and g["subject"]["kind"] == "file" and "names no algorithm" in g["reason"] and g["fills"]
    assert rec[0]["actor"] == {"kind": "rule", "id": gaps.RULE} and rec[0]["inputs"]
    assert gaps.gap_id(g["kind"], g["subject"]) == g["gap"] and len(g["gap"]) == 24
    q = gaps.queue(slice_run.var, events)
    assert len(q["open"]) == 1 and q["filled"] == []
    by = {c["class"]: c for c in q["classes"]}
    assert by["listeners"] == {"class": "listeners", "reached": 4, "gaps": 0, "total": 4, "coverage": 100}
    assert by["services"]["coverage"] == 100 and by["entries"]["gaps"] == 1 and by["entries"]["coverage"] < 100
    assert "key files" in by and by["key files"]["gaps"] == 0
    # A run the rule never ran on says so, rather than zero gaps.
    assert gaps.queue(slice_run.var, [e for e in events if e["payload"].get("rule_id") != gaps.RULE and e["type"] != "gap.recorded"]) is None


def test_a_listener_nobody_scanned_and_a_service_nobody_described_are_gaps(tmp_path, slice_run):
    import json

    from .conftest import JOBS, SCOPE, make_run

    scope = json.loads(json.dumps(SCOPE))
    scope["endpoints"].append({"host": "172.16.106.99", "port": 443, "transport": "tcp", "protocol": "tls", "service": "ghost"})
    import pqch.scout.normalize  # noqa: F401
    from tests import conftest

    old = conftest.SCOPE
    conftest.SCOPE = scope
    try:
        run = make_run(tmp_path / "v", jobs=JOBS)
    finally:
        conftest.SCOPE = old
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(run)
    chains.supply(run, "agency/context.yaml", author="owner")      # the context file knows no "ghost"
    counts = gaps.record(run)
    kinds = counts["gaps_by_kind"]
    assert kinds["listener-not-scanned"] == 1 and kinds["no-owner-facts"] == 1
    q = gaps.queue(run.var, list(run.ledger.events()))
    by = {c["class"]: c for c in q["classes"]}
    assert by["listeners"] == {"class": "listeners", "reached": 4, "gaps": 1, "total": 5, "coverage": 80}
    assert by["services"]["gaps"] == 1 and by["services"]["coverage"] == 80


def test_a_servers_gaps_are_its_unreadable_paths_its_controllers_silence_and_its_suppliers(tmp_path):
    var = tmp_path / "var"
    counts = {}

    def files_then_gaps(run):
        run.ledger.append("platform.observed", {"kind": "scanner", "id": "pqch-system-files"}, {
            "system": "srv1", "source": "files", "files_read": 12, "unreadable": ["/etc/ssh/ssh_host_rsa_key (PermissionError)", "/root/x (absent)"],
            "read_as_uid": 1001})
        counts.update(gaps.record(run))

    srun = system_run(var, before_close=files_then_gaps)
    assert counts["gaps_by_kind"] == {"unreadable-path": 1, "no-supplier-statement": 1, "listener-not-scanned": 1}   # the controller's listener: no job ran
    q = gaps.queue(var, list(srun.ledger.events()))
    by = {c["class"]: c for c in q["classes"]}
    assert by["key files"]["gaps"] == 1 and by["firmware"]["coverage"] == 0
    # With the supplier's statement in, the next scan's gaps are the firmware the statement does not name.
    attest.record(var, EXAMPLE)
    counts2 = {}
    srun2 = system_run(var, name="srv1", before_close=lambda r: counts2.update(gaps.record(r)))
    assert counts2["gaps_by_kind"] == {"firmware-not-attested": 1, "listener-not-scanned": 1}
    q2 = gaps.queue(var, list(srun2.ledger.events()))
    assert next(g for g in q2["open"] if g["kind"] == "firmware-not-attested")["subject"]["name"] == "Example NVMe Drive"
    assert {c["class"]: c["coverage"] for c in q2["classes"]}["firmware"] == 67


def test_a_gap_is_filled_by_evidence_that_exists_and_stays_filled_on_the_next_scan(tmp_path, slice_run):
    prepared(slice_run)
    gaps.record(slice_run)
    slice_run.close()
    gid = next(e["payload"]["gap"] for e in slice_run.ledger.events() if e["type"] == "gap.recorded")
    arun, _ = attest.record(slice_run.var, EXAMPLE, operator="ken")
    with pytest.raises(ValueError, match="not on this deployment"):
        gaps.fill(slice_run.var, gid, evidence="01NOPE", by="ken", basis="x")
    with pytest.raises(ValueError, match="is not on run"):
        gaps.fill(slice_run.var, gid, evidence=f"{arun.id}:01NOEVENT", by="ken", basis="x")
    with pytest.raises(ValueError, match="no run recorded gap"):
        gaps.fill(slice_run.var, "deadbeefdeadbeefdeadbeef", evidence=arun.id, by="ken", basis="x")
    frun, s = gaps.fill(slice_run.var, gid, evidence=arun.id, by="ken", basis="the owner's statement of the key: ML-DSA-65, read from the CA's records")
    assert s["gap"] == gid and next(frun.ledger.events())["payload"]["kind"] == "gapfill"
    q = gaps.queue(slice_run.var, list(slice_run.ledger.events()))
    assert q["open"] == [] and q["filled"][0]["filled"]["by"] == "ken" and q["filled"][0]["filled"]["evidence"]["run"] == arun.id
    assert {c["class"]: c["coverage"] for c in q["classes"]}["entries"] == 100
    # The same gap recorded by a later scan is the same id, so it is already filled there.
    from .conftest import make_run

    later = prepared(make_run(tmp_path / "later"))
    (tmp_path / "later" / "var" / "runs").mkdir(parents=True, exist_ok=True)
    gaps.record(later)
    gid2 = next(e["payload"]["gap"] for e in later.ledger.events() if e["type"] == "gap.recorded")
    assert gid2 == gid


def test_the_cbom_page_shows_the_queue_and_the_coverage(slice_run, monkeypatch):
    from pqch.pipeline import write_cboms

    prepared(slice_run)
    gaps.record(slice_run)
    slice_run.close()
    write_cboms(slice_run)
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        html = TestClient(ui.app).get("/cbom", params={"run": slice_run.id}).text
    assert "What no tool could see" in html and "algorithm-unidentified" in html and "% reached" in html and "1 open, 0 filled" in html
