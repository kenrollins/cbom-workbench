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
    assert by["listeners"] == {"class": "listeners", "reached": 4, "filled": 0, "gaps": 0, "total": 4, "coverage": 100}
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
    assert by["listeners"] == {"class": "listeners", "reached": 4, "filled": 0, "gaps": 1, "total": 5, "coverage": 80}
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
    # An illustrative document is nobody's statement about this server: the gap stays, and says why.
    attest.record(var, EXAMPLE)
    counts2 = {}
    srun2 = system_run(var, name="srv1", before_close=lambda r: counts2.update(gaps.record(r)))
    assert counts2["gaps_by_kind"] == {"no-supplier-statement": 1, "listener-not-scanned": 1}
    q2 = gaps.queue(var, list(srun2.ledger.events()))
    assert "illustrative" in next(g for g in q2["open"] if g["kind"] == "no-supplier-statement")["reason"]
    assert {c["class"]: c["coverage"] for c in q2["classes"]}["firmware"] == 0


def test_a_suppliers_statement_closes_a_firmware_gap_only_when_it_covers_what_is_installed(tmp_path):
    import yaml

    var = tmp_path / "var"
    doc = yaml.safe_load(EXAMPLE.read_text())
    doc["illustrative"] = False                                  # a supplier's own statement, for BIOS 2.4.0
    doc["products"][0]["firmware"].append({"name": "Example NVMe Drive", "version": "any", "supportability": "no-statement"})
    (tmp_path / "real.yaml").write_text(yaml.safe_dump(doc))
    system_run(var)
    attest.record(var, tmp_path / "real.yaml")
    counts = {}
    srun = system_run(var, before_close=lambda r: counts.update(gaps.record(r)))      # the server reports BIOS 2.3.1
    assert counts["gaps_by_kind"] == {"firmware-not-attested": 2, "listener-not-scanned": 1}
    q = gaps.queue(var, list(srun.ledger.events()))
    why = {g["subject"]["name"]: g["reason"] for g in q["open"] if g["kind"] == "firmware-not-attested"}
    assert "is for version 2.4.0; the server reports 2.3.1" in why["BIOS"]            # a version mismatch closes nothing
    assert "makes no statement" in why["Example NVMe Drive"]                          # nor does a row that says nothing
    fw = next(c for c in q["classes"] if c["class"] == "firmware")
    assert (fw["reached"], fw["gaps"], fw["total"], fw["coverage"]) == (1, 2, 3, 33)   # only the controller, at `any`
    # At the installed version the BIOS is covered.
    counts3 = {}
    system_run(var, bios="2.4.0", before_close=lambda r: counts3.update(gaps.record(r)))
    assert counts3["gaps_by_kind"]["firmware-not-attested"] == 1
    # A supplier's statement is preferred to a newer illustration.
    attest.record(var, EXAMPLE)
    assert attest.for_system(var, list(srun.ledger.events()))["illustrative"] is False


def test_a_fill_is_bound_to_what_it_filled_and_does_not_close_the_gap_forever(tmp_path):
    import json

    from tests import conftest

    from .conftest import JOBS, SCOPE, make_run

    scope = json.loads(json.dumps(SCOPE))
    scope["endpoints"].append({"host": "172.16.106.99", "port": 443, "transport": "tcp", "protocol": "tls", "service": "ghost"})

    def scan(where):
        old, conftest.SCOPE = conftest.SCOPE, scope
        try:
            run = make_run(tmp_path / where, jobs=JOBS)
        finally:
            conftest.SCOPE = old
        gaps.record(prepared(run))
        run.close()
        return run

    var = tmp_path / "var"
    first = scan(".")                                              # all runs under one var
    assert first.var == var
    rec = next(e for e in first.ledger.events() if e["type"] == "gap.recorded" and e["payload"]["kind"] == "listener-not-scanned")
    assert rec["payload"]["bound_to"] == {"run": first.id}
    gid = rec["payload"]["gap"]
    evidence, _ = attest.record(var, EXAMPLE, operator="ken")      # stands in for the rescan: a later, verified run
    gaps.fill(var, gid, evidence=evidence.id, by="ken", basis="a rescan from the runner's new leg reached it")
    q1 = gaps.queue(var, list(first.ledger.events()))
    assert gid not in {g["gap"] for g in q1["open"]} and gid in {g["gap"] for g in q1["filled"]}
    ls = next(c for c in q1["classes"] if c["class"] == "listeners")
    assert (ls["reached"], ls["filled"], ls["gaps"], ls["total"]) == (4, 1, 0, 5)      # the total does not move with a fill
    # The next scan misses the listener again: the same gap id, and November's fill does not close it.
    second = scan(".")
    assert gid in {e["payload"]["gap"] for e in second.ledger.events() if e["type"] == "gap.recorded"}
    q2 = gaps.queue(var, list(second.ledger.events()))
    assert gid in {g["gap"] for g in q2["open"]}
    assert next(c for c in q2["classes"] if c["class"] == "listeners")["gaps"] == 1
    with pytest.raises(ValueError, match="taken before"):
        gaps.fill(var, gid, evidence=evidence.id, by="ken", basis="the same evidence again")
    # A gap about a file is bound to the evidence it was recorded from: a fill for another digest is not this gap's.
    frec = next(e for e in second.ledger.events() if e["type"] == "gap.recorded" and e["payload"]["kind"] == "algorithm-unidentified")
    assert frec["payload"]["bound_to"]["fingerprint"]
    assert gaps.honoured({"bound_to": frec["payload"]["bound_to"]}, frec["payload"], frec["ts"], second.id)
    assert not gaps.honoured({"bound_to": {**frec["payload"]["bound_to"], "fingerprint": "0" * 64}}, frec["payload"], frec["ts"], second.id)
    assert not gaps.honoured({}, frec["payload"], frec["ts"], second.id)               # a fill that names no evidence
    assert gaps.honoured({}, {"kind": "no-owner-facts"}, frec["ts"], second.id)        # a standing fact stays filled


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
