"""M2A: the CBOM shown — the document, one entry traced field by field, and a second projection."""

import csv
import io
import warnings
from pathlib import Path

from pqch.assessor import load_policy, structure
from pqch.cbom import anatomy, build_all, tables
from pqch.pipeline import enrich, write_cboms, write_score

POLICY = load_policy("policy/pq-algorithms.yaml")


def built(run):
    structure(run, POLICY)
    enrich(run, author="owner")
    run.close()
    events = list(run.ledger.events())
    return events, build_all(events)["workbench"]


def test_every_field_of_an_entry_is_explained_and_traced(slice_run):
    events, bom = built(slice_run)
    ref = anatomy.default_ref(bom)
    c = anatomy.component(bom, events, ref)
    assert c["kind"] == "wire asset" and "certificate" in c["label"]
    missing = [r["field"] for r in c["rows"] if not r["meaning"]]
    assert missing == [], missing
    by = {r["field"]: r for r in c["rows"]}
    ev = {e["id"]: e for e in events}
    # The scanner's observation behind a standard field, with its raw output's hash.
    obs = by["cryptoProperties.certificateProperties.subjectName"]["evidence"][0]
    assert obs["kind"] == "finding" and ev[obs["event"]]["type"] == "finding.observed" and len(obs["sha256"]) == 64
    # A rule behind an extension field.
    q = by["pqch:quantum-vulnerable"]["evidence"][0]
    assert ev[q["event"]]["payload"]["rule_id"] == "quantum/vulnerable/1"
    # The chain: the served certificate depends on the file holding its key, joined by the public-key rule.
    down = c["depends_on"][0]
    assert down["kind"] == "host asset" and down["link"]["rule"] == "link/public-key/1"
    assert any(x["kind"] == "listener" for x in c["depended_by"])


def test_a_services_supplied_facts_are_traced_to_the_person_who_typed_them(slice_run):
    events, bom = built(slice_run)
    c = anatomy.component(bom, events, "svc:portal")
    owner = next(r for r in c["rows"] if r["field"] == "pqch:owner")
    assert owner["from"] == "supplied" and owner["evidence"][0]["kind"] == "supplied" and owner["evidence"][0]["who"] == "owner"
    pr = next(r for r in c["rows"] if r["field"] == "pqch:priority")
    assert pr["evidence"] and pr["evidence"][0]["who"] == "priority/m-26-15/1"


def test_the_document_summary_counts_what_it_holds(slice_run):
    _, bom = built(slice_run)
    d = anatomy.document(bom)
    assert d["spec"] == "CycloneDX 1.6" and d["by_kind"]["service"] == 4 and d["edges"] > 0
    assert {m["name"] for m in d["meta"]} >= {"pqch:ledger-head", "pqch:run"} and all(m.get("meaning") for m in d["meta"])


def test_a_second_projection_is_a_rebuild_from_the_ledger_not_a_scan(slice_run):
    events, _ = built(slice_run)
    d = tables.load("policy/projections/agency-inventory.yaml")
    r = tables.rebuild(events, d)
    assert r["head"] == events[-1]["hash"] and r["rows"]
    cols = r["columns"]
    row = dict(zip(cols, next(x for x in r["rows"] if x[cols.index("system")] == "portal"
                              and x[cols.index("function")] == "key-establishment"), strict=True))
    assert row["owner"] == "Web team" and row["queue"] == "kex-2030" and row["deadline"] == "2030-12-31"
    assert row["quantum_vulnerable"] == "true" and row["evidence_events"]
    # The same ledger, the same table; and the CSV carries every row.
    assert tables.rebuild(events, d)["rows"] == r["rows"]
    parsed = list(csv.reader(io.StringIO(tables.to_csv(r))))
    assert parsed[0] == cols and len(parsed) == len(r["rows"]) + 1


def test_a_projection_definition_is_checked(tmp_path):
    (tmp_path / "p.yaml").write_text("schema: pqch.projection/1\nid: x\ntitle: x\nrows: {roles: [signature]}\n"
                                     "columns: [{name: a, from: scanner.name}]\n")
    import pytest
    with pytest.raises(ValueError, match=r"asset., service. or item."):
        tables.load(tmp_path / "p.yaml")


def test_the_cbom_page_renders_the_document_an_entry_and_the_projection(tmp_path, monkeypatch, slice_run):
    _events, _ = built(slice_run)
    write_cboms(slice_run)
    write_score(slice_run, Path("eval/answer-keys/mini-agency-m0.yaml"))
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        monkeypatch.setattr(ui, "VAR", slice_run.var)
        client = TestClient(ui.app)
        html = client.get("/cbom").text
        assert "One entry, field by field" in html and "CycloneDX 1.6" in html and "pqch: extension" in html
        assert "no scanner ran" in html and "Web team" in html
        html2 = client.get("/cbom", params={"run": slice_run.id, "ref": "svc:portal"}).text
        assert "benefits enrollment" in html2 and "supplied by owner" in html2
        csv_text = client.get(f"/runs/{slice_run.id}/projection/agency-inventory.csv").text
        assert csv_text.startswith("system,owner,")
        assert client.get(f"/runs/{slice_run.id}/projection/..%2Fsecrets.csv").status_code == 404


def test_two_cboms_are_compared_by_component(slice_run, tmp_path):
    from .conftest import JOBS, make_run
    _events, bom = built(slice_run)
    other = make_run(tmp_path / "b", jobs=[j for j in JOBS if j[0] != "ssh-audit-bastion.json"])
    _ev2, bom2 = built(other)
    d = anatomy.diff(bom, bom2)
    assert d["removed"] and all("172.16.106.21" in x["label"] or x["kind"] != "wire asset" for x in d["removed"])
    assert anatomy.diff(bom, bom)["added"] == [] and anatomy.diff(bom, bom)["changed"] == []


def test_an_entry_shows_what_a_model_was_given_and_said(slice_run):
    _events, bom = built(slice_run)
    fp = next(c for c in bom["components"] if c["bom-ref"].startswith("fp:"))["bom-ref"]
    fake = {fp[3:]: {"id": "E1", "run": "R1", "actor": {"model": "m"}, "payload": {
        "finding": {"subject": {"host": "h"}, "asset": {"name": "X25519"}}, "service": "portal",
        "files": [{"path": "agency/portal/nginx.conf"}], "answer": {"file": "agency/portal/nginx.conf", "line_start": 3, "line_end": 3},
        "line_text": "x", "outcome": "answered", "used": {"steps": 2, "tokens": 9}, "latency_ms": 1000, "key_check": None,
        "settings": {"model": "m", "hardware": "h"}}}}
    w = anatomy.model_work(bom, fp, fake)
    assert w and w[0]["given"]["service"] == "portal" and w[0]["given"]["files"] == ["agency/portal/nginx.conf"]
