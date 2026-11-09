"""M9, the first slice: every finding is a claim; the one in force is chosen by the grade of its
evidence; dissent is shown, not resolved; a person's resolution stands until revoked; one document
over several runs is the same document every time."""

import json
import warnings
from pathlib import Path

import pytest
import yaml

from pqch.cbom import project, project_estate, validate
from pqch.common import canonical
from pqch.ledger import verify
from pqch.run import Run
from pqch.scout.imported import run_import
from pqch.score import score_bom

from .conftest import SCOPE

KEY = Path("eval/answer-keys/mini-agency-m0.yaml")


def props(c: dict) -> dict:
    return {p["name"]: (json.loads(p["value"]) if p["value"][:1] in "[{" else p["value"]) for p in c.get("properties", [])}


def structured(run: Run):
    from pqch.assessor import chains, load_policy, structure

    structure(run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(run)
    return run


def wire_cbom(bom: dict, rename: dict | None = None, tool="other-scanner", version="1") -> dict:
    """A second tool's CBOM of the same listeners, made from the workbench's: the wire entries only,
    some names in the tool's own spelling."""
    comps = []
    for c in bom["components"]:
        p = props(c)
        if p.get("pqch:layer") != "wire" or p.get("pqch:asset-type") == "protocol":
            continue
        name = (rename or {}).get(c["name"], c["name"])
        comps.append({**{k: v for k, v in c.items() if k not in ("properties",)}, "name": name})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"tools": {"components": [{"name": tool, "version": version}]}},
            "components": comps}


def test_every_finding_carries_a_grade_and_an_import_is_reported(slice_run, tmp_path):
    events = list(structured(slice_run).ledger.events())
    grades = {e["payload"]["source"]["tool"]: e["payload"]["source"]["grade"] for e in events if e["type"] == "finding.observed"}
    assert grades == {"testssl.sh": "observed-wire", "ssh-audit": "observed-wire", "cbomkit-theia": "parsed-file"}
    doc = tmp_path / "other.cdx.json"
    doc.write_text(json.dumps(wire_cbom(project(events))))
    irun, _ = run_import(slice_run.var, [(doc, None)], SCOPE)
    assert {e["payload"]["source"]["grade"] for e in irun.ledger.events() if e["type"] == "finding.observed"} == {"reported"}


def test_a_scalar_disagreement_is_dissent_not_a_list():
    from pqch.scout.normalize import _merge

    asset = {"parameters": {"key_bits": 2048, "tool_names": ["a"]}}
    _merge(asset["parameters"], {"key_bits": 1024, "tool_names": ["b"], "curve": "P-256"}, asset)
    assert asset["parameters"] == {"key_bits": 2048, "tool_names": ["a", "b"], "curve": "P-256"}   # the type never changes
    assert asset["dissent"] == {"key_bits": ["2048", "1024"]}


def test_two_tools_on_one_entry_are_one_entry_with_both_claims_and_the_observed_one_in_force(slice_run, tmp_path):
    events = list(structured(slice_run).ledger.events())
    own = project(events)
    # The other tool misnames two groups and is stale on one certificate's date.
    other = wire_cbom(own, rename={"secp256r1": "P-256", "X25519": "x25519"})
    for c in other["components"]:
        if c["cryptoProperties"]["assetType"] == "certificate" and c["cryptoProperties"]["certificateProperties"].get("notValidAfter"):
            c["cryptoProperties"]["certificateProperties"]["notValidAfter"] = "2027-01-01T00:00:00Z"
            break
    doc = tmp_path / "other.cdx.json"
    doc.write_text(json.dumps(other))
    irun, s = run_import(slice_run.var, [(doc, None)], SCOPE)
    assert s["unplaced"] == 0
    bom = project_estate([slice_run, irun])
    assert validate(bom) == []
    own_wire = {c["bom-ref"] for c in own["components"] if props(c).get("pqch:layer") == "wire" and props(c).get("pqch:asset-type") != "protocol"}
    est_wire = {c["bom-ref"] for c in bom["components"] if props(c).get("pqch:layer") == "wire" and props(c).get("pqch:asset-type") != "protocol"}
    assert est_wire == own_wire                                     # no duplicate: a misspelling is the same entry
    multi = [c for c in bom["components"] if "pqch:claims" in props(c)]
    assert len(multi) == len(own_wire)
    for c in multi:
        p = props(c)
        assert [x["grade"] for x in p["pqch:claims"]] == ["observed-wire", "reported"]
        assert p["pqch:in-force"]["grade"] == "observed-wire" and p["pqch:in-force"]["decided_by"] == "precedence/1"
        assert p["pqch:grade"] == "observed-wire" and "other-scanner" in p["pqch:tools"]
    dissent = [c for c in bom["components"] if "pqch:dissent" in props(c)]
    assert len(dissent) == 1
    d = props(dissent[0])["pqch:dissent"]["not_after"]
    assert {x["grade"] for x in d} == {"observed-wire", "reported"} and "2027-01-01T00:00:00Z" in {x["value"] for x in d}
    assert props(dissent[0])["pqch:parameters"]["not_after"] != "2027-01-01T00:00:00Z"     # the observed date is in force
    # Scored together: what the scan covered, no more and no less, and nothing unplanted from the misspellings.
    key = yaml.safe_load(KEY.read_text())
    mine, both = score_bom(own, key)["layers"]["wire"], score_bom(bom, key)["layers"]["wire"]
    assert (both["covered"], both["present"], both["false_positives"]) == (mine["covered"], mine["present"], mine["false_positives"])


def test_a_persons_resolution_sets_the_field_until_revoked(slice_run):
    events = list(structured(slice_run).ledger.events())
    target = next(e for e in events if e["type"] == "finding.observed" and e["payload"]["asset"]["type"] == "certificate")
    fp = target["payload"]["fingerprint"]
    res = slice_run.ledger.append("claim.resolved", {"kind": "human", "id": "ken"},
                                  {"fingerprint": fp, "field": "key_bits", "value": 4096, "basis": "the CA's records"})
    bom = project(list(slice_run.ledger.events()))
    c = next(c for c in bom["components"] if c["bom-ref"] == f"fp:{fp}")
    p = props(c)
    assert p["pqch:parameters"]["key_bits"] == 4096 and p["pqch:resolved"]["key_bits"]["event"] == res["id"]
    assert p["pqch:resolved"]["key_bits"]["basis"] == "the CA's records"
    slice_run.ledger.append("resolution.revoked", {"kind": "human", "id": "ken"}, {"resolution": res["id"], "basis": "mistaken"})
    bom2 = project(list(slice_run.ledger.events()))
    p2 = props(next(c for c in bom2["components"] if c["bom-ref"] == f"fp:{fp}"))
    assert "pqch:resolved" not in p2 and p2["pqch:parameters"].get("key_bits") == target["payload"]["asset"]["parameters"].get("key_bits")
    assert verify(list(slice_run.ledger.events())).ok


def test_the_estate_projection_is_the_same_document_for_the_same_runs(slice_run, tmp_path):
    events = list(structured(slice_run).ledger.events())
    doc = tmp_path / "o.cdx.json"
    doc.write_text(json.dumps(wire_cbom(project(events))))
    irun, _ = run_import(slice_run.var, [(doc, None)], SCOPE)
    slice_run.close()
    a, b = project_estate([slice_run, irun]), project_estate([slice_run, irun])
    assert canonical(a) == canonical(b)
    meta = {p["name"]: p["value"] for p in a["metadata"]["properties"]}
    pins = json.loads(meta["pqch:runs"])
    assert [p["run"] for p in pins] == [slice_run.id, irun.id] and all(len(p["head"]) == 64 for p in pins)
    assert meta["pqch:projection"] == "estate" and "pqch:ledger-head" not in meta
    # A different set of runs is a different document, by serial.
    assert project_estate([slice_run])["serialNumber"] != a["serialNumber"]
    # A ledger that does not verify stops it.
    led = irun.ledger.path
    led.write_text(led.read_text().replace('"grade":"reported"', '"grade":"observed-wire"', 1))
    with pytest.raises(ValueError):
        project_estate([slice_run, irun])


def test_the_imports_page_shows_the_combined_document_and_the_route_serves_it(slice_run, tmp_path, monkeypatch):
    import importlib

    from pqch.pipeline import write_cboms

    events = list(structured(slice_run).ledger.events())
    doc = tmp_path / "o.cdx.json"
    doc.write_text(json.dumps(wire_cbom(project(events), rename={"X25519": "x25519"})))
    irun, _ = run_import(slice_run.var, [(doc, None)], SCOPE, key_path=KEY)
    slice_run.close()
    write_cboms(slice_run)
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
        html = c.get("/imports").text
        assert "The scan and its imports, as one document" in html and "described by more than one tool" in html
        r = c.get("/estate/cbom.json", params={"runs": f"{slice_run.id},{irun.id}"})
        assert r.status_code == 200 and json.loads(r.text)["metadata"]["properties"]
        assert c.get("/estate/cbom.json", params={"runs": "nope;rm"}).status_code == 404
        page = c.get("/cbom", params={"run": slice_run.id}).text
        assert "Claims kept" not in page or "entries with more than one" in page
