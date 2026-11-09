"""M10 item 5: the owner's facts an engagement needs, every step in a bucket a later phase is scoped
by, and the plan handed over as a register with the owner's numbers labelled as the owner's."""

import importlib
import json
import warnings
from datetime import date
from pathlib import Path

from pqch import planning
from pqch.assessor import chains, load_policy, managed, structure
from pqch.cbom import project
from pqch.pipeline import write_cboms, write_score

CAPS = sorted(Path("policy/snapshots").glob("capabilities-*.json"))[-1]
CMVP = sorted(Path("policy/snapshots").glob("cmvp-*.json"))[-1]


def assessed(run):
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(run)
    chains.supply(run, "agency/context.yaml", author="owner")
    managed.assess(run, pack_path="policy/packs/m-26-15.yaml", families_path="policy/algorithm-families.yaml",
                   capabilities_path=CAPS, cmvp_path=CMVP, as_of=date(2026, 10, 20))
    run.close()
    write_cboms(run)
    write_score(run, Path("eval/answer-keys/mini-agency-m0.yaml"))
    return run


def props(c):
    return {p["name"]: (json.loads(p["value"]) if p["value"][:1] in "[{" else p["value"]) for p in c.get("properties", [])}


def test_the_engagements_facts_are_supplied_labelled_and_carried_on_the_service(slice_run):
    assessed(slice_run)
    bom = project(list(slice_run.ledger.events()))
    svc = {c["name"]: props(c) for c in bom["components"] if c["type"] == "application"}
    assert svc["sftp-legacy"]["pqch:system"] == "REC-SFTP" and svc["sftp-legacy"]["pqch:classification"] == "cui"
    assert svc["sftp-legacy"]["pqch:cost-to-fix"]["amount"] == 40000 and "planted" in svc["sftp-legacy"]["pqch:cost-to-fix"]["basis"]
    assert svc["sftp-legacy"]["pqch:vendor-path"].startswith("end-of-life")
    assert {x["name"] for x in svc["portal"]["pqch:supplied"]} >= {"system", "interface", "mission-thread", "classification"}
    assert "pqch:cost-to-fix" not in svc["portal"]                       # not every service has a number, and none is invented


def test_the_context_file_refuses_a_classification_or_a_cost_it_cannot_carry(tmp_path):
    import pytest
    import yaml

    ctx = yaml.safe_load(Path("agency/context.yaml").read_text())
    ctx["services"]["portal"]["classification"] = "sensitive"
    (tmp_path / "c1.yaml").write_text(yaml.safe_dump(ctx))
    with pytest.raises(ValueError, match="classification"):
        chains.load_context(tmp_path / "c1.yaml")
    ctx["services"]["portal"]["classification"] = "cui"
    ctx["services"]["portal"]["cost_to_fix"] = 5000                      # a bare number carries no basis
    (tmp_path / "c2.yaml").write_text(yaml.safe_dump(ctx))
    with pytest.raises(ValueError, match="basis"):
        chains.load_context(tmp_path / "c2.yaml")


def test_every_step_falls_in_a_bucket_from_the_pack(slice_run):
    assessed(slice_run)
    plan = planning.build(slice_run.var, slice_run)
    assert plan and plan["buckets_pack"] == "phase-buckets/1"
    assert all(s["bucket"] for s in plan["order"]) and "unplaced" not in {s["bucket"] for s in plan["order"]}
    assert sum(b["steps"] for b in plan["buckets"]) == len(plan["order"])
    by = {b["id"]: b for b in plan["buckets"]}
    assert "sftp-legacy" in by["applications-mission"]["services"]        # the software nothing configurable can move
    assert by["infrastructure-data-protection"]["steps"] >= 2 and by["identity-pki-signing"]["steps"] >= 1
    assert planning.bucket_of({"id": "supplier:signing", "kind": "supplier"}) == "identity-pki-signing"
    assert planning.bucket_of({"id": "x", "kind": "nothing-known"}) == "unplaced"


def test_the_register_has_a_row_per_step_with_the_owners_facts_and_sums_only_the_owners_costs(slice_run):
    assessed(slice_run)
    plan = planning.build(slice_run.var, slice_run)
    reg = planning.register(plan, list(slice_run.ledger.events()))
    assert reg["schema"] == "pqch.register/1" and reg["steps"] == len(plan["order"]) == len(reg["rows"])
    col = {c: i for i, c in enumerate(reg["columns"])}
    sftp = next(r for r in reg["rows"] if r[col["service"]] == "sftp-legacy" and r[col["step"]].startswith("replace:"))
    assert sftp[col["bucket"]] == "applications-mission" and sftp[col["system"]] == "REC-SFTP"
    assert sftp[col["cost_to_fix"]]["amount"] == 40000 and sftp[col["blocked_on_supplier"]] == "yes"
    assert sftp[col["classification"]] == "cui" and sftp[col["prioritized"]] is True and "high-value-asset" in sftp[col["criteria"]]
    assert sftp[col["not_compatible_entries"]] > 0                                  # the entry rule's counts travel with the row
    en = next(r for r in reg["rows"] if r[col["step"]].startswith("enable:") or r[col["step"]].startswith("require:"))
    assert en[col["fingerprints"]] and en[col["entries"]] > 0
    assert reg["cost"] == {"by_currency": {"USD": 40000}, "services_costed": 1, "services_uncosted": 3,
                           "basis": reg["cost"]["basis"]} and "nothing is estimated" in reg["cost"]["basis"]
    csv_text = planning.register_csv(reg)
    assert csv_text.splitlines()[0].startswith("n,step,title,bucket,") and len(csv_text.splitlines()) == len(reg["rows"]) + 1
    # Same ledger, same register.
    assert planning.register(planning.build(slice_run.var, slice_run), list(slice_run.ledger.events()))["rows"] == reg["rows"]


def test_the_register_is_written_beside_the_run_and_served_live(slice_run, monkeypatch):
    assessed(slice_run)
    out = planning.write_register(slice_run.var, slice_run)
    assert set(out) == {"register.csv", "register.json"} and all(p.is_file() for p in out.values())
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
        r = c.get(f"/runs/{slice_run.id}/register.csv")
        assert r.status_code == 200 and r.text.startswith("n,step,title,bucket,")
        j = c.get(f"/runs/{slice_run.id}/register.json").json()
        assert j["steps"] == len(j["rows"]) and j["buckets"]
        assert c.get(f"/runs/{slice_run.id}/register.xml").status_code == 404
        html = c.get("/plan").text
        assert "Handed to the next phase" in html and "Identity, PKI and signing" in html and "Download the register" in html
