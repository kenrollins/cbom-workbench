"""M10: a supplier's attestation as reported evidence, kept apart from what the server showed and
joined to it by model and version."""

import importlib
import warnings
from pathlib import Path

import pytest
import yaml

from pqch import attest, scope as scope_mod, systems
from pqch.ledger import verify
from pqch.run import Run

EXAMPLE = Path("agency/attestations/example-supplier.yaml")


def system_run(var: Path, *, model="Example Server 1U", vendor="Example Hardware", bios="2.3.1", name="srv1", before_close=None) -> Run:
    """A closed system scan with the platform facts a firmware read and a controller read leave;
    `before_close(run)` may append more before the run closes."""
    scope = {"schema": "pqch.scope/1", "id": "01M40W6W873YWJMWPKGMK3YBMN", "estate": "external", "owned": False,
             "authorized_by": "owner", "endpoints": [{"host": "10.0.0.5", "port": 443, "transport": "tcp", "protocol": "tls"}],
             "images": [], "sources": [], "reach": {"kind": "local"},
             "systems": [{"name": name, "addresses": ["10.0.0.4"], "paths": ["/etc/ssh"], "firmware": True}],
             "controllers": [{"host": "10.0.0.5", "port": 443, "kind": "redfish", "of": name}]}
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="system", kind="scan-system")
    run.ledger.append("platform.observed", {"kind": "scanner", "id": "pqch-system-firmware"}, {
        "system": name, "source": "firmware", "device": {"vendor": vendor, "model": model, "board": "X"},
        "firmware": [{"name": "BIOS", "version": bios, "enforces": ["secure-boot:db"]}],
        "settings": {"secure_boot": True, "tpm": "TPM 2.0"}})
    run.ledger.append("platform.observed", {"kind": "scanner", "id": "pqch-controller-redfish"}, {
        "system": name, "source": "controller",
        "controller": {"host": "10.0.0.5", "model": "ERMC", "firmware_version": "7.1.0", "authenticated": True},
        "device": {"vendor": vendor, "model": model},
        "firmware": [{"name": "BIOS", "version": bios}, {"name": "Example Remote Management Controller", "version": "7.1.0"},
                     {"name": "Example NVMe Drive", "version": "1.2"}],
        "settings": {"fips_mode": "Disabled"}})
    if before_close:
        before_close(run)
    run.close()
    return run


def test_the_document_is_validated_and_a_bad_supportability_is_refused(tmp_path):
    doc = attest.load(EXAMPLE)
    assert doc["issued"] == "2026-11-01" and doc["illustrative"] is True
    doc["products"][0]["firmware"][0]["supportability"] = "maybe"
    (tmp_path / "bad.yaml").write_text(yaml.safe_dump(doc))
    with pytest.raises(Exception, match="maybe"):
        attest.load(tmp_path / "bad.yaml")


def test_an_attestation_is_recorded_as_reported_evidence_and_matched_to_the_scanned_host(tmp_path):
    var = tmp_path / "var"
    srun = system_run(var)
    run, s = attest.record(var, EXAMPLE, operator="ken")
    events = list(run.ledger.events())
    assert verify(events).ok and events[0]["payload"]["kind"] == "attestation" and events[-1]["type"] == "run.closed"
    rec = [e for e in events if e["type"] == "attestation.recorded"]
    assert len(rec) == 1 and rec[0]["actor"] == {"kind": "human", "id": "ken"}
    assert rec[0]["payload"]["grade"] == "reported" and rec[0]["payload"]["illustrative"] is True
    assert rec[0]["payload"]["document"]["sha256"].startswith("sha256:") and (var / rec[0]["payload"]["document"]["path"]).is_file()
    assert not any(e["type"] == "finding.observed" for e in events)         # a statement is never a finding
    m = [e for e in events if e["payload"].get("rule_id") == attest.RULE]
    assert len(m) == 1 and m[0]["inputs"] == [rec[0]["id"]] and m[0]["payload"]["subject"] == {"kind": "system", "name": "srv1", "run": srun.id}
    c = m[0]["payload"]["classification"]
    by = {r["name"]: r for r in c["firmware"]}
    assert by["BIOS"]["observed_version"] == "2.3.1" and by["BIOS"]["attested_version"] == "2.4.0" and by["BIOS"]["agrees"] is False
    assert by["Example Remote Management Controller"]["agrees"] is True          # `any` covers the installed version
    assert by["Example 10G Network Adapter"]["agrees"] is None                    # the server did not report it
    assert (c["agree"], c["differ"], c["unseen"]) == (1, 1, 1) and c["not_attested"] == ["Example NVMe Drive"]
    assert s["matches"] == [{"system": "srv1", "run": srun.id, "agree": 1, "differ": 1, "unseen": 1}]


def test_the_same_document_twice_is_a_no_op_and_a_changed_one_a_new_claim(tmp_path):
    var = tmp_path / "var"
    first, _ = attest.record(var, EXAMPLE)
    again, s = attest.record(var, EXAMPLE)
    assert s["duplicate"] and again.id == first.id and len(attest.runs(var)) == 1
    doc = attest.load(EXAMPLE)
    doc["products"][0]["firmware"][0]["version"] = "2.5.0"
    (tmp_path / "rev4.yaml").write_text(yaml.safe_dump(doc))
    third, s3 = attest.record(var, tmp_path / "rev4.yaml")
    assert not s3["duplicate"] and third.id != first.id and len(attest.runs(var)) == 2
    # The newest statement is the one a host is joined to.
    system_run(var)
    att = attest.for_system(var, list(Run.latest(var, "scan-system").ledger.events()))
    assert att["run"] == third.id and next(r for r in att["firmware"] if r["name"] == "BIOS")["attested_version"] == "2.5.0"


def test_another_model_is_not_joined_and_the_hosts_page_says_so(tmp_path):
    var = tmp_path / "var"
    attest.record(var, EXAMPLE)
    other = system_run(var, model="Other Box 2U", name="srv2")
    assert attest.for_system(var, list(other.ledger.events())) is None
    mine = system_run(var, name="srv1")
    rows = {h["name"]: h for h in systems.hosts(var)}
    assert rows["srv2"]["attestation"] is None and rows["srv2"]["attested"] is None
    assert rows["srv1"]["attested"]["supplier"] == "Example Hardware" and rows["srv1"]["attested"]["illustrative"] is True
    assert rows["srv1"]["attestation"] == ("BIOS: update (version differs); Example Remote Management Controller: update; "
                                           "Example 10G Network Adapter: no-statement (not reported by the server)")
    assert attest.for_system(var, list(mine.ledger.events()))["system"] == "srv1"


def test_the_servers_plan_carries_the_suppliers_answer_on_the_supplier_steps(tmp_path):
    from pqch import planning

    var = tmp_path / "var"
    srun = system_run(var)
    attest.record(var, EXAMPLE)
    att = attest.for_system(var, list(srun.ledger.events()))
    plan = planning.system_build(srun, attestation=att)
    ctl = next(s for s in plan["order"] if s["id"] == "supplier:controller")
    assert "reported, not observed" in ctl["why"] and "supportability update" in ctl["why"] and "X25519MLKEM768" in ctl["why"]
    assert ctl["attested"]["firmware"] == "Example Remote Management Controller" and ctl["attested"]["agrees"] is True
    a = plan["attestation"]
    assert a["named"] == 3 and a["agree"] == 1 and a["differ"] == 1 and a["unseen"] == 1 and a["not_attested"] == 1
    assert a["by_supportability"] == {"update": 2, "replace": 0, "end-of-life": 0, "no-statement": 1}
    bare = planning.system_build(srun)
    assert bare["attestation"] is None and "reported" not in next(s for s in bare["order"] if s["id"] == "supplier:controller")["why"]


def test_the_hosts_cbom_page_shows_the_statement_beside_the_scan_and_marks_it_illustrative(tmp_path, monkeypatch):
    var = tmp_path / "var"
    srun = system_run(var)
    attest.record(var, EXAMPLE)
    monkeypatch.setenv("PQCH_VAR", str(var))
    monkeypatch.setenv("PQCH_TRUSTED_PROXIES", "testclient")
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    monkeypatch.delenv("PQCH_PUBLIC", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app, headers={"X-Forwarded-User": "ken"})
        html = c.get("/cbom", params={"run": srun.id}).text
        assert "What the supplier attests, beside what the server showed" in html
        assert "Illustrative: this statement is a worked example" in html and "same version" in html and "differs" in html
        assert "Example NVMe Drive" in html and "the statement does not name" in html
        hosts = c.get("/hosts").text
        assert "Supplier attests" in hosts and "BIOS: update (version differs)" in hosts and "reported, not observed" in hosts
        plan = c.get("/plan", params={"estate": "system", "run": srun.id}).text
        assert "The supplier's statement (Example Hardware, 2026-11-01" in plan and "illustrative" in plan


def test_an_attested_module_is_looked_up_in_the_dated_cmvp_snapshot(tmp_path):
    from pqch import attest

    rows = attest.cmvp_lookup([{"name": "OpenSSL FIPS Provider", "cmvp_certificate": 4985},
                               {"name": "Example Controller Crypto Library", "cmvp_certificate": None},
                               {"name": "Some module", "cmvp_certificate": 1}])
    assert rows[0]["cmvp"]["state"] == "found" and rows[0]["cmvp"]["status"] and rows[0]["cmvp"]["approved_ml_kem"] is False
    assert rows[0]["cmvp"]["name_matches"] is True
    assert rows[1]["cmvp"]["state"] == "not-validated"
    assert rows[2]["cmvp"]["state"] == "not-in-snapshot" and "look it up" in rows[2]["cmvp"]["basis"]
    var = tmp_path / "var"
    srun = system_run(var)
    attest.record(var, EXAMPLE)
    att = attest.for_system(var, list(srun.ledger.events()))
    assert att["crypto_modules"][0]["cmvp"]["state"] == "not-validated"
