"""M1: the dependency chain, the verifier per class, conflicts settled by rule, and the receipts."""

import json
from pathlib import Path

import httpx
import pytest

from pqch.assessor import chains, conflicts, load_policy, structure, verifiers
from pqch.assessor.explain import explain
from pqch.cbom import build_all
from pqch.common import hash_object, sha256_hex
from pqch.inference import Seam
from pqch.pipeline import enrich, write_cboms, write_score
from pqch.score import score_bom

from .conftest import binding_for, make_run

OTHER_IMAGE = "pqch-agency/portal@sha256:" + "9" * 64

POLICY = load_policy("policy/pq-algorithms.yaml")
KEY = Path("eval/answer-keys/mini-agency-m0.yaml")


def events(run):
    return list(run.ledger.events())


def links(run, rule=None, status=None):
    return [e for e in events(run) if e["type"] == "link.asserted"
            and (rule is None or e["payload"].get("rule_id") == rule)
            and (status is None or e["payload"].get("status") == status)]


def test_a_bound_listener_is_linked_to_its_service_with_the_binding_as_evidence(slice_run):
    structure(slice_run, POLICY)
    counts = chains.link_services(slice_run)
    assert counts == {"service_links": 4, "image_links": 4, "unnamed": 0, "unbound": 0}
    by_id = {e["id"]: e for e in events(slice_run)}
    for ln in links(slice_run, "link/service/1"):
        p = ln["payload"]
        assert p["status"] == "discovered" and p["to"]["kind"] == "service"
        for i in ln["inputs"]:   # every link rests on a binding assessment, the runner's own record
            assert by_id[i]["payload"]["rule_id"] == "binding/scope/1"
            assert by_id[i]["payload"]["classification"]["bound"] is True


def test_an_unbound_listener_gets_no_service_link_and_the_chain_says_so(tmp_path):
    run = make_run(tmp_path, lambda t: binding_for(t, image=OTHER_IMAGE if t.get("host") == "172.16.106.10" else None))
    structure(run, POLICY)
    counts = chains.link_services(run)
    assert counts["unbound"] == 1 and counts["service_links"] == 3
    assert not any(e["payload"]["from"].get("host") == "172.16.106.10" for e in links(run, "link/service/1"))
    from pqch.ui.view import run_view
    v = run_view(run)
    portal = next(ln for ln in v["listeners"] if ln["address"] == "172.16.106.10:443")
    svc = next(c for c in portal["chain"] if c["step"] == "service")
    assert svc["status"] == "missing" and "did not run the scope's image" in svc["why"]
    assert not portal["chain_complete"]


def test_supplied_facts_are_human_links_labelled_supplied_with_the_file_as_evidence(slice_run):
    structure(slice_run, POLICY)
    counts = chains.supply(slice_run, "agency/context.yaml", author="owner")
    assert counts["supplied"] == 24 and counts["services_without_context"] == []
    digest = sha256_hex(Path("agency/context.yaml").read_bytes())
    for e in links(slice_run, status="supplied"):
        assert e["actor"] == {"kind": "human", "id": "owner"}
        assert e["evidence"] == [{"ref": "agency/context.yaml", "sha256": digest}]
        assert e["payload"]["kind"] in ("mission-function", "data-lifetime", "high-value-asset", "fips199-impact",
                                        "owner", "national-security-system")
    # Only services the scope names: the context file knows eight, the slice has four.
    assert {e["payload"]["from"]["name"] for e in links(slice_run, status="supplied")} == {"api", "bastion", "portal", "sftp-legacy"}


def test_the_context_file_is_checked(tmp_path):
    bad = tmp_path / "ctx.yaml"
    bad.write_text("schema: pqch.context/1\nservices:\n  portal: {colour: blue}\n")
    with pytest.raises(ValueError, match="unknown fact"):
        chains.load_context(bad)
    bad.write_text("schema: pqch.context/1\nservices:\n  portal: {data_lifetime_years: ten}\n")
    with pytest.raises(ValueError, match="whole number"):
        chains.load_context(bad)


def test_the_cbom_carries_the_chain_and_labels_every_supplied_fact(slice_run):
    structure(slice_run, POLICY)
    enrich(slice_run, author="owner")
    slice_run.close()
    boms = build_all(events(slice_run))     # validates every document against CycloneDX 1.6
    wb = boms["workbench"]
    svc = {c["name"]: c for c in wb["components"] if c["type"] == "application"}
    assert set(svc) == {"api", "bastion", "portal", "sftp-legacy"}
    props = {p["name"]: p["value"] for p in svc["portal"]["properties"]}
    assert props["pqch:mission-function"] == "benefits enrollment" and props["pqch:data-lifetime-years"] == "10"
    assert {s["name"] for s in json.loads(props["pqch:supplied"])} == {
        "mission-function", "data-lifetime", "high-value-asset", "fips199-impact", "owner", "national-security-system"}
    deps = {d["ref"]: d["dependsOn"] for d in wb["dependencies"]}
    assert deps["svc:portal"] == ["listener:172.16.106.10:443", "img:pqch-agency/portal"]
    assert deps["img:pqch-agency/portal"] and all(r.startswith("fp:") for r in deps["img:pqch-agency/portal"])
    listener = next(c for c in wb["components"] if c["bom-ref"] == "listener:172.16.106.10:443")
    assert {p["name"]: p["value"] for p in listener["properties"]}["pqch:service"] == "portal"
    # The baselines carry none of it: no rule, no service, no supplied fact.
    for name in ("baseline-cbomkit", "baseline-scanners"):
        assert not any(c["type"] in ("application", "container") for c in boms[name]["components"])


def test_the_score_counts_supplied_facts_apart_from_coverage_and_flags_an_unlabelled_one(slice_run, key):
    structure(slice_run, POLICY)
    enrich(slice_run, author="owner")
    slice_run.close()
    wb = build_all(events(slice_run))["workbench"]
    r = score_bom(wb, key)
    assert r["supplied"]["carried"] == r["supplied"]["total"] == 1 and r["supplied"]["unlabelled"] == []
    # Wire coverage is unchanged by the chain: a supplied fact is never coverage.
    assert r["layers"]["wire"]["covered"] == 22
    # Strip the label from the portal's facts: the fact is still carried, and that is a defect.
    for c in wb["components"]:
        if c.get("bom-ref") == "svc:portal":
            for p in c["properties"]:
                if p["name"] == "pqch:supplied":
                    p["value"] = "[]"
    assert score_bom(wb, key)["supplied"]["unlabelled"] == ["portal-context"]


def test_each_finding_class_names_its_verifier_and_the_cbom_carries_it(slice_run):
    structure(slice_run, POLICY)
    counts = verifiers.classes(slice_run, verifiers.load_verifiers("policy/verifiers.yaml"))
    assert counts["classes"] == 8 and counts["without_verifier"] > 0
    rows = {(e["payload"]["subject"]["layer"], e["payload"]["subject"]["type"], e["payload"]["subject"]["role"]):
            e["payload"]["classification"]["verifiable_by"]
            for e in events(slice_run) if e["payload"].get("rule_id") == "verifier/class/1"}
    assert rows[("wire", "algorithm", "key-establishment")] == "wire-kex"
    assert rows[("wire", "certificate", "signature")] == "cert-parse"
    assert all(v == "none" for k, v in rows.items() if k[0] == "host")
    slice_run.close()
    wb = build_all(events(slice_run))["workbench"]
    kinds = {p["value"] for c in wb["components"] for p in c.get("properties", []) if p["name"] == "pqch:verifiable-by"}
    assert kinds == {"wire-kex", "cert-parse", "none"}
    r = score_bom(wb, __import__("yaml").safe_load(KEY.read_text()))
    assert r["verifiers"]["none"] == 29 and r["verifiers"]["wire-kex"] == 14


def test_a_file_no_listener_serves_is_a_conflict_the_wire_wins(slice_run):
    structure(slice_run, POLICY)
    counts = conflicts.resolve(slice_run)
    assert counts == {"conflicts": 1, "wire": 1, "host": 0, "cannot_tell": 0}
    c = next(e for e in events(slice_run) if e["payload"].get("rule_id") == "conflict/resolve/1")
    assert c["actor"]["kind"] == "rule"
    assert c["payload"]["classification"] == {"in_force": "wire", "reason": "not-served"}
    findings = {e["id"]: e["payload"] for e in events(slice_run) if e["type"] == "finding.observed"}
    assert findings[c["payload"]["finding"]]["subject"]["path"].startswith("/etc/ssl/legacy/")
    assert c["payload"]["disagrees_with"] and all(findings[i]["layer"] == "wire" for i in c["payload"]["disagrees_with"])


def test_a_conflict_the_evidence_does_not_decide_is_cannot_tell(tmp_path):
    run = make_run(tmp_path, lambda t: binding_for(t, image=OTHER_IMAGE if t.get("host") == "172.16.106.10" else None))
    structure(run, POLICY)
    conflicts.resolve(run)
    judged = [e["payload"] for e in events(run) if e["payload"].get("rule_id") == "conflict/resolve/1"]
    findings = {e["id"]: e["payload"] for e in events(run) if e["type"] == "finding.observed"}
    portal = [j for j in judged if findings[j["finding"]]["subject"].get("image") == "pqch-agency/portal"]
    assert portal and all(j["classification"] == {"in_force": "cannot-tell", "reason": None} for j in portal)
    assert "did not run the scope's image" in portal[0]["basis"]


def test_a_tools_silence_over_a_file_the_harness_read_is_a_tool_limit(slice_run):
    # The harness's reader finds a certificate in a path cbomkit-theia reported nothing for.
    structure(slice_run, POLICY)
    scan = next(e for e in events(slice_run) if e["type"] == "scan.completed" and "image" in e["payload"]["target"])
    image = scan["payload"]["target"]["image"]
    subject = {"kind": "file", "image": image.split("@")[0], "path": "/etc/tls/mldsa.crt"}
    asset = {"type": "certificate", "role": "signature", "name": "ML-DSA-65", "parameters": {"spki_sha256": "ab" * 32}}
    fp = hash_object({"layer": "host", "subject": subject, "type": "certificate", "role": "signature",
                      "name": "ML-DSA-65", "identity": None})
    slice_run.ledger.append("finding.observed", {"kind": "scanner", "id": "pqch-image-files"}, {
        "schema": "pqch.finding/1", "id": "01M40W6W873YWJMWPKGMK3YBZZ", "observed_at": "2026-10-03T12:00:10Z",
        "layer": "host", "source": {"tool": "pqch-image-files", "version": "m1", "image_digest": scan["payload"]["image_digest"],
                                    "profile": "image-files", "subject_digest": image.split("@")[1]},
        "subject": subject, "asset": asset,
        "evidence": {"raw": "var/raw/x.json", "sha256": "0" * 64, "excerpt": "ML-DSA-65 certificate"},
        "fingerprint": fp}, inputs=[scan["id"]])
    conflicts.resolve(slice_run)
    judged = {e["payload"]["classification"]["reason"]: e["payload"] for e in events(slice_run)
              if e["payload"].get("rule_id") == "conflict/resolve/1"}
    assert judged["tool-limit"]["classification"]["in_force"] == "host"
    assert "cbomkit-theia reported nothing" in judged["tool-limit"]["basis"]


def test_a_ca_certificate_one_tool_marks_is_no_conflict_for_another_tools_reading(slice_run):
    # cbomkit-theia reports the portal's CA certificate with no CA flag; the harness's reader marks the
    # same file is_ca. Neither finding is a conflict: no listener ever serves a CA's certificate.
    structure(slice_run, POLICY)
    scan = next(e for e in events(slice_run) if e["type"] == "scan.completed" and "image" in e["payload"]["target"]
                and e["payload"]["target"]["image"].startswith("pqch-agency/portal"))
    image = scan["payload"]["target"]["image"]
    subject = {"kind": "file", "image": image.split("@")[0], "path": "/etc/ssl/agency-ca.crt"}
    for tool, params, fid in (("cbomkit-theia", {"spki_sha256": "cd" * 32}, "01M40W6W873YWJMWPKGMK3YBY1"),
                              ("pqch-image-files", {"spki_sha256": "cd" * 32, "is_ca": True}, "01M40W6W873YWJMWPKGMK3YBY2")):
        fp = hash_object({"layer": "host", "subject": subject, "type": "certificate", "role": "signature",
                          "name": "ECDSA", "identity": None})
        slice_run.ledger.append("finding.observed", {"kind": "scanner", "id": tool}, {
            "schema": "pqch.finding/1", "id": fid, "observed_at": "2026-10-03T12:00:10Z",
            "layer": "host", "source": {"tool": tool, "version": "x", "image_digest": scan["payload"]["image_digest"],
                                        "profile": "image", "subject_digest": image.split("@")[1]},
            "subject": subject, "asset": {"type": "certificate", "role": "signature", "name": "ECDSA", "parameters": params},
            "evidence": {"raw": "var/raw/x.json", "sha256": "0" * 64, "excerpt": "CA certificate"},
            "fingerprint": fp}, inputs=[scan["id"]])
    counts = conflicts.resolve(slice_run)
    judged = [events(slice_run)[0]["id"] for _ in ()]  # noqa: F841 — placeholder keeps the list form below readable
    paths = [events(slice_run) and next(e["payload"] for e in events(slice_run) if e["id"] == c["payload"]["finding"])["subject"]["path"]
             for c in events(slice_run) if c["payload"].get("rule_id") == "conflict/resolve/1"]
    assert counts["conflicts"] == 1 and "/etc/ssl/agency-ca.crt" not in paths


def _seam(reply: str, roles: dict) -> Seam:
    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "m-fast"}]})
        return httpx.Response(200, json={"model": "m-fast", "usage": {"total_tokens": 9},
                                         "choices": [{"message": {"content": reply}, "finish_reason": "stop"}]})
    cfg = {"schema": "pqch.inference/1", "profile": "test", "roles": roles,
           "tiers": {"fast": {"base_url": "http://seam.test/v1", "api_key_env": "K", "model": "m-fast", "hardware": "test-box"}}}
    return Seam(cfg, transport=httpx.MockTransport(handler))


def test_a_model_may_explain_a_conflict_beside_the_rule_and_never_settles_it(slice_run):
    structure(slice_run, POLICY)
    conflicts.resolve(slice_run)
    # Unbound role: nothing is called, and the count says why.
    out = explain(slice_run, seam=_seam("{}", {"classify-algorithm": {"tier": "fast"}}))
    assert out["explained"] == 0 and "resolve-conflict" in out["skipped"]
    # Bound role, a reply that disagrees with the rule: recorded as the model's, used by no rule.
    out = explain(slice_run, seam=_seam('{"in_force": "host", "reason": "stale-file", "explanation": "x"}',
                                        {"resolve-conflict": {"tier": "fast"}}))
    assert out == {"explained": 1, "agreed": 0, "failed": 0}
    m = next(e for e in events(slice_run) if e["actor"]["kind"] == "model")
    assert m["payload"]["used_by_rules"] is False and m["payload"]["agrees_with_rule"] is False
    rule = next(e for e in events(slice_run) if e["payload"].get("rule_id") == "conflict/resolve/1")
    assert rule["payload"]["classification"] == {"in_force": "wire", "reason": "not-served"}   # unchanged
    slice_run.close()
    wb = build_all(events(slice_run))["workbench"]
    judged = [json.loads(p["value"]) for c in wb["components"] for p in c.get("properties", []) if p["name"] == "pqch:conflict"]
    assert judged == [{"in_force": "wire", "reason": "not-served", "event": rule["id"]}]


def test_the_page_shows_the_chain_and_the_receipts(tmp_path, monkeypatch):
    import warnings
    run = make_run(tmp_path)
    structure(run, POLICY)
    enrich(run, author="owner")
    run.close()
    write_cboms(run)
    write_score(run, KEY)
    monkeypatch.setenv("PQCH_VAR", str(run.var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        monkeypatch.setattr(ui, "VAR", run.var)
        html = TestClient(ui.app).get("/walkthrough").text
    assert "chain complete" in html and "benefits enrollment" in html
    assert html.count('class="tag supplied"') >= 12
    assert "The receipts" in html and "of 4 listeners complete" in html
    assert "not-served" in html and "conflict/resolve/1" in html
    assert "no verifier" in html
