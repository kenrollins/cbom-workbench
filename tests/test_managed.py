"""M2: the policy pack as data, the queues by deadline, and the blockers as explicit states."""

import copy
import json
from datetime import date
from pathlib import Path

import pytest
import yaml

from pqch.assessor import chains, load_policy, managed, structure
from pqch.cbom import build_all
from pqch.common import hash_object
from pqch.policy import check_quotes, family_of, load_families, load_pack, vulnerability

POLICY = load_policy("policy/pq-algorithms.yaml")
PACK = "policy/packs/m-26-15.yaml"
FAM = "policy/algorithm-families.yaml"
CAPS = sorted(Path("policy/snapshots").glob("capabilities-*.json"))[-1]
CMVP = sorted(Path("policy/snapshots").glob("cmvp-*.json"))[-1]


def ev(run):
    return list(run.ledger.events())


def rule(run, rid):
    return [e for e in ev(run) if e["type"] == "assessment.made" and e["payload"].get("rule_id") == rid]


def prepared(run, context="agency/context.yaml"):
    structure(run, POLICY)
    chains.link_services(run)
    chains.supply(run, context, author="owner")
    return managed.assess(run, pack_path=PACK, families_path=FAM, capabilities_path=CAPS, cmvp_path=CMVP,
                          as_of=date(2026, 10, 20))


def test_every_quote_in_the_pack_is_the_memos_own_words():
    pack = load_pack(PACK)
    text = Path(pack["source"]["text"]).read_text()
    assert check_quotes(pack, text) == []
    bad = copy.deepcopy(pack)
    bad["queues"][0]["quote"] = "Agencies must migrate key establishment by 2029."
    assert check_quotes(bad, text) == ["$.queues[0].quote: 'Agencies must migrate key establishment by 2029'"]


def test_a_pack_not_read_first_hand_must_say_unverified(tmp_path):
    assert load_pack("policy/packs/cnsa-2.0.yaml")["verified"] is False
    doc = yaml.safe_load(Path("policy/packs/cnsa-2.0.yaml").read_text())
    doc.pop("verified")
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(doc))
    with pytest.raises(ValueError, match="verified: false"):
        load_pack(tmp_path / "p.yaml")


@pytest.mark.parametrize("role,name,vulnerable,why", [
    ("key-establishment", "X25519", True, "Elliptic Curve Diffie-Hellman"),
    ("key-establishment", "RSA", True, "RSA Key Establishment"),
    ("key-establishment", "X25519MLKEM768", False, "break both"),
    ("key-establishment", "sntrup761x25519", True, "footnote 13"),
    ("signature", "Ed25519", True, "footnote 13"),
    ("signature", "ML-DSA-65", False, "FIPS 204"),
    ("signature", "SomethingNew", True, "footnote 13"),     # unknown asymmetric: footnote 13
])
def test_the_memos_table_and_footnote_13_decide_vulnerability(role, name, vulnerable, why):
    pack, fam = load_pack(PACK), load_families(FAM)
    v, basis = vulnerability(pack, family_of(fam, role, name), role)
    assert v is vulnerable and why in basis


def test_priority_follows_the_memos_criteria_on_the_owners_facts(slice_run):
    prepared(slice_run)
    p = {e["payload"]["subject"]["name"]: e for e in rule(slice_run, "priority/m-26-15/1")}
    assert p["sftp-legacy"]["payload"]["classification"]["criteria"] == ["high-impact", "high-value-asset", "sensitive-in-2030"]
    assert p["portal"]["payload"]["classification"]["criteria"] == ["sensitive-in-2030"]      # 10 years: 2036
    assert p["bastion"]["payload"]["classification"] == {"prioritized": False, "criteria": [], "as_of": "2026-10-20",
                                                         "sensitive_through": 2027}
    supplied = {e["id"] for e in ev(slice_run) if e["type"] == "link.asserted" and e["payload"].get("status") == "supplied"}
    assert set(p["portal"]["inputs"]) <= supplied and p["portal"]["inputs"]


def test_each_item_sits_in_the_queue_the_memo_names_with_its_deadline(slice_run):
    prepared(slice_run)
    q = {(e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]): e["payload"] for e in rule(slice_run, "queue/m-26-15/1")}
    assert q[("portal", "key-establishment")]["classification"]["queue"] == "kex-2030"
    assert q[("portal", "key-establishment")]["classification"]["deadline"] == "2030-12-31"
    assert q[("portal", "signature")]["classification"]["queue"] == "sig-2031"
    assert q[("portal", "signature")]["classification"]["deadline_basis"] == "computed"
    assert q[("bastion", "key-establishment")]["classification"]["queue"] == "remaining-2035"
    # A hybrid group beside a classical one is enabled, not enforced: the item stays open.
    api = q[("api", "key-establishment")]
    assert api["classification"]["state"] == "open" and "enabled, not enforced" in api["basis"]
    assert api["classification"]["post_quantum"] == ["X25519MLKEM768"]


def test_a_service_whose_software_cannot_take_pq_is_blocked_on_its_supplier_and_marked_for_replacement(slice_run):
    prepared(slice_run)
    b = {(e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]): e for e in rule(slice_run, "blocker/supplier/1")}
    sftp = b[("sftp-legacy", "key-establishment")]
    assert sftp["payload"]["classification"] == {"state": "blocked", "replace_priority": True}
    assert "OpenSSH 6.6" in sftp["payload"]["basis"] and sftp["evidence"][0]["ref"].startswith("eval/capabilities/")
    assert b[("bastion", "key-establishment")]["payload"]["classification"]["state"] == "not-blocked"
    assert b[("bastion", "signature")]["payload"]["classification"]["state"] == "blocked"   # no PQ host key in OpenSSH 10
    # The nginx image lists nothing; the same library build was seen offering the hybrid group on the wire.
    assert b[("portal", "key-establishment")]["payload"]["classification"]["state"] == "not-blocked"


def test_the_validated_module_state_comes_from_the_dated_cmvp_snapshot(slice_run):
    prepared(slice_run)
    vm = {(e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]): e["payload"] for e in rule(slice_run, "blocker/validated-module/1")}
    portal = vm[("portal", "key-establishment")]
    assert portal["classification"]["state"] == "available-not-in-use" and portal["classification"]["library"] == "openssl"
    cmvp = json.loads(CMVP.read_text())
    assert all(cmvp["certificates"][str(n)]["approved_ml_kem"] for n in portal["classification"]["certificates"])
    assert vm[("sftp-legacy", "key-establishment")]["classification"]["state"] == "none-validated"


def test_a_national_security_system_is_governed_by_cnsa_and_gets_no_m_26_15_deadline(slice_run, tmp_path):
    ctx = yaml.safe_load(Path("agency/context.yaml").read_text())
    ctx["services"]["portal"]["national_security_system"] = True
    (tmp_path / "ctx.yaml").write_text(yaml.safe_dump(ctx))
    prepared(slice_run, context=tmp_path / "ctx.yaml")
    scope = {e["payload"]["subject"]["name"]: e["payload"]["classification"] for e in rule(slice_run, "pack/scope/1")}
    assert scope["portal"] == {"pack": "cnsa-2.0", "national_security_system": True}
    assert not [e for e in rule(slice_run, "queue/m-26-15/1") if e["payload"]["subject"]["service"] == "portal"]


def test_a_listener_with_no_tls_1_3_is_an_item_against_the_2030_01_02_date(slice_run):
    structure(slice_run, POLICY)
    chains.link_services(slice_run)
    scan = next(e for e in ev(slice_run) if e["type"] == "scan.completed" and e["payload"]["target"].get("host") == "172.16.106.10")
    subject = {"kind": "endpoint", "host": "172.16.106.10", "port": 443, "protocol": "tls", "sni": "portal.agency.test"}
    fp = hash_object({"layer": "wire", "subject": subject, "type": "protocol", "role": "other", "name": "TLS 1.2", "identity": None})
    slice_run.ledger.append("finding.observed", {"kind": "scanner", "id": "testssl.sh"}, {
        "schema": "pqch.finding/1", "id": "01M40W6W873YWJMWPKGMK3YBX1", "observed_at": "2026-10-03T12:00:10Z", "layer": "wire",
        "source": {"tool": "testssl.sh", "version": "x", "image_digest": scan["payload"]["image_digest"], "profile": "tls-targeted"},
        "subject": subject, "asset": {"type": "protocol", "role": "other", "name": "TLS 1.2", "parameters": {"suites_accepted": 3}},
        "evidence": {"raw": "var/raw/x.json", "sha256": "0" * 64, "excerpt": "3 cipher suites accepted with TLSv1.2"},
        "fingerprint": fp}, inputs=[scan["id"]])
    chains.supply(slice_run, "agency/context.yaml", author="owner")
    managed.assess(slice_run, pack_path=PACK, families_path=FAM, capabilities_path=CAPS, cmvp_path=CMVP, as_of=date(2026, 10, 20))
    t = rule(slice_run, "deadline/tls13/1")
    assert len(t) == 1 and t[0]["payload"]["classification"]["queue"] == "tls13-2030"
    assert t[0]["payload"]["classification"]["deadline"] == "2030-01-02" and t[0]["payload"]["source"]["section"] == "4"


def test_the_cbom_carries_owner_queue_deadline_and_vulnerability(slice_run):
    prepared(slice_run)
    slice_run.close()
    wb = build_all(ev(slice_run))["workbench"]
    svc = {c["name"]: {p["name"]: p["value"] for p in c["properties"]} for c in wb["components"] if c["type"] == "application"}
    assert svc["portal"]["pqch:owner"] == "Web team" and svc["portal"]["pqch:queue"] == "kex-2030"
    assert svc["portal"]["pqch:deadline"] == "2030-12-31" and svc["portal"]["pqch:state"] == "open"
    items = json.loads(svc["sftp-legacy"]["pqch:migration"])
    assert {i["function"]: i["blockers"]["supplier"] for i in items} == {"key-establishment": "blocked", "signature": "blocked"}
    vul = {p["value"] for c in wb["components"] for p in c.get("properties", []) if p["name"] == "pqch:quantum-vulnerable"}
    assert vul == {"true", "false"}


def _seam(reply_for):
    import httpx

    from pqch.inference import Seam

    def handler(req):
        body = json.loads(req.content)
        if req.url.path.endswith("/embeddings"):
            # A deterministic embedding: bag of words over a tiny vocabulary.
            vocab = ["key", "establishment", "signature", "2030", "2031", "2035", "prioritize", "replacement", "high", "sensitive"]
            return httpx.Response(200, json={"data": [{"embedding": [t.lower().count(w) + 0.01 for w in vocab]} for t in body["input"]]})
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "m"}]})
        user = body["messages"][-1]["content"]
        return httpx.Response(200, json={"model": "m", "usage": {"total_tokens": 50},
                                         "choices": [{"message": {"content": json.dumps(reply_for(user))}, "finish_reason": "stop"}]})
    cfg = {"schema": "pqch.inference/1", "profile": "t", "roles": {"explain-queue": {"tier": "fast"}},
           "tiers": {"fast": {"base_url": "http://x.test/v1", "api_key_env": "K", "model": "m", "hardware": "box"},
                     "embed": {"base_url": "http://x.test/v1", "api_key_env": "K", "model": "e", "hardware": "box"}}}
    return Seam(cfg, transport=httpx.MockTransport(handler))


def test_an_explanation_is_checked_against_the_rule_that_fired(slice_run, monkeypatch):
    import pqch.assessor.explain_queue as xq
    from pqch.assessor.explain_queue import check, explain
    monkeypatch.setattr(xq, "TOP_K", 99)     # the toy embedding is no ranker; test the check, not retrieval
    prepared(slice_run)
    slice_run.close()

    def right(user):
        q = "kex-2030" if "key-establishment" in user.split("\n")[0] and "Prioritized by: none" not in user else (
            "sig-2031" if "Prioritized by: none" not in user else "remaining-2035")
        return {"queue": q, "cites": [f"queue:{q}"], "explanation": "because"}
    run, s = explain(slice_run.var, slice_run, pack_path=PACK, seam=_seam(right), repeats=3)
    assert s["items"] == s["passed"] == 8 and s["harmful_calls"] == 0 and s["calls"] == 24
    e = next(x for x in run.ledger.events() if x["payload"].get("purpose") == "explain-queue")
    assert e["actor"]["kind"] == "model" and e["payload"]["used_by_rules"] is False
    assert all(isinstance(t["score_milli"], int) for t in e["payload"]["retrieval"]["top"])
    # The check itself: another queue is harmful; an unretrieved passage fails.
    assert check({"queue": "sig-2031", "cites": ["queue:sig-2031"]}, "kex-2030", ["queue:sig-2031"])["harmful"] is True
    assert check({"queue": "kex-2030", "cites": ["queue:kex-2030", "replace"]}, "kex-2030", ["queue:kex-2030"])["why"].startswith("cites passages not retrieved")
    # The rule's own events are untouched by any of it.
    assert not [x for x in slice_run.ledger.events() if x["payload"].get("purpose") == "explain-queue"]


def test_the_page_shows_no_model_explanation_while_the_role_is_unbound(monkeypatch):
    from pqch.ui import view

    class Cfg:
        config = {"roles": {"trace-to-cause": {"tier": "deliberate"}}}  # noqa: RUF012
    monkeypatch.setattr("pqch.inference.default", lambda: Cfg())
    assert view.role_bound("explain-queue") is False and view.role_bound("trace-to-cause") is True
