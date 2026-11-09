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


def test_the_cnsa_pack_is_read_first_hand_and_every_quote_is_the_faqs_own_words():
    pack = load_pack("policy/packs/cnsa-2.0.yaml")
    assert pack["verified"] is True and pack["source"]["read_first_hand"] == date(2026, 11, 9)
    assert pack["source"]["pdf_sha256"].startswith("bc430341") and "Ver. 2.2" in pack["source"]["version"]
    text = Path(pack["source"]["text"]).read_text()
    assert check_quotes(pack, text) == []
    assert [d["by"].isoformat() for d in pack["timeline"]["dates"]][:3] == ["2027-01-01", "2030-12-31", "2031-12-31"]
    assert pack["compatible"]["names"] == {"key-establishment": ["ML-KEM-1024"], "signature": ["ML-DSA-87"],
                                           "encryption": ["AES-256"], "hash": ["SHA-384", "SHA-512"]}
    assert pack["compatible"]["unsettled"] == ["SecP384r1MLKEM1024"]        # no TLS hybrid is NSA-identified
    bad = copy.deepcopy(pack)
    bad["timeline"]["dates"][2]["quote"] = "By December 31, 2033, CNSA 2.0 algorithms are mandated for use"
    assert [b.split(":")[0] for b in check_quotes(bad, text)] == ["$.timeline.dates[2].quote"]


def test_a_pack_not_read_first_hand_must_say_unverified(tmp_path):
    doc = yaml.safe_load(Path("policy/packs/cnsa-2.0.yaml").read_text())
    doc["source"] = {"url": doc["source"]["url"], "read_first_hand": False}
    doc["verified"] = False
    (tmp_path / "p.yaml").write_text(yaml.safe_dump(doc))
    assert load_pack(tmp_path / "p.yaml")["verified"] is False
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


# ---- NIST IR 8547 beside M-26-15 (M8, FR-10)

IR = "policy/packs/ir-8547.yaml"


def test_every_quote_in_the_ir_8547_pack_is_the_reports_own_words():
    pack = load_pack(IR)
    assert pack["source"]["pdf_sha256"].startswith("3049cdfd")
    assert str(pack["transition"]["deprecated_after"]) == "2030-12-31"
    assert str(pack["transition"]["disallowed_after"]) == "2035-12-31"
    text = Path(pack["source"]["text"]).read_text()
    bad = copy.deepcopy(pack)
    bad["transition"]["quote"] = "NIST will disallow quantum-vulnerable public-key cryptography after 2031."
    assert check_quotes(bad, text) and check_quotes(pack, text) == []


def test_each_open_item_names_which_source_set_its_deadline(slice_run):
    prepared(slice_run)
    q = {(e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]): e["payload"]["classification"]
         for e in rule(slice_run, "queue/m-26-15/1")}
    # Prioritized: the memo's dates are earlier than the report's disallowance, and the memo sets them.
    portal = q[("portal", "key-establishment")]
    assert portal["deadline"] == "2030-12-31" and portal["deadline_set_by"] == ["m-26-15 §3.A; 3.D Phase 3"]
    assert portal["deprecated_after"] == "2030-12-31" and portal["disallowed_after"] == "2035-12-31"
    sig = q[("portal", "signature")]
    assert sig["deadline"] == "2031-12-31" and sig["deprecated_after"] == "2030-12-31"
    # Remaining: both sources set 2035-12-31, and the report deprecates the algorithms after 2030.
    bastion = q[("bastion", "key-establishment")]
    assert bastion["deadline"] == "2035-12-31"
    assert bastion["deadline_set_by"] == ["m-26-15 §3.D Phase 5", "ir-8547 Table 4 (§4.1.2)"]
    assert bastion["transition"]["covers"] and "strength_basis" in bastion["transition"]
    # A met item carries no date from either source.
    met = [c for c in q.values() if c["state"] == "met"]
    assert all(c["deadline"] is None and "deprecated_after" not in c for c in met)


def test_a_name_no_ir_8547_row_covers_is_recorded_not_dated():
    fam = load_families(FAM)
    t = managed._transition(load_pack(IR), fam, "key-establishment", ["sntrup761x25519", "X25519"])
    assert t["covers"] == ["X25519"] and t["not_covered"] == ["sntrup761x25519"]
    assert managed._transition(load_pack(IR), fam, "signature", ["DSA"]) is None
    assert managed._transition(load_pack(IR), fam, "signature", ["Ed25519"])["rows"][0]["row"] == "EdDSA"


def test_the_rows_key_size_condition_is_checked_where_the_finding_carries_one():
    fam = load_families(FAM)
    ir = load_pack(IR)
    # RSA-1024 is below 112 bits: already disallowed, not dated 2035. RSA-2048 is 112 and in the row.
    t = managed._transition(ir, fam, "signature", ["RSA"], {"RSA": [{"key_bits": 1024}]})
    assert t["below_condition"] == ["RSA"] and t["parameters_checked"] is True
    t = managed._transition(ir, fam, "signature", ["RSA"], {"RSA": [{"key_bits": 2048}]})
    assert t["below_condition"] == [] and t["parameters_checked"] is True
    # A 1024-bit and a 2048-bit key under one name: the name is not below (its strongest key is in the row).
    t = managed._transition(ir, fam, "signature", ["RSA"], {"RSA": [{"key_bits": 1024}, {"key_bits": 2048}]})
    assert t["below_condition"] == []
    # No key size at all: unchecked, and the item says so.
    t = managed._transition(ir, fam, "key-establishment", ["RSA"], {"RSA": [{}]})
    assert t["unchecked"] == ["RSA"] and t["parameters_checked"] is False
    # Sizes the name itself carries: DH-1024 is 80 bits; X25519, secp256r1 and Ed25519 are 128.
    assert managed._transition(ir, fam, "key-establishment", ["DH-1024"])["below_condition"] == ["DH-1024"]
    for fn, name in (("key-establishment", "X25519"), ("key-establishment", "secp256r1"), ("signature", "Ed25519")):
        t = managed._transition(ir, fam, fn, [name])
        assert t["below_condition"] == [] and t["unchecked"] == [], name
    assert managed.classical_strength("signature", "RSA", "rsa-sig", {"key_bits": 3072}) == 128
    assert managed.classical_strength("key-establishment", "DH-GEX", "finite-field-dh", {}) is None
    assert managed._transition(None, fam, "signature", ["ECDSA"]) is None


def test_the_cbom_says_which_source_set_the_deadline_and_when_ir_8547_deprecates(slice_run):
    prepared(slice_run)
    slice_run.close()
    wb = build_all(ev(slice_run))["workbench"]
    svc = {c["name"]: {p["name"]: p["value"] for p in c["properties"]} for c in wb["components"] if c["type"] == "application"}
    assert svc["portal"]["pqch:deprecated-after"] == "2030-12-31"
    assert "m-26-15" in svc["portal"]["pqch:deadline-set-by"]
    assert "ir-8547" in svc["bastion"]["pqch:deadline-set-by"]


def test_without_the_transition_pack_the_items_are_as_before(slice_run, tmp_path):
    import shutil
    shutil.copy(PACK, tmp_path / "m-26-15.yaml")
    structure(slice_run, POLICY)
    chains.link_services(slice_run)
    chains.supply(slice_run, "agency/context.yaml", author="owner")
    managed.assess(slice_run, pack_path=tmp_path / "m-26-15.yaml", families_path=FAM, capabilities_path=CAPS,
                   cmvp_path=CMVP, as_of=date(2026, 10, 20))
    c = [e["payload"]["classification"] for e in rule(slice_run, "queue/m-26-15/1")]
    assert c and all("deadline_set_by" not in x and "deprecated_after" not in x for x in c)


# ---- M10: every entry tagged under the pack that governs it

def test_every_entry_carries_a_status_and_unknown_is_never_folded_into_a_verdict(slice_run):
    counts = prepared(slice_run)
    events = ev(slice_run)
    fps = {e["payload"]["fingerprint"] for e in events if e["type"] == "finding.observed"}
    tagged = {e["payload"]["subject"]["fingerprint"]: e["payload"] for e in rule(slice_run, "compatibility/entry/1")}
    assert set(tagged) == fps                                   # one judgement per entry, none skipped
    by_status = {}
    for p in tagged.values():
        by_status.setdefault(p["classification"]["status"], set()).add(p["classification"]["name"])
    assert by_status["compatible"] == {"X25519MLKEM768"}
    assert {"RSA", "ECDSA", "DH-1024", "X25519", "Ed25519", "sntrup761x25519"} <= by_status["not-compatible"]
    assert by_status["outside-pack"] <= {"SHA-1", "SHA-256", "SSH 2.0"}   # the memo names no hash or protocol
    assert by_status["unknown"] == {"unknown"}                      # an unopened key: nothing to judge
    assert all(p["classification"]["provisional"] is False and p["classification"]["pack"] == "m-26-15" for p in tagged.values())
    assert counts["compatibility"] == {"m-26-15": {s: len([p for p in tagged.values() if p["classification"]["status"] == s])
                                                   for s in ("not-compatible", "compatible", "outside-pack", "unknown")}}
    # The judgement names its inputs: the findings folded into the entry, and the service link where there is one.
    one = next(p for p in rule(slice_run, "compatibility/entry/1") if p["payload"]["classification"]["service"])
    assert len(one["inputs"]) >= 2


@pytest.mark.parametrize("asset,status,why", [
    ({"type": "certificate", "role": "signature", "name": "RSA", "parameters": {"key_bits": 2048}}, "not-compatible", "RSA"),
    ({"type": "related-crypto-material", "role": "other", "name": "ML-DSA-65", "parameters": {}}, "compatible", "FIPS 204"),
    ({"type": "related-crypto-material", "role": "other", "name": "generic-api-key", "parameters": {}}, "unknown", "names no algorithm"),
    ({"type": "algorithm", "role": "encryption", "name": "RSA", "parameters": {}}, "not-compatible", "RSA Key Establishment"),
    ({"type": "algorithm", "role": "hash", "name": "SHA-256", "parameters": {}}, "outside-pack", "asymmetric algorithms only"),
    ({"type": "protocol", "role": "other", "name": "TLS 1.2", "parameters": {}}, "outside-pack", "protocol version"),
])
def test_the_memos_compatibility_follows_its_resistant_and_vulnerable_families(asset, status, why):
    c = managed.entry_compatibility(load_pack(PACK), load_families(FAM), {"asset": asset})
    assert c["status"] == status and why in c["basis"]


@pytest.mark.parametrize("asset,status,why", [
    ({"type": "algorithm", "role": "key-establishment", "name": "ML-KEM-1024", "parameters": {}}, "compatible", "names for key-establishment"),
    ({"type": "algorithm", "role": "key-establishment", "name": "X25519MLKEM768", "parameters": {}}, "not-compatible", "ML-KEM-1024"),
    ({"type": "algorithm", "role": "key-establishment", "name": "SecP384r1MLKEM1024", "parameters": {}}, "unknown", "does not place"),
    ({"type": "related-crypto-material", "role": "other", "name": "ML-DSA-65", "parameters": {}}, "not-compatible", "ML-DSA-87"),
    ({"type": "algorithm", "role": "hash", "name": "SHA-256", "parameters": {}}, "not-compatible", "SHA-384, SHA-512"),
    ({"type": "algorithm", "role": "mac", "name": "HMAC", "parameters": {}}, "outside-pack", "names no algorithm for mac"),
])
def test_cnsa_names_one_algorithm_per_function_and_leaves_a_hybrid_unsettled(asset, status, why):
    c = managed.entry_compatibility(load_pack("policy/packs/cnsa-2.0.yaml"), load_families(FAM), {"asset": asset})
    assert c["status"] == status and why in c["basis"]


def test_a_national_security_systems_entries_are_judged_under_cnsa_and_are_not_provisional(slice_run, tmp_path):
    ctx = yaml.safe_load(Path("agency/context.yaml").read_text())
    ctx["services"]["portal"]["national_security_system"] = True
    (tmp_path / "ctx.yaml").write_text(yaml.safe_dump(ctx))
    counts = prepared(slice_run, context=tmp_path / "ctx.yaml")
    portal = [e["payload"]["classification"] for e in rule(slice_run, "compatibility/entry/1")
              if e["payload"]["classification"]["service"] == "portal"]
    assert portal and all(c["pack"] == "cnsa-2.0" and c["provisional"] is False for c in portal)   # the FAQ is read first-hand
    scope = next(e for e in rule(slice_run, "pack/scope/1") if e["payload"]["subject"]["name"] == "portal")
    assert "2027-01-01" in scope["payload"]["basis"] and "2031-12-31" in scope["payload"]["basis"] and "not verified" not in scope["payload"]["basis"]
    assert {"X25519", "SHA-256"} <= {c["name"] for c in portal if c["status"] == "not-compatible"}   # SHA-256 is not the suite's hash
    others = [e["payload"]["classification"] for e in rule(slice_run, "compatibility/entry/1")
              if e["payload"]["classification"]["service"] not in (None, "portal")]
    assert others and all(c["pack"] == "m-26-15" and c["provisional"] is False for c in others)
    assert set(counts["compatibility"]) == {"m-26-15", "cnsa-2.0"}


def test_the_cbom_and_the_inventory_carry_the_status(slice_run):
    from pqch.cbom import anatomy, tables

    prepared(slice_run)
    slice_run.close()
    events = ev(slice_run)
    wb = build_all(events)["workbench"]
    tagged = {c["bom-ref"]: json.loads(p["value"]) for c in wb["components"] for p in c.get("properties", [])
              if p["name"] == "pqch:compatibility"}
    assets = [c for c in wb["components"] if c["type"] == "cryptographic-asset" and any(p["name"] == "pqch:fingerprint" for p in c["properties"])]
    assert set(tagged) == {c["bom-ref"] for c in assets}
    assert set(tagged[assets[0]["bom-ref"]]) == {"status", "pack", "provisional", "basis", "event"}
    d = anatomy.compatibility(wb)
    assert d["entries"] == len(assets) and sum(d["all"].values()) == d["entries"] and d["in_use"]["compatible"] <= d["all"]["compatible"]
    assert d["in_use"]["not-compatible"] < d["all"]["not-compatible"]       # the retired certificate is not in use
    assert d["packs"] == ["m-26-15"] and d["provisional"] is False
    t = tables.rebuild(events, tables.load("policy/projections/agency-inventory.yaml"))
    col = t["columns"].index("compatibility")
    assert {r[col] for r in t["rows"]} <= {"compatible", "not-compatible", "unknown", "outside-pack"} and t["rows"]
    for name, bom in build_all(events).items():
        if name.startswith("baseline"):
            assert not any(p["name"] == "pqch:compatibility" for c in bom["components"] for p in c.get("properties", []))


def test_an_algorithm_cnsa_allows_in_one_application_is_judged_by_where_the_entry_is():
    pack = load_pack("policy/packs/cnsa-2.0.yaml")
    fam = load_families(FAM)

    def f(layer, role, name, typ="algorithm"):
        return {"layer": layer, "asset": {"type": typ, "role": role, "name": name, "parameters": {}}}

    got = {(layer, name): managed.entry_compatibility(pack, fam, f(layer, role, name))
           for layer in ("platform", "host", "wire") for role, name in (("signature", "LMS"), ("signature", "XMSS"), ("hash", "SHA3-384"))}
    assert {got[("platform", n)]["status"] for n in ("LMS", "XMSS", "SHA3-384")} == {"compatible"}
    assert "signing firmware and software" in got[("platform", "LMS")]["basis"]
    assert got[("host", "LMS")]["status"] == "unknown" and "does not say what it signs" in got[("host", "LMS")]["basis"]
    assert got[("wire", "SHA3-384")]["status"] == "not-compatible" and "internal hardware integrity" in got[("wire", "SHA3-384")]["basis"]
    assert managed.entry_compatibility(pack, fam, f("wire", "signature", "ML-DSA-87"))["status"] == "compatible"
    assert managed.entry_compatibility(pack, fam, f("platform", "hash", "SHA-256"))["status"] == "not-compatible"


def test_the_plan_and_the_cbom_page_count_the_same_entries(slice_run):
    from pqch import cbom, planning
    from pqch.cbom import anatomy

    prepared(slice_run)
    events = ev(slice_run)
    page = anatomy.compatibility(cbom.project(events))
    plan = planning._compatibility_counts(events)
    assert {s: plan[s] for s in page["all"]} == page["all"] and plan["entries"] == page["entries"]
    judged = len(rule(slice_run, "compatibility/entry/1"))
    assert judged >= page["entries"]        # the rule judges each fingerprint; several can fold onto one entry
