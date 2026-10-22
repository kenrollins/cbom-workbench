import json
"""The verifier (pqch.verifier/1): no model, a pair of probes and a witness, bound to what was probed."""

from pathlib import Path

import pytest

from pqch.runner.client import RunnerRefused
from pqch.verifier import parse_probe, parse_witness, status_of, verify

FIX = Path(__file__).parent / "fixtures"
APPLIED = {"id": "01M40W6W873YWJMWPKGMK3YBMA", "type": "change.applied", "ts": "2026-10-03T12:00:00.000Z"}
NEW = {"container_id": "n" * 64, "image_digest": "sha256:" + "a" * 64}
CHECK = {"schema": "pqch.verifier/1", "kind": "wire-kex", "intent": "require",
         "target": {"host": "172.16.106.10", "port": 443, "protocol": "tls", "sni": "portal.agency.test"},
         "must_accept": ["X25519MLKEM768"], "must_refuse": ["X25519", "secp256r1"]}


def test_parse_probe_on_real_output():
    r = parse_probe((FIX / "probe-refused.txt").read_text())
    assert r["result"] == "refused" and r["negotiated"] is None
    c = parse_probe((FIX / "probe-classical-accepted.txt").read_text())
    assert c["result"] == "accepted" and c["negotiated"] == "X25519" and len(c["cert_sha256"]) == 64
    h = parse_probe((FIX / "probe-hybrid-accepted.txt").read_text())
    assert h["result"] == "accepted" and h["negotiated"] == "X25519MLKEM768"
    assert parse_probe("connect:errno=111\nPQCH_EXIT=1")["result"] == "error"


def test_parse_witness():
    assert parse_witness((FIX / "testssl-api.json").read_bytes()) == {"X25519", "X25519MLKEM768"}
    assert parse_witness((FIX / "testssl-portal.json").read_bytes()) == {"X25519", "secp256r1"}


@pytest.mark.parametrize("pos,neg,status", [
    ("accepted", "refused", "enforced"), ("accepted", "accepted", "enabled-not-enforced"),
    ("refused", "refused", "not-landed"), ("refused", "accepted", "not-landed"),
    ("error", "refused", "inconclusive"), ("accepted", "error", "inconclusive"),
])
def test_status_table(pos, neg, status):
    assert status_of(pos, neg) == status


class FakeRunner:
    """Answers the three probe jobs with captured output, and a binding per probe."""

    def __init__(self, positive, negative, witness, *, container=NEW, started="2026-10-03T12:00:01.000Z",
                 stable=True, refuse=None):
        self.out = {"positive": positive, "negative": negative, "witness": witness}
        self.container, self.started, self.stable, self.refuse = container, started, stable, refuse
        self.calls = []

    def job(self, profile, target, scope_hash, params=None):
        name = "witness" if profile == "tls-witness" else ("positive" if params["tls13"] else "negative")
        self.calls.append((name, profile, params))
        if self.refuse == name:
            raise RunnerRefused(403, "not in the scope")
        return {"tool": "t", "version": "v", "image_digest": "sha256:" + "f" * 64, "status": "ok",
                "started_at": self.started, "ended_at": "2026-10-03T12:00:02.000Z",
                "raw": f"var/raw/{name}", "raw_sha256": "0" * 64,
                "binding": {"container_id": self.container["container_id"],
                            "image_digest": self.container["image_digest"], "stable": self.stable}}


def run(fake):
    raws = {"var/raw/positive": fake.out["positive"], "var/raw/negative": fake.out["negative"],
            "var/raw/witness": fake.out["witness"]}
    return verify(fake, "h", CHECK, change_id="c1", after_event=APPLIED, expect=NEW,
                  read_raw=lambda job: raws[job["raw"]], hardware="test")


ACC_H = (FIX / "probe-hybrid-accepted.txt").read_bytes()
ACC_C = (FIX / "probe-classical-accepted.txt").read_bytes()
REF = (FIX / "probe-refused.txt").read_bytes()
W_HYB = (FIX / "testssl-api.json").read_bytes()
W_CLS = (FIX / "testssl-portal.json").read_bytes()


def _witness(curves: str) -> bytes:
    """The api listener's testssl.sh output with its classical curves line replaced."""
    import json
    doc = json.loads(W_HYB)
    for e in doc:
        if e["id"] == "FS_ECDHE_curves":
            e["finding"] = curves
    return json.dumps(doc).encode()


W_ENF = _witness("")                 # hybrid only
W_EXTRA = _witness("secp384r1")      # hybrid, and a classical group the pair did not sample


def test_enabled_not_enforced_is_its_own_state_and_never_meets_require():
    v = run(FakeRunner(ACC_H, ACC_C, W_HYB))
    assert v["status"] == "enabled-not-enforced" and v["meets_intent"] is False and not v["reasons"]
    assert v["binding"]["container_id"] == NEW["container_id"] and v["binding"]["cert_fingerprint"]


def test_enforced():
    v = run(FakeRunner(ACC_H, REF, W_ENF))
    assert v["status"] == "enforced" and v["meets_intent"] is True and v["also_accepts"] == []


def test_a_classical_group_only_the_witness_saw_rules_out_enforced():
    """M0A review F-44: hybrid plus secp384r1 passed a pair that sampled X25519 and P-256."""
    v = run(FakeRunner(ACC_H, REF, W_EXTRA))
    assert v["status"] == "enabled-not-enforced" and v["meets_intent"] is False
    assert v["also_accepts"] == ["secp384r1"]


def test_a_timed_out_probe_gives_no_verdict_either_way():
    class Slow(FakeRunner):
        def job(self, profile, target, scope_hash, params=None):
            j = super().job(profile, target, scope_hash, params)
            if profile == "tls-witness":
                j.update(status="timeout", raw=None, raw_sha256=None)
            return j
    v = run(Slow(ACC_H, REF, W_ENF))
    assert v["status"] == "inconclusive" and any("timeout" in r for r in v["reasons"])


def test_the_refuse_list_is_every_classical_group_not_the_configured_two():
    from pqch.migrator import render
    policy = render.load("policy/crypto-policy.yaml")
    t = {"service": "portal", "address": "172.16.106.10", "port": 443, "intent": "require"}
    refuse = render.check(policy, t, None)["must_refuse"]
    assert {"secp384r1", "secp521r1", "X448", "ffdhe2048"} <= set(refuse)
    t["intent"] = "none"
    assert "SecP256r1MLKEM768" in render.check(policy, t, None)["must_refuse"]


def test_the_probes_offer_only_the_named_groups():
    fake = FakeRunner(ACC_H, REF, W_HYB)
    run(fake)
    params = {name: p for name, _, p in fake.calls}
    assert params["positive"] == {"groups": "X25519MLKEM768", "tls13": "-tls1_3"}
    assert params["negative"] == {"groups": "X25519:P-256", "tls13": ""}   # the check's own list, verbatim


def test_not_landed():
    assert run(FakeRunner(REF, ACC_C, W_CLS))["status"] == "not-landed"


@pytest.mark.parametrize("fake,reason", [
    (lambda: FakeRunner(ACC_H, REF, W_ENF, container={"container_id": "w" * 64, "image_digest": NEW["image_digest"]}),
     "the one the change was applied to"),
    (lambda: FakeRunner(ACC_H, REF, W_HYB, container={"container_id": NEW["container_id"], "image_digest": "sha256:" + "b" * 64}),
     "runs image"),
    (lambda: FakeRunner(ACC_H, REF, W_HYB, started="2026-10-03T11:59:59.000Z"), "not after change.applied"),
    (lambda: FakeRunner(ACC_H, REF, W_HYB, stable=False), "changed during the probe"),
    (lambda: FakeRunner(ACC_H, REF, W_CLS), "witness"),
    (lambda: FakeRunner(ACC_H, REF, W_HYB, refuse="negative"), "refused the job"),
])
def test_inconclusive(fake, reason):
    v = run(fake())
    assert v["status"] == "inconclusive" and v["meets_intent"] is False
    assert any(reason in r for r in v["reasons"]), v["reasons"]


def test_the_verifier_never_calls_the_inference_seam(monkeypatch):
    import pqch.inference

    def boom(*a, **k):
        raise AssertionError("the verifier called a model")
    monkeypatch.setattr(pqch.inference, "complete", boom)
    monkeypatch.setattr(pqch.inference, "default", boom)
    assert run(FakeRunner(ACC_H, REF, W_ENF))["status"] == "enforced"


def test_a_group_the_server_chose_is_accepted_even_if_the_client_aborts_later():
    """S2: RabbitMQ chose brainpoolP256r1 in TLS 1.2; OpenSSL then aborted with "wrong curve"."""
    raw = ("Peer Temp Key: ECDH, brainpoolP256r1, 256 bits\n"
           "402789B288710000:error:0A00017A:SSL routines:tls12_check_peer_sigalg:wrong curve\n"
           "New, (NONE), Cipher is (NONE)\nPQCH_EXIT=1\n")
    r = parse_probe(raw)
    assert r["result"] == "accepted" and r["negotiated"] == "brainpoolP256r1"
    assert parse_probe((FIX / "probe-refused.txt").read_text())["result"] == "refused"


def test_the_witness_reads_a_finite_field_group_phrase_as_one_group():
    import json as _json

    from pqch.verifier import parse_witness
    raw = _json.dumps([{"id": "FS_KEMs", "finding": "X25519MLKEM768"}, {"id": "FS_ECDHE_curves", "finding": "X25519"},
                       {"id": "DH_groups", "finding": "RFC3526/Oakley Group 14"}]).encode()
    assert parse_witness(raw) == {"X25519MLKEM768", "X25519", "DH-2048"}


def test_a_require_check_probes_tls_1_2_apart_and_an_accepted_handshake_is_not_enforced():
    from pqch import verifier
    check = {"kind": "wire-kex", "intent": "require", "policy_intent": "require", "refuse_tls12": True,
             "target": {"host": "172.16.106.30", "port": 5432, "protocol": "postgres"},
             "must_accept": ["X25519MLKEM768"], "must_refuse": ["X25519", "secp256r1"]}
    jobs = verifier.expected_jobs(check)
    assert jobs["positive"][0] == "tls-group-probe-postgres" and jobs["witness"][0] == "tls-witness-postgres"
    assert jobs["legacy"] == ("tls-legacy-probe-postgres", {})
    base = {"positive": {"result": "accepted"}, "negative": {"result": "refused"},
            "witness": {"result": "accepted", "accepted_groups": ["X25519MLKEM768"]}}
    assert verifier.decide(check, {**base, "legacy": {"result": "refused"}})[0] == "enforced"
    status, also, _ = verifier.decide(check, {**base, "legacy": {"result": "accepted"}})
    assert status == "enabled-not-enforced" and "TLS 1.2" in also
    assert verifier.decide(check, {**base, "legacy": {"result": "error"}})[0] == "inconclusive"
    # A check without the flag, as every check before it, prescribes three jobs, as before.
    old = {k: v for k, v in check.items() if k != "refuse_tls12"} | {"target": {"host": "h", "port": 443, "protocol": "tls"}}
    assert set(verifier.expected_jobs(old)) == {"positive", "negative", "witness"}


def test_an_ssh_check_is_two_clients_and_ssh_audit():
    from pqch import verifier
    from pqch.migrator import render
    policy = render.load("policy/crypto-policy.yaml")
    t = next(x for x in policy["targets"] if x["service"] == "bastion") | {"intent": "require"}
    check = render.check(policy, t, None)
    assert check["kind"] == "ssh-kex" and check["must_accept"] == ["mlkem768x25519-sha256"]
    assert "curve25519-sha256" in check["must_refuse"] and "sntrup761x25519-sha512" in check["must_refuse"]
    jobs = verifier.expected_jobs(check)
    assert jobs["positive"] == ("ssh-kex-probe", {"kex": "mlkem768x25519-sha256"}) and jobs["witness"][0] == "ssh-targeted"
    ok = "debug1: kex: algorithm: mlkem768x25519-sha256\ndebug1: kex: host key algorithm: ssh-ed25519\nPQCH_EXIT=255"
    no = "Unable to negotiate with 172.16.106.21 port 22: no matching key exchange method found. Their offer: mlkem768x25519-sha256\nPQCH_EXIT=255"
    assert verifier.parse("positive", ok.encode(), check)["result"] == "accepted"
    assert verifier.parse("negative", no.encode(), check)["result"] == "refused"
    w = json.dumps({"kex": [{"algorithm": "mlkem768x25519-sha256"}, {"algorithm": "kex-strict-s-v00@openssh.com"}]}).encode()
    assert verifier.parse("witness", w, check)["accepted_groups"] == ["mlkem768x25519-sha256"]
    parsed = {"positive": {"result": "accepted"}, "negative": {"result": "refused"},
              "witness": {"result": "accepted", "accepted_groups": ["mlkem768x25519-sha256", "curve25519-sha256"]}}
    assert verifier.decide(check, parsed)[0] == "enabled-not-enforced"     # the witness overrules the pair


def test_openssh_is_rendered_by_rule_into_one_line():
    from pqch.migrator import render
    policy = render.load("policy/crypto-policy.yaml")
    assert render.render_ssh(policy, "require").endswith("KexAlgorithms mlkem768x25519-sha256\n")
    assert "KexAlgorithms" not in render.render_ssh(policy, "none")
    assert render.is_rendered_shape(render.render_ssh(policy, "enable"), "openssh")
    assert not render.is_rendered_shape("KexAlgorithms x\nPermitRootLogin yes\n", "openssh")



def test_openssh_s_no_match_line_is_a_refusal_and_a_contradiction_is_inconclusive():
    from pqch import verifier
    raw = ("debug1: kex: algorithm: (no match)\nUnable to negotiate with 172.16.107.21 port 22: no matching key "
           "exchange method found. Their offer: mlkem768x25519-sha256\nPQCH_EXIT=255")
    assert verifier.parse_ssh_probe(raw)["result"] == "refused"      # measured 2026-10-21 on the bastion's twin
    check = {"kind": "ssh-kex", "intent": "require", "policy_intent": "require", "target": {"protocol": "ssh"},
             "must_accept": ["mlkem768x25519-sha256"], "must_refuse": ["curve25519-sha256"]}
    parsed = {"positive": {"result": "accepted"}, "negative": {"result": "accepted", "negotiated": "curve25519-sha256"},
              "witness": {"result": "accepted", "accepted_groups": ["mlkem768x25519-sha256"]}}
    status, _, reasons = verifier.decide(check, parsed)
    assert status == "inconclusive" and "witness does not find accepted" in reasons[0]
