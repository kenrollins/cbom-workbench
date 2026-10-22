"""The runner applies only what the ledger shows proposed, approved and checkpointed (F-38)."""

import json

import pytest

from pqch import scope as scope_mod
from pqch.migrator import approve, intervals, propose
from pqch.runner import Refused, Runner
from pqch.runner.apply import Applier

from .conftest import SCOPE
from .test_checkpoints import PySigner
from .test_runner import ExplodingDocker

POLICY = """schema: pqch.crypto-policy/1
key_establishment:
  hybrid: [X25519MLKEM768]
  classical: [X25519, secp256r1]
targets:
  - {service: portal, address: 172.16.106.10, port: 443, intent: require}
"""


class ScopeClient:
    def __init__(self, scope):
        self.s = scope

    def scope(self):
        return self.s, scope_mod.scope_hash(self.s)


@pytest.fixture
def setup(tmp_path):
    var = tmp_path / "var"
    (var / "runs").mkdir(parents=True)
    agency = tmp_path / "agency"
    (agency / "generated" / "portal").mkdir(parents=True)
    (agency / "generated" / "portal" / "tls.conf").write_text("ssl_ecdh_curve X25519:prime256v1;\n")
    (agency / "compose.yaml").write_text("services:\n  portal:\n    image: pqch-agency/portal:m0\n    x-pqch:\n      policy: {software: nginx, mount: /etc/nginx/policy}\n")
    pol = tmp_path / "crypto-policy.yaml"
    pol.write_text(POLICY)
    scope_path = tmp_path / "scope.json"

    def make(owned=True):
        s = {**SCOPE, "owned": owned}
        scope_path.write_text(json.dumps(s))
        signer = PySigner(tmp_path / "signer", var / "runs")
        signer.ensure_key()
        run, props = propose(var, ScopeClient(s), pol, agency, by="ken", authenticated_by="test")
        runner = Runner(scope_path, var / "raw", target_network="n", docker_client=ExplodingDocker())
        applier = Applier(runner, runs_dir=var / "runs", agency_dir=agency, log_dir=tmp_path / "log", signer=signer)
        return run, props[0]["payload"]["change_id"], signer, applier
    return make


def test_the_proposal_carries_diff_rollback_and_check(setup):
    run, _cid, _, _ = setup()
    p = next(e for e in run.ledger.events() if e["type"] == "change.proposed")["payload"]
    assert "+ssl_ecdh_curve X25519MLKEM768;" in p["diff"] and "ssl_protocols TLSv1.3;" in p["new_content"]
    assert p["rollback"] == "ssl_ecdh_curve X25519:prime256v1;\n"
    assert p["check"]["must_accept"] == ["X25519MLKEM768"] and p["check"]["intent"] == "require"


def test_refused_without_an_approval(setup):
    run, cid, signer, applier = setup()
    run.checkpoint(signer)
    with pytest.raises(Refused, match="no approval"):
        applier.authorize(run.id, cid)


def test_refused_when_no_checkpoint_covers_the_approval(setup):
    run, cid, _signer, applier = setup()
    run.ledger.append("approval.granted", {"kind": "human", "id": "ken"},
                      {"change_id": cid, "by": "ken", "authenticated_by": "test"})
    with pytest.raises(Refused, match="no signed checkpoint covers"):
        applier.authorize(run.id, cid)


def test_authorized_once_approved_and_checkpointed_then_never_twice(setup):
    run, cid, signer, applier = setup()
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    _, prop, approval = applier.authorize(run.id, cid)
    assert prop["payload"]["change_id"] == cid and approval["type"] == "approval.granted"
    applier._append_log({"kind": "apply", "change_id": cid})
    with pytest.raises(Refused, match="already been applied"):
        applier.authorize(run.id, cid)


def test_refused_when_denied(setup):
    run, cid, signer, applier = setup()
    approve(run, cid, by="ken", authenticated_by="test", signer=signer, deny=True)
    approve(run, cid, by="mallory", authenticated_by="test", signer=signer)
    with pytest.raises(Refused, match="denied"):
        applier.authorize(run.id, cid)


def test_refused_when_the_ledger_was_cut_behind_a_checkpoint(setup):
    run, cid, signer, applier = setup()
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    lines = run.ledger.path.read_text().splitlines()
    run.ledger.path.write_text("\n".join(lines[:2]) + "\n")
    with pytest.raises(Refused, match="does not verify"):
        applier.authorize(run.id, cid)


def test_an_approval_needs_who_and_how(setup):
    run, cid, signer, _ = setup()
    with pytest.raises(PermissionError):
        approve(run, cid, by="", authenticated_by="test", signer=signer)


def test_refused_on_an_estate_the_harness_does_not_own(setup):
    run, cid, signer, applier = setup(owned=False)
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    _, prop, _ = applier.authorize(run.id, cid)
    with pytest.raises(Refused, match="not an owned estate"):
        applier._target(prop)


def test_time_to_change_from_ledger_timestamps(setup):
    run, cid, signer, _ = setup()
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"},
                      {"change_id": cid, "status": "enforced", "meets_intent": True, "hardware": "test"})
    events = list(run.ledger.events())
    t = intervals(events)[0]
    pol = next(e for e in events if e["type"] == "policy.changed")
    assert t["policy_ts"] == pol["ts"] and t["statuses"] == ["enforced"] and t["meets_intent"]
    assert t["policy_to_verdict_ms"] >= t["approval_to_verdict_ms"] >= 0 and t["hardware"] == "test"


@pytest.mark.parametrize("content,ok", [
    ("# c\nssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768;\n", True),
    ("ssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;\n", True),
    ("ssl_ecdh_curve X25519;\nadd_header X-Injected yes always;\n", False),
    ("ssl_ecdh_curve X25519; location /k { alias /etc/nginx/tls/; }\n", False),
    ("ssl_ecdh_curve X25519;\n}\nserver { listen 80; }\n", False),
    ("include /etc/passwd;\n", False),
])
def test_the_runner_writes_only_protocol_and_key_exchange_lines(content, ok):
    from pqch.migrator import render
    assert render.is_rendered_shape(content) is ok


def test_every_rendered_intent_has_the_rendered_shape():
    from pqch.migrator import render
    policy = render.load("policy/crypto-policy.yaml")
    assert all(render.is_rendered_shape(render.render_tls(policy, i)) for i in render.INTENTS)


def test_time_to_change_only_for_a_change_that_landed(setup):
    run, cid, signer, _ = setup()
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    v = {"change_id": cid, "status": "enforced", "meets_intent": True, "hardware": "test", "durable": "untested"}
    run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"}, v)
    assert intervals(list(run.ledger.events()))[0]["landed"] is False
    run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"},
                      {**v, "status": "not-landed", "meets_intent": False, "durable": False})
    assert intervals(list(run.ledger.events()))[0]["landed"] is False
    run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"}, {**v, "durable": True})
    assert intervals(list(run.ledger.events()))[0]["landed"] is True


RECREATED: list[str] = []


def _apply_with(setup, mutate, *, deployed=None):
    """Approve a real proposal, alter it in the ledger the way a forger in the UI process could, and apply."""
    from .test_ledger import rewrite
    run, cid, signer, applier = setup()
    events = list(run.ledger.events())
    prop = next(e for e in events if e["type"] == "change.proposed")
    mutate(prop["payload"])
    rewrite(run.ledger, events)
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    if deployed is not None:
        (applier.agency_dir / "generated" / "portal" / "tls.conf").write_text(deployed)
    applier._container_at = lambda client, t: {"container_id": "c"}
    applier.runner._client = lambda: None
    applier._recreate = lambda service: RECREATED.append(service)
    applier._wait_listening = lambda *a, **k: True
    applier.runner.binding = lambda client, address: {"container_id": "c2", "image_digest": "sha256:x"}
    return applier.apply(run.id, cid)


def test_applies_when_diff_rollback_and_deployed_file_agree(setup):
    entry = _apply_with(setup, lambda p: None)
    assert entry["kind"] == "apply"


@pytest.mark.parametrize("mutate,deployed,why", [
    (lambda p: p.update(diff="+ssl_ecdh_curve X25519MLKEM768;\n"), None, "diff is not the diff"),
    (lambda p: p.update(diff=""), None, "diff is not the diff"),
    (lambda p: p.update(rollback="something else\n"), None, "rollback does not match"),
    (lambda p: None, "ssl_ecdh_curve X448;\n", "not the configuration now deployed"),
])
def test_refuses_when_what_was_approved_is_not_what_would_be_applied(setup, mutate, deployed, why):
    with pytest.raises(Refused, match=why):
        _apply_with(setup, mutate, deployed=deployed)


def test_a_run_with_another_change_pending_stays_open(setup):
    from pqch.migrator import pending

    run, cid, _signer, _ = setup()
    assert pending(run) == [cid]
    run.ledger.append("approval.denied", {"kind": "human", "id": "ken"}, {"change_id": cid, "by": "ken", "authenticated_by": "test"})
    assert pending(run) == []


def test_the_estate_is_reset_only_on_a_signed_request_and_once(setup, tmp_path):
    from pqch import scope as scope_mod
    from pqch.run import Run

    _run, _cid, signer, applier = setup()
    agency = applier.agency_dir
    (agency / "baseline" / "portal").mkdir(parents=True)
    (agency / "baseline" / "portal" / "tls.conf").write_text("ssl_protocols TLSv1.2 TLSv1.3;\\nssl_ecdh_curve X25519:prime256v1;\\n")
    (agency / "generated" / "portal" / "tls.conf").write_text("ssl_protocols TLSv1.3;\\nssl_ecdh_curve X25519MLKEM768;\\n")
    recreated = []
    applier._recreate = lambda service: recreated.append(service)
    applier._wait_listening = lambda address, port, timeout_s=30: True
    scope, _ = applier.runner.scope()
    r = Run.start(applier.runs_dir.parent, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="estate-reset", kind="reset")
    with pytest.raises(Refused):                       # no request on the record
        applier.reset(r.id)
    r.ledger.append("reset.requested", {"kind": "human", "id": "ken"}, {"by": "ken", "authenticated_by": "test"})
    with pytest.raises(Refused):                       # requested, but no signed checkpoint covers it
        applier.reset(r.id)
    r.checkpoint(signer)
    out = applier.reset(r.id)
    assert recreated == ["portal"] and out["services"][0]["changed"] is True
    assert (agency / "generated" / "portal" / "tls.conf").read_text().startswith("ssl_protocols TLSv1.2 TLSv1.3;")
    with pytest.raises(Refused):                       # once per run
        applier.reset(r.id)
