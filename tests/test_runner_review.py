"""The runner and verifier review (2026-11-21): what each finding broke, and the check that now holds.

An unreadable witness is `inconclusive`; a verdict is bound to a container or is not `enforced`; a
back-to-classical check uses the witness; a reset passes the approval gate; a Compose failure leaves
the service up on the restored file and the ledger saying so; a re-check does not un-land a change.
Fakes only: no Docker, no scan, no network.
"""

import importlib
import json
import subprocess

import pytest

from pqch import verifier
from pqch.ledger import LedgerError
from pqch.migrator import approve, check_for, execute, intervals, render, verify_now
from pqch.migrator.reset import approve_reset, execute_reset, request_reset, reset_estate
from pqch.run import Run
from pqch.runner import Refused
from pqch.runner.client import RunnerClient, RunnerRefused

from .test_apply import ScopeClient
from .test_apply import setup  # noqa: F401  (fixture)
from .test_verifier import ACC_H, APPLIED, CHECK, NEW, REF, W_ENF, FakeRunner
from .test_verifier import run as run_check


# ------------------------------------------------------------ an unreadable witness is inconclusive
@pytest.mark.parametrize("witness", [
    W_ENF[: len(W_ENF) // 2],                                        # truncated JSON
    b"\x1b[0;31m[exception] cannot connect to 172.16.106.21 port 22\x1b[0m\n",   # the tool's error text
    b'{"id": "FS_KEMs"}',                                            # JSON of another shape
    b"[1, 2]",                                                       # a list, of nothing the tool writes
    b"\xff\xfe",                                                     # not text
])
def test_a_witness_that_cannot_be_read_is_inconclusive_not_a_crash_and_not_a_pass(witness):
    v = run_check(FakeRunner(ACC_H, REF, witness))
    assert v["status"] == "inconclusive" and v["meets_intent"] is False
    assert any("witness: the output could not be read" in r for r in v["reasons"]), v["reasons"]


def test_an_ssh_witness_that_is_the_tools_error_text_is_an_error_too():
    check = {"kind": "ssh-kex", "must_accept": ["mlkem768x25519-sha256"], "must_refuse": ["curve25519-sha256"]}
    assert verifier.parse("witness", b"[exception] cannot connect", check)["result"] == "error"
    assert verifier.parse("witness", b'{"banner": {}}', check)["result"] == "error"    # no key-exchange list at all
    ok = json.dumps({"kex": [{"algorithm": "mlkem768x25519-sha256"}]}).encode()
    assert verifier.parse("witness", ok, check)["result"] == "accepted"


def test_stored_output_that_no_longer_matches_its_record_is_inconclusive():
    fake = FakeRunner(ACC_H, REF, W_ENF)

    def read_raw(job):
        if job["raw"].endswith("witness"):
            raise ValueError("raw output var/raw/witness does not match its recorded hash")
        return fake.out[job["raw"].rsplit("/", 1)[1]]
    v = verifier.verify(fake, "h", CHECK, change_id="c1", after_event=APPLIED, expect=NEW, read_raw=read_raw, hardware="test")
    assert v["status"] == "inconclusive" and any("does not match its recorded hash" in r for r in v["reasons"])


def test_ssh_output_that_both_refuses_and_agrees_is_unreadable():
    banner = "Unable to negotiate with you\n"                         # a server may print anything before the exchange
    raw = banner + "debug1: kex: algorithm: curve25519-sha256\nPQCH_EXIT=255"
    assert verifier.parse_ssh_probe(raw)["result"] == "error"


# ------------------------------------------------------------ nothing equals nothing is not a binding
def test_a_verdict_is_not_enforced_when_no_container_was_ever_identified():
    nobody = {"container_id": None, "image_digest": None}
    v = verifier.verify(FakeRunner(ACC_H, REF, W_ENF, container=nobody), "h", CHECK, change_id="c1", after_event=APPLIED,
                        expect=nobody, read_raw=lambda job: {"positive": ACC_H, "negative": REF, "witness": W_ENF}[
                            job["raw"].rsplit("/", 1)[1]], hardware="test")
    assert v["status"] == "inconclusive" and v["meets_intent"] is False
    assert any("names no container" in r for r in v["reasons"]) and any("no container was identified" in r for r in v["reasons"])


def test_a_probe_whose_container_lookup_failed_is_inconclusive_even_when_ids_match():
    class Failing(FakeRunner):
        def job(self, *a, **k):
            j = super().job(*a, **k)
            j["binding"]["error"] = "APIError: 500"
            return j
    v = run_check(Failing(ACC_H, REF, W_ENF))
    assert v["status"] == "inconclusive" and any("APIError" in r for r in v["reasons"])


# ------------------------------------------------------------ back to classical uses the witness
NONE = {"kind": "wire-kex", "intent": "require", "policy_intent": "none",
        "must_accept": ["X25519"], "must_refuse": ["X25519MLKEM768", "SecP256r1MLKEM768"],
        "may_accept": ["X25519", "secp256r1", "ffdhe2048"]}


def _decide(check, groups):
    return verifier.decide(check, {"positive": {"result": "accepted"}, "negative": {"result": "refused"},
                                   "witness": {"result": "accepted", "accepted_groups": groups}})


def test_back_to_classical_is_not_enforced_while_the_witness_finds_a_post_quantum_group():
    status, also, _ = _decide(NONE, ["SecP256r1MLKEM768", "X25519", "X25519MLKEM768"])
    assert status == "enabled-not-enforced" and "X25519MLKEM768" in also
    old = {k: v for k, v in NONE.items() if k != "may_accept"}        # a check written before may_accept
    assert _decide(old, ["X25519", "X25519MLKEM768"])[0] == "enabled-not-enforced"
    assert _decide(old, ["X25519", "secp256r1"])[0] == "enforced"


def test_back_to_classical_keeps_its_classical_groups_and_refuses_a_group_of_no_known_kind():
    assert _decide(NONE, ["X25519", "secp256r1", "DH-2048"])[0] == "enforced"     # classical, one known only by size
    assert _decide(NONE, ["X25519", "FrodoKEM-640"])[0] == "enabled-not-enforced"  # on neither list
    ssh = {"kind": "ssh-kex", "intent": "require", "policy_intent": "none", "must_accept": ["curve25519-sha256"],
           "must_refuse": ["mlkem768x25519-sha256"], "may_accept": ["curve25519-sha256", "ecdh-sha2-nistp256"]}
    assert _decide(ssh, ["curve25519-sha256", "mlkem768x25519-sha256"])[0] == "enabled-not-enforced"
    assert _decide(ssh, ["curve25519-sha256", "ecdh-sha2-nistp256"])[0] == "enforced"


def test_a_proposal_back_to_classical_names_what_the_listener_may_keep():
    policy = render.load("policy/crypto-policy.yaml")
    t = {"service": "portal", "address": "172.16.106.10", "port": 443, "intent": "none"}
    c = check_for(policy, t, None)
    assert "secp384r1" in c["may_accept"] and not set(c["may_accept"]) & set(c["must_refuse"])
    s = check_for(policy, {"service": "bastion", "address": "172.16.106.21", "port": 22, "protocol": "ssh", "intent": "none"}, None)
    assert "ecdh-sha2-nistp256" in s["may_accept"] and "mlkem768x25519-sha256" not in s["may_accept"]
    assert "may_accept" not in check_for(policy, {**t, "intent": "require"}, None)


# ------------------------------------------------------------ apply: a Compose failure
def _ready(setup):  # noqa: F811
    run, cid, signer, applier = setup()
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    applier._container_at = lambda client, t: {"container_id": "c"}
    applier.runner._client = lambda: None
    applier._wait_listening = lambda *a, **k: True
    applier.runner.binding = lambda client, address, network=None: {"container_id": "c2", "image_digest": "sha256:x"}
    return run, cid, signer, applier


@pytest.mark.parametrize("failure", [
    subprocess.TimeoutExpired(["docker", "compose"], 120),
    subprocess.TimeoutExpired(["docker", "compose"], 120, stderr=b"Container portal  Recreate"),
    subprocess.CalledProcessError(1, ["docker", "compose"], stderr="no such service"),
])
def test_a_compose_failure_during_apply_leaves_the_service_up_on_the_restored_file(setup, failure):  # noqa: F811
    run, cid, _signer, applier = _ready(setup)
    path = applier.agency_dir / "generated" / "portal" / "tls.conf"
    before, seen = path.read_text(), []

    def recreate(service):
        seen.append(path.read_text())
        if len(seen) == 1:
            raise failure
    applier._recreate = recreate
    with pytest.raises(Refused, match="put back, and the service is up on it") as r:
        applier.apply(run.id, cid)
    assert seen[0] != before and seen[1] == before and path.read_text() == before    # recreated again, on the old file
    entry = applier.log()[-1]
    assert entry["kind"] == "apply-failed" and entry["restored"] and entry["listening_after_restore"] is True
    assert entry["container_after_restore"] == "c2" and r.value.entry == entry
    assert "None" not in entry["error"] and "b'" not in entry["error"]               # the reason, in words
    assert not path.with_suffix(".tmp").exists()


def test_when_the_restore_cannot_be_brought_up_the_log_says_the_service_is_down(setup):  # noqa: F811
    run, cid, _signer, applier = _ready(setup)

    def recreate(service):
        raise subprocess.TimeoutExpired(["docker", "compose"], 120)
    applier._recreate = recreate
    with pytest.raises(Refused, match="still down"):
        applier.apply(run.id, cid)
    entry = applier.log()[-1]
    assert entry["listening_after_restore"] is False and "timed out" in entry["restore_error"]


class ThroughApplier(ScopeClient):
    """The harness's runner client, answered by an Applier in process: a refusal crosses as it does
    over the socket, as a RunnerRefused carrying the runner's log line."""

    def __init__(self, applier):
        super().__init__(applier.runner.scope()[0])
        self.a = applier

    def _call(self, fn, *args):
        try:
            return fn(*args)
        except Refused as r:
            raise RunnerRefused(r.code, r.reason, getattr(r, "entry", None)) from r

    def apply(self, run_id, change_id):
        return self._call(self.a.apply, run_id, change_id)

    def recreate(self, run_id, change_id):
        return self._call(self.a.recreate, run_id, change_id)

    def reset(self, run_id):
        return self._call(self.a.reset, run_id)


def test_a_failed_apply_is_on_the_ledger_with_the_state_the_estate_was_left_in(setup):  # noqa: F811
    run, cid, signer, applier = _ready(setup)
    calls = []

    def recreate(service):
        calls.append(service)
        if len(calls) == 1:
            raise subprocess.TimeoutExpired(["docker", "compose"], 120)
    applier._recreate = recreate
    with pytest.raises(RunnerRefused):
        execute(run, ThroughApplier(applier), signer, cid)
    events = list(run.ledger.events())
    failed = [e for e in events if e["type"] == "apply.failed"]
    assert len(failed) == 1 and failed[0]["payload"]["listening_after_restore"] is True
    assert failed[0]["payload"]["container_after_restore"] == "c2"
    assert not any(e["type"] == "change.applied" for e in events) and events[-1]["type"] == "checkpoint.signed"
    # Refused before anything was touched: nothing to record.
    run2, cid2, signer2, applier2 = setup()
    with pytest.raises(RunnerRefused, match="no approval"):
        execute(run2, ThroughApplier(applier2), signer2, cid2)
    assert not any(e["type"] == "apply.failed" for e in run2.ledger.events())


def test_an_apply_that_finds_no_container_afterwards_says_so_and_its_verdict_cannot_be_enforced(setup):  # noqa: F811
    run, cid, _signer, applier = _ready(setup)
    applier._recreate = lambda service: None
    applier.runner.binding = lambda client, address, network=None: {"container_id": None, "error": "NotFound: n"}
    import pqch.runner.apply as mod
    real, mod.time.sleep = mod.time.sleep, lambda s: None
    try:
        entry = applier.apply(run.id, cid)
    finally:
        mod.time.sleep = real
    assert entry["containers"][0]["after"] is None and entry["unbound"] == "NotFound: n"
    c = entry["containers"][0]
    v = verifier.verify(FakeRunner(ACC_H, REF, W_ENF, container={"container_id": None, "image_digest": None}), "h", CHECK,
                        change_id=cid, after_event=APPLIED, expect={"container_id": c["after"], "image_digest": c["image_digest"]},
                        read_raw=lambda job: {"positive": ACC_H, "negative": REF, "witness": W_ENF}[job["raw"].rsplit("/", 1)[1]],
                        hardware="test")
    assert v["status"] == "inconclusive"


# ------------------------------------------------------------ recreate follows the ledger
def test_a_recreate_needs_the_apply_on_the_ledger_and_each_earlier_recreate_recorded(setup):  # noqa: F811
    run, cid, signer, applier = _ready(setup)
    applier._recreate = lambda service: None
    entry = applier.apply(run.id, cid)
    with pytest.raises(Refused, match="does not record the apply"):
        applier.recreate(run.id, cid)                               # applied, but the ledger does not say so yet
    run.ledger.append("change.applied", {"kind": "runner", "id": "pqch-runner"}, entry)
    with pytest.raises(Refused, match="does not record the apply"):
        applier.recreate(run.id, cid)                               # said, but under no signed checkpoint
    run.checkpoint(signer)
    rec = applier.recreate(run.id, cid)
    with pytest.raises(Refused, match="records 0"):
        applier.recreate(run.id, cid)                               # the socket alone cannot do it again
    run.ledger.append("service.recreated", {"kind": "runner", "id": "pqch-runner"}, rec)
    run.checkpoint(signer)
    assert applier.recreate(run.id, cid)["kind"] == "recreate"


def test_a_recreate_for_a_change_the_run_does_not_hold_is_refused_and_a_timeout_is_logged(setup):  # noqa: F811
    run, cid, signer, applier = _ready(setup)
    applier._recreate = lambda service: None
    applier._append_log({"kind": "apply", "change_id": "01ZZZZZZZZZZZZZZZZZZZZZZZZ"})
    with pytest.raises(Refused, match="holds no proposal"):          # was a StopIteration, a 500
        applier.recreate(run.id, "01ZZZZZZZZZZZZZZZZZZZZZZZZ")
    entry = applier.apply(run.id, cid)
    run.ledger.append("change.applied", {"kind": "runner", "id": "pqch-runner"}, entry)
    run.checkpoint(signer)

    def slow(service):
        raise subprocess.TimeoutExpired(["docker", "compose"], 120)
    applier._recreate = slow
    with pytest.raises(Refused, match="recreate failed") as r:
        applier.recreate(run.id, cid)
    assert applier.log()[-1]["kind"] == "recreate-failed" and r.value.entry["container_after"] == "c2"


# ------------------------------------------------------------ reset passes the approval gate
BASE = "ssl_protocols TLSv1.2 TLSv1.3;\nssl_ecdh_curve X25519:prime256v1;\n"


def _reset_ready(setup):  # noqa: F811
    _run, _cid, signer, applier = setup()
    agency = applier.agency_dir
    (agency / "baseline" / "portal").mkdir(parents=True)
    (agency / "baseline" / "portal" / "tls.conf").write_text(BASE)
    (agency / "generated" / "portal" / "tls.conf").write_text("ssl_protocols TLSv1.3;\nssl_ecdh_curve X25519MLKEM768;\n")
    applier.recreated = []
    applier._recreate = lambda service: applier.recreated.append(service)
    applier._wait_listening = lambda *a, **k: True
    applier.runner._client = lambda: None
    applier.runner.binding = lambda client, address, network=None: {"container_id": None}
    import pqch.runner.apply as mod
    mod.time.sleep = lambda s: None
    return signer, applier, applier.runs_dir.parent, ThroughApplier(applier)


@pytest.fixture(autouse=True)
def _real_sleep():
    import time

    import pqch.runner.apply as mod
    real = time.sleep
    yield
    mod.time.sleep = real


def test_a_reset_by_one_operator_records_the_request_the_approval_and_what_the_runner_did(setup):  # noqa: F811
    signer, applier, var, client = _reset_ready(setup)
    run, out, _closed = reset_estate(var, client, signer, by="ken", authenticated_by="test")
    types = [e["type"] for e in run.ledger.events() if e["type"] != "checkpoint.signed"]
    assert types == ["run.started", "reset.requested", "approval.granted", "estate.reset", "run.closed"]
    events = list(run.ledger.events())
    req, ap = events[types.index("reset.requested") + 1], next(e for e in events if e["type"] == "approval.granted")
    assert ap["payload"]["change_id"] == req["id"] and ap["payload"]["reset"] is True
    assert out["services"][0]["changed"] and (applier.agency_dir / "generated" / "portal" / "tls.conf").read_text() == BASE
    from pqch.ledger import verify
    assert verify(events).ok


def test_under_separation_a_reset_needs_another_person_with_the_approver_role(setup, monkeypatch):  # noqa: F811
    monkeypatch.setenv("PQCH_SEPARATION_OF_DUTIES", "1")
    signer, applier, var, client = _reset_ready(setup)
    with pytest.raises(RunnerRefused, match="same person"):
        reset_estate(var, client, signer, by="ken", authenticated_by="front door", role="approver", groups=["pqc-approvers"])
    assert applier.recreated == [] and not any(e.get("kind") == "reset" for e in applier.log())
    assert list(Run.latest(var, "reset").ledger.events())[-1]["type"] == "run.closed"      # refused, and over
    run = request_reset(var, client, signer, by="ken", authenticated_by="front door")
    with pytest.raises(RunnerRefused, match="no approval"):
        execute_reset(var, run, client, signer)
    approve_reset(run, signer, by="alice", authenticated_by="front door")                  # no role recorded
    with pytest.raises(RunnerRefused, match="no approver role"):
        execute_reset(var, run, client, signer)
    run2 = request_reset(var, client, signer, by="ken", authenticated_by="front door")
    approve_reset(run2, signer, by="alice", authenticated_by="front door", role="approver", groups=["pqc-approvers"])
    out, _ = execute_reset(var, run2, client, signer)
    assert applier.recreated == ["portal"] and out["approval_event"]


def test_a_denied_reset_and_a_request_in_a_run_of_another_kind_are_refused(setup):  # noqa: F811
    signer, applier, var, client = _reset_ready(setup)
    run = request_reset(var, client, signer, by="ken", authenticated_by="test")
    approve_reset(run, signer, by="alice", authenticated_by="test", deny=True)
    approve_reset(run, signer, by="mallory", authenticated_by="test")
    with pytest.raises(Refused, match="denied"):
        applier.reset(run.id)
    scope, h = client.scope()
    other = Run.start(var, scope, runner_scope_hash=h, profile="m0a-change", kind="change")
    other.ledger.append("reset.requested", {"kind": "human", "id": "ken"}, {"by": "ken", "authenticated_by": "test"})
    approve_reset(other, signer, by="ken", authenticated_by="test")
    with pytest.raises(Refused, match="not a reset run"):
        applier.reset(other.id)
    assert applier.recreated == []


def test_a_reset_writes_only_a_starting_state_of_the_rendered_shape_on_the_estates_own_container(setup):  # noqa: F811
    signer, applier, var, client = _reset_ready(setup)
    base = applier.agency_dir / "baseline" / "portal" / "tls.conf"
    deployed = applier.agency_dir / "generated" / "portal" / "tls.conf"
    was = deployed.read_text()
    base.write_text(BASE + "include /etc/passwd;\n")
    with pytest.raises(RunnerRefused, match="lines the runner does not write"):
        reset_estate(var, client, signer, by="ken", authenticated_by="test")
    base.write_text(BASE)
    applier.runner.binding = lambda client, address, network=None: {"container_id": "x"}

    def not_ours(client, t):
        raise Refused(403, "x is not service portal of the pqch-agency estate")
    applier._container_at = not_ours
    with pytest.raises(RunnerRefused, match="not service portal"):
        reset_estate(var, client, signer, by="ken", authenticated_by="test")
    assert applier.recreated == [] and deployed.read_text() == was


def test_the_repositorys_own_starting_states_have_the_shape_a_reset_requires():
    import yaml
    from pathlib import Path

    services = yaml.safe_load(Path("agency/compose.yaml").read_text())["services"]
    managed = {n: d["x-pqch"]["policy"]["software"] for n, d in services.items() if (d.get("x-pqch") or {}).get("policy")}
    assert managed
    for name, software in managed.items():
        text = (Path("agency/baseline") / name / render.POLICY_FILE[software]).read_text()
        assert render.is_rendered_shape(text, software), name


def test_a_reset_that_compose_times_out_on_is_put_back_logged_and_on_the_ledger(setup):  # noqa: F811
    signer, applier, var, client = _reset_ready(setup)
    deployed = applier.agency_dir / "generated" / "portal" / "tls.conf"
    was, seen = deployed.read_text(), []

    def recreate(service):
        seen.append(deployed.read_text())
        if len(seen) == 1:
            raise subprocess.TimeoutExpired(["docker", "compose"], 120)
    applier._recreate = recreate
    with pytest.raises(RunnerRefused, match="put back"):
        reset_estate(var, client, signer, by="ken", authenticated_by="test")
    assert seen == [BASE, was] and deployed.read_text() == was
    assert applier.log()[-1]["kind"] == "reset-failed" and applier.log()[-1]["failed"] == "portal"
    events = list(Run.latest(var, "reset").ledger.events())
    failed = next(e for e in events if e["type"] == "reset.failed")
    assert failed["payload"]["listening_after_restore"] is True and events[-1]["type"] == "run.closed"
    assert not any(e["type"] == "estate.reset" for e in events)


# ------------------------------------------------------------ a re-check does not un-land a change
def test_a_recheck_with_no_recreate_does_not_turn_a_landed_change_into_one_that_did_not(setup):  # noqa: F811
    run, cid, signer, _ = setup()
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    v = {"change_id": cid, "status": "enforced", "meets_intent": True, "hardware": "test", "durable": "untested"}
    actor = {"kind": "verifier", "id": "v"}
    run.ledger.append("verdict.issued", actor, v)
    decided = run.ledger.append("verdict.issued", actor, {**v, "durable": True})
    landed = intervals(list(run.ledger.events()))[0]
    assert landed["landed"] is True and landed["recheck"] is None
    again = run.ledger.append("verdict.issued", actor, v)                # what `pqch change verify` writes
    t = intervals(list(run.ledger.events()))[0]
    assert t["landed"] is True and t["durable"] is True and t["verdict_ts"] == decided["ts"]
    assert t["policy_to_verdict_ms"] == landed["policy_to_verdict_ms"]   # the time-to-change did not move
    assert t["recheck"] == {"status": "enforced", "ts": again["ts"], "meets_intent": True, "event": again["id"]}
    assert {"change_id", "target", "intent", "landed", "verdict_ts"} <= set(t)
    # A change never decided is not landed by a re-check either.
    run2, cid2, signer2, _ = setup()
    approve(run2, cid2, by="ken", authenticated_by="test", signer=signer2)
    run2.ledger.append("verdict.issued", actor, {**v, "change_id": cid2})
    run2.ledger.append("verdict.issued", actor, {**v, "change_id": cid2})
    assert intervals(list(run2.ledger.events()))[0]["landed"] is False


def test_a_check_on_a_closed_run_is_refused_before_any_probe_runs(setup):  # noqa: F811
    run, cid, signer, _ = setup()
    run.close(signer)

    class NoProbes:
        def __getattr__(self, name):
            raise AssertionError(f"runner.{name} called for a closed run")
    with pytest.raises(LedgerError, match="closed"):
        verify_now(run, NoProbes(), signer, cid, after_event=APPLIED, expect=NEW)


# ------------------------------------------------------------ the socket, the settings, the compose file
def test_the_client_carries_the_runners_log_line_with_a_refusal_made_after_the_estate_was_touched():
    import httpx

    def answer(request):
        if request.url.path == "/apply":
            return httpx.Response(500, json={"detail": {"reason": "recreate failed", "entry": {"kind": "apply-failed"}}})
        return httpx.Response(409, json={"detail": "no approval"})
    c = RunnerClient.__new__(RunnerClient)
    c._http = httpx.Client(transport=httpx.MockTransport(answer), base_url="http://runner")
    with pytest.raises(RunnerRefused) as r:
        c.apply("r", "c")
    assert r.value.reason == "recreate failed" and r.value.entry == {"kind": "apply-failed"}
    with pytest.raises(RunnerRefused) as r:
        c.recreate("r", "c")
    assert r.value.reason == "no approval" and r.value.entry is None


def _service(monkeypatch, tmp_path, owned):
    from .conftest import SCOPE
    p = tmp_path / f"scope-{owned}.json"
    p.write_text(json.dumps({**SCOPE, "owned": owned}))
    monkeypatch.setenv("PQCH_SCOPE", str(p))
    monkeypatch.setenv("PQCH_RAW", str(tmp_path / "raw"))
    monkeypatch.setenv("PQCH_AGENCY_DIR", str(tmp_path / "agency"))
    monkeypatch.setenv("PQCH_SIGNER_SOCKET", str(tmp_path / "signer.sock"))
    monkeypatch.setenv("PQCH_RUNNER_LOG", str(tmp_path / "log"))
    import pqch.runner.service as service
    return importlib.reload(service)


def test_a_runner_whose_scope_is_not_an_owned_estate_has_no_applier_whatever_it_is_given(monkeypatch, tmp_path):
    from fastapi import HTTPException

    service = _service(monkeypatch, tmp_path, owned=False)
    assert service.applier is None and service.get_settings()["applies"] is False
    with pytest.raises(HTTPException) as e:
        service.post_reset(service.Reset(run="01ZZZZZZZZZZZZZZZZZZZZZZZZ"))
    assert e.value.status_code == 503
    monkeypatch.setenv("PQCH_SEPARATION_OF_DUTIES", "1")
    service = _service(monkeypatch, tmp_path, owned=True)
    s = service.get_settings()
    assert service.applier is not None and s["applies"] is True and s["separation_of_duties"] is True
    assert s["change_uids_limited"] is False
    refused = Refused(500, "recreate failed")
    refused.entry = {"kind": "apply-failed"}
    assert service._refusal(refused).detail == {"reason": "recreate failed", "entry": {"kind": "apply-failed"}}
    assert service._refusal(Refused(409, "no approval")).detail == "no approval"


def test_compose_passes_the_runners_enforcement_switches_through_and_never_as_an_empty_value():
    import yaml

    doc = yaml.safe_load(open("compose.yaml"))["services"]
    env = doc["runner"]["environment"]
    for name in ("PQCH_SEPARATION_OF_DUTIES", "PQCH_REQUIRE_AUTHORIZATION", "PQCH_REQUIRE_ROE",
                 "PQCH_RUNNER_CHANGE_UIDS", "PQCH_SOCKET_ALLOW_UIDS"):
        # Named with no value: Compose passes it through when set and leaves it out when not. An
        # empty string would be an empty uid list, which admits nobody.
        assert name in env and env[name] is None, name
    assert doc["app"]["environment"]["PQCH_SEPARATION_OF_DUTIES"] is None
    assert doc["app"]["environment"]["PQCH_APPROVER_GROUP"] is None
    from pqch.peercred import uid_list
    assert uid_list("") == set() and uid_list(None) is None
