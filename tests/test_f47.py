"""M0A review F-47: signer time in checkpoints, the runner's job log, the run id in run.started."""

import base64
import json
import shutil

import pytest

from pqch.ledger import Ledger
from pqch.ledger.checkpoints import verify_signed
from pqch.signer import SignerError, message
from pqch.ui.view import probe_checks

from .test_checkpoints import PySigner
from .test_ledger import rewrite


@pytest.fixture
def signer(slice_run, tmp_path):
    s = PySigner(tmp_path / "signer", slice_run.var / "runs")
    s.ensure_key()
    return s


def test_run_started_names_its_run(slice_run):
    assert next(slice_run.ledger.events())["payload"]["run"] == slice_run.id


def test_the_signers_time_is_in_the_signed_message(slice_run, signer):
    slice_run.close(signer)
    events = list(slice_run.ledger.events())
    cp = events[-2]["payload"]
    assert cp["signed_at"] and verify_signed(events, signer.pub_path.read_bytes()).ok
    # The signature covers the time: strip it, or change it, and the checkpoint fails.
    for mutate in (lambda c: c.pop("signed_at"), lambda c: c.update(signed_at="2026-01-01T00:00:00.000Z")):
        evs = json.loads(json.dumps(events))
        mutate(evs[-2]["payload"])
        rewrite(slice_run.ledger, evs)
        res = verify_signed(list(slice_run.ledger.events()), signer.pub_path.read_bytes())
        assert not res.ok, res


def test_a_checkpoint_from_before_signer_time_still_verifies_and_says_so(slice_run, signer):
    events = list(slice_run.ledger.events())
    head = events[-1]
    sig = signer._sign(message(head["seq"], head["hash"]))
    slice_run.ledger.append("checkpoint.signed", {"kind": "controller", "id": "pqch-signer"}, {
        "schema": "pqch.checkpoint/1", "through_seq": head["seq"], "head_hash": head["hash"], "alg": "ML-DSA-65",
        "key_id": signer.public()["key_id"], "signature": base64.b64encode(sig).decode()})
    res = verify_signed(list(slice_run.ledger.events()), signer.pub_path.read_bytes())
    assert res.ok and res.legacy_checkpoints == 1


def test_the_signer_refuses_an_event_stamped_in_its_future(slice_run, signer):
    slice_run.ledger.append("key.committed", {"kind": "human", "id": "t"}, {"n": 1}, ts="2099-01-01T00:00:00.000Z")
    with pytest.raises(SignerError, match="after the signer's time"):
        signer.checkpoint(slice_run.id, list(slice_run.ledger.events())[-1]["seq"])


def test_an_event_stamped_behind_the_checkpoint_it_follows_fails(slice_run, signer, monkeypatch):
    """The two clocks disagree: a checkpoint signed "in December", then an event stamped now."""
    import pqch.signer
    monkeypatch.setattr(pqch.signer, "utc_now", lambda: "2026-12-01T00:00:00.000Z")
    slice_run.checkpoint(signer)
    slice_run.ledger.append("key.committed", {"kind": "human", "id": "t"}, {"n": 2})
    res = verify_signed(list(slice_run.ledger.events()), signer.pub_path.read_bytes())
    assert not res.ok and "before the checkpoint" in res.error
    with pytest.raises(SignerError, match="before the checkpoint"):
        signer.checkpoint(slice_run.id, list(slice_run.ledger.events())[-1]["seq"])


def test_the_signer_refuses_a_ledger_copied_to_another_run_id(slice_run, signer):
    other = slice_run.var / "runs" / "01M40W6W873YWJMWPKGMK3YBMQ"
    shutil.copytree(slice_run.dir, other)
    with pytest.raises(SignerError, match="copied"):
        signer.checkpoint(other.name, 3)


def test_the_runner_logs_every_job(tmp_path):
    from pqch.runner import JobResult, Runner

    from .test_runner import SCOPE, ExplodingDocker
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(SCOPE))
    r = Runner(p, tmp_path / "raw", target_network="n", docker_client=ExplodingDocker(), log_dir=tmp_path / "log")
    jr = JobResult(job_id="01M40W6W873YWJMWPKGMK3YBMA", profile="tls-group-probe", target={"host": "h"}, tool="t",
                   version="v", image="i", image_digest="sha256:" + "a" * 64, status="ok", exit_code=0,
                   started_at="s", ended_at="e", duration_ms=1, raw="var/raw/x", raw_sha256="b" * 64,
                   binding={"container_id": "c"})
    r._log_job(jr, {"groups": "X25519"})
    assert r.jobs({"01M40W6W873YWJMWPKGMK3YBMA"})[0]["raw_sha256"] == "b" * 64
    assert r.jobs({"01M40W6W873YWJMWPKGMK3YBMB"}) == []


def _verdict(*probes):
    return {"payload": {"probes": list(probes)}}


def _probe(job, **kw):
    return {"job_id": job, "raw_sha256": "r", "started_at": "s", "ended_at": "e", "container_id": "c", **kw}


def test_probe_checks_against_the_runners_log():
    log = [{"job_id": "J1", "raw_sha256": "r", "started_at": "s", "ended_at": "e", "binding": {"container_id": "c"}},
           {"job_id": "J2", "raw_sha256": "r", "started_at": "s", "ended_at": "e", "binding": {"container_id": "c"}}]
    lookup = lambda ids: [e for e in log if e["job_id"] in ids]  # noqa: E731
    ok = probe_checks([_verdict(_probe("J1"))], lookup)
    assert ok["J1"]["ok"] is True
    bad = probe_checks([_verdict(_probe("J2", raw_sha256="x"), _probe("J9"))], lookup)
    assert "hash differs" in bad["J2"]["why"] and "no such job" in bad["J9"]["why"]
    reused = probe_checks([_verdict(_probe("J1")), _verdict(_probe("J1"))], lookup)
    assert "cited by 2 verdicts" in reused["J1"]["why"]
    assert probe_checks([_verdict(_probe("J1"))], lambda ids: None)["J1"]["ok"] is None


def test_intervals_by_the_signers_clock(tmp_path):
    from pqch.migrator import approve, intervals, propose

    from .test_apply import POLICY, ScopeClient
    from .conftest import SCOPE
    var = tmp_path / "var"
    (var / "runs").mkdir(parents=True)
    agency = tmp_path / "agency"
    (agency / "generated" / "portal").mkdir(parents=True)
    (agency / "generated" / "portal" / "tls.conf").write_text("ssl_ecdh_curve X25519:prime256v1;\n")
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    s = PySigner(tmp_path / "s", var / "runs")
    s.ensure_key()
    run, props = propose(var, ScopeClient(SCOPE), pol, agency, by="ken", authenticated_by="t", signer=s)
    cid = props[0]["payload"]["change_id"]
    approve(run, cid, by="ken", authenticated_by="t", signer=s)
    run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"},
                      {"change_id": cid, "status": "enforced", "meets_intent": True, "durable": True, "hardware": "t"})
    run.checkpoint(s)
    t = intervals(list(Ledger(run.ledger.path).events()))[0]
    assert t["signer_policy_ts"] and t["signer_approval_ts"] and t["signer_verdict_ts"]
    assert t["signer_policy_to_verdict_ms"] >= t["signer_approval_to_verdict_ms"] >= 0
