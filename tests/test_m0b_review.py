"""M0B review: what the review broke, and the check that now refuses it (F-54 to F-64)."""

import json
import shutil

import pytest

from pqch.ledger import Ledger
from pqch.ledger.checkpoints import verify_signed
from pqch.migrator import approve, intervals, propose, render
from pqch.runner import Refused
from pqch.signer import SignerError
from pqch.ui.view import probe_checks

from .conftest import SCOPE
from .test_apply import POLICY, ScopeClient
from .test_apply import setup  # noqa: F401  (fixture)
from .test_checkpoints import PySigner
from .test_ledger import rewrite

CHECK = {"schema": "pqch.verifier/1", "kind": "wire-kex", "intent": "require",
         "target": {"host": "172.16.106.10", "port": 443, "protocol": "tls"},
         "must_accept": ["X25519MLKEM768"], "must_refuse": ["X25519", "secp256r1"]}
ACCEPTED = "Negotiated TLS1.3 group: X25519MLKEM768\nNew, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384\nPQCH_EXIT=0\n"
REFUSED = "alert handshake failure\nPQCH_EXIT=1\n"
WITNESS = json.dumps([{"id": "FS_KEMs", "finding": "X25519MLKEM768"}, {"id": "FS_ECDHE_curves", "finding": "No curves offered"}])


# ---------------------------------------------------------------- F-54, signer time
@pytest.fixture
def change(tmp_path):
    var = tmp_path / "var"
    (var / "runs").mkdir(parents=True)
    agency = tmp_path / "agency"
    (agency / "generated" / "portal").mkdir(parents=True)
    (agency / "compose.yaml").write_text("services:\n  portal:\n    image: pqch-agency/portal:m0\n    x-pqch:\n      policy: {software: nginx, mount: /etc/nginx/policy}\n")
    (agency / "generated" / "portal" / "tls.conf").write_text("ssl_ecdh_curve X25519:prime256v1;\n")
    pol = tmp_path / "p.yaml"
    pol.write_text(POLICY)
    s = PySigner(tmp_path / "s", var / "runs")
    s.ensure_key()
    run, props = propose(var, ScopeClient(SCOPE), pol, agency, by="ken", authenticated_by="t", signer=s)
    return run, props[0], s


def test_the_policy_and_the_approval_are_each_written_between_two_signatures(change):
    run, prop, s = change
    cid = prop["payload"]["change_id"]
    approve(run, cid, by="ken", authenticated_by="t", signer=s)
    types = [e["type"] for e in run.ledger.events()]
    assert types[:5] == ["run.started", "checkpoint.signed", "policy.changed", "change.proposed", "checkpoint.signed"]
    assert types[5:8] == ["checkpoint.signed", "approval.granted", "checkpoint.signed"]
    run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"},
                      {"change_id": cid, "status": "enforced", "meets_intent": True, "durable": True, "hardware": "t"})
    run.checkpoint(s)
    t = intervals(list(run.ledger.events()))[0]
    # The bound from the signature before each event is never shorter than the first-seen reading.
    assert t["signer_policy_to_verdict_max_ms"] >= t["signer_policy_to_verdict_ms"] >= 0
    assert t["signer_approval_to_verdict_max_ms"] >= t["signer_approval_to_verdict_ms"] >= 0
    assert t["clocks_disagree_ms"] is None


def test_a_policy_event_stamped_before_the_signature_it_follows_is_refused(tmp_path):
    """Backdating the start of time-to-change. Before the first signature nothing bounds a stamp
    from below; with a signature over run.started, the policy event after it cannot be backdated."""
    from pqch.common import ulid
    runs = tmp_path / "runs"
    s = PySigner(tmp_path / "s", runs)
    s.ensure_key()
    rid, hour_ago = ulid(), "2026-10-05T00:00:00.000Z"
    led = Ledger(runs / rid / "ledger.jsonl")
    led.append("run.started", {"kind": "runner", "id": "r"}, {"run": rid, "scope": SCOPE, "scope_hash": "0" * 64,
                                                               "profile": "t", "schemas": []}, ts=hour_ago)
    cp = s.checkpoint(rid, 0)["checkpoint"]
    led.append("checkpoint.signed", {"kind": "controller", "id": "pqch-signer"}, cp, ts=hour_ago)
    led.append("policy.changed", {"kind": "human", "id": "x"}, {"by": "x"}, ts=hour_ago)
    with pytest.raises(SignerError, match="before the checkpoint"):
        s.checkpoint(rid, 2)


def test_intervals_flag_two_clocks_that_disagree(change):
    run, prop, _signer = change
    cid = prop["payload"]["change_id"]
    events = list(run.ledger.events())
    t = intervals([
        *events,
        {"type": "verdict.issued", "seq": 99, "id": "V", "ts": "2099-01-01T00:00:00.000Z",
         "payload": {"change_id": cid, "status": "enforced", "meets_intent": True, "durable": True}},
        {"type": "checkpoint.signed", "seq": 100, "id": "C", "ts": "2099-01-01T00:00:00.000Z",
         "payload": {"through_seq": 99, "signed_at": events[-1]["payload"]["signed_at"]}}])[0]
    assert t["clocks_disagree_ms"] and t["clocks_disagree_ms"] > 4000


def test_the_signer_refuses_a_ledger_whose_run_started_names_no_run(slice_run, tmp_path):
    s = PySigner(tmp_path / "signer", slice_run.var / "runs")
    s.ensure_key()
    other = slice_run.var / "runs" / "01M40W6W873YWJMWPKGMK3YBMQ"
    shutil.copytree(slice_run.dir, other)
    events = list(Ledger(other / "ledger.jsonl").events())
    del events[0]["payload"]["run"]
    rewrite(Ledger(other / "ledger.jsonl"), events)
    with pytest.raises(SignerError, match="names no run"):
        s.checkpoint(other.name, 3)


def test_the_signers_time_never_runs_backwards_and_checkpoints_only_move_forward(slice_run, tmp_path, monkeypatch):
    import pqch.signer
    s = PySigner(tmp_path / "signer", slice_run.var / "runs")
    s.ensure_key()
    first = slice_run.checkpoint(s)
    monkeypatch.setattr(pqch.signer, "utc_now", lambda: "2026-01-01T00:00:00.000Z")   # the clock steps back
    second = slice_run.checkpoint(s)
    assert second["payload"]["signed_at"] == first["payload"]["signed_at"]
    assert verify_signed(list(slice_run.ledger.events()), s.pub_path.read_bytes(), known=s.record(slice_run.id)).ok
    with pytest.raises(SignerError, match="only move forward"):
        s.checkpoint(slice_run.id, 2)


# ----------------------------------------------------------- F-55, the runner's job log
def _context(tmp_path, *, neg_params=None, started="2026-10-05T10:00:05.000Z", container="NEW", witness=WITNESS,
             status="enforced", neg_raw=REFUSED):
    """A verdict, the events around it, the runner's apply log and job log, and the raw outputs."""
    raws = {"P": ACCEPTED.encode(), "N": neg_raw.encode(), "W": witness.encode()}
    params = {"P": {"groups": "X25519MLKEM768", "tls13": "-tls1_3"},
              "N": neg_params or {"groups": "X25519:P-256", "tls13": ""}, "W": {}}
    jobs = [{"job_id": j, "profile": "tls-witness" if j == "W" else "tls-group-probe", "params": params[j],
             "target": {"host": "172.16.106.10", "port": 443}, "started_at": started,
             "ended_at": "2026-10-05T10:00:09.000Z", "raw": j, "raw_sha256": "h" + j,
             "binding": {"container_id": container}} for j in "PNW"]
    applied = {"type": "change.applied", "id": "A", "payload": {"change_id": "C", "containers": [{"before": "OLD", "after": "NEW"}]}}
    prop = {"type": "change.proposed", "id": "PR", "payload": {"change_id": "C", "check": CHECK}}
    probes = [{"name": n, "job_id": j, "raw_sha256": "h" + j, "started_at": started, "ended_at": "2026-10-05T10:00:09.000Z",
               "container_id": container, "result": r} for n, j, r in
              (("positive", "P", "accepted"), ("negative", "N", "refused"), ("witness", "W", "accepted"))]
    probes[2]["accepted_groups"] = ["X25519MLKEM768"]
    verdict = {"type": "verdict.issued", "id": "V", "payload": {"change_id": "C", "after_event": "A", "status": status,
                                                              "probes": probes, "reasons": []}}
    log = [{"kind": "apply", "run": "R", "change_id": "C", "containers": applied["payload"]["containers"],
            "ended_at": "2026-10-05T10:00:04.000Z"}]
    return {"verdict_events": [verdict], "lookup": lambda ids: [j for j in jobs if j["job_id"] in ids],
            "events": [prop, applied, verdict], "runner_log": log, "run_id": "R",
            "read_raw": lambda job: raws[job["raw"]]}


def _check(**kw):
    c = _context(None, **kw)
    return probe_checks(c.pop("verdict_events"), c.pop("lookup"), **c)


def test_an_honest_verdict_is_borne_out_by_the_runners_record():
    out = _check()
    assert all(v["ok"] for v in out.values()), out
    assert out["verdict:V"]["ok"]


def test_a_negative_probe_run_with_other_groups_than_the_check_names_is_caught():
    out = _check(neg_params={"groups": "X448", "tls13": ""})
    assert "not the job the check prescribes" in out["N"]["why"] and out["verdict:V"]["ok"] is False


def test_a_job_from_before_the_apply_or_against_another_container_is_caught():
    old = _check(started="2026-10-04T13:35:16.000Z")
    assert "started before the runner finished the apply" in old["P"]["why"]
    other = _check(container="SOMETHING-ELSE")
    assert "another container" in other["P"]["why"] and other["verdict:V"]["ok"] is False


def test_a_verdict_that_misreports_the_runners_raw_output_is_caught():
    both = json.dumps([{"id": "FS_KEMs", "finding": "X25519MLKEM768"}, {"id": "FS_ECDHE_curves", "finding": "X25519"}])
    out = _check(witness=both)                       # the verdict records only the hybrid group
    assert "raw output says" in out["W"]["why"]
    out = _check(neg_raw=ACCEPTED.replace("X25519MLKEM768", "X25519"))   # the verdict records "refused"
    assert "raw output says accepted" in out["N"]["why"]


def test_a_verdict_whose_apply_the_runner_never_logged_is_caught():
    c = _context(None)
    c["runner_log"] = []
    out = probe_checks(c.pop("verdict_events"), c.pop("lookup"), **c)
    assert "not in the runner's log" in out["P"]["why"]


# ------------------------------------------------------------ F-56, F-57, F-64, the runner
def test_a_service_that_does_not_come_up_gets_its_previous_configuration_back(setup):  # noqa: F811
    run, cid, signer, applier = setup()
    approve(run, cid, by="ken", authenticated_by="test", signer=signer)
    path = applier.agency_dir / "generated" / "portal" / "tls.conf"
    before = path.read_text()
    seen = []
    applier._container_at = lambda client, t: {"container_id": "c"}
    applier.runner._client = lambda: None
    applier._recreate = lambda service: seen.append(path.read_text())
    applier._wait_listening = lambda *a, **k: path.read_text() == before     # up only on the old file
    with pytest.raises(Refused, match="did not come up"):
        applier.apply(run.id, cid)
    assert path.read_text() == before and seen[0] != before and seen[1] == before
    log = applier.log()
    assert log[-1]["kind"] == "apply-failed" and log[-1]["listening_after_restore"] is True
    assert not any(e["kind"] == "apply" for e in log)


def test_the_recreate_uses_every_compose_file_the_estate_was_started_with(setup, monkeypatch):  # noqa: F811
    import subprocess
    _run, _cid, _signer, applier = setup()
    applier.compose_files = ["/a/compose.yaml", "/b/compose.agency.yaml"]
    calls = []
    monkeypatch.setattr(subprocess, "run", lambda args, **k: calls.append(args))
    applier._recreate("portal")
    assert calls[0][calls[0].index("-f"):][:4] == ["-f", "/a/compose.yaml", "-f", "/b/compose.agency.yaml"]
    assert "--pull" in calls[0] and "--no-build" in calls[0]


def test_a_comment_cannot_carry_a_line_break_the_service_does_not_see():
    good = "# Rendered from policy/crypto-policy.yaml, intent none. Do not edit:\nssl_ecdh_curve X25519;\n"
    assert render.is_rendered_shape(good)
    for sep in ("\r", "\x0c", " ", "\x85"):
        assert not render.is_rendered_shape(good.replace("Do not edit:", f"x{sep}+ssl_ecdh_curve X25519MLKEM768;"))


# ---------------------------------------------------------------------- F-59, the page
def test_healthz_fails_when_the_policy_files_are_gone(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    import pqch.ui.app as ui
    monkeypatch.setattr(ui, "POLICY", tmp_path / "gone.yaml")
    r = TestClient(ui.app).get("/healthz")
    assert r.status_code == 503 and "gone.yaml" in r.json()["missing"][0]
