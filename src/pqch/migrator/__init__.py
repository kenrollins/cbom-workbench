"""The Agile path on the slice: a policy change, proposed, approved, applied, verified.

    propose   policy.changed (human), then change.proposed (rule policy/render/1) for
              every target whose rendered configuration differs from what is deployed;
              the proposal carries the diff, the rollback and the verifier check
    approve   approval.granted (human, with who and how authenticated), then a checkpoint
    execute   the runner applies (change.applied), the verifier probes (verdict.issued),
              checkpoint; the runner recreates the service unchanged (service.recreated),
              the verifier repeats (verdict.issued, durable true or false), checkpoint; close

Nothing is applied without an approval event, and the runner checks that for
itself. Time-to-change is computed from ledger timestamps (`intervals`).
"""

from __future__ import annotations

import os
from pathlib import Path

from pqch import scope as scope_mod
from pqch import verifier
from pqch.common import ms_between, sha256_hex, ulid
from pqch.ledger.checkpoints import SKEW_MS
from pqch.migrator import render
from pqch.run import Run
from pqch.scout import read_raw

RULE = {"kind": "rule", "id": "policy/render/1"}
RUNNER = {"kind": "runner", "id": "pqch-runner"}


def deployed(agency_dir: Path, service: str, software: str = "nginx") -> str:
    p = render.target_path(agency_dir, service, software)
    return p.read_text() if p.exists() else ""


def propose(var: Path, client, policy_path: Path, agency_dir: Path, *, by: str, authenticated_by: str,
            signer=None, seam=None, scan_run: Run | None = None) -> tuple[Run, list[dict]]:
    """Open a change run: the policy as it now stands, and a proposal for each target it changes."""
    policy = render.load(policy_path)
    scope, runner_hash = client.scope()
    run = Run.start(var, scope, runner_scope_hash=runner_hash, profile="m0a-change", kind="change")
    if signer is not None:
        # A signature before the policy event: with the one after the proposals it brackets
        # the event on the signer's clock, so its stamp can be neither backdated nor held.
        run.checkpoint(signer)
    data = Path(policy_path).read_bytes()
    pol_ev = run.ledger.append("policy.changed", {"kind": "human", "id": by}, {
        "path": str(policy_path), "sha256": sha256_hex(data), "by": by, "authenticated_by": authenticated_by,
        "targets": [{k: t[k] for k in ("service", "address", "port", "intent")} for t in policy["targets"]],
    })
    proposals = []
    for t in policy["targets"]:
        ep = scope_mod.endpoint(scope, t["address"], t["port"])
        if ep is None:
            continue
        if t.get("software", "nginx") not in render.RENDERED:
            if _in_force(var, t, agency_dir):
                continue
            ev = _drafted(run, t, policy, ep, agency_dir, pol_ev, var=var, seam=seam, scan_run=scan_run)
            if ev is not None:
                proposals.append(ev)
            continue
        sw = t.get("software", "nginx")
        new = render.render_for(sw, policy, t["intent"])
        old = deployed(agency_dir, t["service"], sw)
        if new == old:
            continue
        diff = render.diff(old, new, t["service"], sw)
        ev = run.ledger.append("change.proposed", RULE, {
            "change_id": ulid(),
            "rule_id": "policy/render/1",
            "target": {"service": t["service"], "address": t["address"], "port": t["port"]},
            "intent": t["intent"],
            "diff": diff,
            "new_content": new, "new_sha256": sha256_hex(new.encode()),
            "rollback": old, "rollback_sha256": sha256_hex(old.encode()),
            "check": render.check(policy, t, ep.get("sni")),
        }, inputs=[pol_ev["id"]])
        proposals.append(ev)
    if signer is not None:
        # A signer time for the policy change: the start of time-to-change on the signer's clock.
        run.checkpoint(signer)
    return run, proposals


def _in_force(var: Path, t: dict, agency_dir: Path) -> bool:
    """A drafted change already in force: the service's deployed policy file is exactly the file of a
    change that landed — verified, and verified again after a recreate — with the same intent. A rule
    renders the same file again and sees no difference; a model would draft afresh, so this says so."""
    from pqch.ui.view import change_runs

    sw = t.get("software", "nginx")
    path = render.target_path(agency_dir, t["service"], sw)
    if not path.exists():
        return False
    have = sha256_hex(path.read_bytes())
    for r in change_runs(var):
        events = list(r.ledger.events())
        props = {e["payload"]["change_id"]: e["payload"] for e in events if e["type"] == "change.proposed"}
        for iv in intervals(events):
            p = props.get(iv["change_id"], {})
            if (iv.get("landed") and p.get("target", {}).get("service") == t["service"]
                    and p.get("intent") == t["intent"] and p.get("new_sha256") == have):
                return True
    return False


def _drafted(run: Run, t: dict, policy: dict, ep: dict, agency_dir: Path, pol_ev: dict, *, var: Path, seam,
             scan_run: Run | None) -> dict | None:
    """A target whose software has no renderer: the change-plan role drafts it from the CBOM.
    Nothing is drafted when the deployed file already holds what the intent asks of a previous
    draft — the policy matched what was deployed — or when the intent is `none` and nothing was set."""
    from pqch.migrator import plan
    from pqch.ui.view import traces_by_fingerprint

    old = deployed(agency_dir, t["service"], t["software"])
    if t["intent"] == "none" and old == render.base(t["software"]):
        return None
    scan_run = scan_run or Run.latest(var, "scan")
    if scan_run is None:
        raise ValueError("a drafted change needs a scan of the estate: its context is the CBOM")
    events = list(scan_run.ledger.events())
    kex = next((e for e in events if e["type"] == "finding.observed" and e["payload"]["layer"] == "wire"
                and e["payload"]["subject"].get("host") == t["address"] and e["payload"]["subject"].get("port") == t["port"]
                and e["payload"]["asset"]["role"] == "key-establishment"
                and e["payload"]["fingerprint"] in traces_by_fingerprint(var)), None)
    trace = kex and traces_by_fingerprint(var)[kex["payload"]["fingerprint"]]
    d = plan.draft(run, scan_run=scan_run, target=t, intent=t["intent"], agency_dir=agency_dir,
                   inputs=[pol_ev["id"]], seam=seam, trace=trace)
    if "type" in d:        # no usable reply: the assessment says why
        return None
    new = d["new"]
    return run.ledger.append("change.proposed", d["actor"], {
        "change_id": ulid(),
        "rule_id": None, "drafted": d["drafted"],
        "target": {"service": t["service"], "address": t["address"], "port": t["port"]},
        "intent": t["intent"],
        "diff": render.diff(old, new, t["service"], t["software"]),
        "new_content": new, "new_sha256": sha256_hex(new.encode()),
        "rollback": old, "rollback_sha256": sha256_hex(old.encode()),
        "check": render.check(policy, t, ep.get("sni")),
    }, inputs=[pol_ev["id"]])


def rehearse(run: Run, client, signer, change_id: str, *, hardware: str = "unlabelled") -> dict:
    """Prove a proposal on a copy of the service in the twin, before approval: the runner starts the
    copy with the proposed file; the verifier runs the change's own check against it."""
    prop = _proposal(run, change_id)
    entry = client.rehearse(run.id, change_id)
    try:
        if not entry["listening"]:
            verdict = {"status": "did-not-start", "meets_intent": False, "logs_tail": entry.get("logs_tail", "")}
        else:
            check = dict(prop["payload"]["check"])
            host, port = entry["twin"].rsplit(":", 1)
            check["target"] = {**check["target"], "host": host, "port": int(port)}
            scope_hash = next(iter(run.ledger.events()))["payload"]["scope_hash"]
            verdict = verifier.verify(client, scope_hash, check, change_id=change_id,
                                      after_event={"id": prop["id"], "ts": entry["ended_at"], "type": "rehearsal"},
                                      expect={"container_id": entry["container"], "image_digest": entry["image_digest"]},
                                      read_raw=lambda job: read_raw(run.var, job), hardware=hardware)
    finally:
        client.rehearse_end(run.id, change_id)
    ev = run.ledger.append("rehearsal.completed", verifier.ACTOR, {
        "change_id": change_id, "twin": entry["twin"], "container": entry["container"],
        "image": entry["image"], "image_digest": entry["image_digest"], "config_sha256": entry["config_sha256"],
        "started_at": entry["started_at"], "listening": entry["listening"], **{"verdict": verdict}},
        inputs=[prop["id"]])
    if signer is not None:
        run.checkpoint(signer)
    return ev


def approve(run: Run, change_id: str, *, by: str, authenticated_by: str, signer, deny: bool = False) -> dict:
    if not by or not authenticated_by:
        raise PermissionError("an approval needs who approved and how they were authenticated")
    prop = _proposal(run, change_id)
    # A signature just before the approval and one just after: the signer's bracket on when it was written.
    run.checkpoint(signer)
    ev = run.ledger.append("approval.denied" if deny else "approval.granted", {"kind": "human", "id": by},
                           {"change_id": change_id, "by": by, "authenticated_by": authenticated_by},
                           inputs=[prop["id"]])
    run.checkpoint(signer)
    return ev


def _proposal(run: Run, change_id: str) -> dict:
    for e in run.ledger.events():
        if e["type"] == "change.proposed" and e["payload"]["change_id"] == change_id:
            return e
    raise KeyError(f"no proposal {change_id} in run {run.id}")


def verify_now(run: Run, client, signer, change_id: str, *, after_event: dict, expect: dict,
               target_override: dict | None = None, repeats: dict | None = None) -> dict:
    """Run the change's check, record the verdict, and checkpoint it."""
    prop = _proposal(run, change_id)
    check = dict(prop["payload"]["check"])
    if target_override:
        check["target"] = {**check["target"], **target_override}
    _, scope_hash = client.scope()
    verdict = verifier.verify(client, scope_hash, check, change_id=change_id, after_event=after_event,
                              expect=expect, read_raw=lambda job: read_raw(run.var, job),
                              hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"))
    if target_override:
        verdict["target_override"] = target_override
    if repeats is not None:
        same = verdict["status"] == repeats["payload"]["status"] and verdict["status"] != "inconclusive"
        verdict["durable"] = same
        verdict["repeats"] = repeats["id"]
    evidence = [{"ref": p["raw"], "sha256": p["raw_sha256"]} for p in verdict["probes"] if p.get("raw")]
    ev = run.ledger.append("verdict.issued", verifier.ACTOR, verdict,
                           inputs=[prop["id"], after_event["id"]], evidence=evidence)
    run.checkpoint(signer)
    return ev


def execute(run: Run, client, signer, change_id: str, *, close: bool = True) -> dict:
    """Apply an approved change through the runner, verify it, then recreate and verify again."""
    prop = _proposal(run, change_id)
    applied = client.apply(run.id, change_id)
    a_ev = run.ledger.append("change.applied", RUNNER, applied, inputs=[prop["id"]])
    c = applied["containers"][0]
    first = verify_now(run, client, signer, change_id, after_event=a_ev,
                       expect={"container_id": c["after"], "image_digest": c["image_digest"]})
    rec = client.recreate(run.id, change_id)
    r_ev = run.ledger.append("service.recreated", RUNNER, rec, inputs=[a_ev["id"]])
    c2 = rec["containers"][0]
    second = verify_now(run, client, signer, change_id, after_event=r_ev,
                        expect={"container_id": c2["after"], "image_digest": c2["image_digest"]}, repeats=first)
    # A run may hold several proposals; it closes once each is applied or denied, not after the first.
    if close and not pending(run):
        run.close(signer)
    return {"applied": a_ev, "verdict": first, "recreated": r_ev, "durable": second}


def pending(run: Run) -> list[str]:
    """The change ids in a run neither applied nor denied yet."""
    events = list(run.ledger.events())
    done = {e["payload"].get("change_id") for e in events if e["type"] in ("change.applied", "approval.denied")}
    return [e["payload"]["change_id"] for e in events if e["type"] == "change.proposed" and e["payload"]["change_id"] not in done]


def _span(a: str | None, b: str | None) -> int | None:
    return ms_between(a, b) if a and b else None


def intervals(events: list[dict]) -> list[dict]:
    """Time-to-change per change, from ledger timestamps.

    policy_to_verdict: from the policy.changed event to the last verdict for the change's
    target. approval_to_verdict: from the approval to the same verdict. Verdicts taken
    against another target (a deliberate wrong-container check) are not counted.
    """
    policy = next((e for e in events if e["type"] == "policy.changed"), None)
    signed = [(e["payload"]["through_seq"], e["payload"]["signed_at"]) for e in events
              if e["type"] == "checkpoint.signed" and e["payload"].get("signed_at")]

    def signer_time(ev):
        """When the signer first signed over this event: the signer's word that it existed by then."""
        if ev is None:
            return None
        return next((t for n, t in signed if n >= ev["seq"]), None)

    def signer_before(ev):
        """The last signature already in the chain when this event was written: the event is
        chained after that checkpoint, so it did not exist before the signer made it."""
        if ev is None:
            return None
        earlier = [e["payload"]["signed_at"] for e in events if e["type"] == "checkpoint.signed"
                   and e["seq"] < ev["seq"] and e["payload"].get("signed_at")]
        return earlier[-1] if earlier else None
    out = []
    for prop in (e for e in events if e["type"] == "change.proposed"):
        cid = prop["payload"]["change_id"]
        approval = next((e for e in events if e["type"] == "approval.granted" and e["payload"]["change_id"] == cid), None)
        verdicts = [e for e in events if e["type"] == "verdict.issued" and e["payload"]["change_id"] == cid
                    and not e["payload"].get("target_override")]
        last = verdicts[-1] if verdicts else None
        out.append({
            "change_id": cid, "target": prop["payload"]["target"], "intent": prop["payload"]["intent"],
            "statuses": [v["payload"]["status"] for v in verdicts],
            "durable": last and last["payload"].get("durable"),
            "meets_intent": bool(last and last["payload"].get("meets_intent")),
            # Landed: the last verdict meets the intent and repeated after the service was recreated.
            "landed": bool(last and last["payload"].get("meets_intent") and last["payload"].get("durable") is True),
            "policy_to_verdict_ms": ms_between(policy["ts"], last["ts"]) if policy and last else None,
            "approval_to_verdict_ms": ms_between(approval["ts"], last["ts"]) if approval and last else None,
            "hardware": last and last["payload"].get("hardware"),
            "policy_ts": policy and policy["ts"], "approval_ts": approval and approval["ts"],
            "verdict_ts": last and last["ts"],
            "signer_policy_ts": signer_time(policy), "signer_approval_ts": signer_time(approval),
            "signer_verdict_ts": signer_time(last),
            "signer_policy_to_verdict_ms": _span(signer_time(policy), signer_time(last)),
            "signer_approval_to_verdict_ms": _span(signer_time(approval), signer_time(last)),
            # The bound that holds whatever the harness stamped: from the last signature before
            # the event was written to the first signature over the verdict. None when the run
            # has no signature before the event (runs from before the bracket was written).
            "signer_policy_to_verdict_max_ms": _span(signer_before(policy), signer_time(last)),
            "signer_approval_to_verdict_max_ms": _span(signer_before(approval), signer_time(last)),
        })
    for t in out:
        # The two clocks are held within SKEW_MS at each end; further apart, one of them is wrong.
        a, b = t["policy_to_verdict_ms"], t["signer_policy_to_verdict_ms"]
        t["clocks_disagree_ms"] = abs(a - b) if a is not None and b is not None and abs(a - b) > 2 * SKEW_MS else None
    return out
