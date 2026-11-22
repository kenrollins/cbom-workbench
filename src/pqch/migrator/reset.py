"""Putting the owned estate back to its starting state, on the record.

A reset rewrites every policy-managed service's configuration, so it passes the same gate as any
other change to the estate: a person asks (`reset.requested`), a person approves (`approval.granted`,
naming the request's event id as its `change_id`, with `reset: true` and — ADR-0008 — the role and
groups the approval rested on), both under signed checkpoints; only then does the runner restore each
file from agency/baseline/ and recreate the service (`estate.reset`). Any change run still open is
closed, since its proposals no longer match the estate. The plan and the score then read the next scan.

Three steps, so two people can take them where separation of duties is on: `request_reset`,
`approve_reset`, `execute_reset`. `reset_estate` is the three in one call for a single operator, who
asks and approves in one act and is recorded as both; under `PQCH_SEPARATION_OF_DUTIES=1` the runner
refuses that, as it refuses a self-approved change.
"""

from __future__ import annotations

from pathlib import Path

from pqch.run import Run
from pqch.runner.client import RunnerRefused

RUNNER = {"kind": "runner", "id": "pqch-runner"}


def request_reset(var: Path, runner, signer, *, by: str, authenticated_by: str) -> Run:
    """Open a reset run holding one person's request, under a signed checkpoint."""
    from pqch.ui.view import change_runs

    if not by or not authenticated_by:
        raise PermissionError("a reset request needs who asked and how they were authenticated")
    scope, runner_hash = runner.scope()
    open_runs = [r.id for r in change_runs(var) if list(r.ledger.events())[-1]["type"] != "run.closed"]
    run = Run.start(var, scope, runner_scope_hash=runner_hash, profile="estate-reset", kind="reset", runner_id="pqch-runner")
    run.checkpoint(signer)
    run.ledger.append("reset.requested", {"kind": "human", "id": by}, {
        "by": by, "authenticated_by": authenticated_by, "baseline": "agency/baseline/", "closes": open_runs})
    run.checkpoint(signer)
    return run


def _request(run: Run) -> dict:
    for e in run.ledger.events():
        if e["type"] == "reset.requested":
            return e
    raise KeyError(f"no reset request in run {run.id}")


def approve_reset(run: Run, signer, *, by: str, authenticated_by: str, role: str | None = None,
                  groups: list[str] | None = None, deny: bool = False) -> dict:
    """Record a person's approval (or denial) of the run's reset request, as `migrator.approve` does
    for a change: who, how authenticated, and the role and groups it rested on."""
    if not by or not authenticated_by:
        raise PermissionError("an approval needs who approved and how they were authenticated")
    req = _request(run)
    run.checkpoint(signer)
    payload = {"change_id": req["id"], "reset": True, "by": by, "authenticated_by": authenticated_by}
    if role:
        payload["role"] = role
    if groups is not None:
        payload["groups"] = sorted(groups)
    ev = run.ledger.append("approval.denied" if deny else "approval.granted", {"kind": "human", "id": by}, payload,
                           inputs=[req["id"]])
    run.checkpoint(signer)
    return ev


def execute_reset(var: Path, run: Run, runner, signer) -> tuple[dict, list[str]]:
    """Have the runner reset the estate on the run's approved request, record what it did, and close
    the change runs the request named and the reset run. A refusal after the runner had begun is
    recorded with the runner's own account of what it left (`reset.failed`), and the run closed: the
    estate is then partly reset, and the ledger says which services were and which one was put back."""
    req = _request(run)
    try:
        out = runner.reset(run.id)
    except RunnerRefused as e:
        if getattr(e, "entry", None):
            run.ledger.append("reset.failed", RUNNER, e.entry, inputs=[req["id"]])
            run.close(signer)
        raise
    run.ledger.append("estate.reset", RUNNER, out, inputs=[req["id"]])
    closed = []
    for rid in req["payload"].get("closes") or []:
        other = Run(var, rid)
        if list(other.ledger.events())[-1]["type"] != "run.closed":
            other.close(signer)
            closed.append(rid)
    run.close(signer)
    return out, closed


def reset_estate(var: Path, runner, signer, *, by: str, authenticated_by: str, role: str | None = None,
                 groups: list[str] | None = None) -> tuple[Run, dict, list[str]]:
    """One operator asks for the reset and approves it in one act; both events name them. `role` and
    `groups` are what the deployment granted them for the approval (the page's approver check)."""
    run = request_reset(var, runner, signer, by=by, authenticated_by=authenticated_by)
    approve_reset(run, signer, by=by, authenticated_by=authenticated_by, role=role, groups=groups)
    try:
        out, closed = execute_reset(var, run, runner, signer)
    except RunnerRefused:
        if list(run.ledger.events())[-1]["type"] != "run.closed":
            run.close(signer)          # refused before anything was touched: nothing more will happen in this run
        raise
    return run, out, closed
