"""Putting the owned estate back to its starting state, on the record.

A person asks (`reset.requested`, signed under a checkpoint); the runner restores every policy-managed
service's file from agency/baseline/ and recreates it (`estate.reset`); any change run still open is
closed, since its proposals no longer match the estate. The plan and the score then read the next scan.
"""

from __future__ import annotations

from pathlib import Path

from pqch.run import Run


def reset_estate(var: Path, runner, signer, *, by: str, authenticated_by: str) -> tuple[Run, dict, list[str]]:
    from pqch.ui.view import change_runs

    scope, runner_hash = runner.scope()
    open_runs = [r.id for r in change_runs(var) if list(r.ledger.events())[-1]["type"] != "run.closed"]
    run = Run.start(var, scope, runner_scope_hash=runner_hash, profile="estate-reset", kind="reset", runner_id="pqch-runner")
    run.checkpoint(signer)
    run.ledger.append("reset.requested", {"kind": "human", "id": by}, {
        "by": by, "authenticated_by": authenticated_by, "baseline": "agency/baseline/", "closes": open_runs})
    run.checkpoint(signer)
    out = runner.reset(run.id)
    run.ledger.append("estate.reset", {"kind": "runner", "id": "pqch-runner"}, out)
    for rid in open_runs:
        Run(var, rid).close(signer)
    run.close(signer)
    return run, out, open_runs
