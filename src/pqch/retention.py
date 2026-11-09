"""Retention (FR-08): a run's artefacts destroyed on the record, its ledger kept.

A run holds raw scanner output, the documents projected from it and, for a system scan, a server's
own files packed in an archive. The ledger is the system of record and stays; what the deployment
need not keep past its retention period is the rest. `pqch retention apply --days N` finds every run
older than N days, deletes its raw outputs and written documents, and records what it destroyed, by
path as the ledger names them, as `artefact.destroyed` events in a run of kind `retention` with the
person who ran it. A dry run lists and destroys nothing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from pqch import scope as scope_mod
from pqch.common import ulid
from pqch.ledger import verify
from pqch.run import Run

KIND = "retention"
KEEP = ("ledger.jsonl",)
UNTOUCHED = (KIND, "attestation", "gapfill")


def candidates(var: str | Path, *, days: int, now: datetime | None = None) -> list[dict]:
    """Runs whose first event is older than `days`, with the artefacts each would lose."""
    var = Path(var)
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=days)
    out = []
    runs = var / "runs"
    for d in sorted(p for p in runs.iterdir() if p.is_dir()) if runs.is_dir() else []:
        led = d / "ledger.jsonl"
        if not led.is_file():
            continue
        r = Run(var, d.name)
        evs = list(r.ledger.events())
        if not evs or not isinstance(evs[0], dict):
            continue
        first = evs[0]
        if first.get("payload", {}).get("kind") in UNTOUCHED:
            continue
        started = datetime.fromisoformat(first["ts"].replace("Z", "+00:00"))
        if started > cutoff:
            continue
        raw = sorted({ev["ref"] for e in evs if isinstance(e, dict) for ev in e.get("evidence") or []
                      if str(ev.get("ref", "")).startswith("var/raw/") and (var / str(ev["ref"]).removeprefix("var/")).is_file()})
        docs = sorted(str(p.relative_to(var)) for p in d.iterdir() if p.is_file() and p.name not in KEEP)
        if raw or docs:
            out.append({"run": d.name, "kind": first["payload"].get("kind"), "started": first["ts"], "raw": raw,
                        "documents": docs, "verifies": verify(evs).ok})
    return out


def apply(var: str | Path, *, days: int, by: str, basis: str, dry_run: bool = False, signer=None,
          now: datetime | None = None) -> dict:
    var = Path(var)
    todo = candidates(var, days=days, now=now)
    if dry_run or not todo:
        return {"dry_run": dry_run, "runs": todo, "destroyed": 0}
    scope = {"schema": "pqch.scope/1", "id": ulid(), "estate": "external", "owned": False, "authorized_by": by,
             "endpoints": [], "images": [], "sources": [], "reach": {"kind": "local"}}
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile=f"retention:{days}d", kind=KIND,
                    runner_id="pqch-retention")
    destroyed = 0
    for c in todo:
        gone = []
        for rel in c["raw"] + c["documents"]:
            p = var / rel.removeprefix("var/")
            if p.is_file():
                p.unlink()
                gone.append(rel)
                destroyed += 1
        run.ledger.append("artefact.destroyed", {"kind": "human", "id": by}, {
            "run": c["run"], "kind": c["kind"], "started": c["started"], "retention_days": days, "destroyed": gone,
            "kept": list(KEEP), "basis": basis})
    run.close(signer)
    return {"dry_run": False, "runs": todo, "destroyed": destroyed, "run": run.id}
