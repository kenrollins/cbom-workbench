"""Retention (FR-08): a run's artefacts destroyed on the record, its ledger kept.

A run holds raw scanner output, the documents projected from it and, for a system scan, a server's
own files packed in an archive. The ledger is the system of record and stays, with the public key
its checkpoints are checked against; what the deployment need not keep past its retention period is
the rest. `pqch retention apply --days N` finds every run older than N days, deletes its raw outputs
and written documents, and records what it destroyed, by path as the ledger names them, as
`artefact.destroyed` events in a run of kind `retention` with the person who ran it. A dry run lists
and destroys nothing.

What it will not do:

- delete a raw output a run it is not destroying still cites. Raw files are shared (a replayed or
  re-scored run cites the output of the run it replays), so the file stays until the last run citing
  it is past the period, and the event says it was kept (`kept_cited`);
- follow an evidence ref out of `var/raw`. A ref is a string in a ledger, and a ledger with `..` in
  a ref verifies; the path is resolved and must lie inside `var/raw`, or it is refused and reported;
- act on a run whose ledger does not verify, or whose first event it cannot read. Such a run is
  skipped and reported, and everything it cites is kept;
- destroy before it has recorded. A `destruction.intended` event with the paths goes on the ledger
  first, the files go second, `artefact.destroyed` with what actually went comes third. A pass cut
  short between the two leaves the intent; the next pass records what that one destroyed.
"""

from __future__ import annotations

import contextlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

from pqch import scope as scope_mod
from pqch.common import parse_ts, ulid
from pqch.ledger import verify
from pqch.run import Run

KIND = "retention"
# The ledger, and the key that verifies its checkpoints offline: a retained ledger must still check.
KEEP = ("ledger.jsonl", "ledger.pub")
UNTOUCHED = (KIND, "attestation", "gapfill")


def _raw_path(var: Path, ref: str) -> Path | None:
    """The file under var/raw that an evidence ref names; None when the ref resolves anywhere else."""
    root = (var / "raw").resolve()
    p = (var / ref.removeprefix("var/")).resolve()
    return p if p != root and p.is_relative_to(root) else None


def _raw_refs(events: list) -> list[str]:
    return sorted({str(ev["ref"]) for e in events if isinstance(e, dict) for ev in e.get("evidence") or []
                   if isinstance(ev, dict) and str(ev.get("ref", "")).startswith("var/raw/")})


def survey(var: str | Path, *, days: int, now: datetime | None = None) -> tuple[list[dict], list[dict]]:
    """Every run under `var`, sorted into the runs that would lose artefacts and the runs skipped.

    A candidate's `raw` is what would be deleted; `kept_cited` is raw output it cites that a run not
    being destroyed cites too; `refused` is a ref that leads outside var/raw.
    """
    var = Path(var)
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=days)
    pending: list[tuple[Path, dict, list[str]]] = []
    skipped: list[dict] = []
    cited: set[Path] = set()          # raw files that a run not being destroyed still points at
    runs = var / "runs"
    for d in sorted(p for p in runs.iterdir() if p.is_dir()) if runs.is_dir() else []:
        if not (d / "ledger.jsonl").is_file():
            continue
        try:
            evs = list(Run(var, d.name).ledger.events())
        except OSError as e:
            skipped.append({"run": d.name, "why": f"the ledger cannot be read ({type(e).__name__})"})
            continue
        refs = _raw_refs(evs)
        why = None
        first = evs[0] if evs and isinstance(evs[0], dict) else None
        payload = first.get("payload") if first else None
        if first is None or not isinstance(payload, dict):
            why = "event 0 cannot be read"
        elif payload.get("kind") not in UNTOUCHED:
            try:
                old = parse_ts(first["ts"]) <= cutoff
            except (KeyError, TypeError, ValueError, AttributeError):
                why = "event 0 carries no time that can be read"
            else:
                check = verify(evs) if old else None
                if check is not None and not check.ok:
                    why = f"the ledger does not verify: {check.error} (event {check.at_seq})"
                elif old:
                    pending.append((d, first, refs))
                    continue
        if why:
            skipped.append({"run": d.name, "why": why})
        cited.update(p for p in (_raw_path(var, r) for r in refs) if p is not None)
    out = []
    for d, first, refs in pending:
        raw, kept, refused = [], [], []
        for ref in refs:
            p = _raw_path(var, ref)
            if p is None:
                refused.append(ref)
            elif p in cited:
                kept.append(ref)
            elif p.is_file():
                raw.append(ref)
        docs = sorted(str(p.relative_to(var)) for p in d.iterdir()
                      if p.is_file() and not p.is_symlink() and p.name not in KEEP)
        if raw or docs:
            out.append({"run": d.name, "kind": first["payload"].get("kind"), "started": first["ts"], "raw": raw,
                        "documents": docs, "kept_cited": kept, "refused": refused, "verifies": True})
    return out, skipped


def candidates(var: str | Path, *, days: int, now: datetime | None = None) -> list[dict]:
    """Runs whose first event is older than `days`, with the artefacts each would lose."""
    return survey(var, days=days, now=now)[0]


def unreconciled(var: str | Path) -> list[dict]:
    """Intents an earlier pass recorded and never answered: it was cut short between deleting and recording."""
    intents: dict[str, dict] = {}
    answered: set[str] = set()
    for d in sorted((Path(var) / "runs").glob("*")):
        if not (d / "ledger.jsonl").is_file():
            continue
        evs = [e for e in Run(var, d.name).ledger.events() if isinstance(e, dict)]
        if not evs or (evs[0].get("payload") or {}).get("kind") != KIND:
            continue
        for e in evs:
            if e.get("type") == "destruction.intended":
                intents[e["id"]] = {"intent": e["id"], "intent_run": d.name, **e["payload"]}
            elif e.get("type") == "artefact.destroyed" and e["payload"].get("intent"):
                answered.add(e["payload"]["intent"])
    return [v for k, v in intents.items() if k not in answered]


def apply(var: str | Path, *, days: int, by: str, basis: str, dry_run: bool = False, signer=None,
          now: datetime | None = None) -> dict:
    var = Path(var)
    todo, skipped = survey(var, days=days, now=now)
    owed = [] if dry_run else unreconciled(var)
    if dry_run or not (todo or owed):
        return {"dry_run": dry_run, "runs": todo, "destroyed": 0, "skipped": skipped}
    scope = {"schema": "pqch.scope/1", "id": ulid(), "estate": "external", "owned": False, "authorized_by": by,
             "endpoints": [], "images": [], "sources": [], "reach": {"kind": "local"}}
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile=f"retention:{days}d", kind=KIND,
                    runner_id="pqch-retention")
    actor = {"kind": "human", "id": by}
    destroyed = 0
    try:
        for o in owed:
            # What the interrupted pass meant to destroy and is no longer there, it destroyed.
            gone = [rel for rel in o.get("paths", []) if not (var / str(rel).removeprefix("var/")).exists()]
            run.ledger.append("artefact.destroyed", actor, {
                "run": o.get("run"), "kind": o.get("kind"), "started": o.get("started"),
                "retention_days": o.get("retention_days"), "destroyed": gone, "kept": list(KEEP),
                "intent": o["intent"], "intent_run": o["intent_run"], "reconciled": True,
                "basis": "an earlier retention pass recorded its intent and was cut short before recording the "
                         "result; these paths are gone"})
        by_this_pass: dict[Path, str] = {}
        for c in todo:
            paths = c["raw"] + c["documents"]
            intent = run.ledger.append("destruction.intended", actor, {
                "run": c["run"], "kind": c["kind"], "started": c["started"], "retention_days": days, "paths": paths,
                "basis": basis})
            gone, earlier, failed = [], [], []
            for rel in paths:
                # A raw path is resolved again here, at the moment of deleting; a document's path was
                # built from the run directory's own listing, never from a ledger.
                p = _raw_path(var, rel) if rel in c["raw"] else var / rel
                if p is None:
                    continue
                if p in by_this_pass:
                    earlier.append(rel)
                    continue
                try:
                    if p.is_file():
                        p.unlink()
                        by_this_pass[p] = c["run"]
                        gone.append(rel)
                        destroyed += 1
                except OSError as e:
                    failed.append({"path": rel, "error": type(e).__name__})
            run.ledger.append("artefact.destroyed", actor, {
                "run": c["run"], "kind": c["kind"], "started": c["started"], "retention_days": days, "destroyed": gone,
                "kept": list(KEEP), "kept_cited": c["kept_cited"], "refused": c["refused"], "basis": basis,
                "intent": intent["id"],
                # Raw output this run cited that went with an older run earlier in this same pass.
                **({"destroyed_earlier": earlier} if earlier else {}), **({"failed": failed} if failed else {})},
                inputs=[intent["id"]])
    except BaseException:
        # The retention run is closed whatever stopped the pass; the first failure is the one reported.
        with contextlib.suppress(Exception):
            run.close(signer)
        raise
    run.close(signer)
    return {"dry_run": False, "runs": todo, "destroyed": destroyed, "run": run.id, "skipped": skipped,
            "reconciled": len(owed)}
