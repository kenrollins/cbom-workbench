"""One run of the slice, start to finish: scope, key, scans, rules, CBOM, score.

Used by the CLI and by the scan button; both call `run_once`.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path

from pqch import cbom, schemas, scout, varmode
from pqch.assessor import load_policy, structure
from pqch.run import Run
from pqch.score import score_run

PROFILE = "m0-targeted"


@contextmanager
def on_the_record(var: Path, kind: str):
    """A run that fails part-way still ends on its ledger. The body puts its run in the yielded dict
    (`run`, and `opened` and `operator` when a scan window is open). If the body raises — the runner
    refused a job, a tool or an engine was unreachable — the window is closed with what happened, a
    `run.failed` event records the reason, the run is checkpointed and closed like any other, and the
    `LATEST` pointers go back to the run they named before, so no page takes a half-made run for the
    estate's latest scan. The error still reaches the caller."""
    names = ("LATEST", f"LATEST_{kind.upper().replace('-', '_')}", f"LATEST_{kind.upper()}")
    before = {n: (var / "runs" / n).read_text() for n in names if (var / "runs" / n).exists()}
    box: dict = {}
    try:
        yield box
    except BaseException as e:
        run = box.get("run")
        if run is not None:
            reason = f"{type(e).__name__}: {e}"[:500]
            try:
                if box.get("opened"):
                    run.ledger.append("window.closed", {"kind": "human", "id": box.get("operator") or "operator"},
                                      {"aborted": True, "reason": reason}, inputs=[box["opened"]["id"]])
                run.ledger.append("run.failed", {"kind": "runner", "id": "pqch-runner"}, {"reason": reason})
                run.close(signer_from_env())
            except Exception:  # noqa: S110 - the first error is the one to report, and it is raised below
                pass
            for n in names:
                ptr = var / "runs" / n
                if ptr.exists() and ptr.read_text().strip() == run.id:
                    if n in before:
                        ptr.write_text(before[n])
                    else:
                        ptr.unlink()
        raise


def run_once(var: Path, client, key_path: Path, *, host: str = "replay", classify: bool = False,
             explain: bool = False, progress: Callable[[dict], None] | None = None) -> tuple[Run, dict]:
    # The scope is the one the runner enforces. The UI service holds no copy of its own.
    scope, runner_hash = client.scope()
    schemas.validate(scope)
    with on_the_record(var, "scan") as rec:
        run = rec["run"] = Run.start(var, scope, runner_scope_hash=runner_hash, profile=PROFILE)
        run.commit_key(key_path, author=os.environ.get("PQCH_OPERATOR", "operator"),
                       commit=os.environ.get("PQCH_KEY_COMMIT"))
        summary = scout.scan(run, client, scope, runner_hash, host=host, progress=progress)
        policy = load_policy(os.environ.get("PQCH_POLICY", "policy/pq-algorithms.yaml"))
        summary["rules"] = structure(run, policy)
        summary["rules"].update(enrich(run, author=os.environ.get("PQCH_OPERATOR", "operator")))
        from pqch.watch import observe

        summary["changes"] = observe(run, Path(os.environ.get("PQCH_AGENCY_DIR", "agency")))
        if explain:
            from pqch.assessor.explain import explain as explain_conflicts

            summary["explained"] = explain_conflicts(run)
        if classify:
            # An optional model step: an engine that does not answer leaves the scan whole. The rules
            # have already run, nothing below reads this, and the summary says what happened.
            from pqch import inference
            from pqch.assessor.wiring import classify_one

            try:
                ev = classify_one(run, policy)
                summary["classification"] = ev and {"actor": ev["actor"], **ev["payload"]}
            except (inference.TierUnavailable, inference.SchemaViolation) as e:
                summary["classification"] = {"not_classified": inference.failure_text(e)}
        run.close(signer_from_env())
        rec["run"] = None        # closed: what follows is rebuilt from the ledger, and the run stands
        write_cboms(run)
        write_score(run, key_path)
        from pqch.planning import write_register

        write_register(var, run)
    return run, summary


def scan_external(var: Path, client, *, progress: Callable[[dict], None] | None = None) -> tuple[Run, dict]:
    """A targeted scan of an external estate: the listeners the runner's scope names, nothing more.
    No answer key and no score — nothing is planted there — and no apply is possible: the runner
    acts only on an owned estate. Rules still run (posture per listener); the run is its own kind,
    so the demonstration page's latest scan is untouched."""
    scope, runner_hash = client.scope()
    schemas.validate(scope)
    if scope.get("estate") != "external" or not scope.get("authorized_by"):
        raise ValueError("scan_external needs an external scope carrying the operator's authorization")
    with on_the_record(var, "scan-external") as rec:
        run = rec["run"] = Run.start(var, scope, runner_scope_hash=runner_hash, profile="external-targeted", kind="scan-external")
        summary = scout.scan(run, client, scope, runner_hash, host="skip", progress=progress)
        policy = load_policy(os.environ.get("PQCH_POLICY", "policy/pq-algorithms.yaml"))
        summary["rules"] = structure(run, policy)
        summary["rules"].update(enrich(run, author=os.environ.get("PQCH_OPERATOR", "operator"), context=None))
        run.close(signer_from_env())
        rec["run"] = None        # closed: what follows is rebuilt from the ledger, and the run stands
        write_cboms(run)
    return run, summary


def copy_refusal(scope: dict) -> str | None:
    """Why a scope cannot be scanned as a copy, or None: it must be an external, unowned estate carrying
    the operator's authorization, declare what it is a copy of and when the copy was taken, and name
    the original of every listener. Anything less is a plain external scan, not a scored copy."""
    if scope.get("estate") != "external" or scope.get("owned") or not scope.get("authorized_by"):
        return "a copy is scanned as an external, unowned estate carrying the operator's authorization"
    if not scope.get("copy"):
        return "the scope declares no `copy` (what it copies and when the copy was taken)"
    unmapped = [f"{e['host']}:{e['port']}" for e in scope["endpoints"] if not e.get("copy_of")]
    if unmapped:
        return "every listener must name the original it is a copy of (`copy_of`); these do not: " + ", ".join(unmapped)
    return None


def scan_copy(var: Path, client, key_path: Path, *, sources: str | None = None,
              progress: Callable[[dict], None] | None = None) -> tuple[Run, dict]:
    """A scored wire scan of a frozen copy of the estate the answer key describes, placed where another
    tool can see it. The listeners the runner's scope names, nothing more: no images, and no apply is
    possible, as for any external estate. The key is committed and the score written through the
    scope's address map (score.address_map), so the copy's CBOM carries the addresses it was seen at
    and one key stays the source of truth; the owner's context is supplied so the score has the shape
    of the estate's own. Its own kind, `scan-copy`: not the latest scan of any estate, and outside the
    gap queue and the plan, which read the estates themselves. The scan window is on the ledger —
    `window.opened` before the first job and `window.closed` after the last, with the addresses the
    scans come from when given — for whoever else watches that wire."""
    scope, runner_hash = client.scope()
    schemas.validate(scope)
    if (why := copy_refusal(scope)):
        raise ValueError(f"scan_copy: {why}")
    operator = os.environ.get("PQCH_OPERATOR", "operator")
    with on_the_record(var, "scan-copy") as rec:
        run = rec["run"] = Run.start(var, scope, runner_scope_hash=runner_hash, profile="copy-wire", kind="scan-copy")
        run.commit_key(key_path, author=operator, commit=os.environ.get("PQCH_KEY_COMMIT"))
        opened = run.ledger.append("window.opened", {"kind": "human", "id": operator}, {
            "purpose": f"wire scan of the copy of {scope['copy']['of']}: {len(scope['endpoints'])} listeners, "
                       "targeted TLS and SSH scans, no change",
            "sources": sources, "listeners": [f"{e['host']}:{e['port']}" for e in scope["endpoints"]]})
        rec["opened"], rec["operator"] = opened, operator
        summary = scout.scan(run, client, scope, runner_hash, host="skip", progress=progress)
        run.ledger.append("window.closed", {"kind": "human", "id": operator},
                          {"jobs": len(summary["jobs"]), "wall_ms": summary["wall_ms"]}, inputs=[opened["id"]])
        rec["opened"] = None
        policy = load_policy(os.environ.get("PQCH_POLICY", "policy/pq-algorithms.yaml"))
        summary["rules"] = structure(run, policy)
        summary["rules"].update(enrich(run, author=operator))
        run.close(signer_from_env())
        rec["run"] = None        # closed: what follows is rebuilt from the ledger, and the run stands
        write_cboms(run)
        summary["score"] = write_score(run, key_path)
    return run, summary


def enrich(run: Run, *, author: str, context: Path | str | None = "env") -> dict:
    """The rules after the structural ones: the service links of the dependency chain, the owner's
    supplied facts, the verifier kind per finding class, and the resolution of each conflict.
    `context` is the owner's context file; `"env"` reads PQCH_CONTEXT, None supplies nothing (an
    external estate has no owner's file in this deployment)."""
    from pqch.assessor import chains, conflicts, verifiers

    out = chains.link_services(run)
    if context == "env":
        context = Path(os.environ.get("PQCH_CONTEXT", "agency/context.yaml"))
    if context is not None and Path(context).is_file():
        out.update(chains.supply(run, Path(context), author=author))
    from pqch.assessor import libraries

    snap = Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots"))
    caps = sorted(snap.glob("capabilities-*.json"))
    out.update(libraries.link(run, json.loads(caps[-1].read_text()) if caps else None))
    out.update(verifiers.classes(run, verifiers.load_verifiers(
        os.environ.get("PQCH_VERIFIERS", "policy/verifiers.yaml"))))
    out.update(conflicts.resolve(run))
    out.update(managed(run))
    from pqch.assessor import gaps

    out.update(gaps.record(run))
    return out


def managed(run: Run) -> dict:
    """The Managed rung's rules over the policy pack and the two dated snapshots."""
    from pqch.assessor import managed as m

    snap = Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots"))
    latest = lambda pattern: (sorted(snap.glob(pattern)) or [None])[-1]  # noqa: E731
    return m.assess(run, pack_path=os.environ.get("PQCH_PACK", "policy/packs/m-26-15.yaml"),
                    families_path=os.environ.get("PQCH_FAMILIES", "policy/algorithm-families.yaml"),
                    capabilities_path=latest("capabilities-*.json"), cmvp_path=latest("cmvp-*.json"))


def score_with_remediation(var: Path, run_dir: Path, key_path: Path, *, recorded_sha256: str | None) -> dict:
    """A run's score as the run records it: every column against the key, then the remediated rule.
    The one entry point for writing a score and for scoring a recorded run again (eval/score.py)."""
    import yaml

    result = score_run(run_dir, key_path, recorded_sha256=recorded_sha256)
    with (run_dir / "ledger.jsonl").open(encoding="utf-8") as f:
        first = json.loads(f.readline())
    key = yaml.safe_load(key_path.read_text())
    remediated_rows(var, first, key, [col["layers"]["wire"] for col in result.get("columns", {}).values()
                                      if col.get("layers", {}).get("wire")])
    return result


def write_score(run: Run, key_path: Path) -> dict:
    """Score the run's CBOMs against the key whose hash the run recorded."""
    recorded = next(e["payload"]["sha256"] for e in run.ledger.events() if e["type"] == "key.committed")
    result = score_with_remediation(run.var, run.dir, key_path, recorded_sha256=recorded)
    result["labels"] = {"hardware": os.environ.get("PQCH_HARDWARE", "unlabelled"),
                        "build": os.environ.get("PQCH_BUILD", "unlabelled"), "run": run.id}
    (run.dir / "score.json").write_text(json.dumps(result, indent=1) + "\n")
    varmode.private(run.dir / "score.json")
    return result


def _names_in(text: str) -> set[str]:
    """The standard names of every group or key exchange a rendered configuration spells."""
    import re

    from pqch.scout import names

    return {names.algorithm_name(tok) for tok in re.split(r"[^A-Za-z0-9@._-]+", text or "") if tok}


def remediated_changes(var: Path, first: dict) -> dict[tuple, dict]:
    """Per listener, the change that removed key-establishment algorithms from it before this run's
    cut-off: the *latest* landed change on the listener, and only when that one requires the hybrid
    group. A later landed change of any other intent (a roll back among them) cancels an earlier
    require, and an estate reset cancels everything before it. For a run of a copy the cut-off is when
    the copy was taken (the scope's `copy.taken`), and the change must be one the copy is declared to
    carry (`copy.carries`): the copy holds what had landed by then, whatever happened to the estate
    since, and nothing else."""
    from pqch.migrator import intervals
    from pqch.ui.view import change_runs

    start = first["ts"]
    copy = first["payload"]["scope"].get("copy") or {}
    if (taken := copy.get("taken")):
        start = taken + "T23:59:59.999Z" if len(taken) == 10 else taken
    resets = []
    runs = var / "runs"
    for d in sorted(runs.iterdir()) if runs.is_dir() else []:
        led = d / "ledger.jsonl"
        if led.is_file() and json.loads(led.open().readline()).get("payload", {}).get("kind") == "reset":
            resets += [e["ts"] for e in Run(var, d.name).ledger.events() if e["type"] == "estate.reset"]
    last_reset = max([t for t in resets if t < start], default="")
    latest: dict[tuple, dict] = {}
    for cr in change_runs(var):
        events = list(cr.ledger.events())
        proposed = {e["payload"]["change_id"]: e["payload"] for e in events if e["type"] == "change.proposed"}
        for iv in intervals(events):
            t = iv.get("target") or {}
            ts = iv.get("verdict_ts") or ""
            where = (t.get("address"), t.get("port"))
            if iv.get("landed") and last_reset < ts < start and ts >= latest.get(where, {}).get("ts", ""):
                latest[where] = {"ts": ts, "intent": iv.get("intent"), "run": cr.id, "change_id": iv["change_id"],
                                 "keeps": _names_in((proposed.get(iv["change_id"]) or {}).get("new_content", ""))}
    carries = copy.get("carries")
    return {where: c for where, c in latest.items()
            if c["intent"] == "require" and (carries is None or c["change_id"] in carries or c["run"] in carries)}


def remediated_rows(var: Path, first: dict, key: dict, rows: list[dict]) -> None:
    """A keyed wire item a column no longer finds because a change removed it is not a miss. It moves
    from `missed` to `remediated` and out of `present` and the denominator, when all of these hold:
    the listener's latest landed change before the cut-off requires the hybrid group
    (`remediated_changes`); the item is a key-establishment algorithm that change's configuration
    does not keep (the group it requires is still there to be found, and missing it is a miss); and
    the column holds some component for that listener, so it looked and did not find. Anything else
    stays missed. `first` is the scored run's first event; the same rule serves a scan, a scan of a
    copy and an imported document."""
    by_listener = remediated_changes(var, first)
    items = {i["id"]: i for i in key.get("items", [])}
    for row in rows:
        looked = set(row.get("listeners") or [])
        moved = []
        for item_id in list(row["missed"]):
            item = items.get(item_id) or {}
            subj, asset = item.get("subject") or {}, item.get("asset") or {}
            hit = by_listener.get((subj.get("host"), subj.get("port")))
            if (hit and item.get("class") == "present" and asset.get("role") == "key-establishment"
                    and asset.get("name") not in hit["keeps"] and f"{subj.get('host')}:{subj.get('port')}" in looked):
                row["missed"].remove(item_id)
                moved.append({"item": item_id, "run": hit["run"], "change_id": hit["change_id"]})
        row["remediated"] = moved
        row["present"] -= len(moved)
        row["denominator"] = row["present"] + row["out_of_reach"]


def signer_from_env():
    """The signer client, when the deployment has one (PQCH_SIGNER_SOCKET)."""
    sock = os.environ.get("PQCH_SIGNER_SOCKET")
    if not sock:
        return None
    from pqch.signer.client import SignerClient

    return SignerClient(sock)


def write_cboms(run: Run) -> dict[str, Path]:
    """Rebuild every CBOM of a run from its ledger. Safe to delete and rerun at any time."""
    out = {}
    marking = os.environ.get("PQCH_MARKING", "").strip()
    for name, bom in cbom.build_all(list(run.ledger.events())).items():
        if marking:
            # The deployment's marking travels with the written document (FR-08); the projection itself
            # stays a function of the ledger, so the marking is added here, at the file, not in project().
            bom["metadata"]["properties"].append({"name": "pqch:marking", "value": marking})
        path = run.dir / f"{name}.cdx.json"
        path.write_text(json.dumps(bom, indent=1, ensure_ascii=False) + "\n")
        varmode.private(path)
        out[name] = path
    return out
