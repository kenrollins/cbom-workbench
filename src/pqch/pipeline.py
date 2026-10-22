"""One run of the slice, start to finish: scope, key, scans, rules, CBOM, score.

Used by the CLI and by the scan button; both call `run_once`.
"""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

from pqch import cbom, scout
from pqch import schemas
from pqch.assessor import load_policy, structure
from pqch.run import Run
from pqch.score import score_run

PROFILE = "m0-targeted"


def run_once(var: Path, client, key_path: Path, *, host: str = "replay", classify: bool = False,
             explain: bool = False, progress: Callable[[dict], None] | None = None) -> tuple[Run, dict]:
    # The scope is the one the runner enforces. The UI service holds no copy of its own.
    scope, runner_hash = client.scope()
    schemas.validate(scope)
    run = Run.start(var, scope, runner_scope_hash=runner_hash, profile=PROFILE)
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
        from pqch.assessor.wiring import classify_one

        ev = classify_one(run, policy)
        summary["classification"] = ev and {"actor": ev["actor"], **ev["payload"]}
    run.close(signer_from_env())
    write_cboms(run)
    write_score(run, key_path)
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
    run = Run.start(var, scope, runner_scope_hash=runner_hash, profile="external-targeted", kind="scan-external")
    summary = scout.scan(run, client, scope, runner_hash, host="skip", progress=progress)
    policy = load_policy(os.environ.get("PQCH_POLICY", "policy/pq-algorithms.yaml"))
    summary["rules"] = structure(run, policy)
    summary["rules"].update(enrich(run, author=os.environ.get("PQCH_OPERATOR", "operator"), context=None))
    run.close(signer_from_env())
    write_cboms(run)
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
    out.update(verifiers.classes(run, verifiers.load_verifiers(
        os.environ.get("PQCH_VERIFIERS", "policy/verifiers.yaml"))))
    out.update(conflicts.resolve(run))
    out.update(managed(run))
    return out


def managed(run: Run) -> dict:
    """The Managed rung's rules over the policy pack and the two dated snapshots."""
    from pqch.assessor import managed as m

    snap = Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots"))
    latest = lambda pattern: (sorted(snap.glob(pattern)) or [None])[-1]  # noqa: E731
    return m.assess(run, pack_path=os.environ.get("PQCH_PACK", "policy/packs/m-26-15.yaml"),
                    families_path=os.environ.get("PQCH_FAMILIES", "policy/algorithm-families.yaml"),
                    capabilities_path=latest("capabilities-*.json"), cmvp_path=latest("cmvp-*.json"))


def write_score(run: Run, key_path: Path) -> dict:
    """Score the run's CBOMs against the key whose hash the run recorded."""
    recorded = next(e["payload"]["sha256"] for e in run.ledger.events() if e["type"] == "key.committed")
    result = score_run(run.dir, key_path, recorded_sha256=recorded)
    remediated(run, key_path, result)
    result["labels"] = {"hardware": os.environ.get("PQCH_HARDWARE", "unlabelled"),
                        "build": os.environ.get("PQCH_BUILD", "unlabelled"), "run": run.id}
    (run.dir / "score.json").write_text(json.dumps(result, indent=1) + "\n")
    return result


def remediated(run: Run, key_path: Path, result: dict) -> None:
    """A keyed wire item the scan no longer finds because a change removed it is not a miss. When a
    change requiring the hybrid group on the item's listener landed — verified, and verified again after
    a recreate — before this scan began, and no estate reset came after it, the item moves from `missed`
    to `remediated`, out of the denominator, in every column. Anything else stays missed."""
    import yaml

    from pqch.migrator import intervals
    from pqch.ui.view import change_runs

    start = next(run.ledger.events())["ts"]
    resets = []
    for d in sorted((run.var / "runs").iterdir()):
        led = d / "ledger.jsonl"
        if led.is_file() and json.loads(led.open().readline()).get("payload", {}).get("kind") == "reset":
            resets += [e["ts"] for e in Run(run.var, d.name).ledger.events() if e["type"] == "estate.reset"]
    last_reset = max([t for t in resets if t < start], default="")
    by_listener = {}
    for cr in change_runs(run.var):
        for iv in intervals(list(cr.ledger.events())):
            t = iv.get("target") or {}
            if iv.get("landed") and iv.get("intent") == "require" and last_reset < (iv.get("verdict_ts") or "") < start:
                by_listener[(t.get("address"), t.get("port"))] = {"run": cr.id, "change_id": iv["change_id"]}
    key = yaml.safe_load(key_path.read_text())
    items = {i["id"]: i for i in key.get("items", [])}
    for col in result.get("columns", {}).values():
        row = col.get("layers", {}).get("wire")
        if not row:
            continue
        moved = []
        for item_id in list(row["missed"]):
            subj = (items.get(item_id) or {}).get("subject") or {}
            asset = (items.get(item_id) or {}).get("asset") or {}
            hit = by_listener.get((subj.get("host"), subj.get("port")))
            if hit and asset.get("role") == "key-establishment":
                row["missed"].remove(item_id)
                moved.append({"item": item_id, **hit})
        row["remediated"] = moved
        row["present"] -= len(moved)


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
    for name, bom in cbom.build_all(list(run.ledger.events())).items():
        path = run.dir / f"{name}.cdx.json"
        path.write_text(json.dumps(bom, indent=1, ensure_ascii=False) + "\n")
        out[name] = path
    return out
