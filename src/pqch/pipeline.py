"""One run of the slice, start to finish: scope, key, scans, rules, CBOM, score.

Used by the CLI and by the scan button; both call `run_once`.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import json

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


def enrich(run: Run, *, author: str, context: Path | None | str = "env") -> dict:
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
    result["labels"] = {"hardware": os.environ.get("PQCH_HARDWARE", "unlabelled"),
                        "build": os.environ.get("PQCH_BUILD", "unlabelled"), "run": run.id}
    (run.dir / "score.json").write_text(json.dumps(result, indent=1) + "\n")
    return result


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
