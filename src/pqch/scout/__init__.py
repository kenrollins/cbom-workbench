"""The scout: deterministic scans through the runner, normalized to findings.

Every job is recorded as a `scan.completed` event carrying the runner's result
(profile, target, scanner digest, start, end, duration, status, raw output by
path and hash). Its findings follow as `finding.observed` events whose inputs
name that scan. A failed or timed-out scan is recorded and yields no findings.

Image scans take minutes and change only when an image does, so they can be
replayed: the most recent earlier scan of the same image digest is recorded
again with `replayed_from`, its original timestamps, and its original raw
output, re-read and re-hashed.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from pqch.common import sha256_hex
from pqch.ledger import verify
from pqch.run import Run
from pqch.scout.normalize import normalize

WIRE_PROFILES = {"tls": "tls-targeted", "ssh": "ssh-targeted", "postgres": "tls-starttls-postgres"}
# Listener protocols that carry TLS, from the first byte or after an upgrade: what the
# certificate and in-use rules treat as a TLS listener.
TLS_PROTOCOLS = ("tls", "postgres")
# Per scoped image: cbomkit-theia as the candidate generator, then the harness's own reader.
HOST_PROFILES = ("image-theia", "image-files")
RUNNER_ACTOR = {"kind": "runner", "id": "pqch-runner"}


def plan(scope: dict, *, host: bool = True) -> list[tuple[str, dict]]:
    jobs = [(WIRE_PROFILES[e["protocol"]], {"host": e["host"], "port": e["port"]})
            for e in scope["endpoints"] if e["protocol"] in WIRE_PROFILES]
    if host:
        jobs += [(prof, {"image": ref}) for ref in scope["images"] for prof in HOST_PROFILES]
    return jobs


def raw_path(var: Path, ref: str) -> Path:
    return var / ref.removeprefix("var/")


def read_raw(var: Path, job: dict) -> bytes:
    data = raw_path(var, job["raw"]).read_bytes()
    if sha256_hex(data) != job["raw_sha256"]:
        raise ValueError(f"raw output {job['raw']} does not match its recorded hash")
    return data


def find_prior_scan(var: Path, profile: str, target: dict, exclude_run: str) -> tuple[str, dict] | None:
    """The most recent earlier successful scan with this profile and target, from any run."""
    runs = sorted((p for p in (var / "runs").iterdir() if p.is_dir() and p.name != exclude_run),
                  reverse=True)
    for d in runs:
        found = None
        events = list(Run(var, d.name).ledger.events())
        if not verify(events).ok:
            continue
        for ev in events:
            p = ev["payload"]
            if (ev["type"] == "scan.completed" and p.get("profile") == profile
                    and p.get("target") == target and p.get("status") == "ok" and p.get("raw")):
                found = (d.name, ev)
        if found:
            return found
    return None


def record(run: Run, job: dict, *, replayed_from: dict | None = None) -> dict:
    """Append the scan and its findings. Returns a summary line."""
    findings, error = [], None
    if job["status"] == "ok" and job.get("raw"):
        try:
            findings = normalize(read_raw(run.var, job), job)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    payload = {**job, "findings": len(findings)}
    if replayed_from:
        payload["replayed_from"] = replayed_from
    if error:
        payload["normalize_error"] = error[:500]
    evidence = [{"ref": job["raw"], "sha256": job["raw_sha256"]}] if job.get("raw") else []
    scan_ev = run.ledger.append("scan.completed", RUNNER_ACTOR, payload, evidence=evidence)
    for f in findings:
        run.ledger.append("finding.observed", {"kind": "scanner", "id": job["tool"]}, f,
                          inputs=[scan_ev["id"]],
                          evidence=[{"ref": f["evidence"]["raw"], "sha256": f["evidence"]["sha256"]}])
    return {"profile": job["profile"], "target": job["target"], "status": job["status"],
            "duration_ms": job["duration_ms"], "findings": len(findings),
            "replayed": bool(replayed_from), "error": error}


def scan(run: Run, client, scope: dict, scope_hash: str, *, host: str = "live", max_workers: int = 8,
         progress: Callable[[dict], None] | None = None) -> dict:
    """Run the scan plan. `host` is `live`, `replay` (fall back to live if no earlier scan) or `skip`."""
    started = time.monotonic()
    live = plan(scope, host=False)
    lines = []
    if host != "skip":
        for profile, target in plan(scope, host=True)[len(live):]:
            prior = find_prior_scan(run.var, profile, target, run.id) if host == "replay" else None
            if prior:
                run_id, ev = prior
                job = {k: v for k, v in ev["payload"].items()
                       if k not in ("findings", "replayed_from", "normalize_error")}
                origin = ev["payload"].get("replayed_from") or {"run": run_id, "event": ev["id"], "ts": ev["ts"]}
                lines.append(record(run, job, replayed_from=origin))
                if progress:
                    progress(lines[-1])
            else:
                live.append((profile, target))
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(client.job, p, t, scope_hash): (p, t) for p, t in live}
        for fut in as_completed(futures):
            lines.append(record(run, fut.result()))
            if progress:
                progress(lines[-1])
    return {"jobs": lines, "wall_ms": round((time.monotonic() - started) * 1000)}
