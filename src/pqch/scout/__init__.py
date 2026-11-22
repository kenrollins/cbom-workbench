"""The scout: deterministic scans through the runner, normalized to findings.

Every job is recorded as a `scan.completed` event carrying the runner's result
(profile, target, scanner digest, start, end, duration, status, raw output by
path and hash). Its findings follow as `finding.observed` events whose inputs
name that scan. A failed or timed-out scan is recorded and yields no findings.

Whether a scan succeeded is the tool's statement, not the container's: a job whose tool wrote that
it could not connect is recorded with status `unreached` (`reached: false`, the tool's words in
`reason`, the runner's own status kept as `runner_status`), and one whose tool reported a fatal
problem and no finding with status `error`. `scan_ok` is the one test of "this scan is evidence".

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
from pqch.scout.normalize import normalize, platform_facts, tool_problem

WIRE_PROFILES = {"tls": "tls-targeted", "ssh": "ssh-targeted", "postgres": "tls-starttls-postgres"}
# Listener protocols that carry TLS, from the first byte or after an upgrade: what the
# certificate and in-use rules treat as a TLS listener.
TLS_PROTOCOLS = ("tls", "postgres")
# Per scoped image: cbomkit-theia as the candidate generator, then the harness's own reader.
HOST_PROFILES = ("image-theia", "image-files", "image-sbom")
RUNNER_ACTOR = {"kind": "runner", "id": "pqch-runner"}


def scan_ok(payload: dict) -> bool:
    """Whether a `scan.completed` payload is a scan that happened and was read: the runner says ok,
    the tool did not say it failed to reach the target, and its output was normalized. A listener is
    reached, and an earlier scan is fit to replay, only when this holds."""
    return (payload.get("status") == "ok" and payload.get("reached") is not False
            and not payload.get("normalize_error"))


def plan(scope: dict, *, host: bool = True) -> list[tuple[str, dict]]:
    # One address and port can serve several names, each with its own certificate and policy. When
    # the scope lists the same listener under more than one name, each job says which name it is for
    # and the runner resolves that entry; a listener listed once is addressed as before.
    shared = {}
    for e in scope["endpoints"]:
        shared[(e["host"], e["port"])] = shared.get((e["host"], e["port"]), 0) + 1
    jobs, seen = [], set()
    for e in scope["endpoints"]:
        if e["protocol"] not in WIRE_PROFILES:
            continue
        target = {"host": e["host"], "port": e["port"]}
        if shared[(e["host"], e["port"])] > 1 and e.get("sni"):
            target["sni"] = e["sni"]
        key = (WIRE_PROFILES[e["protocol"]], tuple(sorted(target.items())))
        if key in seen:     # the same listener listed twice with nothing to tell the entries apart
            continue
        seen.add(key)
        jobs.append((WIRE_PROFILES[e["protocol"]], target))
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
    """The most recent earlier successful scan with this profile and target, from any run. Successful
    is `scan_ok` and a clean exit: only image scans are replayed, and for those tools a non-zero exit
    is a failure (unlike ssh-audit, whose exit code is a policy verdict)."""
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
                    and p.get("target") == target and scan_ok(p) and p.get("exit_code") in (0, None)
                    and p.get("raw")):
                found = (d.name, ev)
        if found:
            return found
    return None


def record(run: Run, job: dict, *, replayed_from: dict | None = None) -> dict:
    """Append the scan and its findings. Returns a summary line."""
    findings, error, problem = [], None, None
    if job["status"] == "ok" and job.get("raw"):
        try:
            raw = read_raw(run.var, job)
            problem = tool_problem(raw, job)
            if not (problem and (problem.get("reached") is False or problem.get("output") is False)):
                findings = normalize(raw, job)
        except Exception as e:
            error = f"{type(e).__name__}: {e}"
    payload = {**job, "findings": len(findings)}
    if replayed_from:
        payload["replayed_from"] = replayed_from
    if error:
        payload["normalize_error"] = error[:500]
    if problem and not findings:
        # The container ran and the tool said its scan did not happen. That is not a scan with
        # nothing to report: the listener is not counted as reached, and the reason is on the record.
        payload["runner_status"] = job["status"]
        payload["status"] = "unreached" if problem.get("reached") is False else "error"
        payload["reason"] = problem["reason"]
        if problem.get("reached") is False:
            payload["reached"] = False
    elif problem:
        payload["tool_problem"] = problem["reason"]      # findings were read before the tool gave up
    status = payload["status"]
    evidence = [{"ref": job["raw"], "sha256": job["raw_sha256"]}] if job.get("raw") else []
    scan_ev = run.ledger.append("scan.completed", RUNNER_ACTOR, payload, evidence=evidence)
    for f in findings:
        run.ledger.append("finding.observed", {"kind": "scanner", "id": job["tool"]}, f,
                          inputs=[scan_ev["id"]],
                          evidence=[{"ref": f["evidence"]["raw"], "sha256": f["evidence"]["sha256"]}])
    if status == "ok" and job.get("raw") and not error:
        facts = platform_facts(read_raw(run.var, job), job)
        if facts:
            run.ledger.append("platform.observed", {"kind": "scanner", "id": job["tool"]}, facts, inputs=[scan_ev["id"]],
                              evidence=[{"ref": job["raw"], "sha256": job["raw_sha256"]}])
        from pqch.scout.normalize import sbom_facts

        sbom = sbom_facts(read_raw(run.var, job), job)
        if sbom:
            run.ledger.append("sbom.observed", {"kind": "scanner", "id": job["tool"]}, sbom, inputs=[scan_ev["id"]],
                              evidence=[{"ref": job["raw"], "sha256": job["raw_sha256"]}])
    return {"profile": job["profile"], "target": job["target"], "status": status,
            "duration_ms": job["duration_ms"], "findings": len(findings),
            "replayed": bool(replayed_from), "error": error or payload.get("reason")}


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
                       if k not in ("findings", "replayed_from", "normalize_error", "runner_status", "reason",
                                    "reached", "tool_problem")}
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
