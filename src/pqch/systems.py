"""A server as an estate: its listeners, its own files and firmware, and its management controller,
scanned into one run (`kind: scan-system`), recorded, and replayed elsewhere.

The estate is `external`: nothing is applied and nothing is scored, and the scope carries the
operator's authorization. Its scope lists the system's listeners as `endpoints`, the system itself
under `systems` (the paths that may be read, whether its firmware is read) and its controller under
`controllers`. The runner does every read; the harness records what comes back and runs the rules.

A run can be exported as a recording: the scope and every job's raw output, with the deployment's
identifiers replaced by the operator's map (addresses, names, a service tag in whatever encodings it
appears). Replaying a recording opens a new run on any host, with no access to the system, whose
every `scan.completed` says where it was replayed from and when the original read was made. The
ledger is new and signed by the replaying host; the evidence is the recording's.
"""
from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path

from pqch import schemas
from pqch import scope as scope_mod
from pqch.common import sha256_hex, ulid, utc_now
from pqch.run import Run

SYSTEM_PROFILES = ("system-theia", "system-files", "system-firmware")
RECORDING_SCHEMA = "pqch.recording/1"


def _rules_and_close(run: Run) -> dict:
    from pqch.assessor import load_policy, structure
    from pqch.pipeline import enrich, signer_from_env, write_cboms

    policy = load_policy(os.environ.get("PQCH_POLICY", "policy/pq-algorithms.yaml"))
    rules = structure(run, policy)
    rules.update(enrich(run, author=os.environ.get("PQCH_OPERATOR", "operator"), context=None))
    run.close(signer_from_env())
    write_cboms(run)
    return rules


def _z(ts: str | None) -> str | None:
    """An ISO 8601 UTC time in the ledger's form: ...Z, not ...+00:00."""
    if not ts:
        return None
    import datetime as dt
    t = dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(dt.UTC)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def recorded_job(var: Path, run: Run, ctl: dict, path: Path, recorder: Path | None) -> tuple[dict, dict]:
    """A controller read made earlier and held as a file, brought in as the controller job's raw
    output. Its time is the read's own; the run says it was recorded, by what, and its hash."""
    data = path.read_bytes()
    doc = json.loads(data)
    when = _z(doc.get("read_at")) or utc_now()
    job_id = ulid()
    raw_rel = f"runs/{run.id}/raw/{job_id}.json"
    (var / raw_rel).parent.mkdir(parents=True, exist_ok=True)
    (var / raw_rel).write_bytes(data)
    rec_digest = "sha256:" + (sha256_hex(recorder.read_bytes()) if recorder and recorder.is_file() else sha256_hex(data))
    job = {"job_id": job_id, "profile": "controller-redfish",
           "target": {"controller": ctl["host"], "port": ctl["port"], "of": ctl["of"]},
           "tool": "pqch-controller-redfish", "version": "1", "image": str(recorder or path.name),
           "image_digest": rec_digest, "status": "ok", "exit_code": 0, "started_at": when, "ended_at": when,
           "duration_ms": 0, "stderr_tail": "", "container": {}, "binding": None,
           "hardware": doc.get("read_from") or "recorded", "raw": f"var/{raw_rel}", "raw_sha256": sha256_hex(data)}
    origin = {"recording": path.name, "recorded_at": when, "recorded_by": str(recorder or "a Redfish read"),
              "recording_sha256": sha256_hex(data), "method": doc.get("method", "Redfish GET only")}
    return job, origin


def scan_system(var: Path, client, *, controller_recordings: dict[str, Path] | None = None,
                recorder: Path | None = None, progress: Callable[[dict], None] | None = None) -> tuple[Run, dict]:
    from pqch import scout

    scope, runner_hash = client.scope()
    schemas.validate(scope)
    if scope.get("estate") != "external" or not scope.get("authorized_by") or not scope.get("systems"):
        raise ValueError("a system scan needs an external scope with the operator's authorization and at least one system")
    run = Run.start(var, scope, runner_scope_hash=runner_hash, profile="system-targeted", kind="scan-system")
    # PostgreSQL listeners: ask whether TLS is offered at all, and scan TLS only where it is.
    lines, refused = [], set()
    for ep in scope["endpoints"]:
        if ep["protocol"] != "postgres":
            continue
        job = client.job("postgres-tls-offer", {"host": ep["host"], "port": ep["port"]}, runner_hash)
        lines.append(scout.record(run, job))
        if progress:
            progress(lines[-1])
        if job["status"] == "ok" and job.get("raw"):
            if json.loads(scout.read_raw(var, job)).get("answer") == "N":
                refused.add((ep["host"], ep["port"]))
    planned = {**scope, "endpoints": [e for e in scope["endpoints"] if (e["host"], e["port"]) not in refused]}
    summary = scout.scan(run, client, planned, runner_hash, host="skip", progress=progress)
    summary["jobs"] = lines + summary["jobs"]
    for s in scope["systems"]:
        for prof in SYSTEM_PROFILES:
            line = scout.record(run, client.job(prof, {"system": s["name"]}, runner_hash))
            summary["jobs"].append(line)
            if progress:
                progress(line)
    for ctl in scope.get("controllers", []):
        rec = (controller_recordings or {}).get(ctl["host"])
        if rec:
            job, origin = recorded_job(var, run, ctl, rec, recorder)
            line = scout.record(run, job, replayed_from=origin)
        else:
            line = scout.record(run, client.job("controller-redfish", {"controller": ctl["host"]}, runner_hash))
        summary["jobs"].append(line)
        if progress:
            progress(line)
    summary["rules"] = _rules_and_close(run)
    return run, summary


# ------------------------------------------------------------------ recordings
def _apply(text: str, pairs: list[tuple[str, str]]) -> str:
    for a, b in pairs:
        text = text.replace(a, b)
    return text


def sanitize_pairs(mapping: dict[str, str]) -> list[tuple[str, str]]:
    """The operator's map, with each identifier's other spellings: upper and lower case, and the
    hexadecimal of its bytes (an SNMP engine ID carries a service tag that way). Longest first, so a
    name is replaced before a shorter name inside it."""
    pairs: dict[str, str] = {}
    for a, b in mapping.items():
        for x, y in ((a, b), (a.lower(), b.lower()), (a.upper(), b.upper()),
                     (a.encode().hex(), b.encode().hex()), (a.encode().hex().upper(), b.encode().hex().upper())):
            if x and x != y:
                pairs.setdefault(x, y)
    return sorted(pairs.items(), key=lambda p: -len(p[0]))


class _HardwareIds:
    """MAC addresses and UUIDs, each replaced by a stand-in that is the same wherever the original
    appears: MACs from the IETF's documentation range (00:00:5E:00:53:xx, RFC 7042), UUIDs numbered.
    A Dell system UUID spells the service tag in its last bytes, so it goes with the tag."""

    MAC = __import__("re").compile(r"(?i)\b(?:[0-9a-f]{2}([:-]))(?:[0-9a-f]{2}\1){4}[0-9a-f]{2}\b")
    UUID = __import__("re").compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")

    def __init__(self):
        self.macs: dict[str, str] = {}
        self.uuids: dict[str, str] = {}

    def __call__(self, text: str) -> str:
        def mac(m):
            k = m.group(0).lower().replace("-", ":")
            sep = m.group(1)
            stand = self.macs.setdefault(k, f"00:00:5e:00:53:{len(self.macs):02x}")
            out = stand.replace(":", sep)
            return out.upper() if m.group(0).isupper() else out

        def uid(m):
            k = m.group(0).lower()
            return self.uuids.setdefault(k, f"00000000-0000-4000-8000-{len(self.uuids):012d}")
        return self.UUID.sub(uid, self.MAC.sub(mac, text))


def export_recording(run: Run, out: Path, *, mapping: dict[str, str] | None = None, leaks: list[str] | None = None,
                     scrub_hardware_ids: bool = False) -> dict:
    """The run's scope and every job's raw output, as a directory another host can replay. With a map,
    every identifier in it is replaced in the scope and in every raw output; `leaks` (patterns that must
    not survive) are then searched for, and the export stops on a match."""
    import re

    events = list(run.ledger.events())
    started = events[0]["payload"]
    pairs = sanitize_pairs(mapping or {})
    hw = _HardwareIds() if scrub_hardware_ids else (lambda t: t)
    out = Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "raw").mkdir(parents=True)
    jobs = []
    for ev in events:
        if ev["type"] != "scan.completed":
            continue
        j = {k: v for k, v in ev["payload"].items() if k not in ("findings", "normalize_error")}
        if j.get("raw"):
            data = (run.var / j["raw"].removeprefix("var/")).read_bytes()
            text = hw(_apply(data.decode("utf-8", errors="surrogateescape"), pairs))
            data = text.encode("utf-8", errors="surrogateescape")
            name = Path(j["raw"]).name
            (out / "raw" / name).write_bytes(data)
            j["raw"], j["raw_sha256"] = f"raw/{name}", sha256_hex(data)
        j = json.loads(hw(_apply(json.dumps(j), pairs)))
        j["original_event"] = ev["id"]
        jobs.append(j)
    scope = json.loads(hw(_apply(json.dumps(started["scope"]), pairs)))
    manifest = {"schema": RECORDING_SCHEMA, "id": ulid(), "source_run": run.id, "source_kind": started.get("kind"),
                "exported_at": utc_now(), "sanitized": bool(pairs) or scrub_hardware_ids, "replacements": len(mapping or {}),
                "hardware_ids_replaced": {"macs": len(getattr(hw, "macs", {})), "uuids": len(getattr(hw, "uuids", {}))},
                "scope": scope, "jobs": jobs}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    hits = []
    for pat in leaks or []:
        rx = re.compile(pat, re.I)
        for f in sorted(out.rglob("*")):
            if f.is_file() and rx.search(f.read_text(errors="replace")):
                hits.append(f"{f.relative_to(out)}: {pat}")
    if hits:
        shutil.rmtree(out)
        raise ValueError("the export still holds identifiers; nothing was written: " + "; ".join(hits[:10]))
    return manifest


def replay_recording(var: Path, rec: Path, *, progress: Callable[[dict], None] | None = None) -> tuple[Run, dict]:
    """A new run from a recording: the recording's scope, and each job's raw output recorded again with
    `replayed_from` naming the recording and the original read's time. No runner is involved and
    nothing is sent; the rules run and the CBOM is written as for a live scan."""
    from pqch import scout

    rec = Path(rec)
    manifest = json.loads((rec / "manifest.json").read_text())
    if manifest.get("schema") != RECORDING_SCHEMA:
        raise ValueError(f"{rec} is not a recording")
    scope = manifest["scope"]
    schemas.validate(scope)
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="system-replayed",
                    runner_id="pqch-replay", kind=manifest.get("source_kind") or "scan-system")
    lines = []
    for j in manifest["jobs"]:
        job = {k: v for k, v in j.items() if k not in ("original_event", "replayed_from")}
        if j.get("raw"):
            data = (rec / j["raw"]).read_bytes()
            if sha256_hex(data) != j["raw_sha256"]:
                raise ValueError(f"{j['raw']} does not match the recording's hash")
            rel = f"runs/{run.id}/raw/{Path(j['raw']).name}"
            (var / rel).parent.mkdir(parents=True, exist_ok=True)
            (var / rel).write_bytes(data)
            job["raw"] = f"var/{rel}"
        origin = {"recording": manifest["id"], "source_run": manifest["source_run"], "original_event": j.get("original_event"),
                  "recorded_at": j.get("started_at"), "sanitized": manifest.get("sanitized", False)}
        if j.get("replayed_from"):
            origin["first_recorded"] = j["replayed_from"]
        line = scout.record(run, job, replayed_from=origin)
        lines.append(line)
        if progress:
            progress(line)
    rules = _rules_and_close(run)
    return run, {"jobs": lines, "rules": rules, "recording": manifest["id"], "source_run": manifest["source_run"]}


# ------------------------------------------------------------------ the hosts view
def hosts(var: Path) -> list[dict]:
    """Every server scanned in this run store, by name: its latest `scan-system` run and what that run
    holds. Reads each run's first event to find the system scans, then the latest run per server."""
    var = Path(var)
    latest: dict[str, tuple[str, str]] = {}
    for led in sorted((var / "runs").glob("*/ledger.jsonl")):
        try:
            with led.open() as f:
                first = json.loads(f.readline())
        except (OSError, ValueError):
            continue
        p = first.get("payload") or {}
        if p.get("kind") != "scan-system":
            continue
        for s in (p.get("scope") or {}).get("systems") or []:
            if s["name"] not in latest or first["ts"] > latest[s["name"]][1]:
                latest[s["name"]] = (led.parent.name, first["ts"])
    out = []
    for name, (run_id, _) in sorted(latest.items()):
        events = list(Run(var, run_id).ledger.events())
        if not events or events[-1]["type"] != "run.closed":
            continue
        scope = events[0]["payload"]["scope"]
        scans = [e["payload"] for e in events if e["type"] == "scan.completed"]
        facts = [e["payload"] for e in events if e["type"] == "platform.observed" and e["payload"].get("system") == name]
        device = next((f.get("device") for f in facts if (f.get("device") or {}).get("model")), {}) or {}
        ctl = next((f.get("controller") for f in facts if f.get("source") == "controller"), None)
        reads = sorted(x["started_at"] for x in scans if x.get("started_at"))
        rec = next((x["replayed_from"].get("recording") for x in scans if (x.get("replayed_from") or {}).get("source_run")), None)
        system = next(s for s in scope["systems"] if s["name"] == name)
        parts = [("listeners", any(x["profile"] in ("ssh-targeted", "tls-targeted", "tls-starttls-postgres", "postgres-tls-offer") for x in scans)),
                 ("files", any(x["profile"] in ("system-files", "system-theia") for x in scans)),
                 ("firmware", any(x["profile"] == "system-firmware" for x in scans)),
                 ("controller", any(x["profile"] == "controller-redfish" for x in scans))]
        out.append({"name": name, "run": run_id, "model": device.get("model"), "vendor": device.get("vendor"),
                    "addresses": system.get("addresses", []),
                    "controller": {"host": ctl.get("host"), "model": ctl.get("model"), "firmware": ctl.get("firmware_version")} if ctl else None,
                    "parts": [k for k, v in parts if v], "findings": sum(1 for e in events if e["type"] == "finding.observed"),
                    "read_from": reads[0] if reads else events[0]["ts"], "read_to": reads[-1] if reads else events[0]["ts"],
                    "replayed": rec, "replayed_at": events[0]["ts"] if rec else None,
                    "this_machine": name == os.environ.get("PQCH_THIS_HOST", "")})
    return out
