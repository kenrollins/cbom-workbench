"""Watch mode: the CBOM as a source of change events. Only what changed is re-examined.

`observe(run, agency_dir)` runs at the end of every scan. It records a `config.observed` event per
service — the path and SHA-256 of each configuration file the service was built from — and
compares this scan with the previous scan of the same estate (the same listeners): a finding fingerprint that appeared
or went, a configuration file whose hash changed, a migration item whose queue or state moved.
Each difference is a `change.observed` event naming the earlier run and event it differs from.

`watch(...)` is a scan followed by the model jobs on the changed records only: a trace for each
new wire finding of key establishment (one already traced on an earlier scan of the same
observation is shown replayed, not traced again), an explanation for each item that is new or
changed queue. Nothing unchanged is sent to a model.
"""

from __future__ import annotations

import json
from pathlib import Path

from pqch.common import sha256_hex
from pqch.ledger import verify
from pqch.run import Run


def _scan_runs(var: Path) -> list[Run]:
    out = []
    for d in sorted(p for p in (Path(var) / "runs").iterdir() if p.is_dir()):
        led = d / "ledger.jsonl"
        if not led.is_file():
            continue
        with led.open() as f:
            try:
                first = json.loads(f.readline())
            except json.JSONDecodeError:
                continue
        if first.get("type") == "run.started" and first["payload"].get("kind", "scan") == "scan":
            out.append(Run(var, d.name))
    return out


def _estate_key(scope: dict) -> tuple:
    """Which estate a scope is of: its kind and its listeners. Not its hash — a rebuilt image changes
    the scope's image digests, and a rebuild is exactly the kind of change watch mode is for."""
    return (scope.get("estate"), tuple(sorted((ep["host"], ep["port"]) for ep in scope["endpoints"])))


def previous(run: Run) -> Run | None:
    """The latest earlier scan run of the same estate — the same listeners — whose ledger verifies."""
    me = _estate_key(next(iter(run.ledger.events()))["payload"]["scope"])
    for r in reversed([r for r in _scan_runs(run.var) if r.id < run.id]):
        events = list(r.ledger.events())
        if events and verify(events).ok and _estate_key(events[0]["payload"]["scope"]) == me:
            return r
    return None


def manifest(agency_dir: Path, service: str) -> list[dict]:
    from pqch.investigator import Workspace

    ws = Workspace(Path(agency_dir), service)
    return [{"path": rel, "sha256": sha256_hex(p.read_bytes())} for rel, p in sorted(ws.files.items())]


def _state(events: list[dict]) -> dict:
    fps = {e["payload"]["fingerprint"]: e for e in events if e["type"] == "finding.observed"}
    configs = {e["payload"]["service"]: e for e in events if e["type"] == "config.observed"}
    items = {(e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]): e for e in events
             if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "queue/m-26-15/1"}
    return {"fps": fps, "configs": configs, "items": items}


def observe(run: Run, agency_dir: Path | None) -> dict:
    events = list(run.ledger.events())
    scope = events[0]["payload"]["scope"]
    actor = {"kind": "scanner", "id": "pqch-watch"}
    if agency_dir and Path(agency_dir).is_dir():
        for svc in sorted({ep["service"] for ep in scope["endpoints"] if ep.get("service")}):
            run.ledger.append("config.observed", actor, {"service": svc, "files": manifest(Path(agency_dir), svc)})
    prev = previous(run)
    counts = {"previous": prev and prev.id, "appeared": 0, "gone": 0, "config": 0, "items": 0}
    if prev is None:
        return counts
    now, before = _state(list(run.ledger.events())), _state(list(prev.ledger.events()))

    def note(kind: str, payload: dict, inputs: list[str]):
        run.ledger.append("change.observed", actor, {"kind": kind, "since": {"run": prev.id, **payload.pop("since", {})},
                                                     **payload}, inputs=inputs)

    for fp, e in sorted(now["fps"].items()):
        if fp not in before["fps"]:
            f = e["payload"]
            note("finding-appeared", {"fingerprint": fp, "layer": f["layer"], "subject": f["subject"],
                                      "asset": {k: f["asset"][k] for k in ("type", "role", "name")}}, [e["id"]])
            counts["appeared"] += 1
    for fp, e in sorted(before["fps"].items()):
        if fp not in now["fps"]:
            f = e["payload"]
            note("finding-gone", {"fingerprint": fp, "layer": f["layer"], "subject": f["subject"],
                                  "asset": {k: f["asset"][k] for k in ("type", "role", "name")},
                                  "since": {"event": e["id"]}}, [])
            counts["gone"] += 1
    for svc, e in sorted(now["configs"].items()):
        old = before["configs"].get(svc)
        if old is None:
            continue
        a = {x["path"]: x["sha256"] for x in old["payload"]["files"]}
        b = {x["path"]: x["sha256"] for x in e["payload"]["files"]}
        changed = sorted(p for p in set(a) | set(b) if a.get(p) != b.get(p))
        if changed:
            note("config-changed", {"service": svc, "files": [{"path": p, "before": a.get(p), "after": b.get(p)} for p in changed],
                                    "since": {"event": old["id"]}}, [e["id"]])
            counts["config"] += 1
    for key, e in sorted(now["items"].items()):
        c = e["payload"]["classification"]
        old = before["items"].get(key)
        oc = old and old["payload"]["classification"]
        if old is None or (oc["state"], oc["queue"]) != (c["state"], c["queue"]):
            note("item-changed", {"service": key[0], "function": key[1], "now": {"state": c["state"], "queue": c["queue"]},
                                  "before": oc and {"state": oc["state"], "queue": oc["queue"]},
                                  "since": {"event": old and old["id"]}}, [e["id"]])
            counts["items"] += 1
    return counts


def changed(run: Run, *, had_previous: bool) -> dict:
    """What this run's `change.observed` events say changed. With no previous scan, everything is
    new: the sets are None, meaning re-examine all."""
    if not had_previous:
        return {"fingerprints": None, "items": None}
    obs = [e["payload"] for e in run.ledger.events() if e["type"] == "change.observed"]
    return {"fingerprints": {o["fingerprint"] for o in obs if o["kind"] == "finding-appeared" and o["layer"] == "wire"},
            "items": {(o["service"], o["function"]) for o in obs if o["kind"] == "item-changed"}}


def watch(var: Path, client, key_path: Path, *, agency_dir: Path, signer=None, progress=None,
          trace: bool = True, explain: bool = True) -> dict:
    """A scan, then the model jobs on the changed records only."""
    import os

    from pqch import inference
    from pqch.pipeline import run_once

    run, summary = run_once(var, client, key_path, host="replay", progress=progress)
    ch = changed(run, had_previous=bool(summary["changes"]["previous"]))
    out = {"run": run.id, "changes": summary["changes"], "traced": 0, "explained": 0}
    if trace:
        from pqch.investigator import investigate
        from pqch.ui.view import traces_by_fingerprint

        already = set(traces_by_fingerprint(var))
        # A service whose configuration changed is traced again: its old traces read other files.
        changed_svc = {e["payload"]["service"] for e in run.ledger.events()
                       if e["type"] == "change.observed" and e["payload"]["kind"] == "config-changed"}
        scope = next(iter(run.ledger.events()))["payload"]["scope"]
        listeners = {(ep["host"], ep["port"]) for ep in scope["endpoints"] if ep.get("service") in changed_svc}
        stale = {e["payload"]["fingerprint"] for e in run.ledger.events() if e["type"] == "finding.observed"
                 and (e["payload"]["subject"].get("host"), e["payload"]["subject"].get("port")) in listeners}
        already -= stale
        fps = ch["fingerprints"]
        if fps is None:
            fps = {e["payload"]["fingerprint"] for e in run.ledger.events() if e["type"] == "finding.observed"}
        fps = (fps | stale) - already
        if fps:
            inv, traces = investigate(var, run, agency_dir=agency_dir, signer=signer, only_fingerprints=fps,
                                      key_path=Path(os.environ.get("PQCH_KEY", "agency/answer-key.yaml")))
            out["traced"], out["investigate_run"] = len(traces), inv and inv.id
    if explain:
        from pqch.assessor.explain_queue import explain as explain_items

        try:
            ex, s = explain_items(var, run, pack_path=os.environ.get("PQCH_PACK", "policy/packs/m-26-15.yaml"),
                                  signer=signer, only_items=ch["items"])
            out["explained"], out["explain_run"] = s["items"], ex and ex.id
        except inference.TierUnavailable as e:
            out["explain_skipped"] = str(e)
    return out
