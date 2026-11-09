"""`gap/record/1`: what no tool could see, as a queue on the ledger (M10).

A discovery leaves gaps: a key file the reader could not open, a listener no scan reached, a
service nobody supplied facts for, a controller certificate whose key the controller does not
report, a firmware no supplier has made a statement about. Left implicit they are reported as
coverage; written down they are the manual gap-fill queue a discovery phase plans for. This rule
writes each as a `gap.recorded` event at the end of a run's rules, with the asset class it falls
in, the reason, and what would fill it. A gap's id is the hash of its kind and subject, so the same
gap on the next scan is the same gap, and a person closes one with a `gap.filled` event in a run of
kind `gapfill` that cites the evidence brought (a run and an event on it) and says why it fills the
gap. The queue a page shows is the run's recorded gaps less the ones filled; the coverage per asset
class is counted from the same numbers, reached against reached plus gaps.
"""

from __future__ import annotations

from pathlib import Path

from pqch.common import hash_object, ulid
from pqch.ledger import verify
from pqch.run import Run

RULE = "gap/record/1"
KIND = "gapfill"

# What fills each kind of gap: the words the queue shows.
FILLS = {
    "key-not-opened": "a privileged, read-only read of the file, or the owner's statement of the key's algorithm and size",
    "algorithm-unidentified": "the material opened by a reader that can name its algorithm, or the owner's statement",
    "listener-not-scanned": "a scan that reaches the listener (a runner with a leg on its network, or the scope's authorization widened)",
    "scan-failed": "the job run again once its cause is removed; the failure is on the ledger",
    "no-owner-facts": "the system owner's facts for the service, typed into the context file",
    "unreadable-path": "a privileged, read-only read of the path",
    "controller-certificate-key-unknown": "the supplier's statement of the algorithms behind the controller's identity certificates",
    "no-supplier-statement": "the supplier's attestation for the model (pqch attest)",
    "firmware-not-attested": "the supplier's statement extended to this firmware",
}
CLASS = {
    "key-not-opened": "key files", "algorithm-unidentified": "entries", "listener-not-scanned": "listeners",
    "scan-failed": "listeners", "no-owner-facts": "services", "unreadable-path": "key files",
    "controller-certificate-key-unknown": "controller", "no-supplier-statement": "firmware", "firmware-not-attested": "firmware",
}


def gap_id(kind: str, subject: dict) -> str:
    return hash_object({"kind": kind, "subject": subject})[:24]


def _reached(events: list[dict]) -> dict:
    """What the run reached, per class, counted beside the gaps it will record."""
    scope = events[0]["payload"]["scope"]
    ok = {(p["target"].get("host"), p["target"].get("port")) for p in (e["payload"] for e in events if e["type"] == "scan.completed")
          if p.get("status") == "ok" and "host" in p["target"]}
    eps = [(e["host"], e["port"]) for e in scope.get("endpoints", [])]
    return {"listeners": {"total": len(eps), "reached": sum(1 for k in eps if k in ok)}}


def record(run: Run) -> dict:
    """Write every gap the run's evidence leaves as a `gap.recorded` event. Returns counts by kind."""
    events = list(run.ledger.events())
    scope = events[0]["payload"]["scope"]
    kind = events[0]["payload"].get("kind", "scan")
    counts: dict[str, int] = {}
    seen: set[str] = set()

    def gap(k: str, subject: dict, reason: str, *, asset_class: str | None = None, inputs: list[str] = ()):
        gid = gap_id(k, subject)
        if gid in seen:
            return
        seen.add(gid)
        run.ledger.append("gap.recorded", {"kind": "rule", "id": RULE}, {
            "gap": gid, "rule_id": RULE, "kind": k, "asset_class": asset_class or CLASS[k], "subject": subject,
            "reason": reason, "fills": FILLS[k]}, inputs=list(inputs))
        counts[k] = counts.get(k, 0) + 1

    findings = {e["id"]: e["payload"] for e in events if e["type"] == "finding.observed"}
    # Key material a reader could not open, and entries whose algorithm nothing identified.
    unknown_fps = {e["payload"]["subject"]["fingerprint"] for e in events if e["type"] == "assessment.made"
                   and e["payload"].get("rule_id") == "compatibility/entry/1" and e["payload"]["classification"]["status"] == "unknown"}
    for fid, f in findings.items():
        p = f["asset"].get("parameters") or {}
        if p.get("opened") is False:
            gap("key-not-opened", f["subject"], f"the reader could not open it ({p.get('why', 'unreadable')}); its algorithm and size are not known",
                inputs=[fid])
        elif f["fingerprint"] in unknown_fps and f["subject"]["kind"] != "platform":
            gap("algorithm-unidentified", f["subject"], f"the entry names no algorithm a table places ({f['asset']['name']})", inputs=[fid])
    # Listeners the scan did not reach, and jobs that failed.
    scans = [e for e in events if e["type"] == "scan.completed"]
    ok = {(e["payload"]["target"].get("host"), e["payload"]["target"].get("port")) for e in scans
          if e["payload"].get("status") == "ok" and "host" in e["payload"]["target"]}
    tried = {(e["payload"]["target"].get("host"), e["payload"]["target"].get("port")) for e in scans if "host" in e["payload"]["target"]}
    for ep in scope.get("endpoints", []):
        key = (ep["host"], ep["port"])
        subj = {"kind": "endpoint", "host": ep["host"], "port": ep["port"], "protocol": ep["protocol"]}
        if key in ok:
            continue
        failed = [e for e in scans if (e["payload"]["target"].get("host"), e["payload"]["target"].get("port")) == key]
        if key in tried:
            why = "; ".join(sorted({f"{e['payload']['profile']}: {e['payload'].get('status')}"
                                    + (f" ({e['payload']['normalize_error'][:80]})" if e['payload'].get('normalize_error') else "") for e in failed}))
            gap("scan-failed", subj, f"every job on it ended other than ok: {why}", inputs=[e["id"] for e in failed])
        else:
            gap("listener-not-scanned", subj, "the scope names it and no job ran against it")
    # Services the scope names with no owner's facts.
    supplied = {e["payload"]["from"]["name"] for e in events if e["type"] == "link.asserted" and e["payload"].get("status") == "supplied"}
    for svc in sorted({ep.get("service") for ep in scope.get("endpoints", []) if ep.get("service")}):
        if svc not in supplied and kind == "scan":
            gap("no-owner-facts", {"kind": "service", "name": svc}, "no scan can discover its mission function, data lifetime, owner or system; nobody supplied them")
    # A server read whole: paths the reader could not open, the controller's unreported keys, the supplier's silence.
    for e in events:
        if e["type"] != "platform.observed":
            continue
        p = e["payload"]
        if p.get("source") == "files":
            for path in p.get("unreadable") or []:
                if "(absent)" in path:
                    continue
                gap("unreadable-path", {"kind": "file", "host": p.get("system"), "path": path.split(" (")[0]},
                    f"unreadable to the scan's user (uid {p.get('read_as_uid')}); what it holds is not in the inventory", inputs=[e["id"]])
    for fid, f in findings.items():
        if f["subject"]["kind"] == "platform" and f["subject"].get("component", "").startswith("bmc:certificate:") and f["asset"]["name"] == "unknown":
            gap("controller-certificate-key-unknown", f["subject"],
                "the controller reports the certificate's issuer and dates and not its key; the algorithm is unknown", inputs=[fid])
    if kind == "scan-system":
        from pqch import attest

        obs = attest.observed(events)
        att = attest.for_system(run.var, events) if obs["device"].get("model") else None
        if obs["device"].get("model") and not att:
            gap("no-supplier-statement", {"kind": "device", "system": obs["system"], "vendor": obs["device"].get("vendor"), "model": obs["device"]["model"]},
                "no supplier's attestation names this model: what signs its firmware, which modules it carries and its route forward are unstated")
        elif att:
            for name in att["not_attested"]:
                gap("firmware-not-attested", {"kind": "firmware", "system": obs["system"], "name": name},
                    f"the server reports it and {att['supplier']}'s statement does not name it")
    # The rule's own mark, so a run with no gap says the rule ran and found none.
    run.ledger.append("assessment.made", {"kind": "rule", "id": RULE}, {
        "subject": {"kind": "run", "run": run.id}, "rule_id": RULE,
        "classification": {"gaps": sum(counts.values()), "by_kind": counts},
        "basis": "every gap the run's evidence leaves, recorded as gap.recorded; none hidden in a coverage figure"})
    return {"gaps": sum(counts.values()), "gaps_by_kind": counts}


def fills(var: str | Path) -> dict[str, dict]:
    """Every `gap.filled` on this deployment, by gap id (the latest), from verified ledgers."""
    from pqch.ui.view import runs_of_kind

    out: dict[str, dict] = {}
    for r in runs_of_kind(Path(var), KIND):
        evs = list(r.ledger.events())
        if not verify(evs).ok:
            continue
        for e in evs:
            if e["type"] == "gap.filled":
                out[e["payload"]["gap"]] = {**e["payload"], "run": r.id, "event": e["id"], "ts": e["ts"], "by": e["actor"]["id"]}
    return out


def queue(var: str | Path, events: list[dict]) -> dict | None:
    """The run's gaps, open and filled, and the coverage per asset class counted from them. None for a
    run that recorded no gap rule (before the rule existed), so a page says nothing rather than zero."""
    recorded = [e for e in events if e["type"] == "gap.recorded"]
    if not _ran(events):
        return None
    filled = fills(var)
    rows = []
    for e in recorded:
        p = e["payload"]
        f = filled.get(p["gap"])
        rows.append({**p, "event": e["id"], "filled": f})
    open_rows = [r for r in rows if not r["filled"]]
    reached = _reached(events)
    scope = events[0]["payload"]["scope"]
    findings = [e["payload"] for e in events if e["type"] == "finding.observed"]
    named = {ep.get("service") for ep in scope.get("endpoints", []) if ep.get("service")}
    supplied = {e["payload"]["from"]["name"] for e in events if e["type"] == "link.asserted" and e["payload"].get("status") == "supplied"}
    files_read = sum((e["payload"].get("files_read") or 0) for e in events if e["type"] == "platform.observed" and e["payload"].get("source") == "files")
    key_files = sum(1 for f in findings if f["asset"]["type"] == "related-crypto-material" and f["subject"]["kind"] == "file")
    ctl_certs = [f for f in findings if f["subject"].get("component", "").startswith("bmc:certificate:")]
    fw_names = {fw["name"] for e in events if e["type"] == "platform.observed" for fw in (e["payload"].get("firmware") or [])}
    by_kind = lambda k: sum(1 for r in open_rows if r["kind"] == k)  # noqa: E731
    classes = {
        "listeners": {"reached": reached["listeners"]["reached"], "gaps": by_kind("listener-not-scanned") + by_kind("scan-failed")},
        "entries": {"reached": len({f["fingerprint"] for f in findings}) - by_kind("algorithm-unidentified") - by_kind("key-not-opened"),
                    "gaps": by_kind("algorithm-unidentified") + by_kind("key-not-opened")},
        "key files": {"reached": max(files_read, key_files), "gaps": by_kind("unreadable-path") + by_kind("key-not-opened")},
        "services": {"reached": len(named & supplied), "gaps": by_kind("no-owner-facts")},
        "controller": {"reached": sum(1 for f in ctl_certs if f["asset"]["name"] != "unknown"), "gaps": by_kind("controller-certificate-key-unknown")},
        "firmware": {"reached": len(fw_names) - by_kind("firmware-not-attested") - (len(fw_names) if by_kind("no-supplier-statement") else 0),
                     "gaps": by_kind("firmware-not-attested") + (len(fw_names) if by_kind("no-supplier-statement") else by_kind("no-supplier-statement"))},
    }
    out_classes = []
    for name, c in classes.items():
        total = c["reached"] + c["gaps"]
        if total == 0:
            continue
        out_classes.append({"class": name, "reached": c["reached"], "gaps": c["gaps"], "total": total,
                            "coverage": round(100 * c["reached"] / total)})
    return {"open": open_rows, "filled": [r for r in rows if r["filled"]], "recorded": len(rows),
            "classes": out_classes, "rule": RULE}


def _ran(events: list[dict]) -> bool:
    """Whether the gap rule ran on this ledger: its mark is there even when it found nothing."""
    return any(e["type"] == "assessment.made" and e["payload"].get("rule_id") == RULE for e in events)


def fill(var: str | Path, gid: str, *, evidence: str, by: str, basis: str, signer=None) -> tuple[Run, dict]:
    """Close a gap with the evidence a person brought: `evidence` is a run id, or run:event. The run
    must exist and verify, and the event be on it; a gap nobody recorded is refused."""
    var = Path(var)
    run_id, _, event_id = evidence.partition(":")
    if not run_id.isalnum() or (event_id and not event_id.isalnum()):
        raise ValueError("evidence is a run id, or run:event")
    er = Run(var, run_id)
    evs = list(er.ledger.events()) if er.ledger.exists() else []
    if not evs or not verify(evs).ok:
        raise ValueError(f"run {run_id} is not on this deployment or does not verify")
    if event_id and not any(e["id"] == event_id for e in evs):
        raise ValueError(f"event {event_id} is not on run {run_id}")
    found = None
    from pqch.ui.view import runs_of_kind

    for r in runs_of_kind(var, "scan") + runs_of_kind(var, "scan-system") + runs_of_kind(var, "scan-external"):
        for e in r.ledger.events():
            if e["type"] == "gap.recorded" and e["payload"]["gap"] == gid:
                found = (r.id, e)
    if not found:
        raise ValueError(f"no run recorded gap {gid}")
    scope = {"schema": "pqch.scope/1", "id": ulid(), "estate": "external", "owned": False, "authorized_by": by,
             "endpoints": [], "images": [], "sources": [], "reach": {"kind": "local"}}
    from pqch import scope as scope_mod

    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile=f"gapfill:{gid}", kind=KIND, runner_id="pqch-gap")
    ev = run.ledger.append("gap.filled", {"kind": "human", "id": by}, {
        "gap": gid, "kind": found[1]["payload"]["kind"], "subject": found[1]["payload"]["subject"], "recorded_on": found[0],
        "recorded_event": found[1]["id"], "evidence": {"run": run_id, "event": event_id or None}, "basis": basis})
    run.close(signer)
    return run, {"run": run.id, "event": ev["id"], "gap": gid, "kind": found[1]["payload"]["kind"]}
