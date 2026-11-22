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
class is counted from the same numbers against a total that a fill does not move: reached by a tool,
filled by a person, open.

A fill is bound to what it filled (`bound_to`, on the gap and copied onto its fill). A gap about a
file or an entry is bound to the evidence it was recorded from, the finding's fingerprint and the
digest of the image or file it was read in, so a replaced file is a new gap under the same id. A gap
about one scan's reach (a job that failed, a listener no job ran against) is bound to that run: a
fill closes it there, and on another run only when the fill's evidence was taken after that run
recorded the gap. A gap about a fact that does not move between scans (a service's owner, a model's
supplier) carries no binding and stays filled. A supplier's document closes a firmware gap only when
it covers what is installed (`attest.match`): an illustrative document, a statement for another
version or a row that makes no statement leaves the gap open, with the reason.
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


# Gaps about what one scan reached, not about the estate: a fill is good for the run it was made for.
TRANSIENT = ("scan-failed", "listener-not-scanned")


def gap_id(kind: str, subject: dict) -> str:
    return hash_object({"kind": kind, "subject": subject})[:24]


def _bound_to_finding(f: dict) -> dict:
    """What a gap recorded from a finding is bound to: the entry's fingerprint and the digest of what it
    was read in, where the finding carries one."""
    out = {"fingerprint": f["fingerprint"]}
    for k in ("subject_digest", "image_digest"):
        if (f.get("source") or {}).get(k):
            out[k] = f["source"][k]
    if (f["asset"].get("parameters") or {}).get("sha256"):
        out["sha256"] = f["asset"]["parameters"]["sha256"]
    return out


def honoured(fill: dict, recorded: dict, recorded_ts: str, run_id: str) -> bool:
    """Whether a fill closes this recording of its gap. A gap with no binding is a standing fact and any
    fill closes it; a gap bound to evidence is closed by a fill of the same evidence; a gap bound to a
    run is closed by a fill made for that run, or by one whose evidence was taken after the recording."""
    b = recorded.get("bound_to")
    if not b:
        return True
    if "run" in b:
        started = (fill.get("evidence") or {}).get("started")
        return fill.get("recorded_on") == run_id or bool(started and started > recorded_ts)
    return fill.get("bound_to") == b


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

    def gap(k: str, subject: dict, reason: str, *, asset_class: str | None = None, inputs: list[str] = (),
            bound_to: dict | None = None):
        gid = gap_id(k, subject)
        if gid in seen:
            return
        seen.add(gid)
        if k in TRANSIENT:
            bound_to = {"run": run.id}
        run.ledger.append("gap.recorded", {"kind": "rule", "id": RULE}, {
            "gap": gid, "rule_id": RULE, "kind": k, "asset_class": asset_class or CLASS[k], "subject": subject,
            "reason": reason, "fills": FILLS[k], **({"bound_to": bound_to} if bound_to else {})}, inputs=list(inputs))
        counts[k] = counts.get(k, 0) + 1

    findings = {e["id"]: e["payload"] for e in events if e["type"] == "finding.observed"}
    # Key material a reader could not open, and entries whose algorithm nothing identified.
    unknown_fps = {e["payload"]["subject"]["fingerprint"] for e in events if e["type"] == "assessment.made"
                   and e["payload"].get("rule_id") == "compatibility/entry/1" and e["payload"]["classification"]["status"] == "unknown"}
    for fid, f in findings.items():
        p = f["asset"].get("parameters") or {}
        if p.get("opened") is False:
            gap("key-not-opened", f["subject"], f"the reader could not open it ({p.get('why', 'unreadable')}); its algorithm and size are not known",
                inputs=[fid], bound_to=_bound_to_finding(f))
        elif f["fingerprint"] in unknown_fps and f["subject"]["kind"] != "platform":
            gap("algorithm-unidentified", f["subject"], f"the entry names no algorithm a table places ({f['asset']['name']})", inputs=[fid],
                bound_to=_bound_to_finding(f))
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
                "the controller reports the certificate's issuer and dates and not its key; the algorithm is unknown", inputs=[fid],
                bound_to=_bound_to_finding(f))
    if kind == "scan-system":
        from pqch import attest

        obs = attest.observed(events)
        att = attest.for_system(run.var, events) if obs["device"].get("model") else None
        device = {"kind": "device", "system": obs["system"], "vendor": obs["device"].get("vendor"), "model": obs["device"].get("model")}
        if obs["device"].get("model") and not att:
            gap("no-supplier-statement", device,
                "no supplier's attestation names this model: what signs its firmware, which modules it carries and its route forward are unstated")
        elif att and att.get("illustrative"):
            # An illustration shows what a statement would say; it is nobody's word about this server.
            gap("no-supplier-statement", device,
                f"the only document that names this model is illustrative ({att['supplier']}, {att['issued']}): no supplier has "
                "made a statement about it")
        elif att:
            for name in att["not_attested"]:
                gap("firmware-not-attested", {"kind": "firmware", "system": obs["system"], "name": name},
                    f"the server reports it and {att['supplier']}'s statement does not name it",
                    bound_to={"version": obs["firmware"].get(name)})
            # Named, and still not covered: another version, or a row that makes no statement.
            for r in att.get("not_covered") or []:
                gap("firmware-not-attested", {"kind": "firmware", "system": obs["system"], "name": r["name"]},
                    f"{att['supplier']}'s statement names it and does not cover what is installed: {r['reason']}",
                    bound_to={"version": obs["firmware"].get(r["name"])})
    # The rule's own mark, so a run with no gap says the rule ran and found none.
    run.ledger.append("assessment.made", {"kind": "rule", "id": RULE}, {
        "subject": {"kind": "run", "run": run.id}, "rule_id": RULE,
        "classification": {"gaps": sum(counts.values()), "by_kind": counts},
        "basis": "every gap the run's evidence leaves, recorded as gap.recorded; none hidden in a coverage figure"})
    return {"gaps": sum(counts.values()), "gaps_by_kind": counts}


def all_fills(var: str | Path) -> dict[str, list[dict]]:
    """Every `gap.filled` on this deployment, by gap id, oldest first, from verified ledgers."""
    from pqch.ui.view import runs_of_kind

    out: dict[str, list[dict]] = {}
    for r in runs_of_kind(Path(var), KIND):
        evs = list(r.ledger.events())
        if not verify(evs).ok:
            continue
        for e in evs:
            if e["type"] == "gap.filled":
                out.setdefault(e["payload"]["gap"], []).append(
                    {**e["payload"], "run": r.id, "event": e["id"], "ts": e["ts"], "by": e["actor"]["id"]})
    for rows in out.values():
        rows.sort(key=lambda f: f["ts"])
    return out


def fills(var: str | Path) -> dict[str, dict]:
    """The latest `gap.filled` per gap id. Whether it closes a given run's recording of the gap is
    `honoured`'s to say, not this function's."""
    return {gid: rows[-1] for gid, rows in all_fills(var).items()}


def queue(var: str | Path, events: list[dict]) -> dict | None:
    """The run's gaps, open and filled, and the coverage per asset class counted from them. None for a
    run that recorded no gap rule (before the rule existed), so a page says nothing rather than zero.
    Each class is three numbers against one total: reached by a tool, filled by a person, open; the
    total is what the scope or the findings hold, so a fill moves a gap from open to filled and nothing
    else. Coverage is reached plus filled over the total."""
    recorded = [e for e in events if e["type"] == "gap.recorded"]
    if not _ran(events):
        return None
    filled = all_fills(var)
    run_id = events[0]["payload"].get("run") or ""
    rows = []
    for e in recorded:
        p = e["payload"]
        f = next((x for x in reversed(filled.get(p["gap"], [])) if honoured(x, p, e["ts"], run_id)), None)
        rows.append({**p, "event": e["id"], "filled": f})
    open_rows = [r for r in rows if not r["filled"]]
    reached = _reached(events)
    scope = events[0]["payload"]["scope"]
    findings = [e["payload"] for e in events if e["type"] == "finding.observed"]
    named = {ep.get("service") for ep in scope.get("endpoints", []) if ep.get("service")}
    supplied = {e["payload"]["from"]["name"] for e in events if e["type"] == "link.asserted" and e["payload"].get("status") == "supplied"}
    files_read = sum((e["payload"].get("files_read") or 0) for e in events if e["type"] == "platform.observed" and e["payload"].get("source") == "files")
    # Key files are files, not findings: one file read by two readers is one file.
    key_files = len({hash_object(f["subject"]) for f in findings
                     if f["asset"]["type"] == "related-crypto-material" and f["subject"]["kind"] == "file"})
    ctl_certs = [f for f in findings if f["subject"].get("component", "").startswith("bmc:certificate:")]
    fw_names = {fw["name"] for e in events if e["type"] == "platform.observed" for fw in (e["payload"].get("firmware") or [])}

    def split(*kinds: str) -> tuple[int, int]:
        """(open, filled) among this run's gaps of these kinds."""
        mine = [r for r in rows if r["kind"] in kinds]
        return sum(1 for r in mine if not r["filled"]), sum(1 for r in mine if r["filled"])

    def cls(total: int | None, reached_: int | None, *kinds: str) -> dict:
        """One class. Give the total (reached is the rest) or what was reached (the total is the sum)."""
        o, f = split(*kinds)
        if total is None:
            total = reached_ + o + f
        return {"reached": max(total - o - f, 0), "filled": f, "gaps": o, "total": max(total, o + f)}

    no_statement = split("no-supplier-statement")
    if no_statement[0] or no_statement[1]:
        # No supplier's statement at all: every firmware the server reports is the gap, open or filled.
        firmware = {"reached": 0, "filled": len(fw_names) if no_statement[1] else 0,
                    "gaps": len(fw_names) if no_statement[0] else 0, "total": len(fw_names)}
    else:
        firmware = cls(len(fw_names), None, "firmware-not-attested")
    classes = {
        "listeners": cls(None, reached["listeners"]["reached"], "listener-not-scanned", "scan-failed"),
        # Entries as the CBOM page counts them: the projection's entries, onto which several fingerprints
        # can fold; never fewer than the gaps recorded against them.
        "entries": cls(_cbom_entries(events), None, "algorithm-unidentified", "key-not-opened"),
        # A key file the reader could not open is one of the files found, so it is not also reached; a
        # path nobody could read was never among them, so it adds to the total.
        "key files": cls(max(files_read, key_files) + sum(split("unreadable-path")), None, "unreadable-path", "key-not-opened"),
        "services": cls(None, len(named & supplied), "no-owner-facts"),
        "controller": cls(None, sum(1 for f in ctl_certs if f["asset"]["name"] != "unknown"), "controller-certificate-key-unknown"),
        "firmware": firmware,
    }
    out_classes = []
    for name, c in classes.items():
        if c["total"] == 0:
            continue
        out_classes.append({"class": name, **c, "coverage": round(100 * (c["reached"] + c["filled"]) / c["total"])})
    return {"open": open_rows, "filled": [r for r in rows if r["filled"]], "recorded": len(rows),
            "classes": out_classes, "rule": RULE}


def _cbom_entries(events: list[dict]) -> int:
    """The entries of the CBOM these events project (its components that carry a fingerprint)."""
    from pqch import cbom

    return sum(1 for c in cbom.project(events).get("components", [])
               if any(p["name"] == "pqch:fingerprint" for p in c.get("properties", [])))


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
        revs = list(r.ledger.events())
        if not any(e["type"] == "gap.recorded" and e["payload"]["gap"] == gid for e in revs):
            continue
        if not verify(revs).ok:
            continue            # a recording on a ledger that does not verify is nobody's record
        for e in revs:
            if e["type"] == "gap.recorded" and e["payload"]["gap"] == gid:
                found = (r.id, e)
    if not found:
        raise ValueError(f"no run recorded gap {gid}")
    if found[1]["payload"]["kind"] in TRANSIENT and not evs[0]["ts"] > found[1]["ts"]:
        raise ValueError(f"run {run_id} was taken before run {found[0]} recorded the gap: evidence that a scan now "
                         "reaches the listener has to be later than the scan that did not")
    scope = {"schema": "pqch.scope/1", "id": ulid(), "estate": "external", "owned": False, "authorized_by": by,
             "endpoints": [], "images": [], "sources": [], "reach": {"kind": "local"}}
    from pqch import scope as scope_mod

    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile=f"gapfill:{gid}", kind=KIND, runner_id="pqch-gap")
    ev = run.ledger.append("gap.filled", {"kind": "human", "id": by}, {
        "gap": gid, "kind": found[1]["payload"]["kind"], "subject": found[1]["payload"]["subject"], "recorded_on": found[0],
        "recorded_event": found[1]["id"], "evidence": {"run": run_id, "event": event_id or None, "started": evs[0]["ts"]},
        **({"bound_to": found[1]["payload"]["bound_to"]} if found[1]["payload"].get("bound_to") else {}), "basis": basis})
    run.close(signer)
    return run, {"run": run.id, "event": ev["id"], "gap": gid, "kind": found[1]["payload"]["kind"]}
