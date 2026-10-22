"""The workbench on NIST's crypto-agility frame: each box of NIST CSWP 39's Figure 3 filled with this
deployment's live state, for one estate at a time.

The layout is NIST's (CSWP 39, December 2025, Fig. 3, "Crypto agility strategic plan for managing an
organization's cryptographic risks"), redrawn and credited on the page; NIST has not reviewed or
endorsed it. The contents are read from the ledgers: for each box, which part of the workbench does
that job, what it holds now, who acts there — scanner, rule, model, person or verifier — and, where
a model acts, which one and how it measured against its floor. A box an estate does not reach says
why, which is how the two estates' maturity is told apart.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from pqch.ledger import verify
from pqch.run import Run

# Where a model acts, with the measurement that put it there (spike S3; note 13). Each is a claim the
# BRIEF's facts table carries with its run.
MODELS = {
    "trace": {"role": "trace-to-cause", "model": "Nemotron 3.5 Super VL 120B, GB10", "score": "27 of 30, floor 24"},
    "call-site": {"role": "call-site-read", "model": "Gemma 4 31B, four L4s, reasoning on", "score": "29 of 30, floor 27"},
    "draft": {"role": "change-plan", "model": "Gemma 4 31B, four L4s", "score": "27 of 30, none harmful, floor 24"},
    "conflict": {"role": "resolve-conflict", "model": "Nemotron 3.5 Super VL, GB10", "score": "26 of 29, floor 24; explains beside the rule"},
    "names": {"role": "normalize-name", "model": "Nemotron 3.5 Super VL, GB10", "score": "28 of 30, floor 28; fallback to the name table"},
}


def _events(run: Run | None) -> list[dict]:
    if run is None or not run.ledger.exists():
        return []
    ev = list(run.ledger.events())
    return ev if verify(ev).ok else []


def _latest(var: Path, kind: str) -> Run | None:
    r = Run.latest(var, kind)
    return r if r and r.ledger.exists() else None


def _rules(events: list[dict]) -> Counter:
    return Counter(e["payload"].get("rule_id") for e in events if e["type"] == "assessment.made" and e["payload"].get("rule_id"))


INTENT = {"enable": "offer a hybrid post-quantum key exchange", "require": "require a hybrid post-quantum key exchange"}


def _span_words(ms: int) -> str:
    s = ms / 1000
    return f"{s:.1f} s" if s < 120 else (f"{s / 60:.0f} min" if s < 7200 else f"{s / 3600:.1f} h")


def _change_story(var: Path) -> dict | None:
    """The most recent change that landed — verified, and verified again after a recreate — as a sequence
    of steps through the frame, each with its ledger timestamp."""
    from pqch.common import ms_between
    from pqch.migrator import intervals
    from pqch.ui.view import _rederives, change_runs

    for run in reversed(change_runs(var)):
        events = _events(run)
        props = {e["payload"]["change_id"]: e for e in events if e["type"] == "change.proposed"}
        # Only a change whose every verdict re-derives from its raw output: the review's forgeries are not a story.
        # Toward post-quantum only: a change back to classical (a review's rollback) is not the loop's story.
        landed = [t for t in intervals(events) if t.get("landed") and t.get("intent") in INTENT and all(
            _rederives(var, e["payload"], props[t["change_id"]]) for e in events
            if e["type"] == "verdict.issued" and e["payload"].get("change_id") == t["change_id"])]
        if not landed:
            continue
        cid = landed[-1]["change_id"]
        box = {"policy.changed": "governance", "change.proposed": "migration", "rehearsal.completed": "tools",
               "approval.granted": "governance", "change.applied": "migration", "verdict.issued": "tools",
               "service.recreated": "migration", "checkpoint.signed": "repository"}
        words = {"policy.changed": "a person changes the crypto policy", "change.proposed": "the change is proposed, with its diff and the check that will count",
                 "rehearsal.completed": "rehearsed on a copy", "approval.granted": "a person approves",
                 "change.applied": "the runner applies it", "verdict.issued": "the verifier probes the listener — no model",
                 "service.recreated": "the service is recreated, to repeat the check", "checkpoint.signed": "the ledger is signed (ML-DSA-65)"}
        steps, t0 = [], None
        for e in events:
            t = e["type"]
            if t not in box or (e["payload"].get("change_id") not in (None, cid) and t != "policy.changed"):
                continue
            if t == "checkpoint.signed" and (not steps or steps[-1]["type"] == "checkpoint.signed"):
                continue
            t0 = t0 or e["ts"]
            label = words[t]
            if t == "verdict.issued":
                label += f": {e['payload']['status']}" + (", durable" if e["payload"].get("durable") is True else "")
            if t in ("approval.granted",):
                label += f" ({e['payload'].get('by')})"
            steps.append({"box": box[t], "type": t, "ts": e["ts"], "ms": ms_between(t0, e["ts"]), "label": label})
        # The machine's part is approval to proof; policy to proof also counts the time it waited for a person.
        lv = landed[-1]
        steps.append({"box": "kpi", "type": "kpi", "ts": steps[-1]["ts"], "ms": steps[-1]["ms"],
                      "label": f"approval to proof {lv['approval_to_verdict_ms'] / 1000:.1f} s; policy to proof "
                               f"{_span_words(lv['policy_to_verdict_ms'])}, the rest waiting for a person"})
        prop = next(e for e in events if e["type"] == "change.proposed" and e["payload"]["change_id"] == cid)
        return {"run": run.id, "change_id": cid, "hardware": landed[-1].get("hardware"),
                "approval_s": round(lv["approval_to_verdict_ms"] / 1000, 1), "policy_words": _span_words(lv["policy_to_verdict_ms"]), "service": prop["payload"]["target"]["service"],
                "intent": prop["payload"]["intent"], "intent_words": INTENT[prop["payload"]["intent"]], "steps": steps,
                "drafted": prop["actor"]["kind"] == "model"}
    return None


def mini_agency(var: Path) -> dict:
    from pqch.cbom import project
    from pqch.ui.view import receipts_view, run_view

    scan = _latest(var, "scan")
    ev = _events(scan)
    view = run_view(scan) if scan else {}
    bom = project(ev) if ev else {"components": []}
    kinds = Counter((json.loads(next((p["value"] for p in c.get("properties", []) if p["name"] == "pqch:subject"), "{}")).get("kind"),
                     c["type"]) for c in bom["components"])
    props = lambda c: {p["name"]: p["value"] for p in c.get("properties", [])}  # noqa: E731
    rules = _rules(ev)
    managed = (view.get("managed") or {}).get("counts", {})
    receipts = receipts_view(var, view)
    code = _events(_latest(var, "scan-code"))
    code_uses = sum(1 for e in code if e["payload"].get("purpose") == "call-site-read" and e["payload"]["classification"].get("in_use"))
    score = ((view.get("score") or {}).get("columns") or {}).get("workbench") or {}
    L = score.get("layers", {})
    ch = receipts["changes"]
    pending = None
    latest_change = _events(_latest(var, "change"))
    props_ = [e for e in latest_change if e["type"] == "change.proposed"]
    # Waiting for approval: proposals in an open change run neither applied nor denied.
    open_run = bool(latest_change) and latest_change[-1]["type"] != "run.closed"
    done_ids = {e["payload"].get("change_id") for e in latest_change if e["type"] in ("change.applied", "approval.denied")}
    props_ = [e for e in props_ if e["payload"]["change_id"] not in done_ids] if open_run else []
    if props_:
        rehearsed = {e["payload"]["change_id"] for e in latest_change if e["type"] == "rehearsal.completed"
                     and e["payload"]["verdict"].get("meets_intent")}
        pending = [{"service": e["payload"]["target"]["service"], "by": "model" if e["actor"]["kind"] == "model" else "rule",
                    "rehearsed": e["payload"]["change_id"] in rehearsed} for e in props_]
    story = _change_story(var)
    from pqch import planning
    plan = planning.build(var, scan) if scan else None
    from pqch.ui.view import packages_view
    pk = packages_view(Run.latest(var, "package"))
    pk = pk if pk and not pk.get("broken") else None
    services = sum(1 for c in bom["components"] if c["type"] == "application")
    tools = sorted({s["tool"] for s in view.get("scans", [])})
    queues = (view.get("managed") or {}).get("queues", {})
    flagged = sum(len(L.get(k, {}).get("flagged_decoys", [])) for k in L)
    decoys = sum(L.get(k, {}).get("decoys", 0) for k in L if L.get(k, {}).get("scanned"))
    d = {
        "estate": "mini-agency", "title": "The mini-agency",
        "about": "Eight small services built in this lab with every weakness planted, so every answer can be checked against a key.",
        "run": scan and scan.id, "scan_run": scan and scan.id, "span": None,
        "boxes": {
            "governance": {
                "here": "policy packs and the owner's facts",
                "lines": ["OMB M-26-15 as data: every rule in the memo's own words, checked against its text",
                          "CNSA 2.0 carried unverified (the primary was not readable)",
                          f"the crypto policy: {', '.join(t for t in ('portal', 'records-db', 'bastion'))} under policy",
                          f"owner's facts for {services} services — mission, data lifetime, impact, owner — labelled supplied"],
                "who": ["person", "rule"], "link": "/walkthrough#queues", "state": "on"},
            "assets": {
                "here": "what the scans reached",
                "lines": [f"{sum(n for (k, t), n in kinds.items() if t == 'application')} services, "
                          f"{sum(1 for c in bom['components'] if props(c).get('pqch:kind') == 'listener')} listeners, "
                          f"{sum(1 for c in bom['components'] if c['type'] == 'container')} images",
                          f"{kinds.get(('endpoint', 'cryptographic-asset'), 0)} assets on the wire, {kinds.get(('file', 'cryptographic-asset'), 0)} in image files",
                          f"code: {len([e for e in code if e['type'] == 'finding.observed'])} candidate call sites in one federal repository, {code_uses} judged uses"],
                "who": ["scanner"], "link": "/cbom", "state": "on"},
            "tools": {
                "here": "scanners, rules, runner, verifier",
                "lines": [f"discovery: {', '.join(tools)} — {len(view.get('scans', []))} jobs a scan; a rule pack and a model on code",
                          f"assessment: {len(rules)} rules over the findings",
                          "any other tool's CBOM can be imported and scored against the same key (bring your own scanner)",
                          "configuration: rendered by rule (nginx, OpenSSH) or drafted by a model (PostgreSQL)",
                          f"enforcement: the runner applies only on approval; the verifier's probes decide — {ch['verdicts']} verdicts"],
                "ai": [MODELS["trace"], MODELS["call-site"]], "who": ["scanner", "rule", "model", "verifier"],
                "link": "/walkthrough#cbom", "state": "on"},
            "repository": {
                "here": "the signed ledger and the CBOM built from it",
                "lines": [f"{len(ev)} events in the latest scan, hash-chained, checkpointed with ML-DSA-65",
                          f"a CycloneDX 1.6 CBOM of {len(bom['components'])} components, rebuilt from the ledger, never edited",
                          "projected again on demand: an agency inventory in milliseconds, no scan"],
                "who": ["rule"], "link": "/cbom", "state": "on"},
            "engine": {
                "here": "queues, blockers and the plan, by rule",
                "lines": ["the migration plan: what depends on what, what comes first, in what order — computed from the CBOM",f"{managed.get('open', 0)} migration items open: " + "; ".join(f"{len(v)} in {k}" for k, v in queues.items()),
                          f"{managed.get('supplier_blocked', 0)} blocked on a supplier; {managed.get('validated_none', 0)} with no validated module",
                          f"{rules.get('conflict/resolve/1', 0)} conflicts between file and wire settled by rule"],
                "ai": [MODELS["conflict"], MODELS["names"]], "who": ["rule", "model"],
                "link": "/plan", "state": "on"},
            "kpi": {
                "here": "the receipts",
                "lines": [f"coverage against the answer key: wire {L.get('wire', {}).get('covered', '?')} of {L.get('wire', {}).get('denominator', '?')}, "
                          f"images {L.get('host', {}).get('covered', '?')} of {L.get('host', {}).get('denominator', '?')}; {flagged} of {decoys} decoys flagged",
                          f"{ch['landed']} changes verified landed; {ch['not_borne_out']} verdicts that do not re-derive, counted apart",
                          (f"approval to proof: {story['approval_s']} s for the last change that landed" if story else "no change landed yet")],
                "who": ["verifier"], "link": "/walkthrough#score", "state": "on"},
            "mitigation": {
                "here": "where no change can be made",
                "lines": [f"{managed.get('supplier_blocked', 0)} items whose software cannot take post-quantum cryptography: marked for replacement (M-26-15 §3.C.3)",
                          (f"{len(pk['packages'])} change packages: why no configuration change can do it, with the runtime's own list; "
                           f"what would unblock it; the CBOM entries it covers; the test that will count"
                           + (f" — {sum(1 for x in pk['packages'] if x['unblock'])} with an upgrade path already in the estate" if pk['packages'] else ""))
                          if pk else "change packages: none issued yet"],
                "who": ["rule"], "link": "/packages" if pk else "/walkthrough#queues", "state": "on" if pk else "partial"},
            "migration": {
                "here": "a change, proposed, rehearsed, approved, applied",
                "lines": [f"{ch['applied']} changes applied, {ch['landed']} verified landed",
                          (f"waiting for approval: {', '.join(p['service'] + (' (drafted by a model' if p['by'] == 'model' else ' (by rule') + (', rehearsed)' if p['rehearsed'] else ')') for p in pending)}"
                           if pending else "nothing waiting for approval")],
                "ai": [MODELS["draft"]], "who": ["model", "person", "verifier"], "link": "/resolve", "state": "on"},
        },
        "loop": "verified by re-scan; watch mode re-examines only what changed",
        "story": story,
    }
    # One headline a box: a number and a few words, the rest behind a click.
    wire = kinds.get(("endpoint", "cryptographic-asset"), 0)
    files = kinds.get(("file", "cryptographic-asset"), 0)
    _heads(d, {
        "governance": ("M-26-15", "as data, every quote checked; owner's facts for " + str(services) + " services"),
        "assets": (f"{services} services", f"{wire} assets on the wire, {files} in image files; {code_uses} call sites in one repository's code"),
        "tools": (f"{len(view.get('scans', []))}", f"scanner jobs a scan; {len(rules)} rules; {ch['verdicts']} verdicts by probe"),
        "repository": (f"{len(bom['components'])}", f"CBOM components, rebuilt from {len(ev)} signed ledger events"),
        "engine": ((f"{plan['steps']}", f"plan steps from the CBOM: {len(plan['dependencies'])} shared dependencies, {plan['waiting']} waiting on another")
                   if plan else (f"{managed.get('open', 0)}", f"migration items open; {managed.get('supplier_blocked', 0)} blocked on a supplier")),
        "kpi": (f"{L.get('wire', {}).get('covered', '?')}/{L.get('wire', {}).get('denominator', '?')}",
                f"keyed wire items found; {ch['landed']} changes verified landed"),
        "mitigation": ((f"{len(pk['packages'])}", "change packages for software that cannot take post-quantum cryptography") if pk else
                       (f"{managed.get('supplier_blocked', 0)}", "items to replace: the software cannot take post-quantum cryptography")),
        "migration": (f"{ch['landed']}", "changes verified landed; " + (f"{len(pending)} waiting for approval" if pending else "none waiting")),
    })
    return d


def _heads(d: dict, heads: dict) -> None:
    for k, (big, small) in heads.items():
        d["boxes"][k]["big"], d["boxes"][k]["small"] = big, small


def lab(var: Path, capture: dict | None, scan_view: dict | None, house: dict | None = None) -> dict:
    cv = capture or {}
    sv = scan_view or {}
    lst = sv.get("listeners", [])
    posture = Counter((ln.get("posture") or {}).get("posture") for ln in lst if ln.get("posture"))
    certs = sum(1 for ln in lst for r in ln.get("rows", []) if r.get("type") == "certificate")
    hs, hy = cv.get("handshakes", 0), cv.get("hybrid", 0)
    loss = (cv.get("loss") or {}).get("median_bp")
    span = cv.get("span") or [None, None]
    from pqch import planning
    plan = planning.lab_build(capture, house) if capture and house else None
    d = {
        "estate": "lab", "title": "A real network",
        "about": "The owner's own lab, every VLAN, under the owner's written authorization. Nothing here is planted and there is no answer key.",
        "run": cv.get("run"), "scan_run": sv.get("run"), "span": span,
        "boxes": {
            "governance": {
                "here": "the authorization",
                "lines": ["the owner's authorization, recorded in the first event of every run",
                          "no owner's facts yet — mission, data lifetime, impact — so the policy pack has nothing to rank",
                          "nothing may be changed: the workbench did not build this estate"],
                "who": ["person"], "link": "/lab", "state": "partial"},
            "assets": {
                "here": "what was seen and what was reached",
                "lines": [f"{len(cv.get('clients', []))} clients and {len(cv.get('inside_servers', []))} TLS listeners seen inside, "
                          f"{len(cv.get('ssh', []))} SSH servers, {len(cv.get('outside', []))} names outside",
                          f"{len(lst)} listeners in the scope for targeted checks; {certs} certificates read from them",
                          "no images or code read: host evidence needs its own authorization"],
                "who": ["scanner"], "link": "/lab", "state": "partial"},
            "tools": {
                "here": "a passive sensor and targeted checks",
                "lines": ["discovery: Zeek on a mirror of the firewall trunk, every handshake; testssl.sh and ssh-audit on the listed listeners",
                          "assessment: observed posture per listener, capability per client — by rule",
                          f"targeted checks: {sum(posture.values())} of {len(lst)} listeners answered; "
                          + ", ".join(f"{n} {k}" for k, n in posture.most_common()),
                          "configuration and enforcement: none — nothing is sent but the targeted checks"],
                "who": ["scanner", "rule"], "link": "/lab", "state": "partial"},
            "repository": {
                "here": "the same ledger, and the house's CBOM built from it",
                "lines": ([f"a CycloneDX 1.6 CBOM of the house: {house['entries']:,} entries, {house['both']} of them seen by both layers and merged into one"]
                          if house else []) + [f"{cv.get('ledger', {}).get('events', 0):,} events in the latest capture run, hash-chained; still open for the daily ingest, so not yet signed",
                          f"{sv.get('ledger', {}).get('events', 0):,} in the latest targeted scan, closed and signed (ML-DSA-65)",
                          "kept with the deployment; nothing from it is published"],
                "who": ["rule"], "link": "/lab#house-cbom", "state": "on"},
            "engine": {
                "here": "posture and the plan, not yet priority",
                "lines": [f"{hy:,} of {hs:,} handshakes negotiated a hybrid post-quantum group" if hs else "no capture yet",
                          "which listeners still choose classical when offered better, and which clients never offer it",
                          "a plan of who holds whom back: servers refusing what clients offer, clients holding servers back, by VLAN",
                          "no queues: the policy pack needs the owner's facts, and none are supplied"],
                "who": ["rule"], "link": "/plan?estate=lab", "state": "partial"},
            "kpi": {
                "here": "the capture's own measures",
                "lines": [f"median capture loss {loss / 100:.1f}%, shown beside every count" if loss is not None else "capture loss not measured",
                          "no coverage score: a real network has no answer key"],
                "who": ["rule"], "link": "/lab", "state": "partial"},
            "mitigation": {"here": "change packages", "lines": ["planned: for an estate it does not own, the workbench hands over a package and verifies the result"],
                           "who": [], "link": "/lab", "state": "off"},
            "migration": {"here": "not here", "lines": ["the workbench applies nothing to an estate it did not build (ADR-0003)"],
                          "who": [], "link": "/lab", "state": "off"},
        },
        "loop": "a daily ingest of the capture; no change to verify yet",
        "story": None,
    }
    _heads(d, {
        "governance": ("authorized", "by the owner, every VLAN; no owner's facts yet"),
        "assets": (f"{len(cv.get('clients', []))}", f"clients inside; {len(cv.get('inside_servers', [])) + len(cv.get('ssh', []))} servers, {len(cv.get('outside', []))} names outside"),
        "tools": ("passive", f"Zeek on a mirror; targeted checks on {len(lst)} listeners"),
        "repository": ((f"{house['entries']:,}", "CBOM entries for the house, the capture and the scan merged by fingerprint") if house else
                       (f"{cv.get('ledger', {}).get('events', 0):,}", "ledger events from the capture, kept off the public site")),
        "engine": ((f"{plan['steps']}", f"plan steps: {len(plan['dependencies'])} client groups hold servers back; {plan['waiting']} steps waiting")
                   if plan else (f"{100 * hy // hs}%" if hs else "—", f"of {hs:,} handshakes negotiated a hybrid group" if hs else "no capture yet")),
        "kpi": (f"{loss / 100:.1f}%" if loss is not None else "—", "median capture loss, shown beside every count"),
        "mitigation": ("—", "planned: a change package to hand over"),
        "migration": ("—", "nothing is changed on an estate the workbench did not build"),
    })
    return d


# NIST's own labels in Figure 3, in its order, each marked for an estate as reached ("on"), in part
# ("partial") or not ("off"), with what does it here. The figure's "..." boxes are left out.
NIST = {
    "governance": ["Standards", "Regulations, Mandates", "Technology Supply Chains", "Threats", "Processes",
                   "Business Requirements", "Partner Ecosystem", "Stakeholders", "Crypto Policies", "Crypto Architecture"],
    "assets": ["Code", "Libraries", "Applications", "Files", "Protocols", "Systems"],
    "tools": ["Data", "Crypto", "Vulnerability", "Assets", "Log", "Zero-Trust"],
}

ITEMS = {
    "mini-agency": {
        "Standards": ("on", "FIPS 203 and 204 names, CycloneDX 1.6 for the CBOM"),
        "Regulations, Mandates": ("on", "OMB M-26-15 as a policy pack, quotes checked against the memo; CNSA 2.0 unverified"),
        "Technology Supply Chains": ("on", "each runtime's own algorithm list and the CMVP snapshot decide the supplier and validated-module blockers"),
        "Threats": ("on", "M-26-15's table of quantum-vulnerable algorithms, as data"),
        "Processes": ("on", "propose, rehearse on a copy, approve, apply, verify — each an event on the ledger"),
        "Business Requirements": ("on", "the owner's facts per service: mission function, data lifetime, impact"),
        "Partner Ecosystem": ("off", "not modelled"),
        "Stakeholders": ("on", "an owner per service, supplied and labelled"),
        "Crypto Policies": ("on", "the crypto policy: which services must offer or require a post-quantum group"),
        "Crypto Architecture": ("partial", "one policy-file shape per software (nginx, PostgreSQL, OpenSSH)"),
        "Code": ("on", "one pinned federal repository: rule pack, then a model judges each call site"),
        "Libraries": ("partial", "each runtime's TLS library and version, read for its capability list; not yet a CBOM entry"),
        "Applications": ("on", "eight services, each tied to its listeners and image"),
        "Files": ("on", "keys, certificates and configuration in each image"),
        "Protocols": ("on", "TLS and SSH, every group and version each listener accepts"),
        "Systems": ("on", "the containers and the network they sit on"),
        "Data": ("off", "no data-discovery tool"),
        "Crypto": ("on", "testssl.sh, ssh-audit, cbomkit-theia, the workbench's readers"),
        "Vulnerability": ("on", "quantum-vulnerable by rule, from the memo's table"),
        "Assets": ("on", "chains: service → listener → asset → file, by rule"),
        "Log": ("on", "the ledger: every observation, decision and change, hash-chained and signed"),
        "Zero-Trust": ("off", "not modelled"),
    },
    "lab": {
        "Standards": ("on", "the same algorithm names and CBOM format"),
        "Regulations, Mandates": ("partial", "the pack is loaded, but without the owner's facts it ranks nothing"),
        "Technology Supply Chains": ("off", "no runtime lists or module records gathered for these devices"),
        "Threats": ("partial", "the memo's table is loaded; here only posture marks classical key exchange"),
        "Processes": ("partial", "authorization and scope only; no change process — nothing is changed here"),
        "Business Requirements": ("off", "no owner's facts supplied"),
        "Partner Ecosystem": ("off", "not modelled"),
        "Stakeholders": ("partial", "the owner, as the one who authorized"),
        "Crypto Policies": ("off", "no crypto policy for this estate"),
        "Crypto Architecture": ("off", "not modelled"),
        "Code": ("off", "not read"),
        "Libraries": ("off", "not read"),
        "Applications": ("partial", "named only as far as a handshake names them"),
        "Files": ("off", "not read"),
        "Protocols": ("on", "every TLS and SSH handshake on the trunk; what each listed listener accepts"),
        "Systems": ("on", "every client and server that spoke, by VLAN"),
        "Data": ("off", "no data-discovery tool"),
        "Crypto": ("on", "Zeek on a mirror; testssl.sh and ssh-audit on the listed listeners"),
        "Vulnerability": ("partial", "posture per listener — classical, mixed or post-quantum; the quantum-vulnerable rule is not run here"),
        "Assets": ("partial", "listeners and clients; no chain to software"),
        "Log": ("on", "the capture's logs, ingested daily into the ledger"),
        "Zero-Trust": ("off", "not modelled"),
    },
}


def build(estate: str, var: Path, capture: dict | None = None, scan_view: dict | None = None, house: dict | None = None) -> dict:
    d = lab(var, capture, scan_view, house) if estate == "lab" else mini_agency(var)
    items = ITEMS[d["estate"]]
    d["nist"] = {region: [{"label": n, "state": items[n][0], "what": items[n][1]} for n in names]
                 for region, names in NIST.items()}
    return d
