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


# What the CBOM contributes at each step of the loop. The same sentence for every change: it is what the
# record is for, not what one change did.
CBOM_ROLE = {
    "discover": "Each finding becomes a CBOM entry, tied to the listener it was seen on, with the scanner's raw output and its hash as evidence.",
    "structure": "The links turn an algorithm on a port into part of a service with a mission and a data lifetime — the facts every later step reasons from. Typed-in facts stay labelled supplied.",
    "prioritize": "The queue is computed from the CBOM's entries and the owner's facts, so when either changes it is recomputed, not re-typed.",
    "trace": "The model is handed one CBOM finding and the files the CBOM links to its service, not the estate. What it says is recorded as a claim beside the evidence, never as a fact.",
    "policy": "The policy is written against the services the CBOM names; the distance between the policy and the CBOM is the work.",
    "draft": "Everything the draft was shown is on the proposal, by CBOM entry and file hash, so a reviewer can see what it was given and the rollback is recorded before anything changes.",
    "rehearse": "The copy runs the image digest the CBOM recorded for the service, so the rehearsal tests what is actually deployed.",
    "matrix": "The approver sees, before deciding, which kinds of client the change would refuse; on a real network the CBOM's client entries from passive capture say who those clients are.",
    "approve": "Nothing is applied without an approval event on the ledger, and the approval names the proposal it approves.",
    "apply": "The CBOM's links from service to container and image are how the runner knows which container is the service's own and touches no other.",
    "prove": "No model takes part. The verdict is bound to the container, the image digest and the certificate it probed, and re-derives from the probes' raw output.",
    "update": "The CBOM is rebuilt from the new scan; both scans stay on the ledger, and the difference between them is the evidence the change landed.",
    "next": "The loop starts again from the CBOM: what is still open for this service, and the plan's place for it.",
}


def _runs_of(var: Path, kind: str) -> list[Run]:
    """Every run of one kind, oldest first, by its first event."""
    out = []
    d = Path(var) / "runs"
    for p in sorted(x for x in d.iterdir() if x.is_dir()) if d.is_dir() else []:
        r = Run(var, p.name)
        if r.ledger.exists():
            first = next(iter(r.ledger.events()), None)
            if first and first["payload"].get("kind") == kind:
                out.append(r)
    return out


def _at(subject: dict | None, target: dict) -> bool:
    s = subject or {}
    return s.get("host") == target["address"] and s.get("port") == target["port"]


def _for_service(e: dict, service: str, target: dict) -> bool:
    p, s = e["payload"], e["payload"].get("subject") or {}
    return _at(s, target) or s.get("service") == service or (s.get("kind") == "service" and s.get("name") == service) \
        or (p.get("classification") or {}).get("service") == service


def _name(x) -> str | None:
    return x.get("name") if isinstance(x, dict) else None


def _kind_of(asset: dict) -> str:
    if asset.get("type") == "certificate":
        return "certificate"
    if asset.get("type") == "protocol":
        return "protocol"
    return {"key-establishment": "key exchange", "signature": "signature"}.get(asset.get("role"), asset.get("role") or "")


def _asset_words(asset: dict) -> str:
    n, prm = asset["name"], asset.get("parameters") or {}
    if asset.get("type") == "certificate":
        return f"{n}-{prm['key_bits']} certificate" if prm.get("key_bits") else f"{n} certificate"
    if prm.get("mode") == "key-transport":
        return f"{n} key transport"
    return n


def _change_story(var: Path) -> dict | None:
    """One weakness from finding to fixed: the last change that landed toward post-quantum, every verdict
    re-deriving from its raw output, told as the steps the loop takes — who acts at each, what happened,
    and what the CBOM contributes — from the scan that found it to the scan that shows it gone. Read from
    the ledgers alone."""
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
        if landed:
            break
    else:
        return None
    cid = landed[-1]["change_id"]
    prop = props[cid]
    target, intent, service = prop["payload"]["target"], prop["payload"]["intent"], prop["payload"]["target"]["service"]
    mine = [e for e in events if e["payload"].get("change_id") == cid]
    one = lambda t: next((e for e in mine if e["type"] == t), None)  # noqa: E731
    verdicts = [e for e in mine if e["type"] == "verdict.issued"]
    drafted = prop["payload"].get("drafted") or {}
    listener = f"{target['address']}:{target['port']}"

    # The scan the change was drafted from, else the last before the policy changed; and the first after it landed.
    scans = _runs_of(var, "scan")
    pol = next((e for e in events if e["type"] == "policy.changed"), None)
    before = next((r for r in scans if r.id == (drafted.get("context") or {}).get("scan_run")), None) or \
        next((r for r in reversed(scans) if pol and r.id < run.id), None)
    after = next((r for r in scans if r.id > run.id and verdicts and next(iter(r.ledger.events()))["ts"] > verdicts[-1]["ts"]), None)
    bev, aev = _events(before), _events(after)
    found = [e for e in bev if e["type"] == "finding.observed" and _at(e["payload"].get("subject"), target)]
    now = [e for e in aev if e["type"] == "finding.observed" and _at(e["payload"].get("subject"), target)]

    steps = []

    def step(key, box, title, who, did, details=(), link=None, model=None, ev=None):
        steps.append({"key": key, "box": box, "title": title, "who": who, "did": did, "cbom": CBOM_ROLE[key],
                      "details": [d for d in details if d], "link": link, "model": model,
                      "when": (ev or {}).get("ts", "")[:10]})

    if found:
        kex = [_asset_words(e["payload"]["asset"]) for e in found if _kind_of(e["payload"]["asset"]) == "key exchange"]
        certs = [_asset_words(e["payload"]["asset"]) for e in found if _kind_of(e["payload"]["asset"]) == "certificate"]
        protos = [e["payload"]["asset"]["name"] for e in found if _kind_of(e["payload"]["asset"]) == "protocol"]
        tools = sorted({e["actor"].get("id", "") for e in found})
        step("discover", "tools", "Found", ["scanner"],
             f"A scan of {service}'s listener ({listener}) records what it accepts: key exchange by {', '.join(kex)}"
             + (f"; {', '.join(protos)}" if protos else "") + (f"; it serves an {', '.join(certs)}" if certs else "") + ".",
             [f"{_asset_words(e['payload']['asset'])} — {_kind_of(e['payload']['asset'])}, seen by {e['actor'].get('id')}" for e in found]
             + [f"{len(found)} findings from {', '.join(tools)}, scan {before.id}"],
             link=f"/cbom?run={before.id}", ev=found[0])
    facts = {e["payload"]["kind"]: (e["payload"]["to"] or {}).get("value") for e in bev
             if e["type"] == "link.asserted" and e["payload"].get("status") == "supplied"
             and _name(e["payload"].get("from")) == service}
    links = [e for e in bev if e["type"] == "link.asserted" and e["payload"].get("status") == "discovered"
             and _name(e["payload"].get("to")) == service]
    if links or facts:
        fw = []
        if facts.get("mission-function"):
            fw.append(f"mission: {facts['mission-function']}")
        if facts.get("data-lifetime") is not None:
            fw.append(f"data secret for {facts['data-lifetime']} years")
        if facts.get("high-value-asset"):
            fw.append("a high-value asset")
        if facts.get("fips199-impact"):
            fw.append(f"FIPS 199 {facts['fips199-impact']} impact")
        if facts.get("owner"):
            fw.append(f"owner: {facts['owner']}")
        step("structure", "repository", "Connected", ["rule", "person"],
             f"Rules link the listener to the {service} service and the image it runs, from what the runner saw at the address; "
             f"the owner's facts attach to the service: {'; '.join(fw)}.",
             [f"{e['payload']['kind']}: {e['payload'].get('basis')}" for e in links[:2]]
             + [f"supplied by the owner: {k} = {v}" for k, v in facts.items()],
             link=f"/cbom?run={before.id}" if before else None, ev=(links or [None])[0])
    assess = [e for e in bev if e["type"] == "assessment.made" and _for_service(e, service, target)]
    prio = next((e["payload"]["classification"] for e in assess if e["payload"].get("rule_id") == "priority/m-26-15/1"), None)
    queues = [e["payload"]["classification"] for e in assess if e["payload"].get("rule_id") == "queue/m-26-15/1"]
    kq = next((q for q in queues if (q.get("queue") or "").startswith("kex")), None)
    blocked = next((e["payload"]["classification"] for e in assess if e["payload"].get("rule_id") == "blocker/supplier/1"), None)
    if kq:
        why = f"prioritized ({', '.join(prio['criteria'])}; the data must stay secret through {prio['sensitive_through']})" if prio and prio.get("prioritized") else "not prioritized"
        step("prioritize", "engine", "Ranked", ["rule"],
             f"The OMB M-26-15 rules mark the service {why} and open a key-establishment item in queue {kq['queue']}, due {kq['deadline']}: "
             f"{', '.join(kq['vulnerable'])} {'is' if len(kq['vulnerable']) == 1 else 'are'} quantum-vulnerable"
             + (f"; {', '.join(kq['post_quantum'])} is offered but not enforced" if kq.get("post_quantum") and not kq.get("enforced") else "") + "."
             + (" Its software can take post-quantum cryptography, so no supplier blocks it." if blocked and blocked.get("state") == "not-blocked" else ""),
             [f"queue {q['queue']}, due {q['deadline']} ({q.get('deadline_basis')}): {', '.join(q['vulnerable'])}" for q in queues if q.get("queue")],
             link="/plan", ev=next(e for e in assess if e["payload"].get("rule_id") == "queue/m-26-15/1"))
    tid = (drafted.get("context") or {}).get("trace")
    trace = next((e for r in _runs_of(var, "investigate") for e in _events(r) if e["id"] == tid), None) if tid else None
    if trace:
        tp = trace["payload"]
        answer = tp.get("answer") or {}
        note = next((s.get("note") for s in reversed(tp.get("steps", [])) if s.get("action") == "answer"), "")
        read = [s.get("path") for s in tp.get("steps", []) if s.get("action") == "read"]
        agrees = (tp.get("key_check") or {}).get("agrees")
        step("trace", "tools", "Traced to its cause", ["model"],
             f"A model, given the {tp['finding']['asset']['name']} finding and the service's {len(tp.get('files', []))} configuration files, "
             f"reads {', '.join(read) or 'them'} and answers: {note}",
             [f"answer: cause {answer.get('cause')}" + (f", {answer['file']} lines {answer['line_start']}–{answer['line_end']}" if answer.get("file") else ""),
              f"{tp['used']['steps']} of {tp['budget']['steps']} steps of its budget used" if tp.get("used") else None,
              ("the answer key agrees" if agrees else "the answer key disagrees") if agrees is not None else None,
              f"recorded as: {tp.get('claim')}" if tp.get("claim") else None],
             model=MODELS["trace"], ev=trace)
    if pol:
        step("policy", "governance", "Policy set", ["person"],
             f"The central crypto policy sets {service}'s intent to {intent}: {INTENT[intent]}.",
             [f"policy file sha256 {pol['payload']['sha256'][:16]}…", f"recorded by: {pol['payload'].get('by')}"], ev=pol)
    plus = [ln[1:] for ln in prop["payload"].get("diff", "").splitlines() if ln.startswith("+") and not ln.startswith("+++")]
    if drafted:
        ctx = drafted.get("context") or {}
        calls = drafted.get("calls") or []
        same = len({json.dumps(c.get("reply"), sort_keys=True) for c in calls}) == 1
        step("draft", "migration", "Change drafted", ["model"],
             f"A model drafts the edit from what the CBOM holds: {len(ctx.get('findings', []))} findings on the listener"
             + (", the trace" if ctx.get("trace") else "") + f" and {len(ctx.get('files', []))} files, each by hash. "
             + (f"Asked {len(calls)} times, it gave the same edit each time." if same and len(calls) > 1 else f"Asked {len(calls)} times."),
             [f"+ {ln}" for ln in plus] + [f"files shown: {', '.join(f['path'] for f in ctx.get('files', []))}",
                                          "the rollback is recorded with the proposal"],
             link=f"/resolve?change={run.id}", model=MODELS["draft"], ev=prop)
    else:
        step("draft", "migration", "Change rendered", ["rule"],
             f"The rule {prop['payload'].get('rule_id')} renders the policy into {service}'s configuration.",
             [f"+ {ln}" for ln in plus] + ["the rollback is recorded with the proposal"], link=f"/resolve?change={run.id}", ev=prop)

    def probes(v):
        out = []
        for p in v.get("probes", []):
            what = {"positive": "a client offering only the post-quantum group", "negative": "a client offering only classical groups",
                    "legacy": "a TLS 1.2 client", "witness": "testssl.sh, as a witness"}.get(p["name"], p["name"])
            out.append(f"{what}: {p['result']}" + (f" ({p['negotiated']})" if p.get("negotiated") else ""))
        return out
    reh = one("rehearsal.completed")
    if reh:
        v = reh["payload"]["verdict"]
        step("rehearse", "tools", "Rehearsed on a copy", ["verifier"],
             f"A copy of {service} with the edit is started beside the estate, and the verifier probes it: {v['status']}"
             + (", as the policy intends." if v.get("meets_intent") else ", which is not what the policy intends."),
             [*probes(v), f"copy at {reh['payload']['twin']}, same image digest {reh['payload']['image_digest'][7:19]}…"], ev=reh)
    mx = one("matrix.completed")
    if mx:
        rows = mx["payload"]["rows"]
        out = [r["label"] for r in rows if r["effect"] == "shut out"]
        step("matrix", "tools", "Who it would shut out", ["verifier"],
             f"Each kind of client is tried against the copy, before and after: {len(rows) - len(out)} still served"
             + (f"; shut out: {'; '.join(out)}." if out else "; none shut out."),
             [f"{r['label']} (offers {r['offers']}): {r['today']['result']} → {r['proposed']['result']}" for r in rows], ev=mx)
    ap = one("approval.granted")
    if ap:
        step("approve", "governance", "Approved", ["person"],
             f"A person reviews the diff, the rehearsal and the matrix, and approves: {ap['payload'].get('by')}.",
             [f"approval event {ap['id']}"], link=f"/resolve?change={run.id}", ev=ap)
    apl = one("change.applied")
    if apl:
        c = apl["payload"].get("config") or {}
        step("apply", "migration", "Applied", ["runner"],
             f"The runner writes the approved file and replaces {service}'s container; the service is listening again.",
             [f"{c.get('path')}: sha256 {c.get('sha256_before', '')[:12]}… → {c.get('sha256_after', '')[:12]}…" if c else None,
              f"applies only with approval event {apl['payload'].get('approval_event')}"], ev=apl)
    if verdicts:
        last = verdicts[-1]["payload"]
        step("prove", "tools", "Proved on the wire", ["verifier"],
             f"The verifier probes the live listener: {verdicts[0]['payload']['status']}. Then the service is recreated from scratch "
             f"and the probes repeated: {last['status']}{', durable' if last.get('durable') is True else ''}.",
             [*probes(verdicts[0]["payload"]), f"bound to container {(last.get('binding') or {}).get('container_id', '')[:12]}, " f"certificate {(last.get('binding') or {}).get('cert_fingerprint', '')[:12]}…"],
             link=f"/resolve?change={run.id}", ev=verdicts[-1])
    if after and now:
        was = {_asset_words(e["payload"]["asset"]) for e in found}
        is_ = {_asset_words(e["payload"]["asset"]) for e in now}
        gone, kept = sorted(was - is_), [_asset_words(e["payload"]["asset"]) for e in now]
        aq = [e["payload"]["classification"] for e in aev if e["type"] == "assessment.made"
              and e["payload"].get("rule_id") == "queue/m-26-15/1" and _for_service(e, service, target)]
        met = any(q.get("state") == "met" and q.get("enforced") for q in aq)
        step("update", "repository", "The CBOM shows it", ["scanner", "rule"],
             f"The next scan's CBOM for the listener holds {', '.join(kept)}"
             + (f"; gone: {', '.join(gone)}" if gone else "") + "."
             + (" The key-establishment item is met." if met else ""),
             [f"no longer accepted: {g}" for g in gone] + [f"scan {after.id}"], link=f"/cbom?run={after.id}", ev=now[0])
        nxt = [q for q in aq if q.get("state") == "open"]
        if nxt:
            step("next", "engine", "What is next", ["rule"],
                 "Still open for " + service + ": " + "; ".join(f"queue {q['queue']} ({', '.join(q['vulnerable'])}), due {q['deadline']}" for q in nxt)
                 + ". The plan says where that comes in the order.",
                 [], link="/plan", ev=aev[-1] if aev else None)
    who = Counter(w for s in steps for w in s["who"])
    return {"run": run.id, "change_id": cid, "service": service, "intent": intent, "intent_words": INTENT[intent],
            "listener": listener, "steps": steps, "who": who, "before": before.id if before else None,
            "after": after.id if after else None, "drafted": bool(drafted),
            "signed": sum(1 for e in events if e["type"] == "checkpoint.signed")}


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
                          (f"the last change that landed: {story['service']}, {story['intent_words']}, proved on the wire and again after a restart" if story else "no change landed yet")],
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
        "governance": ("OMB M-26-15", "the federal memo as data, every quote checked; owner's facts for " + str(services) + " services"),
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
