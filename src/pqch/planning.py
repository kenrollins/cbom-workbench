"""From the CBOM to a migration plan: what depends on what, what comes first, in what order.

The CBOM says what the estate holds and how its parts connect; the policy pack says what is due when.
Together they answer the planning questions an inventory alone cannot:

- *what depends on what* — a certificate authority whose root every leaf it issued must be reissued
  under; a library build several services share; one key served on two listeners; a trust anchor for
  clients the agency does not run;
- *what comes first* — the memo's prioritization, the data's lifetime, what is quantum-vulnerable today;
- *in what order* — TLS 1.3 before a hybrid group, a hybrid group offered before it is required, the
  software replaced before the CA that its certificate chains to is re-rooted, the CA before its
  leaves; and procurement started now for what no setting can move.

Every step names the CBOM entries it moves, its deadline, what it waits for and what it unblocks, and
its state read from the ledger (done when a change landed). Rules only: the plan is computed from the
latest scan's ledger at the moment it is shown, the way the queues are, and it names that run.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from pqch.run import Run

DUE_TLS13 = "2030-01-02"

# What each kind of step was computed from: the CBOM fields and records no list of systems carries.
FIELDS = {
    "replace": ["the runtime's own list of algorithms it supports", "the queue item and its deadline", "the supplier blocker"],
    "tls13": ["the protocol versions each listener negotiates, on the wire", "listener to service, from the runner's binding"],
    "enable": ["the groups each listener accepts, on the wire", "the library build behind the service"],
    "require": ["posture: hybrid accepted beside classical, on the wire", "the queue and its deadline", "the owner's data lifetime"],
    "ca": ["certificate issuer, linking each leaf to its CA", "the CA file's basicConstraints, read in each image",
           "which services hold the root", "the supplier blockers of those services"],
    "reissue": ["the certificate each listener serves", "its issuer", "one key across listeners, by its SPKI hash"],
    "retire": ["files in images that no listener serves: host evidence against wire evidence"],
}


def _sw_family(software: str) -> str:
    return software.split(" ")[0]


def build(var: Path, scan: Run, snapshots_dir: str | Path = "policy/snapshots", assume: frozenset = frozenset()) -> dict | None:
    from pqch.ui.view import packages_view, queues_view, run_view

    view = run_view(scan)
    if not view or view.get("broken"):
        return None
    events = list(scan.ledger.events())
    q = queues_view(var, events)
    if not q:
        return None
    snaps = sorted(Path(snapshots_dir).glob("capabilities-*.json"))
    snapshot = json.loads(snaps[-1].read_text()) if snaps else {"services": {}}
    finds = {e["id"]: e for e in events if e["type"] == "finding.observed"}
    ref = lambda fid: {"fingerprint": finds[fid]["payload"]["fingerprint"], "event": fid}  # noqa: E731

    # ---- the estate as the CBOM states it: services, their listeners, posture, certificates
    service_of: dict[str, str] = {}
    posture: dict[str, dict] = {}
    for ln in view["listeners"]:
        svc = (ln.get("service") or {}).get("name") or ln.get("service_named")
        if svc:
            service_of[ln["address"]] = svc
            posture[ln["address"]] = ln.get("posture") or {}
    leaf: dict[str, list[dict]] = defaultdict(list)       # service -> served certificates
    for fid, e in finds.items():
        p = e["payload"]
        s = p["subject"]
        if p["layer"] == "wire" and p["asset"]["type"] == "certificate" and s.get("kind") == "endpoint":
            addr = f"{s['host']}:{s['port']}"
            if addr in service_of:
                prm = p["asset"]["parameters"]
                leaf[service_of[addr]].append({"listener": addr, "subject": prm.get("subject"), "issuer": prm.get("issuer"),
                                               "spki": prm.get("spki_sha256"), "name": p["asset"]["name"], **ref(fid)})
    ca_files: dict[str, list[dict]] = defaultdict(list)    # CA subject -> where its certificate sits
    image_service = {img.split("@")[0]: (ch or {}).get("service") for img, ch in (view.get("image_chains") or {}).items()}
    for fid, e in finds.items():
        p = e["payload"]
        prm = p["asset"]["parameters"]
        # A certificate authority by its own basicConstraints, as the workbench's reader parsed it.
        if p["layer"] == "host" and p["asset"]["type"] == "certificate" and prm.get("is_ca") is True:
            ca_files[prm["subject"]].append({"service": image_service.get(p["subject"]["image"]) or p["subject"]["image"].split("/")[-1],
                                             "path": p["subject"]["path"], "referenced_by": prm.get("referenced_by") or [], **ref(fid)})

    # ---- what depends on what
    deps = []
    for ca, where in ca_files.items():
        leaves = [(svc, c) for svc, cs in leaf.items() for c in cs if c["issuer"] == ca and c["subject"] != ca]
        if leaves:
            deps.append({"kind": "certificate-authority", "id": f"ca:{ca}", "name": ca,
                         "what": f"issues the certificates of {', '.join(sorted({s for s, _ in leaves}))}; its root sits in "
                                 f"{', '.join(sorted({w['service'] for w in where}))} as a trust anchor",
                         "services": sorted({s for s, _ in leaves} | {w["service"] for w in where}),
                         "entries": [c for _, c in leaves] + where,
                         "consequence": "a post-quantum signature for any of them means a new ML-DSA root, distributed to every "
                                        "service that holds the old one, and every leaf reissued under it"})
        else:
            deps.append({"kind": "client-trust-anchor", "id": f"ca:{ca}", "name": ca,
                         "what": f"held by {', '.join(sorted({w['service'] for w in where}))} to verify certificates that "
                                 "clients present; it issues none of the estate's own certificates",
                         "services": sorted({w["service"] for w in where}), "entries": where,
                         "consequence": "the keys behind it belong to the clients — partners, other agencies — so their "
                                        "migration is theirs to make and this service's to wait for"})
    # Services on one library build: the snapshot's same-build lists, joined into groups.
    group_of: dict[str, set] = {}
    for svc, s in snapshot.get("services", {}).items():
        g = set(s.get("same_build") or []) | {svc}
        for m in list(g):
            g |= group_of.get(m, set())
        for m in g:
            group_of[m] = g
    for members in {tuple(sorted(g)) for g in group_of.values()}:
        if len(members) < 2:
            continue
        pq = [m for m in members for a, svc in service_of.items() if svc == m and (posture.get(a) or {}).get("kex_pq")]
        sw = snapshot["services"][members[0]]["software"]
        deps.append({"kind": "library-build", "id": "build:" + ",".join(members), "name": sw,
                     "what": f"{', '.join(members)} run the same library build ({', '.join(snapshot['services'][members[0]]['library'])})",
                     "services": list(members), "entries": [], "negotiates": sorted(set(pq)),
                     "consequence": (f"{' and '.join(sorted(set(pq)))} already {'negotiates' if len(set(pq)) == 1 else 'negotiate'} a hybrid group on it, so for the rest "
                                     "enabling one is configuration only, and an upgrade of the build moves all of them at once")
                     if pq else "an upgrade of the build moves all of them at once"})
    by_spki: dict[str, list[dict]] = defaultdict(list)
    for svc, cs in leaf.items():
        for c in cs:
            if c["spki"]:
                by_spki[c["spki"]].append({**c, "service": svc})
    for spki, cs in by_spki.items():
        if len({c["listener"] for c in cs}) > 1:
            deps.append({"kind": "shared-key", "id": f"key:{spki}", "name": f"one {cs[0]['name']} key",
                         "what": f"served on {', '.join(sorted({c['listener'] for c in cs}))}",
                         "services": sorted({c["service"] for c in cs}), "entries": cs,
                         "consequence": "rotating or reissuing it changes every listener at once; plan them as one step"})

    # ---- what comes first
    prio = {}
    for e in events:
        p = e["payload"]
        if e["type"] == "assessment.made" and p.get("rule_id") == "priority/m-26-15/1":
            prio[p["subject"]["name"]] = p["classification"]
    facts = {}
    for e in events:
        p = e["payload"]
        if e["type"] == "link.asserted" and p.get("status") == "supplied":
            facts.setdefault(p["from"]["name"], {})[p["kind"]] = p["to"]["value"]
    rows = q["rows"]
    blocked = {(r["service"], r["function"]) for r in rows if (r["blockers"].get("blocker/supplier/1") or {}).get("state") == "blocked"}
    ranking = []
    for svc, c in prio.items():
        f = facts.get(svc, {})
        ranking.append({"service": svc, "prioritized": c["prioritized"], "criteria": c.get("criteria") or [],
                        "sensitive_through": c.get("sensitive_through"), "lifetime": f.get("data-lifetime"),
                        "hva": f.get("high-value-asset") is True, "impact": f.get("fips199-impact"),
                        "mission": f.get("mission-function"), "owner": f.get("owner"),
                        "open": [r["function"] for r in rows if r["service"] == svc],
                        "blocked": sorted(fn for s, fn in blocked if s == svc),
                        "kex_now": sorted({p2 for a, s in service_of.items() if s == svc for p2 in [(posture.get(a) or {}).get("posture")] if p2})})
    ranking.sort(key=lambda r: (not r["prioritized"], -len(r["criteria"]), -(r["sensitive_through"] or 0), not r["hva"], r["service"]))
    rank = {r["service"]: i for i, r in enumerate(ranking)}

    # ---- in what order
    steps: dict[str, dict] = {}

    def step(sid, **kw):
        steps.setdefault(sid, {"id": sid, "depends_on": [], "entries": [], "state": "ready", **kw})
        return steps[sid]

    # Required since the scan: a change with intent `require` that landed — verified, and verified
    # again after a recreate — after this scan was taken. A rollback or an `enable` is not.
    from pqch.migrator import intervals
    from pqch.ui.view import change_runs
    landed = {}
    for cr in change_runs(var):
        ce = list(cr.ledger.events())
        for iv in intervals(ce):
            if iv.get("landed") and iv.get("intent") in ("enable", "require") and (iv.get("verdict_ts") or "") > events[-1]["ts"]:
                landed[(iv["target"]["service"], iv["intent"])] = {"run": cr.id, "change_id": iv["change_id"], "ts": iv["verdict_ts"]}
    # Where each step stands in the open change run, by the ledger alone: the latest change run's
    # proposals, each with the furthest event about it. Nothing here is new state (plan page, 2026-11-04).
    changes: dict[tuple, dict] = {}
    runs_ = change_runs(var)
    if runs_:
        ce = list(runs_[-1].ledger.events())
        for prop in (e for e in ce if e["type"] == "change.proposed"):
            cid = prop["payload"]["change_id"]
            rel = [e for e in ce if e["payload"].get("change_id") == cid]
            iv = next((i for i in intervals(ce) if i["change_id"] == cid), None)
            status = ("landed" if iv and iv.get("landed") else
                      "applied" if any(e["type"] == "change.applied" for e in rel) else
                      "approved" if any(e["type"] == "approval.granted" for e in rel) else
                      "rehearsed" if any(e["type"] == "rehearsal.completed" for e in rel) else "proposed")
            changes[((prop["payload"].get("target") or {}).get("service"), prop["payload"].get("intent"))] = {
                "run": runs_[-1].id, "change_id": cid, "status": status}
    met = {(r["service"], r["function"]) for r in q.get("met", [])}
    pk = packages_view(Run.latest(var, "package"))
    pk = pk if pk and not pk.get("broken") else None
    for svc in sorted({s for s, _ in blocked}, key=lambda s: rank.get(s, 99)):
        fns = sorted(fn for s, fn in blocked if s == svc)
        cap = snapshot["services"].get(svc, {})
        ups = [o for o, s in snapshot["services"].items() if o != svc and _sw_family(s["software"]) == _sw_family(cap.get("software", "?"))
               and (s.get("pq") or {}).get("kex" if "key-establishment" in fns else "sig")]
        due_row = min((r for r in rows if r["service"] == svc and r["function"] in fns), key=lambda r: r["deadline"])
        due = due_row["deadline"]
        step(f"replace:{svc}", kind="replace", service=svc, due=due, wave="now", **_set_by(due_row),
             title=f"Start replacing {cap.get('software', svc)} on {svc}" if not ups else f"Upgrade {svc} to the {cap['software'].split(' ')[0]} the estate already runs on {', '.join(ups)}",
             why=f"its software lists no post-quantum algorithm for {' or '.join(fns)}; nothing configurable can move it, "
                 f"and replacement takes procurement time, so it starts now for a {due} deadline",
             resolve=("/packages#" + svc + "-" + fns[0]) if pk else "/walkthrough#queues", resolve_label="change package")
    for r in rows:
        svc, fn = r["service"], r["function"]
        addrs = [a for a, s in service_of.items() if s == svc]
        if fn == "key-establishment":
            pre = [f"replace:{svc}"] if (svc, fn) in blocked else []
            tls13 = [t for t in q.get("tls13", []) if t["service"] == svc and t["state"] == "open"]
            if tls13:
                st = step(f"tls13:{svc}", kind="tls13", service=svc, due=DUE_TLS13, wave="2030",
                          title=f"TLS 1.3 on {svc}", depends_on=list(pre),
                          why="M-26-15 requires TLS 1.3 everywhere by 2030; a hybrid group exists only in TLS 1.3")
                pre = [st["id"]]
            accepts = any((posture.get(a) or {}).get("kex_pq") for a in addrs)
            fps = [ref(fid) for fid, e in finds.items() if e["payload"]["layer"] == "wire"
                   and f"{e['payload']['subject'].get('host')}:{e['payload']['subject'].get('port')}" in addrs
                   and e["payload"]["asset"]["role"] == "key-establishment"]
            build_note = next((d["consequence"] for d in deps if d["kind"] == "library-build" and svc in d["services"]), None)
            if not accepts:
                st = step(f"enable:{svc}", kind="enable", service=svc, due=r["deadline"], wave="2030", **_set_by(r), depends_on=list(pre),
                          title=f"Offer the hybrid group on {svc}", entries=fps,
                          why="clients that can use X25519MLKEM768 get it; nobody is refused" + (f"; {build_note}" if build_note else ""),
                          resolve="/resolve", resolve_label="propose the change")
                pre = [st["id"]]
            st = step(f"require:{svc}", kind="require", service=svc, due=r["deadline"], wave="2030", **_set_by(r), depends_on=list(pre),
                      title=f"Require the hybrid group on {svc}", entries=fps,
                      why=("it already offers the hybrid group but still accepts classical key exchange: enabled, not enforced. "
                           if accepts else "") + "M-26-15 counts a classical key exchange still accepted as open; requiring refuses "
                           "every client that cannot offer the hybrid group, so the clients are measured first",
                      resolve="/resolve", resolve_label="change, with its compatibility matrix")
            if (svc, "require") in landed or (svc, fn) in met:
                st["state"] = "done"
                st["done"] = landed.get((svc, "require"))
                for d in st["depends_on"]:
                    steps[d]["state"] = "done"
            elif (svc, "enable") in landed and f"enable:{svc}" in steps:
                steps[f"enable:{svc}"]["state"] = "done"
                steps[f"enable:{svc}"]["done"] = landed[(svc, "enable")]
        else:
            pre = [f"replace:{svc}"] if (svc, fn) in blocked else []
            mine = leaf.get(svc, [])
            ca = next((c["issuer"] for c in mine if c["issuer"] and c["issuer"] != c["subject"]), None)
            if ca:
                cid = f"ca:{ca}"
                cst = step(cid, kind="ca", service=None, due=r["deadline"], wave="2031", **_set_by(r),
                           title=f"Stand up an ML-DSA root for {ca.split(',')[0].replace('CN=', '')} and distribute it",
                           why="every service holding the old root must be able to verify ML-DSA before any leaf moves; "
                               "a service whose software cannot is a blocker of the root, not only of itself")
                if r["deadline"] < cst["due"]:
                    cst.update(due=r["deadline"], **_set_by(r))
                cst["depends_on"] = sorted(set(cst["depends_on"]) | set(pre))
                pre = [cid]
            shared = next((d for d in deps if d["kind"] == "shared-key" and svc in d["services"]), None)
            step(f"reissue:{svc}", kind="reissue", service=svc, due=r["deadline"], wave="2031", **_set_by(r), depends_on=pre,
                 title=f"Reissue {svc}'s certificate with ML-DSA" if mine else f"Move {svc}'s host keys to a post-quantum signature",
                 entries=[{"fingerprint": c["fingerprint"], "event": c["event"]} for c in mine],
                 why=("issued by the internal CA: waits for the new root" if ca else "self-signed: the service's own software decides")
                     + ("; no software in the estate lists a post-quantum signature for it yet" if (svc, fn) in blocked and not any(
                         (o.get("pq") or {}).get("sig") and _sw_family(o["software"]) == _sw_family(snapshot["services"].get(svc, {}).get("software", "?"))
                         for o in snapshot["services"].values()) else "")
                     + (f"; {shared['what']} — one key, both listeners" if shared else ""),
                 resolve="/packages#" + svc + "-signature" if (svc, fn) in blocked and pk else None)
    for d in deps:
        if d["kind"] == "client-trust-anchor":
            for svc in d["services"]:
                s = steps.get(f"reissue:{svc}")
                if s:
                    s["external"] = f"its clients' certificates chain to {d['name'].split(',')[0].replace('CN=', '')}: their move, not the agency's"
    unserved = [ref(e["payload"]["finding"]) for e in events if e["type"] == "assessment.made"
                and e["payload"].get("rule_id") == "in-use/not-served/1" and e["payload"].get("finding") in finds
                and finds[e["payload"]["finding"]]["payload"]["asset"]["type"] in ("certificate", "related-crypto-material")]
    if unserved:
        step("retire", kind="retire", service=None, due=None, wave="now", entries=unserved,
             title=f"Retire {len(unserved)} certificates and keys nothing serves",
             why="files in images that no listener serves: they inflate the inventory and outlive the services they belonged to")

    # Each configurable step carries its change's status and opens the resolution page at that change.
    # A step whose service's software lists no post-quantum key exchange is blocked, not open: the runner
    # cannot carry it out until the replacement lands, so it gets no button (demo box, 2026-11-04).
    for st in steps.values():
        if st["kind"] in ("enable", "require"):
            ch = changes.get((st["service"], st["kind"]))
            st["change"] = ch
            st["status"] = ("landed" if st["state"] == "done" else
                            "blocked" if (st["service"], "key-establishment") in blocked else
                            ch["status"] if ch else "open")
            if ch:
                st["resolve"] = f"/resolve?change={ch['run']}#change-{ch['change_id']}"
            elif st["status"] == "blocked":
                st["resolve"] = steps[f"replace:{st['service']}"]["resolve"]
                st["resolve_label"] = "change package"
        elif st["kind"] == "replace":
            st["status"] = "package"
    freed = _settle(steps, assume)
    for st in steps.values():
        st["fields"] = FIELDS.get(st["kind"], [])
    order = _topo(steps, rank)
    # The step each prioritized service is at: its first configurable step not yet done, or its last if
    # all are; a service nothing configurable can move points at its change package.
    # The Step cell follows the key-exchange lane, which is what the ranking orders: the service's
    # first enable/require step not yet done; its replacement step when that lane is blocked; its last
    # when all landed; none when the service already negotiates a hybrid group.
    for r in ranking:
        kex = [steps[i] for i in order if steps[i].get("service") == r["service"] and steps[i]["kind"] in ("enable", "require")]
        nxt = next((s for s in kex if s["state"] != "done"), None)
        if nxt and nxt["status"] == "blocked":
            r["step"] = steps[f"replace:{r['service']}"]
        else:
            r["step"] = nxt or (kex[-1] if kex else None)
    actions = [steps[i] for i in order if steps[i]["kind"] in ("replace", "enable", "require")]
    first_open = next((s["id"] for s in actions if s["state"] != "done" and s["status"] not in ("blocked", "package")), None)
    traps = _traps(deps, steps, rows, blocked)
    waves = []
    for w, label in (("now", "Now — what takes longest to start"), ("2030", "By 2030 — key establishment, prioritized systems first"),
                     ("2031", "By 2031 — signatures")):
        ws = [steps[i] for i in order if steps[i]["wave"] == w]
        if ws:
            waves.append({"id": w, "label": label, "steps": ws})
    return {"order": [dict(steps[i], n=k + 1) for k, i in enumerate(order)], "run": scan.id, "dependencies": deps, "ranking": ranking, "waves": waves, "steps": len(steps), "traps": traps, "actions": actions, "first_open": first_open,
            "scan_ts": events[-1]["ts"], "entries": len({e["fingerprint"] for st in steps.values() for e in st["entries"]}),
            "assumed": sorted(a for a in assume if a in steps), "freed": freed, "whatif": _whatif(steps, assume, freed),
            "done": sum(1 for s in steps.values() if s["state"] == "done" and not s.get("assumed")),
            "waiting": sum(1 for s in steps.values() if s["state"] == "waiting")}


def _settle(steps: dict, assume: frozenset) -> list[str]:
    """Set each step waiting while any step it depends on is not done. With `assume` — steps taken as
    done for a what-if — return the steps that were waiting without it and are free with it."""
    def waiting(done: set) -> set:
        return {s["id"] for s in steps.values() if s["id"] not in done and any(d in steps and d not in done for d in s["depends_on"])}
    done = {s["id"] for s in steps.values() if s["state"] == "done"}
    before = waiting(done)
    for a in assume:
        if a in steps and a not in done:
            steps[a]["state"], steps[a]["assumed"] = "done", True
            done.add(a)
    after = waiting(done)
    for s in steps.values():
        s["unblocks"] = sorted(t["id"] for t in steps.values() if s["id"] in t["depends_on"])
        if s["id"] in after:
            s["state"] = "waiting"
    return sorted(before - after - done)


def _whatif(steps: dict, assume: frozenset, freed: list[str]) -> list[dict]:
    """What an assumption changes, in detail: each step taken as done, each step it frees, and each step
    further on that is closer but still waits — with exactly what it still waits for."""
    if not assume:
        return []
    out = []
    for a in sorted(assume):
        if a in steps:
            out.append({"change": "assumed", **_brief(steps[a], steps)})
    for f in freed:
        out.append({"change": "freed", **_brief(steps[f], steps)})
    reach, frontier = set(), set(assume) | set(freed)
    while frontier:
        nxt = {t["id"] for t in steps.values() for f in frontier if f in t["depends_on"]} - reach - set(assume) - set(freed)
        reach |= nxt
        frontier = nxt
    for r in sorted(reach, key=lambda x: (steps[x].get("due") or "9999", x)):
        if steps[r]["state"] == "waiting":
            out.append({"change": "closer", **_brief(steps[r], steps)})
    return out


def _brief(s: dict, steps: dict) -> dict:
    still = [steps[d]["title"] for d in s["depends_on"] if d in steps and steps[d]["state"] != "done"]
    return {"id": s["id"], "title": s["title"], "due": s.get("due"), "why": s["why"], "entries": len(s["entries"]),
            "service": s.get("service"), "still_waits_for": still, "unblocks": [steps[u]["title"] for u in s.get("unblocks", []) if u in steps]}


def _set_by(row: dict) -> dict:
    """Which source set a step's due date, and NIST IR 8547's deprecation date when the item has one
    (the queue item's `deadline_set_by`; absent on a ledger assessed before IR 8547 was a pack)."""
    out = {}
    if row.get("deadline_set_by"):
        out["due_set_by"] = row["deadline_set_by"]
    if row.get("deprecated_after"):
        out["deprecated_after"] = row["deprecated_after"]
    tr = row.get("transition") or {}
    if tr.get("unchecked"):
        out["key_size_unchecked"] = tr["unchecked"]
    if tr.get("below_condition"):
        out["already_disallowed"] = tr["below_condition"]
    return out


def _traps(deps: list[dict], steps: dict, rows: list[dict], blocked: set) -> list[dict]:
    """For each dependency the plan rests on, the step a plan made from a list of systems would take
    in the wrong order, and what the CBOM shows instead. Each is computed from this estate."""
    out = []
    for d in deps:
        if d["kind"] == "certificate-authority":
            ca = next((s for s in steps.values() if s["kind"] == "ca"), None)
            if ca and ca["depends_on"]:
                waits = ", ".join(x.split(":", 1)[1] for x in ca["depends_on"])
                out.append({"dependency": d["id"], "sheet": "re-issue each service's certificate with ML-DSA, one row at a time",
                            "cbom": f"{len(d['services'])} services chain to one internal CA; its new root must be verifiable "
                                    f"everywhere it is held, and {waits} cannot verify ML-DSA until their software is replaced — "
                                    "so the replacement comes first, then the root, then every leaf at once"})
        elif d["kind"] == "library-build" and d.get("negotiates"):
            others = [x for x in d["services"] if x not in d["negotiates"]]
            out.append({"dependency": d["id"], "sheet": f"budget an upgrade for each of {', '.join(d['services'])}",
                        "cbom": f"{', '.join(d['services'])} run one library build, on which {' and '.join(d['negotiates'])} already "
                                f"{'negotiates' if len(d['negotiates']) == 1 else 'negotiate'} the hybrid group: for "
                                f"{', '.join(others) or 'the rest'} it is a setting, not an upgrade"})
        elif d["kind"] == "shared-key":
            out.append({"dependency": d["id"], "sheet": "replace the certificate on the service's main listener",
                        "cbom": f"the same key is {d['what']}: reissue for one and the other still serves the old key"})
        elif d["kind"] == "client-trust-anchor":
            out.append({"dependency": d["id"], "sheet": f"move {', '.join(d['services'])} to post-quantum signatures on the agency's schedule",
                        "cbom": f"{', '.join(d['services'])} trusts client certificates from {d['name'].split(',')[0].replace('CN=', '')}, "
                                "whose keys its partners hold: their reissue sets the pace"})
    req = [s for s in steps.values() if s["kind"] == "require" and s["state"] != "done"]
    if req:
        out.append({"dependency": None, "sheet": "switch each service to post-quantum key exchange when its row comes up",
                    "cbom": f"{len(req)} services still accept classical key exchange; requiring the hybrid group refuses every client "
                            "that cannot offer it, so each is offered first, its clients measured, then required"})
    if blocked:
        by = defaultdict(list)
        for s_, fn in sorted(blocked):
            by[s_].append({"key-establishment": "key exchange", "signature": "signatures"}[fn])
        what = "; ".join(f"{s_} ({' and '.join(f)})" for s_, f in by.items())
        out.append({"dependency": None, "sheet": "schedule every service's change for its deadline year",
                    "cbom": f"no setting can move {what}: the software lists no post-quantum algorithm for it, so that work is "
                            "procurement, and it starts now"})
    # Strongest first: the orderings a row-by-row plan gets most wrong.
    kind = {d["id"]: d["kind"] for d in deps}
    weight = {"certificate-authority": 0, "procurement": 1, "library-build": 2, "require": 3, "shared-key": 4, "client-trust-anchor": 5}

    def strength(t):
        if t["dependency"]:
            return weight[kind[t["dependency"]]]
        return weight["procurement" if "procurement" in t["cbom"] else "require"]
    return sorted(out, key=strength)


def _topo(steps: dict, rank: dict) -> list[str]:
    """Dependencies first; among steps free at the same time, earlier deadline, then higher priority."""
    done, out = set(), []
    key = lambda s: (s["due"] or "9999", rank.get(s.get("service"), 50), s["id"])  # noqa: E731
    while len(out) < len(steps):
        ready = [s for s in steps.values() if s["id"] not in done and all(d in done or d not in steps for d in s["depends_on"])]
        if not ready:
            ready = [s for s in steps.values() if s["id"] not in done]
        nxt = min(ready, key=key)
        done.add(nxt["id"])
        out.append(nxt["id"])
    return out


def lab_build(capture: dict | None, house: dict | None, assume: frozenset = frozenset()) -> dict | None:
    """The lab estate's plan. No owner's facts are supplied, so nothing is ranked by mission; lanes are
    hosts ordered by how much they are used. What the CBOM gives instead is who holds whom back: a
    server that refuses a hybrid group its clients offer is the blocker; a listener that accepts one no
    client offers waits for its clients; requiring the hybrid group refuses a measured share of today's
    handshakes, from known VLANs."""
    if not capture or not house:
        return None
    servers = {f"{s['host']}:{s['port']}": s for s in capture.get("inside_servers", [])}
    ssh = {f"{s['host']}:{s['port']}": s for s in capture.get("ssh", [])}
    vlan_of_comp: dict[str, Counter] = defaultdict(Counter)
    for c in house["doc"]["components"]:
        props: dict[str, list] = {}
        for p in c.get("properties", []):
            props.setdefault(p["name"], []).append(p["value"])
        sj = json.loads(props.get("pqch:subject", ["{}"])[0])
        if sj.get("kind") != "endpoint":
            continue
        for pv in props.get("pqch:parameters", []):
            for v, n in (json.loads(pv).get("client_vlans") or {}).items():
                vlan_of_comp[f"{sj['host']}:{sj['port']}"][int(v)] += n
    vlans = {v["vlan"]: v for v in capture.get("vlans", [])}
    steps: dict[str, dict] = {}
    deps = []

    def step(sid, **kw):
        return steps.setdefault(sid, {"id": sid, "depends_on": [], "entries": [], "state": "ready", "fields": [], **kw})

    for v, info in sorted(vlans.items()):
        behind = info.get("legacy", 0) + info.get("classical13", 0)
        if not behind:
            continue
        hosts = sorted({a.rsplit(":", 1)[0] for a, vs in vlan_of_comp.items() if v in vs})
        deps.append({"kind": "client-vlan", "id": f"vlan:{v}", "name": f"VLAN {v} clients",
                     "what": f"{info['clients']} clients: " + ", ".join(x for x in (
                         f"{info.get('hybrid', 0)} offer a hybrid group" if info.get("hybrid") else "",
                         f"{info.get('classical13', 0)} offer TLS 1.3 without one" if info.get("classical13") else "",
                         f"{info.get('legacy', 0)} never offer TLS 1.3" if info.get("legacy") else "") if x),
                     "services": hosts, "entries": [],
                     "consequence": f"every listener their handshakes reach refuses {behind} of them once it requires the hybrid group"})
        step(f"clients:{v}", kind="clients", service=f"VLAN {v}", wave="next", due=None,
             title=f"Upgrade or replace the clients on VLAN {v} that cannot offer a hybrid group",
             why=deps[-1]["what"] + "; a client is the blocker wherever it is the one that cannot follow",
             fields=["what each client offered, in every handshake (capture)", "the client's VLAN, from the frame's tag"],
             touch=[f"vlan:{v}"])
    quiet: list[str] = []
    for r in house["listeners"]:
        a = r["address"]
        host = a.rsplit(":", 1)[0]
        cap = servers.get(a) or ssh.get(a)
        hs = (cap or {}).get("handshakes") or (cap or {}).get("sessions") or 0
        offered = (servers.get(a) or {}).get("hybrid_offered")
        vs = sorted(vlan_of_comp.get(a, {}))
        client_deps = [f"clients:{v}" for v in vs if f"clients:{v}" in steps]
        touch = [f"vlan:{v}" for v in vs]
        if "capture" not in r["layers"]:
            if not r["hybrid_accepted"]:
                quiet.append(a)
            continue
        if "scan" not in r["layers"]:
            step(f"scope:{a}", kind="scope", service=host, wave="now", due=None, title=f"Add {a} to the scope for a targeted check",
                 why=f"seen in {hs:,} captured handshakes but never asked what it accepts", fields=["every server that spoke, from the capture"], touch=touch)
            continue
        pre = []
        if not r["hybrid_accepted"]:
            st = step(f"enable:{a}", kind="enable", service=host, wave="now", due=None, title=f"Offer a hybrid group on {a}",
                      why=(f"clients offered one in {offered:,} of its {hs:,} handshakes and it refused every one: the server is the blocker"
                           if offered else "it accepts no hybrid group"),
                      fields=["what the listener accepts when asked (targeted scan)", "what its clients offered (capture)"], touch=touch)
            pre = [st["id"]]
        refused = (hs - offered) if offered is not None else None
        why = ("" if offered is None else
               f"requiring it today would refuse {refused:,} of {hs:,} handshakes ({round(100 * refused / hs) if hs else 0}%), from clients on VLAN "
               + ", ".join(str(v) for v in vs) + "; ")
        if r["hybrid_accepted"] and not r["hybrid_chosen"] and offered == 0:
            why += "it accepts a hybrid group no client has offered: enabled, never used"
        if r["protocol"] == "ssh":
            why += ("the capture records the key exchange each SSH session agreed, not what the client offered: "
                    "the clients are measured first, with a probe per kind of client")
        step(f"require:{a}", kind="require", service=host, wave="then", due=None, title=f"Require the hybrid group on {a}",
             depends_on=pre + client_deps, why=why.rstrip("; ") or "the clients are measured first",
             fields=["posture on the wire, chosen against accepted (capture and scan merged)", "the share of handshakes whose client offered a hybrid group",
                     "the clients' VLANs"], touch=touch)
        for c in r["certs"]:
            if c.get("bits") and c["bits"] < 2048:
                step(f"cert:{a}", kind="cert", service=host, wave="now", due=None,
                     title=f"Replace the {c['name']}-{c['bits']} certificate on {a}",
                     why=f"{c['name']}-{c['bits']} is below today's classical floor, before any quantum question; valid until {c['not_after']}",
                     fields=["the certificate the listener presents (targeted scan)"])
    if quiet:
        step("enable:quiet", kind="enable", service="no traffic seen", wave="now", due=None,
             title=f"Offer a hybrid group on {len(quiet)} listeners no captured handshake reached",
             why="the targeted scan finds no hybrid group accepted on " + ", ".join(quiet) + "; with no traffic across the mirror there is "
                 "nothing to measure about their clients — embedded management interfaces, mostly, whose path is the vendor's firmware",
             fields=["what each listener accepts when asked (targeted scan)", "every server that spoke, from the capture: these did not"])
    for s in steps.values():
        s.setdefault("touch", [])
    freed = _settle(steps, assume)
    use = Counter()
    for a, srv in {**servers, **ssh}.items():
        use[a.rsplit(":", 1)[0]] += srv.get("handshakes") or srv.get("sessions") or 0
    vl = sorted({s["service"] for s in steps.values() if s["kind"] == "clients"}, key=lambda x: int(x.split()[1]))
    hosts = sorted({s["service"] for s in steps.values() if s["kind"] != "clients" and s["service"] != "no traffic seen"}, key=lambda h: (-use[h], h))
    lanes = [{"id": v, "label": f"{v} clients", "sub": f"{vlans[int(v.split()[1])]['clients']} clients"} for v in vl] + \
        [{"id": h, "label": h, "sub": f"{use[h]:,} handshakes seen"} for h in hosts] + \
        ([{"id": "no traffic seen", "label": "no traffic seen", "sub": f"{len(quiet)} listeners"}] if quiet else [])
    rank = {h: i for i, h in enumerate(hosts)}
    order = _topo(steps, rank)
    waves = [{"id": w, "label": label, "steps": [steps[i] for i in order if steps[i]["wave"] == w]}
             for w, label in (("now", "Now"), ("next", "Clients"), ("then", "Then require"))]
    waves = [w for w in waves if w["steps"]]
    traps = []
    blocker = max((s for s in steps.values() if s["kind"] == "enable" and "refused every one" in s["why"]), key=lambda s: len(s["why"]), default=None)
    if blocker:
        traps.append({"dependency": None, "sheet": "wait for the clients to support post-quantum key exchange",
                      "cbom": f"{blocker['title'].replace('Offer a hybrid group on ', '')}: {blocker['why']}"})
    unused = next((s for s in steps.values() if s["kind"] == "require" and "never used" in s["why"]), None)
    if unused:
        traps.append({"dependency": None, "sheet": "count a server that supports the hybrid group as done",
                      "cbom": f"{unused['title'].replace('Require the hybrid group on ', '')}: {unused['why']}"})
    worst = max((d for d in deps), key=lambda d: vlans[int(d["id"].split(':')[1])].get("legacy", 0), default=None)
    if worst:
        traps.append({"dependency": worst["id"], "sheet": "require the hybrid group on every server by the deadline",
                      "cbom": f"{worst['name']}: {worst['what']}; {worst['consequence']}"})
    return {"order": [dict(steps[i], n=k + 1) for k, i in enumerate(order)], "run": capture.get("run"), "estate": "lab", "dependencies": deps, "lanes": lanes, "ranking": [],
            "wave_labels": {"now": "now", "next": "clients", "then": "then require"}, "waves": waves, "steps": len(steps),
            "traps": traps, "entries": house["entries"], "done": 0,
            "assumed": sorted(a for a in assume if a in steps), "freed": freed, "whatif": _whatif(steps, assume, freed),
            "waiting": sum(1 for s in steps.values() if s["state"] == "waiting")}


# ---------------------------------------------------------------- one server
SYSTEM_LANES = [("services", "Services on the host", "what its applications listen with"),
                ("os", "Operating system", "its SSH server and its own files"),
                ("controller", "Management controller", "the BMC: its settings and its firmware"),
                ("firmware", "Firmware and boot chain", "the BIOS, Secure Boot, the TPM")]



def _latest_date(v) -> str:
    """A finding's date parameter as `YYYY-MM-DD`. The collector folds findings that share a key identity
    and merges their parameters, so a date may arrive as a list (two Secure Boot KEK certificates on
    one key, the demo box): the latest counts."""
    if isinstance(v, list):
        return max((_latest_date(x) for x in v), default="")
    return (v or "")[:10] if isinstance(v, str) else ""

def system_build(run: Run, assume: frozenset = frozenset(), pack_path: str | Path = "policy/packs/m-26-15.yaml",
                 cnsa_path: str | Path = "policy/packs/cnsa-2.0.yaml") -> dict | None:
    """A server's plan, from its system scan (`kind: scan-system`): what to fix on it, in what order,
    and what waits for its supplier. Rules only, over the run's findings and `platform.observed`
    facts. No owner's facts are supplied for a single server, so nothing is prioritized: its key
    establishment and signatures fall in the memo's remaining queue, by 2035, and the plan says what
    the dates would be if the owner named it a high-value or high-impact system."""
    import datetime as dt

    import yaml

    events = list(run.ledger.events())
    if not events or events[0]["payload"].get("kind") != "scan-system":
        return None
    scope = events[0]["payload"]["scope"]
    system = (scope.get("systems") or [{}])[0].get("name", "system")
    ctl = (scope.get("controllers") or [None])[0]
    addresses = set((scope.get("systems") or [{}])[0].get("addresses") or [])
    pack = yaml.safe_load(Path(pack_path).read_text())
    q = {x["id"]: x for x in pack["queues"]}
    cnsa = yaml.safe_load(Path(cnsa_path).read_text()) if Path(cnsa_path).is_file() else {}
    fw_sign = next((x for x in (cnsa.get("timeline") or cnsa.get("dates") or []) if "firmware" in str(x.get("category", ""))), None)
    remaining = str(q["remaining-2035"]["deadline"])
    ir_path = Path(pack_path).with_name("ir-8547.yaml")
    ir = (yaml.safe_load(ir_path.read_text()) or {}).get("transition", {}) if ir_path.is_file() else {}
    kex_pri, sig_pri, tls13 = str(q["kex-2030"]["deadline"]), str(q["sig-2031"]["deadline"]), str(q["tls13-2030"]["deadline"])
    when = events[0]["ts"][:10]
    today = dt.date.fromisoformat(when)

    finds = {e["id"]: e for e in events if e["type"] == "finding.observed"}
    facts = [e["payload"] for e in events if e["type"] == "platform.observed"]
    # When the server was read: the jobs' own times, which a replay keeps; the run's own time is the replay's.
    scans = [e["payload"] for e in events if e["type"] == "scan.completed"]
    reads = sorted(x["started_at"] for x in scans if x.get("started_at"))
    replayed = next((x["replayed_from"].get("recording") for x in scans
                     if (x.get("replayed_from") or {}).get("source_run")), None)
    fact = {f["source"]: f for f in facts}
    post = {(e["payload"]["subject"]["host"], e["payload"]["subject"]["port"]): e["payload"]["classification"]
            for e in events if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "posture/kex-auth/1"}

    def ref(fid):
        return {"fingerprint": finds[fid]["payload"]["fingerprint"], "event": fid}

    def where(f):
        s = f["subject"]
        return f"{s['host']}:{s['port']}" if s["kind"] == "endpoint" else s.get("path") or s.get("component")

    def pick(pred):
        return [fid for fid, e in finds.items() if pred(e["payload"])]

    steps: dict[str, dict] = {}
    deps: list[dict] = []

    def step(sid, **kw):
        kw.setdefault("depends_on", [])
        kw.setdefault("entries", [])
        kw.setdefault("touch", [])
        return steps.setdefault(sid, {"id": sid, "state": "ready", "fields": [], **kw})

    def lane_of(host, port=None):
        if ctl and host == ctl["host"]:
            return "controller"
        return "os" if host in addresses and port == 22 else "services"

    # --- Before any quantum question: what crosses in the clear.
    clear: dict[str, list[str]] = {}
    for fid in pick(lambda p: p["asset"]["name"] == "PostgreSQL" and p["asset"]["parameters"].get("tls_offered") is False):
        clear.setdefault(finds[fid]["payload"]["subject"]["host"], []).append(fid)
    for host, fids in sorted(clear.items()):
        ports = sorted(finds[x]["payload"]["subject"]["port"] for x in fids)
        step(f"tls-on:{host}", kind="tls-on", service="services", wave="now", due=None,
             title=f"Turn on TLS at the database listener{'s' if len(ports) > 1 else ''} on {host} ({', '.join(f':{p}' for p in ports)})",
             why="each answers PostgreSQL's request for TLS with a refusal, so every connection, its password included, crosses "
                 "the network in the clear: a gap today, before any quantum question, and nothing to migrate until TLS is there",
             fields=["the listener's answer to an SSLRequest (probe)"], entries=[ref(x) for x in fids])
        on = f"tls-on:{host}"
        en = step(f"enable:{host}:db", kind="enable", service="services", wave="next", due=remaining, depends_on=[on],
                  title=f"Then offer an ML-KEM hybrid group on the database listener{'s' if len(ports) > 1 else ''} on {host}",
                  why="once TLS is on, it starts with whatever groups the TLS library offers; the hybrid has to be offered beside them",
                  fields=["the listener's answer to an SSLRequest (probe)"])
        step(f"require:{host}:db", kind="require", service="services", wave="then", due=remaining, depends_on=[en["id"]],
             title=f"Then require the hybrid on the database listener{'s' if len(ports) > 1 else ''} on {host}",
             why="required once its clients, the applications that connect to the pooler, are seen to offer it",
             fields=["posture on the wire, after TLS is on"])

    # --- Self-signed defaults on TLS listeners.
    for fid in pick(lambda p: p["layer"] == "wire" and p["asset"]["type"] == "certificate"
                    and p["asset"]["parameters"].get("subject") and p["asset"]["parameters"].get("subject") == p["asset"]["parameters"].get("issuer")):
        f = finds[fid]["payload"]
        a, prm = where(f), f["asset"]["parameters"]
        host, port = f["subject"]["host"], f["subject"]["port"]
        sid = f"cert:{a}"
        if sid in steps:
            steps[sid]["entries"].append(ref(fid))
            continue
        default = "CN=localhost" in prm["subject"]
        step(sid, kind="ca-issue", service=lane_of(host, port), wave="next", due=None,
             title=f"Replace the self-signed certificate on {a} with one the organization's CA issues",
             why=(f"it serves {'a product default' if default else 'a certificate it signed itself'} ({f['asset']['name']}"
                  f"{'-' + str(prm['key_bits']) if prm.get('key_bits') else ''}): no client can tell it from an impostor's, and a "
                  "certificate outside the CA cannot be moved to a post-quantum signature with the rest; issue it from the CA "
                  "now, and it re-roots with the CA later"),
             fields=["the certificate the listener presents: subject equals issuer"], entries=[ref(fid)])

    # --- Key establishment on the wire: the hybrid offered or not.
    for (host, port), c in sorted(post.items()):
        a = f"{host}:{port}"
        on_wire = pick(lambda p, h=host, pt=port: p["layer"] == "wire" and p["subject"].get("host") == h and p["subject"].get("port") == pt
                       and p["asset"]["role"] == "key-establishment")
        if not on_wire:
            continue
        pq = c.get("kex_pq") or []
        lane = lane_of(host, port)
        nist = [k for k in pq if "MLKEM" in k.upper()]
        if lane == "controller":
            continue   # the controller's offers move with its firmware: the supplier step below
        if nist:
            step(f"require:{a}", kind="require", service=lane, wave="then", due=remaining,
                 title=f"Require the ML-KEM hybrid on {a}", why=f"it already accepts {', '.join(nist)} beside classical groups",
                 fields=["posture on the wire"], entries=[ref(x) for x in on_wire])
            continue
        if pq:
            up = step(f"upgrade:{a}", kind="enable", service=lane, wave="next", due=remaining,
                      title=f"Upgrade the server on {a} to one that offers ML-KEM key exchange",
                      why=(f"it negotiates {', '.join(pq)}, a post-quantum hybrid that is not in FIPS 203 and not on the memo's list; "
                           "the federal hybrid is ML-KEM (for OpenSSH, mlkem768x25519-sha256, from release 9.9). Due by "
                           f"{remaining} as a remaining system; by {kex_pri} if the owner names this server high-value"),
                      fields=["what the listener accepts (targeted scan)", "the quantum-vulnerable table (M-26-15, Appendix A)"],
                      entries=[ref(x) for x in on_wire])
        else:
            up = step(f"enable:{a}", kind="enable", service=lane, wave="next", due=remaining,
                      title=f"Offer an ML-KEM hybrid group on {a}",
                      why=f"it accepts only classical key exchange ({', '.join((c.get('kex_classical') or [])[:5])}); a recording made today "
                          "can be decrypted once a quantum computer exists. Due by "
                          f"{remaining} as a remaining system; by {kex_pri} if named high-value",
                      fields=["what the listener accepts (targeted scan)"], entries=[ref(x) for x in on_wire])
        step(f"require:{a}", kind="require", service=lane, wave="then", due=remaining,
             title=f"Then require the hybrid on {a}", depends_on=[up["id"]],
             why="offered first, so clients that can follow are seen to; required once the clients that cannot are known",
             fields=["posture on the wire"])
        for fid in pick(lambda p, h=host, pt=port: p["subject"].get("host") == h and p["subject"].get("port") == pt
                        and p["asset"]["name"] in ("TLS 1.2",) and p["asset"]["type"] == "protocol"):
            steps[up["id"]]["entries"].append(ref(fid))

    # --- The controller: settings the owner can change, and what moves only with its firmware.
    ctl_fact = fact.get("controller") or {}
    settings = ctl_fact.get("settings") or {}
    if ctl:
        cname = f"{ctl['host']}"
        snmp = pick(lambda p: p["subject"].get("component") == "bmc:snmp" and p["asset"]["parameters"].get("community_strings_accepted"))
        if snmp:
            step("bmc:snmp", kind="setting", service="controller", wave="now", due=None,
                 title=f"Restrict the controller's SNMP to version 3 ({cname})",
                 why="it accepts SNMP v1 and v2c, which authenticate with a community string sent in the clear; v3 authenticates "
                     "and encrypts. A setting, today",
                 fields=["the controller's SNMP settings (Redfish)"], entries=[ref(x) for x in snmp])
        if settings.get("fips_mode") == "Disabled":
            step("bmc:fips", kind="setting", service="controller", wave="now", due=None,
                 title=f"Decide on the controller's FIPS mode ({cname})",
                 why=f"it is off; the module it would use is {settings.get('fips_module', 'not named')}. Where the estate must use "
                     "validated modules, this is a setting; the module's validation has its own clock (note 10)",
                 fields=["the controller's security settings (Redfish)"])
        ssh_cfg = pick(lambda p: p["subject"].get("component") == "bmc:ssh-config" and p["asset"]["role"] == "key-establishment")
        wire_ctl = pick(lambda p: p["layer"] == "wire" and p["subject"].get("host") == ctl["host"] and p["asset"]["role"] == "key-establishment")
        ident = pick(lambda p: p["subject"].get("component", "").startswith("bmc:certificate:"))
        fwv = ctl_fact.get("controller", {}).get("firmware_version")
        sup = step("supplier:controller", kind="supplier", service="controller", wave="supplier", due=remaining,
                   title=f"Controller firmware with ML-KEM key exchange, from the vendor (now {fwv or 'unknown'})",
                   why="its HTTPS and SSH accept only classical key exchange, on the wire and as configured; its SSH list is the "
                       "vendor's to extend, and its web server's groups are fixed in the firmware. Ask the vendor for the release "
                       f"and the date; it falls in the memo's remaining queue, by {remaining}",
                   fields=["what its listeners accept (targeted scan)", "its configured key exchange (Redfish)", "its firmware version (Redfish)"],
                   entries=[ref(x) for x in wire_ctl + ssh_cfg])
        step("require:controller", kind="require", service="controller", wave="then", due=remaining,
             title="Then require the hybrid on the controller's HTTPS and SSH", depends_on=[sup["id"]],
             why="once the firmware offers it; the controller's clients are a handful of administrators' tools",
             fields=["posture on the wire"])
        if ident:
            step("supplier:identity", kind="supplier", service="controller", wave="supplier", due=sig_pri,
                 title="Ask the vendor which algorithms sign the controller's identity certificates",
                 why=f"the controller holds {len(ident)} certificates from the vendor's own CAs (factory identity, TPM attestation, "
                     "component verification) and reports their issuers and dates but not their keys: the CBOM lists them as "
                     "algorithm unknown until the vendor attests to them",
                 fields=["the controller's certificate list (Redfish)"], entries=[ref(x) for x in ident])
        deps.append({"kind": "supplier", "id": "dep:controller", "name": "The controller's firmware",
                     "what": f"its TLS, its SSH and its identity certificates are set by the vendor's firmware ({fwv or 'version unknown'})",
                     "services": ["controller"], "entries": [ref(x) for x in wire_ctl + ident],
                     "consequence": "none of them moves with an operating-system update; each waits for a firmware release"})

    # --- Firmware and the boot chain.
    fwf = fact.get("firmware") or {}
    sb_on = (fwf.get("settings") or {}).get("secure_boot")
    sbc = {fid: finds[fid]["payload"] for fid in pick(lambda p: p["subject"].get("component", "").startswith("secure-boot:"))}

    def expired(p):
        na = p["asset"]["parameters"].get("not_after")
        return bool(na) and dt.date.fromisoformat(na[:10]) < today
    ms2011 = [fid for fid, p in sbc.items() if "Microsoft" in p["asset"]["parameters"].get("subject", "") and "2011" in p["asset"]["parameters"].get("subject", "")]
    ms2023 = [fid for fid, p in sbc.items() if "Microsoft" in p["asset"]["parameters"].get("subject", "") and "2023" in p["asset"]["parameters"].get("subject", "")]
    bios = next((x for x in fwf.get("firmware") or [] if x["name"] == "BIOS"), {})
    if ms2011 and not ms2023:
        upd = step("fw:ca2023", kind="firmware", service="firmware", wave="next", due=None,
                   title=f"Install the 2023 Microsoft UEFI CAs: a BIOS release that carries them, or a signed db and KEK update (BIOS now {bios.get('version', '?')})",
                   why=f"the boot chain trusts only Microsoft's 2011 CAs, which expired in 2026 ({sum(1 for x in ms2011 if expired(sbc[x]))} of "
                       f"{len(ms2011)} past their dates on {when}); bootloaders and option ROMs signed under the 2023 CAs will not verify",
                   fields=["the Secure Boot databases, read from the firmware's variables"], entries=[ref(x) for x in ms2011])
        if sb_on is False:
            step("fw:secureboot", kind="firmware", service="firmware", wave="then", due=None, depends_on=[upd["id"]],
                 title="Then turn Secure Boot on",
                 why="it is off, so nothing the firmware loads is checked against these databases at all; turning it on before the "
                     "2023 CAs are in risks a server that will not boot a newly signed loader",
                 fields=["the Secure Boot state, from the firmware's variables and the controller"])
    elif sb_on is False:
        step("fw:secureboot", kind="firmware", service="firmware", wave="now", due=None, title="Turn Secure Boot on",
             why="it is off, so nothing the firmware loads is checked", fields=["the Secure Boot state"])
    roots = [fid for fid, p in sbc.items() if p["subject"]["component"] in ("secure-boot:PK", "secure-boot:KEK", "secure-boot:db")
             and p["asset"]["name"] in ("RSA", "ECDSA") and not p["asset"]["parameters"].get("revoked")]
    if roots:
        longest = max((_latest_date(sbc[x]["asset"]["parameters"].get("not_after")) for x in roots), default="")
        fw_due = f"{fw_sign.get('exclusive_by')}" if fw_sign else None
        step("supplier:signing", kind="supplier", service="firmware", wave="supplier", due=fw_due or sig_pri,
             depends_on=["fw:ca2023"] if "fw:ca2023" in steps else [],
             title="A post-quantum firmware-signing root, and a way to rotate the platform key, KEK and db, from the vendor",
             why=f"every key the boot chain trusts is RSA or ECDSA ({len(roots)} certificates, valid to {longest}); a firmware "
                 "signature is checked for the life of the hardware, so the root has to change before the hardware retires"
                 + (f"; CNSA 2.0 sets {fw_sign['exclusive_by']} for software and firmware signing in national security systems"
                    f"{' (the pack marks that date unverified)' if fw_sign.get('verified') is False else ''}" if fw_sign else ""),
             fields=["the Secure Boot databases' certificates and keys", "the quantum-vulnerable table"], entries=[ref(x) for x in roots])
        deps.append({"kind": "firmware-trust", "id": "dep:bootchain", "name": f"The BIOS ({bios.get('version', '?')}) and its trust databases",
                     "what": f"the BIOS enforces {len(sbc)} certificates in the platform key, KEK, db and dbx when Secure Boot is on",
                     "services": ["firmware"], "entries": [ref(x) for x in sbc],
                     "consequence": "a new CA or a new signing algorithm arrives as a firmware or key-database update, signed by the key it replaces"})

    # --- The host's own files.
    ff = fact.get("files") or {}
    unread = [u for u in ff.get("unreadable") or [] if "(absent)" not in u]
    if unread:
        step("os:privileged-read", kind="inventory", service="os", wave="now", due=None,
             title=f"Read the {len(unread)} paths an unprivileged read could not open",
             why=f"the scan read the host's files as an ordinary user (uid {ff.get('read_as_uid')}); {', '.join(unread[:4])}"
                 f"{' and more' if len(unread) > 4 else ''} hold private keys the inventory cannot see. One privileged, read-only pass "
                 "fills the gap; until then the CBOM lists their public halves only",
             fields=["the reader's list of unreadable paths"])
    files = pick(lambda p: p["layer"] == "host" and p["asset"]["role"] in ("signature", "other")
                 and p["asset"]["name"] in ("RSA", "ECDSA", "Ed25519", "DSA"))
    if files:
        waits = [x for x in ("os:privileged-read",) if x in steps] + [k for k in steps if k.startswith("upgrade:") and steps[k]["service"] == "os"]
        step("os:keys", kind="replace", service="os", wave="then", due=remaining, depends_on=waits,
             title=f"Reissue the host's own certificates and keys under post-quantum signatures as their software allows ({len(files)} files)",
             why="SSH host keys, the cluster CA and service certificates on the host are RSA, ECDSA or Ed25519: each moves when the "
                 "software that uses it accepts ML-DSA, and a CA before the certificates it issued",
             fields=["files read on the host: certificates, public keys, the CA flag"], entries=[ref(x) for x in files])
    for s in steps.values():
        s.setdefault("touch", [])
        s["touch"] = [d["id"] for d in deps if s["service"] in d["services"]]
    freed = _settle(steps, assume)
    # A server's list runs by wave: today's settings, then updates, then requiring, then the supplier;
    # dependencies first within that, then the earlier deadline, then the lane.
    rank = {lane: i for i, (lane, _, _) in enumerate(SYSTEM_LANES)}
    wave_rank = {"now": 0, "next": 1, "supplier": 2, "then": 3}
    done_ids, order = set(), []
    while len(order) < len(steps):
        ready = [x for x in steps.values() if x["id"] not in done_ids and all(d in done_ids or d not in steps for d in x["depends_on"])] \
            or [x for x in steps.values() if x["id"] not in done_ids]
        nxt = min(ready, key=lambda x: (wave_rank.get(x["wave"], 9), x["due"] or "9999", rank.get(x["service"], 9), x["id"]))
        done_ids.add(nxt["id"])
        order.append(nxt["id"])
    lanes = [{"id": lid, "label": label, "sub": sub} for lid, label, sub in SYSTEM_LANES if any(s["service"] == lid for s in steps.values())]
    waves = [{"id": w, "label": label, "steps": [steps[i] for i in order if steps[i]["wave"] == w]}
             for w, label in (("now", "Now: settings"), ("next", "Next: updates"), ("supplier", "From the vendor"), ("then", "Then: require"))]
    waves = [w for w in waves if w["steps"]]
    traps = []
    hybrid_on_host = [(key, c["kex_pq"]) for key, c in post.items()
                      if c.get("kex_pq") and key[0] in addresses and not any("MLKEM" in k.upper() for k in c["kex_pq"])]
    if hybrid_on_host:
        (h, p), kex = hybrid_on_host[0]
        traps.append({"dependency": None, "sheet": "mark the server post-quantum ready: its SSH negotiates a hybrid",
                      "cbom": f"{h}:{p} negotiates {', '.join(kex)}, "
                              "which is not ML-KEM; the controller on the same box offers no hybrid, and "
                              + ("its database pooler offers no TLS at all" if any(k.startswith("tls-on:") for k in steps) else "its other listeners none")})
    if "fw:ca2023" in steps:
        traps.append({"dependency": "dep:bootchain", "sheet": "turn Secure Boot on",
                      "cbom": "the only Microsoft CAs in its databases expired in 2026 and their 2023 replacements are absent: update the databases first"})
    if ctl:
        traps.append({"dependency": "dep:controller", "sheet": "patch the operating system and rescan",
                      "cbom": "the controller's TLS, SSH and identity certificates and the boot chain's keys sit below the operating system; "
                              "an OS update changes none of them"})
    if unread:
        traps.append({"dependency": None, "sheet": "count a scan run as an ordinary user as complete",
                      "cbom": f"{len(unread)} paths, the private host keys among them, were unreadable to it: the inventory says so instead of omitting them"})
    return {"order": [dict(steps[i], n=k + 1) for k, i in enumerate(order)], "run": run.id, "estate": "system", "system": system,
            "dependencies": deps, "lanes": lanes, "ranking": [],
            "wave_labels": {"now": "now", "next": "next", "supplier": "vendor", "then": "then"}, "waves": waves,
            "steps": len(steps), "traps": traps, "entries": len(finds), "done": 0,
            "assumed": sorted(a for a in assume if a in steps), "freed": freed, "whatif": _whatif(steps, assume, freed),
            "waiting": sum(1 for s in steps.values() if s["state"] == "waiting"),
            "read_from": min(reads) if reads else events[0]["ts"], "read_to": max(reads) if reads else events[0]["ts"],
            "replayed": replayed, "replayed_at": events[0]["ts"] if replayed else None,
            "device": next((f.get("device") for f in facts if f.get("device", {}).get("model")), {}),
            "deadlines": {"remaining": remaining, "kex_prioritized": kex_pri, "sig_prioritized": sig_pri, "tls13": tls13,
                          "deprecated_after": str(ir["deprecated_after"]) if ir.get("deprecated_after") else None,
                          "disallowed_after": str(ir["disallowed_after"]) if ir.get("disallowed_after") else None}}
