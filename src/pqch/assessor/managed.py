"""The Managed rung: what is quantum-vulnerable, which systems come first, which queue each
item waits in and by when, and what blocks it. Rules only; every result an event naming its
inputs, the pack and the section of the memo it rests on.

- `quantum/vulnerable/1` — per algorithm name and role seen in the run: the family
  (`policy/algorithm-families.yaml`) and whether the pack's table, or its footnote 13, makes it
  quantum-vulnerable. Every finding of that name is an input.
- `pack/scope/1` — per service: which pack governs it, from the owner's
  `national-security-system` fact (M-26-15 does not govern a national security system; CNSA 2.0
  does). A pack with `verified: false` governs but sets no deadline; CNSA 2.0, read first-hand
  on 2026-11-09, names its own dates in the basis.
- `priority/m-26-15/1` — per service: which of §3.C.2's criteria hold, from the owner's supplied
  facts; the supplied links are the inputs.
- `queue/m-26-15/1` — per service and function (key establishment, signature): the vulnerable
  assets the service still offers or holds in use, the queue the memo puts them in and its
  deadline; `met` when there are none. A vulnerable algorithm still accepted beside a
  post-quantum one keeps the item open (Appendix A §5: only acceptable algorithms). With NIST
  IR 8547's pack beside it (`policy/packs/ir-8547.yaml`), the item also carries the report's
  deprecation and disallowance dates for the vulnerable names its tables cover; the deadline is
  the earlier of the memo's queue date and the disallowance, and `deadline_set_by` names the
  source of that date (both when they agree).
- `deadline/tls13/1` — per TLS listener: whether it offered TLS 1.3, against §4's date.
- `blocker/supplier/1` — per open item: whether the service's software can offer a post-quantum
  algorithm in that function at all, from the capability snapshot; when it cannot, the item is
  blocked on its supplier and marked for replacement (§3.C.3).
- `blocker/validated-module/1` — per open item: whether the service runs a validated module,
  and whether the CMVP snapshot holds one for its library whose approved algorithms include the
  post-quantum algorithm the function needs.
- `compatibility/entry/1` — per entry (one per finding fingerprint): its status under the pack
  that governs the service it belongs to — `compatible`, `not-compatible`, `unknown` or
  `outside-pack` — with the rule it rested on. `unknown` is a state, never folded into either
  verdict: the entry's algorithm is not identified, or the pack does not place the name. A status
  from a pack not read first-hand is `provisional` (none is, since the CNSA 2.0 FAQ was read
  first-hand on 2026-11-09; the flag stays for the next pack).
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from pqch.policy import classical_strength, family_of, load_families, load_pack, sensitive_through, vulnerability
from pqch.run import Run

FUNCTIONS = ("key-establishment", "signature")
NEEDS = {"key-establishment": ("approved_ml_kem", "ML-KEM"), "signature": ("approved_ml_dsa", "ML-DSA")}


def _actor(rule: str) -> dict:
    return {"kind": "rule", "id": rule}


def _library(software: str) -> str:
    s = software.lower()
    for key in ("openssh", "java", "erlang", "openssl"):
        if key in s:
            return key
    return "unknown"


SYMMETRIC_ROLES = ("encryption", "hash", "mac")
STATUSES = ("compatible", "not-compatible", "unknown", "outside-pack")


def algorithm_role(families: dict, finding: dict) -> str | None:
    """The function whose table names the entry's algorithm: a certificate's key signs; a key's algorithm
    is looked up in the signature table, then key establishment; RSA used for encryption is key
    transport. None when the entry names no algorithm a table has (an API key, an unopened key file)."""
    a = finding["asset"]
    if a["type"] == "protocol":
        return None
    if a["type"] == "certificate":
        return "signature"
    if a["type"] == "related-crypto-material" or a["role"] == "other":
        return next((r for r in ("signature", "key-establishment") if a["name"] in (families.get(r) or {})), None)
    if a["role"] == "encryption" and a["name"] in (families.get("key-establishment") or {}):
        return "key-establishment"
    return a["role"]


def _nss_basis(nss_pack: dict | None) -> str:
    """Why a national security system has no M-26-15 queue item: CNSA 2.0 governs it, with its own dates
    when the pack is read first-hand and none when it is not."""
    head = "the owner marks it a national security system; CNSA 2.0 governs it (M-26-15 §3.B excludes it)"
    if not nss_pack or not nss_pack.get("verified"):
        return head + ", and that pack is not verified, so no deadline is set"
    dates = (nss_pack.get("timeline") or {}).get("dates") or []
    return head + "; its dates are the suite's, not the memo's: " + ", ".join(
        f"{d['by']} {d['what']}" for d in dates if d["id"] in ("new-acquisitions", "phase-out", "mandate"))


def entry_compatibility(pack: dict, families: dict, finding: dict) -> dict:
    """One entry's status under one pack, from the pack's `compatible` block: by the families the pack
    calls resistant or vulnerable (M-26-15), or by the names it lists per function (CNSA 2.0)."""
    a = finding["asset"]
    name = a["name"]
    comp = pack.get("compatible") or {}
    if a["type"] == "protocol":
        return {"status": "outside-pack", "algorithm_role": None, "family": None,
                "basis": "a protocol version, not an algorithm; the TLS 1.3 obligation is its own rule (deadline/tls13/1)"}
    role = algorithm_role(families, finding)
    if role is None:
        return {"status": "unknown", "algorithm_role": None, "family": None,
                "basis": f"the entry names no algorithm a table places ({name}); nothing can be judged from it"}
    fam = family_of(families, role, name)
    if comp.get("basis") == "named-algorithms":
        names = comp.get("names") or {}
        if name in (comp.get("unsettled") or []):
            return {"status": "unknown", "algorithm_role": role, "family": fam,
                    "basis": f"the pack does not place {name}: a hybrid whose ML-KEM part is the suite's; no verdict either way"}
        sp = (comp.get("specific") or {}).get(role) or {}
        if name in (sp.get("names") or []):
            # Allowed in one application only: the platform layer is a system's firmware and controller.
            if finding.get("layer") == "platform":
                return {"status": "compatible", "algorithm_role": role, "family": fam,
                        "basis": f"{name} is allowed for {sp['application']}, and the entry is in a system's firmware"}
            return {"status": sp.get("elsewhere", "unknown"), "algorithm_role": role, "family": fam,
                    "basis": f"{name} is allowed only for {sp['application']}; this entry is on the {finding.get('layer')} layer"
                             + (", and the evidence does not say what it signs" if sp.get("elsewhere", "unknown") == "unknown" else "")}
        if role in names:
            ok = name in names[role]
            return {"status": "compatible" if ok else "not-compatible", "algorithm_role": role, "family": fam,
                    "basis": (f"{name} is one the pack names for {role}" if ok else
                              f"the pack names {', '.join(names[role])} for {role}; {name} is not among them")}
        return {"status": "outside-pack", "algorithm_role": role, "family": fam,
                "basis": f"the pack names no algorithm for {role}"}
    if role in SYMMETRIC_ROLES:
        return {"status": "outside-pack", "algorithm_role": role, "family": fam,
                "basis": "the memo's table names asymmetric algorithms only; it says nothing of a symmetric algorithm or hash"}
    v, why = vulnerability(pack, fam, role)
    if v is False:
        return {"status": "compatible", "algorithm_role": role, "family": fam, "basis": f"quantum-resistant: {why}"}
    if v is True:
        return {"status": "not-compatible", "algorithm_role": role, "family": fam, "basis": f"quantum-vulnerable: {why}"}
    return {"status": "unknown", "algorithm_role": role, "family": fam, "basis": why}


def _transition(tr: dict | None, families: dict, fn: str, names: list[str],
                params_by_name: dict[str, list[dict]] | None = None) -> dict | None:
    """IR 8547's dates for the vulnerable names of one function: which rows cover them, which names no
    row covers, and the row's key-size condition checked where the findings carry a key size: a name
    whose every known key is below the condition is `below_condition` (already disallowed under SP
    800-131A Rev. 2, not dated 2035), a name with no key size is `unchecked`. None when no transition
    pack is loaded or no name is covered."""
    import re
    if not tr:
        return None
    f = tr["functions"][fn]
    covered, rows, missing, below, unchecked = [], [], [], [], []
    for name in names:
        fam = family_of(families, fn, name)
        row = next((r for r in f["rows"] if name in r.get("names", []) or fam in r.get("families", [])), None)
        if row is None:
            missing.append(name)
            continue
        covered.append(name)
        if row["row"] not in [r["row"] for r in rows]:
            rows.append({"row": row["row"], "parameters": row["parameters"]})
        need = int(re.search(r"(\d+) bits", row["parameters"]).group(1))
        strengths = [s for s in (classical_strength(fn, name, fam, p) for p in (params_by_name or {}).get(name) or [{}])
                     if s is not None]
        if not strengths:
            unchecked.append(name)
        elif max(strengths) < need:
            below.append(name)
    if not covered:
        return None
    t = tr["transition"]
    return {"pack": tr["id"], "pdf_sha256": tr["source"].get("pdf_sha256"), "section": f["section"], "table": f["table"],
            "deprecated_after": str(t["deprecated_after"]), "disallowed_after": str(t["disallowed_after"]),
            "dates_basis": t["dates_basis"], "covers": covered, "not_covered": missing, "rows": rows,
            "parameters_checked": not unchecked, "unchecked": unchecked, "below_condition": below,
            "strength_basis": "SP 800-57 Part 1 Rev. 5 Table 2, from the finding's key size; computed"}


def assess(run: Run, *, pack_path: str | Path, families_path: str | Path, capabilities_path: str | Path | None,
           cmvp_path: str | Path | None, as_of: date | None = None,
           transition_path: str | Path | None = None) -> dict:
    """`transition_path` defaults to `ir-8547.yaml` beside the pack, when it is there."""
    pack = load_pack(pack_path)
    if transition_path is None:
        sibling = Path(pack_path).with_name("ir-8547.yaml")
        transition_path = sibling if sibling.is_file() else None
    tr = load_pack(transition_path) if transition_path else None
    # The pack for a national security system, beside the memo's, when it is there.
    nss_path = Path(pack_path).with_name("cnsa-2.0.yaml")
    packs = {pack["id"]: pack, **({"cnsa-2.0": load_pack(nss_path)} if nss_path.is_file() and pack["id"] != "cnsa-2.0" else {})}
    families = load_families(families_path)
    caps = json.loads(Path(capabilities_path).read_text()) if capabilities_path and Path(capabilities_path).is_file() else None
    cmvp = json.loads(Path(cmvp_path).read_text()) if cmvp_path and Path(cmvp_path).is_file() else None
    events = list(run.ledger.events())
    as_of = as_of or date.fromisoformat(events[0]["ts"][:10])
    src = {"pack": pack["id"], "pdf_sha256": pack["source"].get("pdf_sha256")}
    findings = {e["id"]: e["payload"] for e in events if e["type"] == "finding.observed"}
    in_use = {e["payload"]["finding"]: e["payload"]["classification"]["in_use"] for e in events
              if e["type"] == "assessment.made" and "in_use" in e["payload"].get("classification", {})}
    svc_of_listener, svc_of_image, facts = {}, {}, {}
    for e in events:
        if e["type"] != "link.asserted" or isinstance(e["payload"]["from"], str):
            continue
        p = e["payload"]
        if p.get("status") == "supplied":
            facts.setdefault(p["from"]["name"], {})[p["kind"]] = (p["to"]["value"], e["id"])
        elif p["from"]["kind"] == "endpoint":
            svc_of_listener[(p["from"]["host"], p["from"]["port"])] = (p["to"]["name"], e["id"])
        elif p["from"]["kind"] == "image":
            svc_of_image[p["from"]["image"].split("@")[0]] = (p["to"]["name"], e["id"])
    counts = {"names": 0, "vulnerable_names": 0, "prioritized": 0, "items_open": 0, "items_met": 0,
              "tls13_missing": 0, "supplier_blocked": 0, "validated_module": {}, "compatibility": {}}

    # Vulnerability, per name and role.
    by_name: dict[tuple[str, str], list[str]] = {}
    for fid, f in findings.items():
        if f["asset"]["role"] in FUNCTIONS:
            by_name.setdefault((f["asset"]["role"], f["asset"]["name"]), []).append(fid)
    vuln: dict[tuple[str, str], tuple[bool | None, str, str]] = {}
    for (role, name), ids in sorted(by_name.items()):
        fam = family_of(families, role, name)
        v, why = vulnerability(pack, fam, role)
        vuln[(role, name)] = (v, fam, why)
        run.ledger.append("assessment.made", _actor("quantum/vulnerable/1"), {
            "subject": {"kind": "algorithm-name", "role": role, "name": name}, "rule_id": "quantum/vulnerable/1",
            "classification": {"family": fam, "quantum_vulnerable": v, "findings": len(ids)},
            "basis": why, "source": {**src, "section": pack["quantum_vulnerable"]["section"]},
        }, inputs=ids)
        counts["names"] += 1
        counts["vulnerable_names"] += int(bool(v))

    # Which pack governs each service, and its priority under M-26-15.
    services = sorted(set(facts) | {s for s, _ in svc_of_listener.values()} | {s for s, _ in svc_of_image.values()})
    priority: dict[str, tuple[bool, list[str], str]] = {}
    for svc in services:
        f = facts.get(svc, {})
        nss = f.get("national-security-system", (False, None))[0]
        governs = "cnsa-2.0" if nss else pack["id"]
        run.ledger.append("assessment.made", _actor("pack/scope/1"), {
            "subject": {"kind": "service", "name": svc}, "rule_id": "pack/scope/1",
            "classification": {"pack": governs, "national_security_system": bool(nss)},
            "basis": (_nss_basis(packs.get("cnsa-2.0")) if nss else
                      "not a national security system, so M-26-15 governs it (§3.B)"),
        }, inputs=[f["national-security-system"][1]] if "national-security-system" in f else [])
        if nss:
            continue
        held, inputs = [], []
        for c in pack["prioritize"]["criteria"]:
            kind = {"fips199_impact": "fips199-impact", "high_value_asset": "high-value-asset",
                    "data_lifetime_years": "data-lifetime"}[c["fact"]]
            if kind not in f:
                continue
            value, ev = f[kind]
            inputs.append(ev)
            if "equals" in c and value == c["equals"]:
                held.append(c["id"])
            elif "sensitive_through_year_at_least" in c and isinstance(value, int) \
                    and sensitive_through(as_of, value) >= c["sensitive_through_year_at_least"]:
                held.append(c["id"])
        missing = [k for k in ("fips199-impact", "high-value-asset", "data-lifetime") if k not in f]
        basis = (", ".join(held) + " hold" if held else "none of the criteria holds") + \
            (f"; not supplied: {', '.join(missing)}" if missing else "")
        lifetime = f.get("data-lifetime", (None,))[0]
        run.ledger.append("assessment.made", _actor("priority/m-26-15/1"), {
            "subject": {"kind": "service", "name": svc}, "rule_id": "priority/m-26-15/1",
            "classification": {"prioritized": bool(held), "criteria": held, "as_of": as_of.isoformat(),
                               "sensitive_through": sensitive_through(as_of, lifetime) if isinstance(lifetime, int) else None},
            "basis": basis, "source": {**src, "section": pack["prioritize"]["section"]},
        }, inputs=inputs)
        priority[svc] = (bool(held), held, basis)
        counts["prioritized"] += int(bool(held))

    # The service each finding belongs to.
    def service_of(f: dict) -> tuple[str, str] | None:
        s = f["subject"]
        if s["kind"] == "endpoint":
            return svc_of_listener.get((s["host"], s["port"]))
        if s["kind"] == "file":
            return svc_of_image.get(s.get("image", ""))
        return None

    # Every entry's status under the pack that governs its service (the memo's where it has none).
    governs_svc = {svc: ("cnsa-2.0" if facts.get(svc, {}).get("national-security-system", (False,))[0] else pack["id"])
                   for svc in services}
    by_fp: dict[str, list[str]] = {}
    for fid, f in findings.items():
        by_fp.setdefault(f["fingerprint"], []).append(fid)
    for fp, ids in sorted(by_fp.items()):
        f = findings[ids[0]]
        owner = service_of(f)
        governs = governs_svc.get(owner[0], pack["id"]) if owner else pack["id"]
        gp = packs.get(governs) or pack
        c = entry_compatibility(gp, families, f)
        provisional = gp.get("verified") is False or (gp.get("compatible") or {}).get("verified") is False
        run.ledger.append("assessment.made", _actor("compatibility/entry/1"), {
            "subject": {"kind": "asset", "fingerprint": fp}, "rule_id": "compatibility/entry/1",
            "classification": {"status": c["status"], "pack": gp["id"], "provisional": provisional,
                               "algorithm_role": c["algorithm_role"], "family": c["family"], "name": f["asset"]["name"],
                               "service": owner[0] if owner else None},
            "basis": c["basis"] + ("; provisional: the pack is not read first-hand" if provisional else ""),
            "source": {"pack": gp["id"], "pdf_sha256": gp["source"].get("pdf_sha256"),
                       "section": (gp.get("compatible") or {}).get("section")},
        }, inputs=ids + ([owner[1]] if owner else []))
        cc = counts["compatibility"].setdefault(gp["id"], {})
        cc[c["status"]] = cc.get(c["status"], 0) + 1

    queues = {q["id"]: q for q in pack["queues"]}
    cap = (caps or {}).get("services", {})
    certs = list(((cmvp or {}).get("certificates") or {}).values())
    for svc in sorted(priority):
        prioritized = priority[svc][0]
        for fn in FUNCTIONS:
            vulnerable, resistant, link_events = [], [], set()
            for fid, f in findings.items():
                if f["asset"]["role"] != fn:
                    continue
                owner = service_of(f)
                if owner is None or owner[0] != svc or in_use.get(fid) is False:
                    continue
                v = vuln.get((fn, f["asset"]["name"]), (None,))[0]
                (vulnerable if v else resistant if v is False else []).append(fid)
                link_events.add(owner[1])
            q = queues["kex-2030" if fn == "key-establishment" else "sig-2031"] if prioritized else queues["remaining-2035"]
            names_v = sorted({findings[i]["asset"]["name"] for i in vulnerable})
            names_r = sorted({findings[i]["asset"]["name"] for i in resistant})
            state = "open" if vulnerable else "met"
            deadline, set_by, t = (str(q["deadline"]), [f"{pack['id']} §{q['section']}"], None) if vulnerable else (None, [], None)
            if vulnerable:
                by_name: dict[str, list[dict]] = {}
                for i in vulnerable:
                    by_name.setdefault(findings[i]["asset"]["name"], []).append(findings[i]["asset"].get("parameters") or {})
                t = _transition(tr, families, fn, names_v, by_name)
                if t and t["below_condition"] == t["covers"]:
                    # Every covered key is below the row's condition: already disallowed, and the 2035 date
                    # does not apply to it. The memo's queue date stands alone.
                    t = {**t, "deprecated_after": None, "disallowed_after": None}
                elif t:
                    t_by = f"{t['pack']} {t['table']} (§{t['section']})"
                    if t["disallowed_after"] < deadline:
                        deadline, set_by = t["disallowed_after"], [t_by]
                    elif t["disallowed_after"] == deadline:
                        set_by.append(t_by)
            basis = (f"{svc} still offers or holds {', '.join(names_v)}" +
                     (f" beside {', '.join(names_r)}: enabled, not enforced" if names_r else "")
                     if vulnerable else
                     (f"only {', '.join(names_r)} in this function" if names_r else "nothing in this function was observed"))
            item = run.ledger.append("assessment.made", _actor("queue/m-26-15/1"), {
                "subject": {"kind": "migration-item", "service": svc, "function": fn}, "rule_id": "queue/m-26-15/1",
                "classification": {"state": state, "queue": q["id"] if vulnerable else None,
                                   "deadline": deadline,
                                   "deadline_basis": q["deadline_basis"] if vulnerable else None,
                                   "prioritized": prioritized, "vulnerable": names_v, "post_quantum": names_r,
                                   "enforced": not vulnerable and bool(names_r),
                                   **({"deadline_set_by": set_by} if tr and vulnerable else {}),
                                   **({"deprecated_after": t["deprecated_after"], "disallowed_after": t["disallowed_after"],
                                       "transition": t} if t and t["disallowed_after"] else {}),
                                   **({"transition": t} if t and not t["disallowed_after"] else {})},
                "basis": basis, "source": {**src, "section": q["section"]},
            }, inputs=sorted(set(vulnerable) | set(resistant) | link_events))
            if not vulnerable:
                counts["items_met"] += 1
                continue
            counts["items_open"] += 1
            # The supplier: can the software offer a post-quantum algorithm in this function at all?
            c = cap.get(svc)
            role = "kex" if fn == "key-establishment" else "sig"
            if c is None:
                sup = {"state": "unknown", "replace": False, "basis": "no capability snapshot for this service"}
            elif c["pq"][role] is None and c.get("same_build") and (caps or {}).get("same_build_check", {}).get("identical"):
                seen = sorted({findings[i]["asset"]["name"] for i, f in findings.items()
                               if f["asset"]["role"] == fn and vuln.get((fn, f["asset"]["name"]), (None,))[0] is False
                               and service_of(f) and service_of(f)[0] in c["same_build"]})
                peers = [x for x in c["same_build"] if x != svc] or c["same_build"]
                sup = ({"state": "not-blocked", "replace": False,
                        "basis": f"the image's library is the same build as the one in {' and '.join(peers)}, which "
                                 f"this run observed offering {', '.join(seen)} for {fn}"} if seen else
                       {"state": "unknown", "replace": False,
                        "basis": "the image lists nothing, and no image of the same build was observed with a post-quantum algorithm here"})
            elif c["pq"][role]:
                sup = {"state": "not-blocked", "replace": False,
                       "basis": f"{c['software']} lists {', '.join(c['pq'][role][:4])}{' and more' if len(c['pq'][role]) > 4 else ''}"}
            else:
                sup = {"state": "blocked", "replace": True,
                       "basis": f"{c['software']} lists no post-quantum algorithm for {fn}: the change needs the "
                                f"supplier's software, not a configuration line; §3.C.3 gives it priority for replacement"}
            run.ledger.append("assessment.made", _actor("blocker/supplier/1"), {
                "subject": {"kind": "migration-item", "service": svc, "function": fn}, "rule_id": "blocker/supplier/1",
                "classification": {"state": sup["state"], "replace_priority": sup["replace"]},
                "basis": sup["basis"],
                "source": {**src, "section": pack["replace"]["section"],
                           "capabilities": c and {"taken_at": caps["taken_at"], "raw": c["raw"], "sha256": c["sha256"]}},
            }, inputs=[item["id"]], evidence=[{"ref": c["raw"], "sha256": c["sha256"]}] if c else [])
            counts["supplier_blocked"] += int(sup["state"] == "blocked")
            # The validated module: in use, available, or none.
            lib = _library(c["software"]) if c else "unknown"
            flag, alg = NEEDS[fn]
            avail = sorted(int(x["certificate"]) for x in certs if x.get(flag) and lib in x["module"].lower())
            if c and c["fips"]["active"]:
                vm = {"state": "in-use", "basis": "the image's FIPS provider is active"}
            elif cmvp is None:
                vm = {"state": "unknown", "basis": "no CMVP snapshot"}
            elif avail:
                vm = {"state": "available-not-in-use",
                      "basis": f"the service runs its library's default provider, not a validated module; the CMVP "
                               f"snapshot of {cmvp['taken_at'][:10]} holds {len(avail)} active {lib} module(s) whose "
                               f"approved algorithms include {alg} (certificate {', '.join(map(str, avail))})"}
            else:
                vm = {"state": "none-validated",
                      "basis": f"no active certificate in the CMVP snapshot of {cmvp['taken_at'][:10] if cmvp else '?'} "
                               f"for an {lib} module lists {alg} among its approved algorithms" if lib[0] in "aeiou" else
                               f"for a {lib} module lists {alg} among its approved algorithms"
                               + ("; the image carries a FIPS provider that is not active" if c and c["fips"]["module_present"] else "")}
            run.ledger.append("assessment.made", _actor("blocker/validated-module/1"), {
                "subject": {"kind": "migration-item", "service": svc, "function": fn},
                "rule_id": "blocker/validated-module/1",
                "classification": {"state": vm["state"], "library": lib, "certificates": avail},
                "basis": vm["basis"],
                "source": {"cmvp": cmvp and {"taken_at": cmvp["taken_at"], "source": cmvp["source"]}},
            }, inputs=[item["id"]])
            counts["validated_module"][vm["state"]] = counts["validated_module"].get(vm["state"], 0) + 1

    # TLS 1.3, per TLS listener.
    tls_q = queues["tls13-2030"]
    scope = events[0]["payload"]["scope"]
    for ep in scope["endpoints"]:
        if ep["protocol"] not in tls_q["applies_to_protocol"]:
            continue
        mine = [(i, f) for i, f in findings.items() if f["asset"]["type"] == "protocol" and f["subject"]["kind"] == "endpoint"
                and (f["subject"]["host"], f["subject"]["port"]) == (ep["host"], ep["port"])]
        if not mine:
            continue    # no version list for this listener in the run: nothing is judged
        versions = sorted({f["asset"]["name"] for _, f in mine})
        ok = "TLS 1.3" in versions
        svc = svc_of_listener.get((ep["host"], ep["port"]), (None, None))
        run.ledger.append("assessment.made", _actor("deadline/tls13/1"), {
            "subject": {"kind": "endpoint", "host": ep["host"], "port": ep["port"], "protocol": ep["protocol"]},
            "rule_id": "deadline/tls13/1",
            "classification": {"state": "met" if ok else "open", "queue": None if ok else tls_q["id"],
                               "deadline": None if ok else str(tls_q["deadline"]), "versions": versions,
                               "service": svc[0]},
            "basis": f"offered {', '.join(versions)}" + ("" if ok else "; no TLS 1.3"),
            "source": {**src, "section": tls_q["section"]},
        }, inputs=[i for i, _ in mine] + ([svc[1]] if svc[1] else []))
        counts["tls13_missing"] += int(not ok)
    return counts
