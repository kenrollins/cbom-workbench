"""The Managed rung: what is quantum-vulnerable, which systems come first, which queue each
item waits in and by when, and what blocks it. Rules only; every result an event naming its
inputs, the pack and the section of the memo it rests on.

- `quantum/vulnerable/1` — per algorithm name and role seen in the run: the family
  (`policy/algorithm-families.yaml`) and whether the pack's table, or its footnote 13, makes it
  quantum-vulnerable. Every finding of that name is an input.
- `pack/scope/1` — per service: which pack governs it, from the owner's
  `national-security-system` fact (M-26-15 does not govern a national security system; CNSA 2.0
  does). A pack with `verified: false` governs but sets no deadline.
- `priority/m-26-15/1` — per service: which of §3.C.2's criteria hold, from the owner's supplied
  facts; the supplied links are the inputs.
- `queue/m-26-15/1` — per service and function (key establishment, signature): the vulnerable
  assets the service still offers or holds in use, the queue the memo puts them in and its
  deadline; `met` when there are none. A vulnerable algorithm still accepted beside a
  post-quantum one keeps the item open (Appendix A §5: only acceptable algorithms).
- `deadline/tls13/1` — per TLS listener: whether it offered TLS 1.3, against §4's date.
- `blocker/supplier/1` — per open item: whether the service's software can offer a post-quantum
  algorithm in that function at all, from the capability snapshot; when it cannot, the item is
  blocked on its supplier and marked for replacement (§3.C.3).
- `blocker/validated-module/1` — per open item: whether the service runs a validated module,
  and whether the CMVP snapshot holds one for its library whose approved algorithms include the
  post-quantum algorithm the function needs.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

from pqch.policy import family_of, load_families, load_pack, sensitive_through, vulnerability
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


def assess(run: Run, *, pack_path: str | Path, families_path: str | Path, capabilities_path: str | Path | None,
           cmvp_path: str | Path | None, as_of: date | None = None) -> dict:
    pack = load_pack(pack_path)
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
              "tls13_missing": 0, "supplier_blocked": 0, "validated_module": {}}

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
            "basis": ("the owner marks it a national security system; CNSA 2.0 governs it, and that pack is not "
                      "verified, so no deadline is set" if nss else
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
            basis = (f"{svc} still offers or holds {', '.join(names_v)}" +
                     (f" beside {', '.join(names_r)}: enabled, not enforced" if names_r else "")
                     if vulnerable else
                     (f"only {', '.join(names_r)} in this function" if names_r else "nothing in this function was observed"))
            item = run.ledger.append("assessment.made", _actor("queue/m-26-15/1"), {
                "subject": {"kind": "migration-item", "service": svc, "function": fn}, "rule_id": "queue/m-26-15/1",
                "classification": {"state": state, "queue": q["id"] if vulnerable else None,
                                   "deadline": str(q["deadline"]) if vulnerable else None,
                                   "deadline_basis": q["deadline_basis"] if vulnerable else None,
                                   "prioritized": prioritized, "vulnerable": names_v, "post_quantum": names_r,
                                   "enforced": not vulnerable and bool(names_r)},
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
