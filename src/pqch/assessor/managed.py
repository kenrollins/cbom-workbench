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
- `queue/cnsa-2.0/1` — per national security system and function: the entries the service still
  offers or holds in use that are not compatible under CNSA 2.0's table, with the suite's own dates
  as data (new acquisitions, phase-out, mandate) and the mandate date as the item's deadline. Only
  what the verified pack carries: an unverified pack gives the item no date. Before this rule a
  national security system left the queue with nothing said; now it has an item, in a rule of its
  own, so the memo's queue stays the memo's.
- `priority/m-26-15/1` — per service: which of §3.C.2's criteria hold, from the owner's supplied
  facts; the supplied links are the inputs.
- `queue/m-26-15/1` — per service and function (key establishment, signature): the vulnerable
  assets the service still offers or holds in use, the queue the memo puts them in and its
  deadline; `met` only when an acceptable algorithm was observed in the function and nothing
  else; `not-assessed` when no finding of the function was attributed to the service (a listener
  the runner could not bind, a scan of a copy with no binding at all) or when what was observed
  could not be identified. Absence of evidence is never `met`. A vulnerable algorithm still
  accepted beside a post-quantum one keeps the item open (Appendix A §5: only acceptable
  algorithms), and so does one that is post-quantum by design and not a NIST standard
  (`not_standardised`; footnote 13). `only_resistant_observed` is what one scan's enumeration
  shows; `enforced` is true only when a change requiring the hybrid group landed on the service
  before the scan (the verifier's pair of probes, verified again after a recreate) and nothing
  rolled it back or reset the estate since: a scan's list is not a refusal. With NIST
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
  verdict: the entry's algorithm is not identified (a tool's `unknown` or `unspecified` is not a
  name, and gets no verdict from `quantum/vulnerable/1` either), or the pack does not place the
  name. Under CNSA 2.0 a symmetric cipher is judged by its algorithm and key size and a hash by
  its function, whatever the tool's spelling (`aes256-gcm@openssh.com` is AES with a 256-bit key);
  the FAQ's table names no MAC, so a MAC stays outside the pack. A status
  from a pack not read first-hand is `provisional` (none is, since the CNSA 2.0 FAQ was read
  first-hand on 2026-11-09; the flag stays for the next pack).
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime
from pathlib import Path

from pqch.policy import (PQ_NOT_STANDARDISED, classical_strength, family_of, identified, load_families, load_pack,
                         sensitive_through, vulnerability)
from pqch.run import Run

FUNCTIONS = ("key-establishment", "signature")
NEEDS = {"key-establishment": ("approved_ml_kem", "ML-KEM"), "signature": ("approved_ml_dsa", "ML-DSA")}
# A CMVP snapshot older than this is said to be stale in the blocker's event. The threshold is ours
# (a snapshot is retaken by hand; certificates move to Historical on their sunset dates), not CMVP's.
CMVP_STALE_DAYS = 180


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

_AES = re.compile(r"^aes[-_ ]?(128|192|256)?(?![0-9])", re.I)
_SHA2 = re.compile(r"^sha[-_ ]?(1|224|256|384|512)$", re.I)
_TLS_VERSION = re.compile(r"^(D?TLS|SSL) ?v? ?(\d)(?:\.?(\d))?$", re.I)


def symmetric_identity(role: str, name: str, params: dict | None) -> tuple[str, str | None]:
    """A symmetric cipher's or hash's name as a pack's table writes it, whatever the tool's spelling:
    (`AES-256`, None) for `aes256-gcm@openssh.com`, `AES-256-GCM` or `AES` with a 256-bit key;
    (`AES`, "no key size") when the finding carries none; (`SHA-384`, None) for `SHA384`. A name that is
    neither comes back as it is."""
    params = params or {}
    if role == "encryption":
        m = _AES.match(name)
        if m:
            bits = m.group(1) or params.get("key_bits")
            return (f"AES-{bits}", None) if bits else ("AES", "no key size")
    if role == "hash":
        m = _SHA2.match(name)
        if m:
            return f"SHA-{m.group(1)}", None
    return name, None


def tls_version(name: str) -> str | None:
    """A protocol finding's name as a TLS or SSL version (`TLS 1.3`, from `TLS 1.3`, `TLSv1.3` or zeek's
    `TLSv13`), or None when it is not one (`PostgreSQL`, `SSH 2.0`)."""
    m = _TLS_VERSION.match(name.strip())
    if not m:
        return None
    return f"{m.group(1).upper()} {m.group(2)}.{m.group(3) or 0}"


def _cmvp_active(cert: dict, as_of: date) -> bool:
    """A certificate the snapshot marks Active whose sunset, when the snapshot gives one, has not passed."""
    if cert.get("status") != "Active":
        return False
    try:
        return datetime.strptime(cert["sunset"], "%m/%d/%Y").date() >= as_of if cert.get("sunset") else True
    except ValueError:
        return True


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
    if not identified(name):
        return {"status": "unknown", "algorithm_role": None, "family": None,
                "basis": f"the tool did not identify the entry's algorithm (it wrote {name!r}); nothing can be judged from it"}
    role = algorithm_role(families, finding)
    if role is None:
        return {"status": "unknown", "algorithm_role": None, "family": None,
                "basis": f"the entry names no algorithm a table places ({name}); nothing can be judged from it"}
    fam = family_of(families, role, name)
    if comp.get("basis") == "named-algorithms":
        names = comp.get("names") or {}
        if role in ("encryption", "hash") and role in names:
            canon, missing = symmetric_identity(role, name, a.get("parameters"))
            said = name if canon == name else f"{name} ({canon})"
            if missing:
                return {"status": "unknown", "algorithm_role": role, "family": fam,
                        "basis": f"the pack names {', '.join(names[role])} for {role}; {name} carries {missing}, so it cannot be placed"}
            if canon in names[role]:
                return {"status": "compatible", "algorithm_role": role, "family": fam,
                        "basis": f"{said} is one the pack names for {role}"}
            name_said = said
        else:
            name_said = name
        if role == "mac":
            return {"status": "outside-pack", "algorithm_role": role, "family": fam,
                    "basis": "the pack names no algorithm for mac: its table gives a hash (SHA-384 or SHA-512) and says "
                             "nothing of a message authentication code built on one"}
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
                              f"the pack names {', '.join(names[role])} for {role}; {name_said} is not among them"
                              + ("; it is post-quantum by design but not a NIST-standardised algorithm"
                                 if fam == PQ_NOT_STANDARDISED else ""))}
        return {"status": "outside-pack", "algorithm_role": role, "family": fam,
                "basis": f"the pack names no algorithm for {role}"}
    if role in SYMMETRIC_ROLES:
        return {"status": "outside-pack", "algorithm_role": role, "family": fam,
                "basis": "the memo's table names asymmetric algorithms only; it says nothing of a symmetric algorithm or hash"}
    v, why = vulnerability(pack, fam, role)
    if fam == PQ_NOT_STANDARDISED:
        # Not acceptable, and said in its own words: never "quantum-vulnerable".
        return {"status": "not-compatible", "algorithm_role": role, "family": fam, "basis": why}
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
              "items_not_assessed": 0, "tls13_missing": 0, "supplier_blocked": 0, "validated_module": {},
              "compatibility": {}, "nss_items": {}}
    # What a verifier's pair of probes established before this scan: the change standing on each service.
    try:
        from pqch.planning import standing_changes

        standing = standing_changes(run.var, before=events[0]["ts"])
    except (OSError, ValueError):
        standing = {}

    # Vulnerability, per name and role.
    by_name: dict[tuple[str, str], list[str]] = {}
    for fid, f in findings.items():
        if f["asset"]["role"] in FUNCTIONS:
            by_name.setdefault((f["asset"]["role"], f["asset"]["name"]), []).append(fid)
    vuln: dict[tuple[str, str], tuple[bool | None, str, str]] = {}
    for (role, name), ids in sorted(by_name.items()):
        if identified(name):
            fam = family_of(families, role, name)
            v, why = vulnerability(pack, fam, role)
        else:
            fam, v, why = "unknown", None, (f"the tool did not identify the algorithm (it wrote {name!r}): not a name the "
                                            "table or footnote 13 can be asked about; nothing is judged from it")
        vuln[(role, name)] = (v, fam, why)
        run.ledger.append("assessment.made", _actor("quantum/vulnerable/1"), {
            "subject": {"kind": "algorithm-name", "role": role, "name": name}, "rule_id": "quantum/vulnerable/1",
            "classification": {"family": fam, "quantum_vulnerable": v, "findings": len(ids),
                               **({"identified": False} if not identified(name) else {}),
                               **({"post_quantum_by_design": True, "standardised": False, "acceptable": False}
                                  if fam == PQ_NOT_STANDARDISED else {})},
            "basis": why, "source": {**src, "section": pack["quantum_vulnerable"]["section"]},
        }, inputs=ids)
        counts["names"] += 1
        counts["vulnerable_names"] += int(bool(v))

    # Which pack governs each service, and its priority under M-26-15.
    services = sorted(set(facts) | {s for s, _ in svc_of_listener.values()} | {s for s, _ in svc_of_image.values()})
    priority: dict[str, tuple[bool, list[str], str]] = {}
    nss_services: dict[str, list[str]] = {}
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
            nss_services[svc] = [f["national-security-system"][1]]
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
            vulnerable, resistant, other, unnamed, link_events = [], [], [], [], set()
            for fid, f in findings.items():
                if f["asset"]["role"] != fn:
                    continue
                owner = service_of(f)
                if owner is None or owner[0] != svc or in_use.get(fid) is False:
                    continue
                v, fam = vuln.get((fn, f["asset"]["name"]), (None, None))[:2]
                (vulnerable if v else resistant if v is False else other if fam == PQ_NOT_STANDARDISED else unnamed).append(fid)
                link_events.add(owner[1])
            q = queues["kex-2030" if fn == "key-establishment" else "sig-2031"] if prioritized else queues["remaining-2035"]
            names_v = sorted({findings[i]["asset"]["name"] for i in vulnerable})
            names_r = sorted({findings[i]["asset"]["name"] for i in resistant})
            names_o = sorted({findings[i]["asset"]["name"] for i in other})
            names_u = sorted({findings[i]["asset"]["name"] for i in unnamed})
            # Open while anything not acceptable is still accepted; met only on evidence: an acceptable
            # algorithm observed and nothing else. Nothing attributed to the service, or only what no
            # tool could name, is not-assessed: absence of evidence is not compliance.
            is_open = bool(vulnerable or other)
            state = "open" if is_open else "met" if resistant and not unnamed else "not-assessed"
            deadline, set_by, t = (str(q["deadline"]), [f"{pack['id']} §{q['section']}"], None) if is_open else (None, [], None)
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
            if is_open:
                basis = (f"{svc} still offers or holds {', '.join(names_v + names_o)}"
                         + (f" beside {', '.join(names_r)}: enabled, not enforced" if names_r else "")
                         + (f"; {', '.join(names_o)} is post-quantum by design but not a NIST-standardised algorithm, "
                            "so the memo does not accept it (footnote 13)" if names_o else ""))
            elif state == "met":
                basis = f"only {', '.join(names_r)} in this function"
            elif unnamed:
                basis = (f"{svc} holds {len(unnamed)} entr{'y' if len(unnamed) == 1 else 'ies'} in this function whose algorithm "
                         f"no tool identified ({', '.join(names_u)})"
                         + (f" beside {', '.join(names_r)}" if names_r else "") + ": not assessed, neither met nor open")
            else:
                basis = ("no finding of this function was attributed to the service: not assessed. A listener is joined "
                         "to its service only when the runner bound it to the scope's image, and this run has no such "
                         "evidence for it; nothing observed is not the same as met")
            # Enforced is the verifier's word, not a scan's: a change requiring the hybrid group that landed on
            # this service before the scan, with nothing rolling it back since.
            st = standing.get(svc) if fn == "key-establishment" else None
            enforced_by = ({"run": st["run"], "change_id": st["change_id"], "verdict_ts": st["ts"]}
                           if st and st["intent"] == "require" and state == "met" else None)
            item = run.ledger.append("assessment.made", _actor("queue/m-26-15/1"), {
                "subject": {"kind": "migration-item", "service": svc, "function": fn}, "rule_id": "queue/m-26-15/1",
                "classification": {"state": state, "queue": q["id"] if is_open else None,
                                   "deadline": deadline,
                                   "deadline_basis": q["deadline_basis"] if is_open else None,
                                   "prioritized": prioritized, "vulnerable": names_v, "post_quantum": names_r,
                                   "not_standardised": names_o, "unidentified": names_u,
                                   "only_resistant_observed": state == "met",
                                   "enforced": enforced_by is not None, "enforced_by": enforced_by,
                                   **({"deadline_set_by": set_by} if tr and is_open else {}),
                                   **({"deprecated_after": t["deprecated_after"], "disallowed_after": t["disallowed_after"],
                                       "transition": t} if t and t["disallowed_after"] else {}),
                                   **({"transition": t} if t and not t["disallowed_after"] else {})},
                "basis": basis, "source": {**src, "section": q["section"]},
            }, inputs=sorted(set(vulnerable) | set(resistant) | set(other) | set(unnamed) | link_events))
            if not is_open:
                counts["items_met" if state == "met" else "items_not_assessed"] += 1
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
            # By the library's name in the module's name, among certificates the snapshot marks Active and not
            # past their sunset. That finds modules for the library, not a module this service can load: the
            # basis names each module and its vendor so the reader sees whose it is.
            mods = sorted(({"certificate": int(x["certificate"]), "module": x["module"], "vendor": x.get("vendor")}
                           for x in certs if x.get(flag) and lib in x["module"].lower() and _cmvp_active(x, as_of)),
                          key=lambda m: m["certificate"])
            avail = [m["certificate"] for m in mods]
            taken = cmvp["taken_at"][:10] if cmvp else None
            age = (as_of - date.fromisoformat(taken)).days if taken else None
            stale = age is not None and age > CMVP_STALE_DAYS
            art = "an" if lib[0] in "aeiou" else "a"
            if c and c["fips"]["active"]:
                vm = {"state": "in-use",
                      "basis": "the image's FIPS provider is active; which validated module it is, and whether its "
                               f"certificate lists {alg}, the capability snapshot does not say"}
            elif cmvp is None:
                vm = {"state": "unknown", "basis": "no CMVP snapshot"}
            elif avail:
                vm = {"state": "available-not-in-use",
                      "basis": f"the service runs its library's default provider, not a validated module; the CMVP "
                               f"snapshot of {taken} holds {len(avail)} active module(s) with {lib} in the name whose "
                               f"approved algorithms include {alg}: "
                               + "; ".join(f"certificate {m['certificate']}, {m['module']} ({m['vendor'] or 'vendor not given'})" for m in mods)
                               + ". Matched by name: whether this service can run one of them is not established"}
            else:
                vm = {"state": "none-validated",
                      "basis": f"no active certificate in the CMVP snapshot of {taken} for {art} {lib} module lists {alg} "
                               "among its approved algorithms"
                               + ("; the image carries a FIPS provider that is not active" if c and c["fips"]["module_present"] else "")}
            if stale and vm["state"] != "unknown":
                vm["basis"] += f"; the snapshot is {age} days old on {as_of.isoformat()}, so a certificate's status may have changed"
            run.ledger.append("assessment.made", _actor("blocker/validated-module/1"), {
                "subject": {"kind": "migration-item", "service": svc, "function": fn},
                "rule_id": "blocker/validated-module/1",
                "classification": {"state": vm["state"], "library": lib, "certificates": avail, "modules": mods,
                                   "matched_by": "library name in module name", "snapshot_age_days": age,
                                   "snapshot_stale": stale},
                "basis": vm["basis"],
                "source": {"cmvp": cmvp and {"taken_at": cmvp["taken_at"], "source": cmvp["source"]}},
            }, inputs=[item["id"]])
            counts["validated_module"][vm["state"]] = counts["validated_module"].get(vm["state"], 0) + 1

    # A national security system: CNSA 2.0's own item per function, with the suite's dates as data.
    nss_pack = packs.get("cnsa-2.0")
    for svc in sorted(nss_services):
        verified = bool(nss_pack and nss_pack.get("verified"))
        dates = {d["id"]: str(d["by"]) for d in ((nss_pack or {}).get("timeline") or {}).get("dates") or []} if verified else {}
        for fn in FUNCTIONS:
            bad, good, unplaced, link_events = [], [], [], set()
            for fid, f in findings.items():
                owner = service_of(f)
                if f["asset"]["role"] != fn or owner is None or owner[0] != svc or in_use.get(fid) is False:
                    continue
                st_ = entry_compatibility(nss_pack, families, f)["status"] if nss_pack else "unknown"
                (bad if st_ == "not-compatible" else good if st_ == "compatible" else unplaced).append(fid)
                link_events.add(owner[1])
            names = lambda ids: sorted({findings[i]["asset"]["name"] for i in ids})  # noqa: E731
            state = "open" if bad else "met" if good and not unplaced else "not-assessed"
            want = ", ".join(((nss_pack or {}).get("compatible") or {}).get("names", {}).get(fn, []))
            basis = (f"{svc} still offers or holds {', '.join(names(bad))}; the suite names {want} for {fn}" if bad else
                     f"only {', '.join(names(good))} in this function" if state == "met" else
                     f"{', '.join(names(unplaced))} could not be placed under the suite: not assessed" if unplaced else
                     "no finding of this function was attributed to the service: not assessed, which is not the same as met")
            if not verified:
                basis += "; the pack is not verified, so no date is set"
            run.ledger.append("assessment.made", _actor("queue/cnsa-2.0/1"), {
                "subject": {"kind": "migration-item", "service": svc, "function": fn}, "rule_id": "queue/cnsa-2.0/1",
                "classification": {"state": state, "pack": "cnsa-2.0", "verified": verified,
                                   "deadline": dates.get("mandate") if bad else None,
                                   "deadline_basis": "stated" if bad and dates.get("mandate") else None,
                                   "new_acquisitions": dates.get("new-acquisitions"), "phase_out": dates.get("phase-out"),
                                   "mandate": dates.get("mandate"),
                                   "not_compatible": names(bad), "compatible": names(good), "unplaced": names(unplaced)},
                "basis": basis,
                "source": {"pack": "cnsa-2.0", "pdf_sha256": ((nss_pack or {}).get("source") or {}).get("pdf_sha256"),
                           "section": ((nss_pack or {}).get("timeline") or {}).get("section")},
            }, inputs=sorted(set(bad) | set(good) | set(unplaced) | link_events | set(nss_services[svc])))
            counts["nss_items"][state] = counts["nss_items"].get(state, 0) + 1

    # TLS 1.3, per TLS listener.
    tls_q = queues["tls13-2030"]
    scope = events[0]["payload"]["scope"]
    for ep in scope["endpoints"]:
        if ep["protocol"] not in tls_q["applies_to_protocol"]:
            continue
        mine = [(i, f) for i, f in findings.items() if f["asset"]["type"] == "protocol" and f["subject"]["kind"] == "endpoint"
                and (f["subject"]["host"], f["subject"]["port"]) == (ep["host"], ep["port"])]
        # A protocol finding is a TLS version only when its name is one: `PostgreSQL` (the probe's answer to
        # an SSLRequest) and `SSH 2.0` are protocols, not versions of TLS.
        versions = sorted({v for _, f in mine if (v := tls_version(f["asset"]["name"]))})
        refused = [i for i, f in mine if (f["asset"].get("parameters") or {}).get("tls_offered") is False]
        if not versions and not refused:
            continue    # no version list for this listener in the run: nothing is judged
        ok = "TLS 1.3" in versions
        svc = svc_of_listener.get((ep["host"], ep["port"]), (None, None))
        run.ledger.append("assessment.made", _actor("deadline/tls13/1"), {
            "subject": {"kind": "endpoint", "host": ep["host"], "port": ep["port"], "protocol": ep["protocol"]},
            "rule_id": "deadline/tls13/1",
            "classification": {"state": "met" if ok else "open", "queue": None if ok else tls_q["id"],
                               "deadline": None if ok else str(tls_q["deadline"]), "versions": versions,
                               "service": svc[0], **({"tls_refused": True} if refused and not versions else {})},
            "basis": (f"offered {', '.join(versions)}" + ("" if ok else "; no TLS 1.3") if versions else
                      "the listener refused TLS: no version was offered, so the connection is in the clear"),
            "source": {**src, "section": tls_q["section"]},
        }, inputs=[i for i, f in mine if tls_version(f["asset"]["name"]) or i in refused] + ([svc[1]] if svc[1] else []))
        counts["tls13_missing"] += int(not ok)
    return counts
