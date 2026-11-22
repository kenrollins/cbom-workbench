"""The lab estate as one CBOM: the passive capture's entries for the house, and the targeted scan's
entries for the listeners in its scope, merged by fingerprint.

An entry's fingerprint is its subject and asset, not the tool that saw it, so the same key exchange on
the same listener is one entry whether Zeek saw it chosen in a real handshake or testssl.sh found it
accepted. Merged, an entry carries the evidence of both layers, and a listener's entries say what no
single layer can: a group accepted and never chosen, or chosen only because nothing better is accepted.

Only the house goes in: the capture's entries marked `inside` (listeners and clients on the lab's own
VLANs). The outside names stay in the capture's ledger. Nothing here is published (CLAUDE.md, Rules).
"""

from __future__ import annotations

import json
import re
from collections import Counter

from pqch.cbom import project

# A standardised post-quantum key establishment, alone or in a hybrid, by its standard name. OpenSSH's
# NTRU Prime hybrid is post-quantum by design and not standardised: the posture rule lists it apart
# (`kex_pq_not_standardised`), and a listener offering only that does not read here as accepting one.
HYBRID = re.compile(r"mlkem|ml-kem|kyber", re.I)


def _date(v) -> str:
    """`YYYY-MM-DD` from a parameter that may be a list after the collector merged two findings."""
    if isinstance(v, list):
        return max((_date(x) for x in v), default="")
    return (v or "")[:10] if isinstance(v, str) else ""


def _props(c: dict) -> dict:
    return {p["name"]: p["value"] for p in c.get("properties", [])}


def _subject(c: dict) -> dict:
    return json.loads(_props(c).get("pqch:subject", "{}"))


def _params(c: dict) -> dict:
    return json.loads(_props(c).get("pqch:parameters", "{}"))


def _merge(a: dict, b: dict) -> dict:
    """One entry seen by two layers: the first's fields, both layers' evidence and tools."""
    out = json.loads(json.dumps(a))
    pa, pb = _props(a), _props(b)
    def split(v: str) -> set[str]:
        return {t.strip() for t in v.split(",") if t.strip()}

    def merged(name: str, empty: str) -> str:
        """Both layers' value of one property as one property: a reader that keys properties by name
        would keep only the last of two."""
        a_, b_ = pa.get(name, empty), pb.get(name, empty)
        if name == "pqch:parameters":
            return json.dumps({**json.loads(b_ or "{}"), **json.loads(a_ or "{}")}, sort_keys=True, separators=(",", ":"))
        return ",".join(sorted(split(a_) | split(b_)))

    keep = [p for p in out.get("properties", []) if p["name"] not in ("pqch:tools", "pqch:evidence", "pqch:parameters")]
    keep += [{"name": "pqch:tools", "value": merged("pqch:tools", "")},
             {"name": "pqch:evidence", "value": merged("pqch:evidence", "")},
             {"name": "pqch:parameters", "value": merged("pqch:parameters", "{}")}]
    out["properties"] = keep
    occ = (a.get("evidence") or {}).get("occurrences", []) + [
        o for o in (b.get("evidence") or {}).get("occurrences", []) if o not in (a.get("evidence") or {}).get("occurrences", [])]
    if occ:
        out.setdefault("evidence", {})["occurrences"] = occ
    return out


def build(capture_events: list[dict] | None, scan_bom: dict | None) -> dict | None:
    """The merged document and what it shows, or None when neither layer has run."""
    cap = project(capture_events) if capture_events else {"components": []}
    inside = [c for c in cap["components"] if _params(c).get("inside")]
    scan = [c for c in (scan_bom or {}).get("components", []) if c["type"] == "cryptographic-asset"]
    if not inside and not scan:
        return None
    by_fp: dict[str, dict] = {}
    layers: dict[str, set] = {}
    for src, comps in (("capture", inside), ("scan", scan)):
        for c in comps:
            fp = _props(c).get("pqch:fingerprint") or c["bom-ref"]
            by_fp[fp] = _merge(by_fp[fp], c) if fp in by_fp else c
            layers.setdefault(fp, set()).add(src)
            if src == "capture":
                by_fp[fp]["_capture"] = _params(c)
            else:
                by_fp[fp]["_scan"] = _params(c)
    entries = list(by_fp.values())

    # Per listener: what the capture saw chosen, what the scan found accepted, the certificate.
    listeners: dict[str, dict] = {}
    for c in entries:
        sj = _subject(c)
        if sj.get("kind") != "endpoint":
            continue
        key = f"{sj['host']}:{sj['port']}"
        ln = listeners.setdefault(key, {"address": key, "protocol": sj.get("protocol"), "sni": sj.get("sni"),
                                        "chosen": [], "accepted": [], "certs": [], "layers": set(), "offered_hybrid": 0})
        p = _props(c)
        fp = p.get("pqch:fingerprint") or c["bom-ref"]
        ln["layers"] |= layers[fp]
        if c["cryptoProperties"]["assetType"] == "certificate":
            sp = c.get("_scan", {})
            ln["certs"].append({"name": c["name"], "bits": sp.get("key_bits"), "not_after": _date(sp.get("not_after")),
                                "self_signed": sp.get("self_signed")})
        elif p.get("pqch:role") == "key-establishment":
            if "_capture" in c:
                cp = c["_capture"]
                n = cp.get("chosen", cp.get("negotiated", 0))
                if n:
                    ln["chosen"].append({"name": c["name"], "n": n})
                ln["offered_hybrid"] = max(ln["offered_hybrid"], cp.get("clients_offered_hybrid", 0))
            if "_scan" in c:
                ln["accepted"].append(c["name"])
    rows = []
    for ln in listeners.values():
        acc_h = [g for g in ln["accepted"] if HYBRID.search(g)]
        cho_h = sum(x["n"] for x in ln["chosen"] if HYBRID.search(x["name"]))
        if "scan" not in ln["layers"]:
            reading = "seen only in the capture: not in the scope for a targeted check"
        elif "capture" not in ln["layers"]:
            reading = "asked only: no handshake to it crossed the mirror"
        elif acc_h and cho_h:
            reading = "accepts a hybrid group and negotiates it"
        elif acc_h and ln["protocol"] == "ssh":
            # The capture records what an SSH session agreed, not what its client offered.
            reading = "accepts a hybrid group; every captured session agreed a classical one"
        elif acc_h:
            reading = ("accepts a hybrid group, never chosen: no client offered one" if not ln["offered_hybrid"]
                       else "accepts a hybrid group, yet chose classical")
        else:
            reading = "accepts no hybrid group" + (f", though clients offered one in {ln['offered_hybrid']:,} handshakes"
                                                    if ln["offered_hybrid"] else "")
        rows.append({**ln, "layers": sorted(ln["layers"]), "hybrid_accepted": acc_h, "hybrid_chosen": cho_h,
                     "chosen": sorted(ln["chosen"], key=lambda x: -x["n"]), "reading": reading})
    rows.sort(key=lambda r: (len(r["layers"]) != 2, [int(x) if x.isdigit() else x for x in re.split(r"[.:]", r["address"])]))

    clients = {_subject(c)["host"] for c in entries if _subject(c).get("kind") == "client"}
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {**((scan_bom or {}).get("metadata") or {}),
                     "properties": [{"name": "pqch:estate", "value": "lab (the house only)"},
                                    {"name": "pqch:merged-from", "value": "capture and targeted scan, by fingerprint"}]},
        "components": [{k: v for k, v in c.items() if not k.startswith("_")} for c in entries],
    }
    # A document of its own: its serial names what it was merged from, and it is checked like any
    # other the workbench writes. The errors travel with it; whoever serves it decides.
    from pqch.cbom import _serial, validate

    doc["serialNumber"] = _serial("house", (cap.get("serialNumber"), (scan_bom or {}).get("serialNumber")))
    errors = validate(doc)
    return {
        "doc": doc,
        "errors": errors,
        "entries": len(entries),
        "by_type": dict(Counter(c["cryptoProperties"]["assetType"] for c in entries).most_common()),
        "both": sum(1 for s in layers.values() if s == {"capture", "scan"}),
        "capture_only": sum(1 for s in layers.values() if s == {"capture"}),
        "scan_only": sum(1 for s in layers.values() if s == {"scan"}),
        "clients": len(clients),
        "client_entries": sum(1 for c in entries if _subject(c).get("kind") == "client"),
        "listeners": rows,
        "certs": sum(1 for c in entries if c["cryptoProperties"]["assetType"] == "certificate"),
    }
