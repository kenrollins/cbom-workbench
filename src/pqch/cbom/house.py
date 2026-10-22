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

HYBRID = re.compile(r"mlkem|kyber|sntrup", re.I)


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
    tools = sorted(set(pa.get("pqch:tools", "").split(", ")) | set(pb.get("pqch:tools", "").split(", ")) - {""})
    keep = [p for p in out.get("properties", []) if p["name"] not in ("pqch:tools", "pqch:evidence", "pqch:parameters")]
    keep += [{"name": "pqch:tools", "value": ", ".join(tools)},
             {"name": "pqch:evidence", "value": pa.get("pqch:evidence", "")},
             {"name": "pqch:evidence", "value": pb.get("pqch:evidence", "")},
             {"name": "pqch:parameters", "value": pa.get("pqch:parameters", "{}")},
             {"name": "pqch:parameters", "value": pb.get("pqch:parameters", "{}")}]
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
            ln["certs"].append({"name": c["name"], "bits": sp.get("key_bits"), "not_after": (sp.get("not_after") or "")[:10],
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
    return {
        "doc": doc,
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
