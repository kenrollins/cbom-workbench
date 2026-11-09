"""A supplier's attestation as evidence: what a vendor says of its product's cryptography, kept apart
from what the server showed, and joined to it by model and version.

The hardware half of an inventory is the half discovery tools reach worst: the algorithm a firmware
image is signed with, the modules a controller's firmware carries, whether the installed version has
a route to post-quantum algorithms. Those facts come from the supplier. A `pqch.attestation/1`
document (`schemas/attestation.json`) is brought in with `pqch attest`, which records it on a run of
its own (kind `attestation`): one `attestation.recorded` event per product, graded `reported`, keyed
by the document's hash so the same document brought in twice is a no-op and a changed one a new
claim. Nothing in it becomes a finding: the server's own evidence stays the stronger claim, and the
pages show the two beside each other. Where a system scan on this deployment matches a product, the
run also records `attestation/match/1`: for each firmware the statement names, the version the server
reported and whether they agree. A disagreement is recorded, never resolved by overwriting.

The join is by the device's vendor and model as its firmware reports them, case-insensitive with
whitespace collapsed, and by each firmware's name; a statement at version `any` covers every version.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from pqch import schemas, varmode
from pqch import scope as scope_mod
from pqch.common import sha256_hex, ulid
from pqch.ledger import verify
from pqch.run import Run

SCHEMA = "pqch.attestation/1"
KIND = "attestation"
RULE = "attestation/match/1"


def _norm(s: str | None) -> str:
    return re.sub(r"\s+", " ", (s or "").strip()).lower().rstrip(".,")


def load(path: str | Path) -> dict:
    """The document, validated. YAML or JSON."""
    raw = Path(path).read_bytes()
    # YAML reads a date as a date; the document is carried as JSON, so every scalar is a JSON one.
    doc = json.loads(json.dumps(yaml.safe_load(raw), default=lambda o: o.isoformat() if hasattr(o, "isoformat") else str(o)))
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ValueError(f"{path}: not a {SCHEMA} document")
    schemas.validate(doc)
    return doc


def _minimal_scope(operator: str) -> dict:
    """An attestation touches no network; its run's scope names nothing to reach."""
    return {"schema": "pqch.scope/1", "id": ulid(), "estate": "external", "owned": False, "authorized_by": operator,
            "endpoints": [], "images": [], "sources": [], "reach": {"kind": "local"}}


def runs(var: str | Path) -> list[Run]:
    """Every attestation run under var, oldest first."""
    from pqch.ui.view import runs_of_kind

    return runs_of_kind(Path(var), KIND)


def recorded(var: str | Path) -> list[dict]:
    """Every product statement on this deployment, with the run and event that hold it, newest first.
    A ledger that does not verify contributes nothing."""
    out = []
    for run in runs(var):
        events = list(run.ledger.events())
        if not verify(events).ok:
            continue
        for e in events:
            if e["type"] == "attestation.recorded":
                out.append({**e["payload"], "run": run.id, "event": e["id"], "ts": e["ts"]})
    out.sort(key=lambda r: r["ts"], reverse=True)
    return out


def _system_runs(var: Path) -> list[tuple[Run, list[dict]]]:
    from pqch.ui.view import runs_of_kind

    out = []
    for r in runs_of_kind(var, "scan-system"):
        events = list(r.ledger.events())
        if events and events[-1]["type"] == "run.closed" and verify(events).ok:
            out.append((r, events))
    return out


def observed(events: list[dict]) -> dict:
    """What a system scan's `platform.observed` facts say of the device and its firmware versions:
    {"system", "device": {vendor, model}, "firmware": {name: version}, "controller": {...}}."""
    device, firmware, ctl, system = {}, {}, None, None
    for e in events:
        if e["type"] != "platform.observed":
            continue
        p = e["payload"]
        system = system or p.get("system")
        for k, v in (p.get("device") or {}).items():
            if v and not device.get(k):
                device[k] = v
        for fw in p.get("firmware") or []:
            if fw.get("name") and fw.get("name") not in firmware:
                firmware[fw["name"]] = fw.get("version")
        if p.get("source") == "controller":
            ctl = p.get("controller")
    return {"system": system, "device": device, "firmware": firmware, "controller": ctl}


def match(product: dict, obs: dict) -> dict | None:
    """One product statement against one system's observations: None when the model is not this
    product; else each firmware the statement names with the version the server reported and whether
    they agree (`None` when the server did not report that firmware)."""
    dev = obs.get("device") or {}
    if _norm(product["model"]) != _norm(dev.get("model")):
        return None
    if product.get("vendor") and dev.get("vendor") and _norm(product["vendor"]) != _norm(dev["vendor"]):
        return None
    by_name = {_norm(k): (k, v) for k, v in (obs.get("firmware") or {}).items()}
    rows = []
    for fw in product.get("firmware") or []:
        hit = by_name.get(_norm(fw["name"]))
        seen = hit[1] if hit else None
        attested = fw["version"]
        rows.append({"name": fw["name"], "observed_name": hit[0] if hit else None, "observed_version": seen,
                     "attested_version": attested,
                     "agrees": None if hit is None else (attested == "any" or _norm(attested) == _norm(seen)),
                     "supportability": fw["supportability"], "signing": fw.get("signing"), "post_quantum": fw.get("post_quantum"),
                     "statement": fw.get("statement")})
    not_attested = sorted(k for k in (obs.get("firmware") or {}) if _norm(k) not in {_norm(fw["name"]) for fw in product.get("firmware") or []})
    return {"model": product["model"], "vendor": product.get("vendor"), "firmware": rows, "not_attested": not_attested,
            "tpm": product.get("tpm"), "crypto_modules": product.get("crypto_modules") or []}


def record(var: str | Path, path: str | Path, *, operator: str = "operator", signer=None) -> tuple[Run, dict]:
    """Bring one attestation in. The same document (by hash) already on a verified ledger is a no-op
    that returns that run; otherwise a new run records each product and matches it against every
    closed system scan on this deployment."""
    var = Path(var)
    raw = Path(path).read_bytes()
    digest = "sha256:" + sha256_hex(raw)
    doc = load(path)
    for prev in recorded(var):
        if prev["document"]["sha256"] == digest:
            return Run(var, prev["run"]), {"duplicate": True, "run": prev["run"], "document": prev["document"],
                                           "supplier": doc["supplier"], "products": len(doc["products"]), "matches": []}
    scope = _minimal_scope(operator)
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile=f"attestation:{doc['supplier']}",
                    kind=KIND, runner_id="pqch-attest")
    stored = run.dir / ("attestation" + ("".join(Path(path).suffixes) or ".yaml"))
    stored.write_bytes(raw)
    varmode.private(stored)
    document = {"name": Path(path).name, "path": str(stored.relative_to(var)), "sha256": digest}
    actor = {"kind": "human", "id": operator}
    systems = _system_runs(var)
    matches = []
    for product in doc["products"]:
        ev = run.ledger.append("attestation.recorded", actor, {
            "schema": SCHEMA, "grade": "reported", "document": document, "supplier": doc["supplier"], "issued": doc["issued"],
            "reference": doc.get("reference"), "illustrative": bool(doc.get("illustrative")), "product": product,
        })
        for srun, events in systems:
            obs = observed(events)
            m = match(product, obs)
            if m is None:
                continue
            agree = [r for r in m["firmware"] if r["agrees"] is True]
            differ = [r for r in m["firmware"] if r["agrees"] is False]
            unseen = [r for r in m["firmware"] if r["agrees"] is None]
            run.ledger.append("assessment.made", {"kind": "rule", "id": RULE}, {
                "subject": {"kind": "system", "name": obs["system"], "run": srun.id}, "rule_id": RULE,
                "classification": {"matched": True, "model": product["model"], "firmware": m["firmware"],
                                   "agree": len(agree), "differ": len(differ), "unseen": len(unseen),
                                   "not_attested": m["not_attested"]},
                "basis": (f"the server reports {obs['device'].get('vendor', '')} {obs['device'].get('model', '')}; the statement names "
                          f"{len(m['firmware'])} firmware(s): {len(agree)} at the attested version, {len(differ)} at another version, "
                          f"{len(unseen)} the server did not report; {len(m['not_attested'])} the server reports and the statement does not name"),
            }, inputs=[ev["id"]])
            matches.append({"system": obs["system"], "run": srun.id, "agree": len(agree), "differ": len(differ), "unseen": len(unseen)})
    run.close(signer)
    return run, {"duplicate": False, "run": run.id, "document": document, "supplier": doc["supplier"],
                 "products": len(doc["products"]), "matches": matches}


def for_system(var: str | Path, events: list[dict]) -> dict | None:
    """The latest statement that matches a system scan's device, joined firmware by firmware to what
    the scan observed, for the pages: reported evidence beside observed, never merged into it."""
    obs = observed(events)
    if not obs["device"].get("model"):
        return None
    for r in recorded(var):
        m = match(r["product"], obs)
        if m:
            import os

            m["crypto_modules"] = cmvp_lookup(m["crypto_modules"], os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots"))
            return {"supplier": r["supplier"], "issued": r["issued"], "reference": r.get("reference"),
                    "illustrative": r.get("illustrative", False), "document": r["document"], "run": r["run"], "event": r["event"],
                    "system": obs["system"], **m}
    return None


def cmvp_lookup(modules: list[dict], snapshots: str | Path = "policy/snapshots") -> list[dict]:
    """Each attested module against the dated CMVP snapshot: the certificate's status, sunset, the
    module as CMVP names it, and whether its approved algorithms include ML-KEM and ML-DSA. A module
    with no certificate, or one the snapshot does not hold, says so."""
    snaps = sorted(Path(snapshots).glob("cmvp-*.json"))
    snap = json.loads(snaps[-1].read_text()) if snaps else None
    certs = (snap or {}).get("certificates") or {}
    out = []
    for m in modules:
        n = m.get("cmvp_certificate")
        row = {**m, "cmvp": None}
        if n is None:
            row["cmvp"] = {"state": "not-validated", "basis": "the statement names no CMVP certificate"}
        elif snap is None:
            row["cmvp"] = {"state": "unknown", "basis": "no CMVP snapshot on this deployment"}
        elif str(n) in certs:
            c = certs[str(n)]
            row["cmvp"] = {"state": "found", "status": c.get("status"), "sunset": c.get("sunset"), "module": c.get("module"),
                           "vendor": c.get("vendor"), "standard": c.get("standard"), "approved_ml_kem": c.get("approved_ml_kem"),
                           "approved_ml_dsa": c.get("approved_ml_dsa"), "taken_at": snap.get("taken_at"),
                           "name_matches": _norm(c.get("module")) == _norm(m.get("name"))}
        else:
            row["cmvp"] = {"state": "not-in-snapshot", "taken_at": snap.get("taken_at"),
                           "basis": f"certificate {n} is not in the snapshot of {str(snap.get('taken_at'))[:10]} ({len(certs)} certificates, searched for the libraries the estate runs); look it up at CMVP"}
        out.append(row)
    return out


def summary_line(att: dict | None) -> str | None:
    """One line for a table cell: each firmware's supportability, or None."""
    if not att:
        return None
    parts = []
    for fw in att["firmware"]:
        mark = "" if fw["agrees"] else (" (version differs)" if fw["agrees"] is False else " (not reported by the server)")
        parts.append(f"{fw['name']}: {fw['supportability']}{mark}")
    return "; ".join(parts)


def as_json(obj) -> str:
    return json.dumps(obj, indent=1, sort_keys=True)
