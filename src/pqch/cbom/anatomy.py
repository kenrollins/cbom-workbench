"""The anatomy of a CBOM: the document, one component in it, every field explained and traced.

Read-only over a run's ledger and the CBOM rebuilt from it. For one component it returns the
component exactly as the CycloneDX document carries it, a row per field saying whether
CycloneDX 1.6 defines it or the `pqch:` namespace adds it, what it means (`fields.yaml`), and
the ledger events its value came from — the scanner's observation with its tool, excerpt and
raw-output hash, the rule that judged it, or the person who supplied it — and the components it
depends on and that depend on it.
"""

from __future__ import annotations

import json
from collections import Counter
from functools import cache
from importlib import resources

import yaml


@cache
def fields() -> dict:
    return yaml.safe_load(resources.files(__package__).joinpath("fields.yaml").read_text())


def _props(c: dict) -> dict:
    return {p["name"]: p["value"] for p in c.get("properties", [])}


def _flatten(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else k)
    else:
        yield prefix, obj


def kind_of(c: dict) -> str:
    k = _props(c).get("pqch:kind")
    if k:
        return k
    return {"application": "service", "container": "image"}.get(c["type"], _props(c).get("pqch:layer", "asset") + " asset")


def label_of(c: dict) -> str:
    p = _props(c)
    if p.get("pqch:layer"):
        s = json.loads(p["pqch:subject"])
        where = f"{s['host']}:{s['port']}" if s["kind"] == "endpoint" else (s.get("path") or s.get("host", ""))
        return f"{c['name']} {p.get('pqch:asset-type', '')} · {where}"
    return c["name"]


def document(bom: dict) -> dict:
    comps = bom.get("components", [])
    meta = {p["name"]: p["value"] for p in bom.get("metadata", {}).get("properties", [])}
    by_kind = Counter(kind_of(c) for c in comps)
    by_asset = Counter(c.get("cryptoProperties", {}).get("assetType") for c in comps if c["type"] == "cryptographic-asset"
                       and _props(c).get("pqch:layer"))
    return {"spec": f"{bom['bomFormat']} {bom['specVersion']}", "serial": bom["serialNumber"],
            "timestamp": bom["metadata"]["timestamp"],
            "tools": [f"{t['name']} {t['version']}" for t in bom["metadata"]["tools"]["components"]],
            "meta": [{"name": k, "value": v, **fields()["metadata"].get(k, {})} for k, v in meta.items()],
            "components": len(comps), "by_kind": dict(by_kind), "by_asset_type": {k or "—": v for k, v in by_asset.items()},
            "dependencies": len(bom.get("dependencies", [])),
            "edges": sum(len(d["dependsOn"]) for d in bom.get("dependencies", []))}


def entries(bom: dict) -> list[dict]:
    order = {"service": 0, "image": 1, "listener": 2, "wire asset": 3, "host asset": 4}
    out = [{"ref": c["bom-ref"], "kind": kind_of(c), "label": label_of(c)} for c in bom.get("components", [])]
    return sorted(out, key=lambda e: (order.get(e["kind"], 9), e["label"]))


def default_ref(bom: dict) -> str | None:
    """An entry with a long chain: a certificate the wire served whose key is a file in an image."""
    dep = {d["ref"]: d["dependsOn"] for d in bom.get("dependencies", [])}
    for c in bom.get("components", []):
        p = _props(c)
        if p.get("pqch:layer") == "wire" and p.get("pqch:asset-type") == "certificate" and dep.get(c["bom-ref"]):
            if "5432" in p.get("pqch:subject", ""):
                return c["bom-ref"]
    for want in ("certificate", None):
        for c in bom.get("components", []):
            p = _props(c)
            if p.get("pqch:layer") == "wire" and dep.get(c["bom-ref"]) and want in (None, p.get("pqch:asset-type")):
                return c["bom-ref"]
    return (bom.get("components") or [{}])[0].get("bom-ref")


def _finding_evidence(ev: dict, by_id: dict) -> dict:
    f = ev["payload"]
    scan = by_id.get(ev["inputs"][0]) if ev["inputs"] else None
    return {"event": ev["id"], "seq": ev["seq"], "kind": "finding", "who": f"{f['source']['tool']} {f['source']['version']}",
            "what": f["evidence"]["excerpt"], "raw": f["evidence"]["raw"], "sha256": f["evidence"]["sha256"],
            "scanner_digest": f["source"].get("image_digest"),
            "scan": scan and {"event": scan["id"], "profile": scan["payload"]["profile"], "ms": scan["payload"]["duration_ms"],
                              "replayed": bool(scan["payload"].get("replayed_from"))}}


def _rule_evidence(ev: dict) -> dict:
    p = ev["payload"]
    actor = ev["actor"]
    return {"event": ev["id"], "seq": ev["seq"], "kind": actor["kind"], "who": p.get("rule_id") or actor["id"],
            "what": p.get("basis", ""), "source": p.get("source")}


def component(bom: dict, events: list[dict], ref: str) -> dict | None:
    comp = next((c for c in bom.get("components", []) if c["bom-ref"] == ref), None)
    if comp is None:
        return None
    F = fields()
    by_id = {e["id"]: e for e in events}
    p = _props(comp)
    finding_ids = [i for i in (p.get("pqch:evidence") or "").split(",") if i in by_id and by_id[i]["type"] == "finding.observed"]
    fset = set(finding_ids)
    first = by_id[finding_ids[0]]["payload"] if finding_ids else None

    # Every rule or person's event that speaks about this component.
    def about(e: dict) -> bool:
        if e["type"] not in ("assessment.made", "link.asserted"):
            return False
        pl = e["payload"]
        if pl.get("finding") in fset or (isinstance(pl.get("from"), str) and (pl["from"] in fset or pl.get("to") in fset)):
            return True
        if set(e.get("inputs", [])) & fset and pl.get("rule_id") in ("quantum/vulnerable/1", "verifier/class/1",
                                                                      "posture/kex-auth/1", "queue/m-26-15/1"):
            return True
        name = comp["name"]
        if comp["type"] == "application":
            subj = pl.get("subject") or {}
            return (subj.get("name") == name or subj.get("service") == name
                    or (isinstance(pl.get("from"), dict) and pl["from"].get("name") == name)
                    or (isinstance(pl.get("to"), dict) and pl["to"].get("name") == name and pl["to"].get("kind") == "service"))
        if p.get("pqch:kind") == "listener":
            s = json.loads(p["pqch:subject"])
            subj = pl.get("subject") or (pl.get("from") if isinstance(pl.get("from"), dict) else {}) or {}
            return subj.get("host") == s["host"] and subj.get("port") == s["port"]
        if comp["type"] == "container":
            return isinstance(pl.get("from"), dict) and pl["from"].get("image", "").split("@")[0] == name
        return False

    related = [e for e in events if about(e)]

    def evidence_for(key: str, origin: str) -> list[dict]:
        src = (F[origin].get(key) or {}).get("from", "")
        if src in ("finding",) and finding_ids:
            return [_finding_evidence(by_id[i], by_id) for i in finding_ids]
        if src == "supplied":
            kind = {"pqch:mission-function": "mission-function", "pqch:data-lifetime-years": "data-lifetime",
                    "pqch:high-value-asset": "high-value-asset", "pqch:owner": "owner"}.get(key)
            return [_rule_evidence(e) | {"who": e["actor"]["id"], "kind": "supplied"} for e in related
                    if e["type"] == "link.asserted" and e["payload"].get("status") == "supplied"
                    and (kind is None or e["payload"]["kind"] == kind)]
        if src.startswith("rule:") or src == "rule":
            rules = [r.strip().removeprefix("rule:") for r in src.split(",")]
            return [_rule_evidence(e) for e in related if src == "rule" or e["payload"].get("rule_id") in rules]
        return []

    rows = []
    for path, value in _flatten({k: v for k, v in comp.items() if k != "properties"}):
        key = path.replace(".occurrences.0", ".occurrences") if "occurrences" in path else path
        if key.startswith("evidence.occurrences"):
            key = "evidence.occurrences"
        info = F["cyclonedx"].get(key) or F["cyclonedx"].get(path) or {}
        rows.append({"field": path, "origin": "CycloneDX 1.6", "value": value, "meaning": info.get("meaning", ""),
                     "evidence": evidence_for(key, "cyclonedx") if key in F["cyclonedx"] else []})
    for name, value in p.items():
        info = F["pqch"].get(name, {})
        try:
            shown = json.loads(value) if value[:1] in "[{" else value
        except (TypeError, json.JSONDecodeError):
            shown = value
        rows.append({"field": name, "origin": "pqch: extension", "value": shown, "meaning": info.get("meaning", ""),
                     "from": info.get("from", ""), "evidence": evidence_for(name, "pqch") if name in F["pqch"] else []})

    deps = {d["ref"]: d["dependsOn"] for d in bom.get("dependencies", [])}
    names = {c["bom-ref"]: (kind_of(c), label_of(c)) for c in bom.get("components", [])}
    evid = {c["bom-ref"]: set((_props(c).get("pqch:evidence") or "").split(",")) for c in bom.get("components", [])}

    def link(a: str, b: str) -> dict | None:
        """The ledger event that joined two components, when one did: a link between their findings."""
        ea, eb = evid.get(a, set()), evid.get(b, set())
        for e in events:
            if e["type"] == "link.asserted" and isinstance(e["payload"]["from"], str) \
                    and e["payload"]["from"] in ea | eb and e["payload"]["to"] in ea | eb:
                return {"event": e["id"], "rule": e["payload"].get("rule_id"), "basis": e["payload"].get("basis")}
        return None

    depends_on = [{"ref": r, "kind": names.get(r, ("?", r))[0], "label": names.get(r, ("?", r))[1], "link": link(ref, r)}
                  for r in deps.get(ref, [])]
    depended_by = [{"ref": a, "kind": names.get(a, ("?", a))[0], "label": names.get(a, ("?", a))[1], "link": link(a, ref)}
                   for a, bs in deps.items() if ref in bs]
    raw_json = json.dumps(comp, indent=1, ensure_ascii=False)
    return {"ref": ref, "kind": kind_of(comp), "label": label_of(comp), "json": raw_json, "rows": rows,
            "depends_on": depends_on, "depended_by": depended_by,
            "standard_fields": sum(1 for r in rows if r["origin"].startswith("CycloneDX")),
            "extension_fields": sum(1 for r in rows if r["origin"].startswith("pqch")),
            "observation": first and {"layer": first["layer"], "subject": first["subject"]},
            "events": len({x["event"] for r in rows for x in r["evidence"]})}


def diff(before: dict, after: dict) -> dict:
    """Two CBOMs compared by component reference: added, removed, and changed with the fields that
    changed. The reference of an observed asset is its fingerprint, so a component that keeps its
    reference is the same observation; volatile document fields are left out."""
    # Event ids are new on every scan of the same observation: references to events are left out,
    # so what is compared is what the record says, not which event said it.
    skip = {"pqch:evidence", "pqch:service-evidence"}

    def comp_map(bom):
        return {c["bom-ref"]: c for c in bom.get("components", [])}

    a, b = comp_map(before), comp_map(after)

    def strip(v):
        if isinstance(v, dict):
            return {k: strip(x) for k, x in v.items() if k != "event"}
        if isinstance(v, list):
            return [strip(x) for x in v]
        return v

    def fields_of(c):
        out = dict(_flatten({k: v for k, v in c.items() if k != "properties"}))
        for k, v in _props(c).items():
            if k in skip:
                continue
            try:
                parsed = json.loads(v) if isinstance(v, str) and v[:1] in "[{" else v
            except json.JSONDecodeError:
                parsed = v
            out[k] = json.dumps(strip(parsed), sort_keys=True) if isinstance(parsed, (dict, list)) else parsed
        return out

    changed = []
    for ref in sorted(set(a) & set(b)):
        fa, fb = fields_of(a[ref]), fields_of(b[ref])
        delta = [{"field": k, "before": fa.get(k), "after": fb.get(k)} for k in sorted(set(fa) | set(fb)) if fa.get(k) != fb.get(k)]
        if delta:
            changed.append({"ref": ref, "kind": kind_of(b[ref]), "label": label_of(b[ref]), "fields": delta})
    return {"added": [{"ref": r, "kind": kind_of(b[r]), "label": label_of(b[r])} for r in sorted(set(b) - set(a))],
            "removed": [{"ref": r, "kind": kind_of(a[r]), "label": label_of(a[r])} for r in sorted(set(a) - set(b))],
            "changed": changed, "same": len(set(a) & set(b)) - len(changed)}


def model_work(bom: dict, ref: str, traces: dict, manifests: dict | None = None) -> list[dict]:
    """What a model did with this entry: each trace of its observation, with the CBOM context the
    investigator handed over — the finding, the service the chain joins it to, the files read —
    and the answer, which stays the model's claim."""
    comp = next((c for c in bom.get("components", []) if c["bom-ref"] == ref), None)
    if comp is None:
        return []
    fp = _props(comp).get("pqch:fingerprint")
    t = traces.get(fp) if fp else None
    if not t:
        return []
    p = t["payload"]
    now = (manifests or {}).get(p["service"])
    if now is not None and {f["path"]: f["sha256"] for f in p["files"]} != now:
        return []        # traced over files that have since changed
    return [{"job": "trace to cause", "event": t["id"], "run": t["run"], "actor": t["actor"],
             "given": {"finding": {"subject": p["finding"]["subject"], "asset": p["finding"]["asset"]},
                       "service": p["service"], "files": [f["path"] for f in p["files"]]},
             "answer": p["answer"], "line_text": p["line_text"], "outcome": p["outcome"],
             "steps": p["used"]["steps"], "tokens": p["used"]["tokens"], "latency_ms": p["latency_ms"],
             "key_check": p.get("key_check"), "settings": p["settings"]}]
