"""Score a CBOM against an answer key, by layer (agency/answer-key.yaml, header).

For each layer: present items covered, out-of-reach items (in the denominator,
always reported as known misses), and false positives. A false positive is a
decoy reported, or an unplanted claim: a key-establishment or signature
component on a keyed listener that matches no item. The key is exact for
asymmetric cryptography on the wire, so such a claim is wrong, not extra.
Other components that match no item are counted as unkeyed: outside the key's
scope (hashes, symmetric algorithms, material derived from a keyed file).
A layer in which a column holds no component at all is marked not scanned, and
its decoys are not presented as avoided. Listener postures are scored where
the CBOM states one.

An item is reported when a component matches it and is not marked
`pqch:in-use` = `false`.

Supplied items (class `supplied`: the owner's mission function, data lifetime
and high-value status) are never coverage. They are scored separately: carried
when the CBOM's service component holds every fact and labels each one as
supplied; a fact carried without the label is a defect, listed as such.
The verifier kinds the CBOM states per entry (`pqch:verifiable-by`) are
counted, so the receipts can say how many entries no verifier can confirm.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from pqch.common import sha256_hex

LAYERS = ("wire", "host", "code")
COLUMNS = (("baseline-cbomkit", "CBOMkit alone"), ("baseline-scanners", "Scanners alone"),
           ("workbench", "Workbench"))


def _props(c: dict) -> dict:
    return {p["name"]: p["value"] for p in c.get("properties", [])}


def _repo(image_ref: str) -> str:
    """The repository path, without registry host, tag or digest: where an image is served
    from is not which image it is."""
    name = image_ref.split("@")[0]
    last = name.rsplit("/", 1)[-1]
    name = name.rsplit(":", 1)[0] if ":" in last else name
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        name = rest
    return name


def _component_view(c: dict) -> dict | None:
    p = _props(c)
    if p.get("pqch:kind") in ("listener", "service", "image") or "pqch:layer" not in p:
        return None
    return {
        "layer": p["pqch:layer"],
        "subject": json.loads(p["pqch:subject"]),
        "type": p["pqch:asset-type"],
        "role": p["pqch:role"],
        "name": p["pqch:name"],
        "parameters": json.loads(p.get("pqch:parameters", "{}")),
        "in_use": p.get("pqch:in-use", "unknown"),
        "verifiable_by": p.get("pqch:verifiable-by"),
        "ref": c["bom-ref"],
    }


def matches(item: dict, comp: dict) -> bool:
    if item["layer"] != comp["layer"]:
        return False
    asset = item.get("asset", {})
    s = comp["subject"]
    if item["layer"] == "wire":
        subj = item.get("subject", {})
        if "port" not in subj or s.get("kind") != "endpoint":
            return False
        return (s["host"] == subj["host"] and s["port"] == subj["port"]
                and comp["role"] == asset.get("role") and comp["name"] == asset.get("name")
                and ("type" not in asset or comp["type"] == asset["type"]))
    if item["layer"] == "host":
        return (s.get("kind") == "file" and _repo(s.get("image", "")) == item["image"]
                and s["path"] in item["paths"] and comp["type"] == asset.get("type")
                and comp["name"] == asset.get("name"))
    if item["layer"] == "code":
        return (s.get("kind") == "call-site" and s["path"] == item["path"]
                and item["contains"] in comp["parameters"].get("line_text", ""))
    return False


def score_bom(bom: dict, key: dict) -> dict:
    comps = [v for c in bom.get("components", []) if (v := _component_view(c))]
    items = [i for i in key["items"] if i["class"] != "supplied"]
    layers = {}
    matched_refs: set[str] = set()
    keyed_listeners = {(e["host"], e["port"]) for e in key.get("posture", [])}
    for layer in LAYERS:
        row = {"present": 0, "covered": 0, "out_of_reach": 0, "decoys": 0, "false_positives": 0,
               "missed": [], "flagged_decoys": [], "covered_items": [], "unplanted": [],
               "scanned": any(c["layer"] == layer for c in comps)}
        for item in (i for i in items if i["layer"] == layer):
            hits = [c for c in comps if matches(item, c)]
            matched_refs.update(c["ref"] for c in hits)
            reported = any(c["in_use"] != "false" for c in hits)
            if item["class"] == "present":
                row["present"] += 1
                if reported:
                    row["covered"] += 1
                    row["covered_items"].append(item["id"])
                else:
                    row["missed"].append(item["id"])
            elif item["class"] == "out-of-reach":
                row["out_of_reach"] += 1
                row["missed"].append(item["id"])
            elif item["class"] == "decoy":
                row["decoys"] += 1
                if reported:
                    row["false_positives"] += 1
                    row["flagged_decoys"].append(item["id"])
        row["denominator"] = row["present"] + row["out_of_reach"]
        layers[layer] = row
    for c in comps:
        s = c["subject"]
        if (c["layer"] == "wire" and c["ref"] not in matched_refs and c["in_use"] != "false"
                and c["role"] in ("key-establishment", "signature")
                and (s.get("host"), s.get("port")) in keyed_listeners):
            matched_refs.add(c["ref"])
            layers["wire"]["unplanted"].append(f"{s['host']}:{s['port']} {c['role']} {c['name']}")
            layers["wire"]["false_positives"] += 1

    posture = None
    listeners = [_props(c) for c in bom.get("components", []) if _props(c).get("pqch:kind") == "listener"]
    if any("pqch:posture" in p for p in listeners):
        stated = {}
        for p in listeners:
            s = json.loads(p["pqch:subject"])
            stated[(s["host"], s["port"])] = p.get("pqch:posture")
        expect = {(e["host"], e["port"]): e["posture"] for e in key.get("posture", [])}
        posture = {"correct": sum(stated.get(k) == v for k, v in expect.items()), "total": len(expect),
                   "wrong": [f"{h}:{p}" for (h, p), v in expect.items() if stated.get((h, p)) != v]}

    unkeyed = [c for c in comps if c["ref"] not in matched_refs]
    return {"layers": layers, "posture": posture, "unkeyed": len(unkeyed),
            "components": len(comps), "supplied": score_supplied(bom, key),
            "verifiers": count_verifiers(comps)}


_FACTS = {"mission_function": "pqch:mission-function", "data_lifetime_years": "pqch:data-lifetime-years",
          "high_value_asset": "pqch:high-value-asset"}
_KINDS = {"mission_function": "mission-function", "data_lifetime_years": "data-lifetime",
          "high_value_asset": "high-value-asset"}


def score_supplied(bom: dict, key: dict) -> dict | None:
    """The key's supplied items against the CBOM's service components: carried and labelled, carried
    unlabelled (a defect), or missed. None when the key holds no supplied item."""
    items = [i for i in key["items"] if i["class"] == "supplied"]
    if not items:
        return None
    services = {}
    for c in bom.get("components", []):
        p = _props(c)
        if p.get("pqch:kind") == "service":
            services[c["name"]] = {"props": p, "labelled": {s["name"] for s in json.loads(p.get("pqch:supplied", "[]"))}}
    out = {"total": len(items), "carried": 0, "unlabelled": [], "missed": []}
    for item in items:
        svc = services.get(item["subject"]["service"])
        facts = item.get("facts", {})
        if svc is None:
            out["missed"].append(item["id"])
            continue
        held = all(_FACTS[k] in svc["props"] and json.loads(svc["props"][_FACTS[k]]) == v
                   if not isinstance(v, str) else svc["props"].get(_FACTS[k]) == v for k, v in facts.items())
        if not held:
            out["missed"].append(item["id"])
        elif any(_KINDS[k] not in svc["labelled"] for k in facts):
            out["unlabelled"].append(item["id"])
        else:
            out["carried"] += 1
    return out


def count_verifiers(comps: list[dict]) -> dict:
    """How many entries each verifier kind can confirm; `unstated` when the CBOM says nothing."""
    out: dict[str, int] = {}
    for c in comps:
        k = c.get("verifiable_by") or "unstated"
        out[k] = out.get(k, 0) + 1
    return out


def score_run(run_dir: Path, key_path: Path, *, recorded_sha256: str | None) -> dict:
    """All three columns for one run. Refuses a key whose hash differs from the one the run recorded."""
    data = key_path.read_bytes()
    digest = sha256_hex(data)
    if not recorded_sha256:
        raise ValueError("the run recorded no answer key (no key.committed event); it cannot be scored")
    if digest != recorded_sha256:
        raise ValueError(f"answer key {key_path} has sha256 {digest[:12]}, the run recorded {recorded_sha256[:12]}")
    key = yaml.safe_load(data)
    out = {"key": {"path": str(key_path), "sha256": digest}, "columns": {}}
    for name, label in COLUMNS:
        bom = json.loads((run_dir / f"{name}.cdx.json").read_text())
        out["columns"][name] = {"label": label, **score_bom(bom, key)}
    return out


def table(result: dict) -> str:
    """The score as a plain-text table, one row per layer."""
    cols = result["columns"]
    lines = [f"{'':<10}" + "".join(f"{cols[n]['label']:>24}" for n, _ in COLUMNS)]
    for layer in LAYERS:
        cells = []
        for n, _ in COLUMNS:
            r = cols[n]["layers"][layer]
            cells.append("not scanned" if not r["scanned"] and not r["denominator"]
                         else f"{r['covered']}/{r['denominator']}  fp {r['false_positives']}"
                              f" (decoys {len(r['flagged_decoys'])}/{r['decoys']})")
        lines.append(f"{layer:<10}" + "".join(f"{c:>24}" for c in cells))
    lines.append(f"{'posture':<10}" + "".join(
        f"{('—' if cols[n]['posture'] is None else str(cols[n]['posture']['correct']) + '/' + str(cols[n]['posture']['total'])):>24}"
        for n, _ in COLUMNS))
    lines.append(f"{'unkeyed':<10}" + "".join(f"{cols[n]['unkeyed']:>24}" for n, _ in COLUMNS))
    return "\n".join(lines)
