"""The CycloneDX 1.6 CBOM: a pure function of the ledger (ADR-0001, decision 4).

`project(events)` builds the workbench CBOM: one component per finding
fingerprint, one protocol component per listener, one `application` component
per service and one `container` per image the rules linked, the dependency
chain the rules asserted (service -> listener -> asset -> file; service ->
image -> file), the owner's supplied facts on the service with each one
labelled supplied, and the rules' judgements as `pqch:` properties. The same
events in give the same document out, byte for byte; nothing here reads the
clock or draws a random number.

`project(events, tools=..., rules=False)` builds a baseline from the same
ledger: the findings of the named tools only, with no rule applied.

Every document is validated against the CycloneDX 1.6.1 JSON schema, vendored
in `schema/` (CycloneDX/specification tag 1.6.1, commit 8a27bfd).
"""

from __future__ import annotations

import json
import uuid
from functools import cache
from importlib import resources

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from pqch.common import canonical

SPEC_VERSION = "1.6"

_PRIMITIVE = {
    "key-establishment": "key-agree",
    "signature": "signature",
    "encryption": "pke",
    "hash": "hash",
    "mac": "mac",
    "other": "other",
}
_KEM_NAMES = ("MLKEM", "ML-KEM", "sntrup")


@cache
def _validator() -> Draft7Validator:
    pkg = resources.files(__package__).joinpath("schema")
    docs = {n: json.loads(pkg.joinpath(n).read_text())
            for n in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")}
    registry = Registry().with_resources((d["$id"], Resource.from_contents(d)) for d in docs.values())
    return Draft7Validator(docs["bom-1.6.schema.json"], registry=registry,
                           format_checker=Draft7Validator.FORMAT_CHECKER)


def validate(bom: dict) -> list[str]:
    """Schema errors, as readable strings. Empty when the document is valid."""
    return [f"{'/'.join(map(str, e.absolute_path))}: {e.message}"
            for e in sorted(_validator().iter_errors(bom), key=lambda e: list(map(str, e.path)))]


def _prop(name: str, value) -> dict:
    if not isinstance(value, str):
        value = canonical(value).decode()
    return {"name": f"pqch:{name}", "value": value}


def _location(subject: dict) -> str:
    if subject["kind"] == "endpoint":
        return f"{subject['host']}:{subject['port']}"
    if subject["kind"] == "file":
        return f"{subject.get('image') or subject.get('host')}:{subject['path']}"
    if subject["kind"] == "client":
        return f"client:{subject['host']}"
    return f"{subject['repo']}@{subject['commit']}:{subject['path']}#L{subject['line']}"


def _listener_ref(subject: dict) -> str:
    return f"listener:{subject['host']}:{subject['port']}"


def _crypto_properties(asset: dict) -> dict:
    t, p = asset["type"], asset.get("parameters", {})
    if t == "algorithm":
        prim = _PRIMITIVE.get(asset["role"], "other")
        if asset["role"] == "key-establishment" and any(k in asset["name"] for k in _KEM_NAMES):
            prim = "kem"
        props = {"primitive": prim}
        if p.get("curve"):
            props["curve"] = p["curve"]
        if p.get("key_bits"):
            props["parameterSetIdentifier"] = str(p["key_bits"])
        return {"assetType": "algorithm", "algorithmProperties": props}
    if t == "certificate":
        props = {"certificateFormat": "X.509"}
        for src, dst in (("subject", "subjectName"), ("issuer", "issuerName"),
                         ("not_before", "notValidBefore"), ("not_after", "notValidAfter")):
            if isinstance(p.get(src), str):
                props[dst] = p[src]
        return {"assetType": "certificate", "certificateProperties": props}
    if t == "related-crypto-material":
        kinds = p.get("kind") or ["unknown"]
        kind = kinds[0] if len(kinds) == 1 else "key"
        # CycloneDX 1.6 names the kinds of material it knows; the harness's finer kinds (a
        # keystore, DH parameters) are carried in pqch:parameters and mapped onto the nearest.
        props = {"type": kind if kind in _RCM_TYPES else _RCM_MAP.get(kind, "other")}
        if isinstance(p.get("key_bits"), int):
            props["size"] = p["key_bits"]
        return {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": props}
    return {"assetType": "protocol", "protocolProperties": {"type": "other"}}


_RCM_TYPES = {"private-key", "public-key", "secret-key", "key", "ciphertext", "signature", "digest",
              "initialization-vector", "nonce", "seed", "salt", "shared-secret", "tag", "additional-data",
              "password", "credential", "token", "other", "unknown"}
_RCM_MAP = {"keystore": "key", "dh-parameters": "other"}


def project(events: list[dict], *, tools: set[str] | None = None, rules: bool = True,
            label: str = "workbench") -> dict:
    head = events[-1]
    started = events[0]

    # Findings, folded by fingerprint.
    comps: dict[str, dict] = {}
    finding_fp: dict[str, str] = {}
    tool_versions: dict[str, str] = {}
    for ev in events:
        if ev["type"] != "finding.observed":
            continue
        f = ev["payload"]
        if tools is not None and f["source"]["tool"] not in tools:
            continue
        fp = f["fingerprint"]
        finding_fp[ev["id"]] = fp
        tool_versions[f["source"]["tool"]] = f["source"]["version"]
        c = comps.setdefault(fp, {"finding": f, "events": [], "tools": set(), "in_use": None,
                                  "in_use_rule": None, "links": set()})
        c["events"].append(ev["id"])
        c["tools"].add(f["source"]["tool"])

    postures: dict[tuple[str, int], dict] = {}
    deps: dict[str, set[str]] = {}
    svc_of_listener: dict[tuple[str, int], tuple[str, str]] = {}      # (host, port) -> (service, event)
    svc_of_image: dict[str, tuple[str, str]] = {}                      # image ref -> (service, event)
    supplied: dict[str, dict[str, dict]] = {}                          # service -> kind -> {value, event, by}
    conflicts: dict[str, dict] = {}                                    # finding event id -> judgement
    verifiable: dict[tuple[str, str, str], tuple[str, str]] = {}       # (layer, type, role) -> (kind, event)
    qvuln: dict[tuple[str, str], dict] = {}                            # (role, name) -> classification
    priority: dict[str, dict] = {}                                     # service -> classification
    migration: dict[str, list[dict]] = {}                              # service -> items
    blockers: dict[tuple[str, str], dict] = {}                         # (service, function) -> rule -> state
    tls13: dict[tuple[str, int], dict] = {}
    if rules:
        for ev in events:
            p = ev["payload"]
            rid = p.get("rule_id") if ev["type"] == "assessment.made" else None
            if rid == "quantum/vulnerable/1":
                qvuln[(p["subject"]["role"], p["subject"]["name"])] = {**p["classification"], "event": ev["id"]}
                continue
            if rid == "priority/m-26-15/1":
                priority[p["subject"]["name"]] = {**p["classification"], "event": ev["id"]}
                continue
            if rid == "queue/m-26-15/1":
                migration.setdefault(p["subject"]["service"], []).append(
                    {"function": p["subject"]["function"], **{k: p["classification"][k] for k in
                     ("state", "queue", "deadline", "deadline_basis")}, "event": ev["id"]})
                continue
            if rid in ("blocker/supplier/1", "blocker/validated-module/1"):
                blockers.setdefault((p["subject"]["service"], p["subject"]["function"]), {})[
                    rid.split("/")[1]] = p["classification"]["state"]
                continue
            if rid == "deadline/tls13/1":
                tls13[(p["subject"]["host"], p["subject"]["port"])] = {**p["classification"], "event": ev["id"]}
                continue
            if ev["type"] == "link.asserted" and isinstance(p["from"], str):
                if p["from"] in finding_fp and p["to"] in finding_fp:
                    a, b = finding_fp[p["from"]], finding_fp[p["to"]]
                    comps[a]["links"].add(b)
                    deps.setdefault(a, set()).add(b)
            elif ev["type"] == "link.asserted" and p.get("status") == "supplied":
                supplied.setdefault(p["from"]["name"], {})[p["kind"]] = {
                    "value": p["to"]["value"], "event": ev["id"], "by": ev["actor"]["id"]}
            elif ev["type"] == "link.asserted" and p["to"].get("kind") == "service":
                if p["from"]["kind"] == "endpoint":
                    svc_of_listener[(p["from"]["host"], p["from"]["port"])] = (p["to"]["name"], ev["id"])
                elif p["from"]["kind"] == "image":
                    svc_of_image[p["from"]["image"]] = (p["to"]["name"], ev["id"])
            elif ev["type"] == "assessment.made" and p.get("rule_id") == "conflict/resolve/1":
                conflicts[p["finding"]] = {**p["classification"], "event": ev["id"]}
            elif ev["type"] == "assessment.made" and p.get("rule_id") == "verifier/class/1":
                sj = p["subject"]
                verifiable[(sj["layer"], sj["type"], sj["role"])] = (p["classification"]["verifiable_by"], ev["id"])
            elif ev["type"] == "assessment.made" and "in_use" in p.get("classification", {}):
                fp = finding_fp.get(p["finding"])
                if fp:
                    comps[fp]["in_use"] = p["classification"]["in_use"]
                    comps[fp]["in_use_rule"] = p["rule_id"]
            elif ev["type"] == "assessment.made" and "posture" in p.get("classification", {}):
                postures[(p["subject"]["host"], p["subject"]["port"])] = p["classification"]

    components = []
    listeners: dict[str, dict] = {}
    for fp in sorted(comps):
        c = comps[fp]
        f = c["finding"]
        subj = f["subject"]
        in_use = "true" if f["layer"] == "wire" else (
            "unknown" if c["in_use"] is None else str(c["in_use"]).lower())
        props = [
            _prop("layer", f["layer"]),
            _prop("subject", subj),
            _prop("asset-type", f["asset"]["type"]),
            _prop("role", f["asset"]["role"]),
            _prop("name", f["asset"]["name"]),
            _prop("parameters", f["asset"].get("parameters", {})),
            _prop("fingerprint", fp),
            _prop("evidence", ",".join(c["events"])),
            _prop("tools", ",".join(sorted(c["tools"]))),
        ]
        if rules:
            props.append(_prop("in-use", in_use))
            if c["in_use_rule"]:
                props.append(_prop("in-use-rule", c["in_use_rule"]))
            kind = verifiable.get((f["layer"], f["asset"]["type"], f["asset"]["role"]))
            props.append(_prop("verifiable-by", kind[0] if kind else "unstated"))
            judged = next((conflicts[e] for e in c["events"] if e in conflicts), None)
            if judged:
                props.append(_prop("conflict", judged))
            qv = qvuln.get((f["asset"]["role"], f["asset"]["name"]))
            if qv:
                props.append(_prop("family", qv["family"]))
                props.append(_prop("quantum-vulnerable", "unknown" if qv["quantum_vulnerable"] is None
                                   else str(qv["quantum_vulnerable"]).lower()))
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"fp:{fp}",
            "name": f["asset"]["name"],
            "cryptoProperties": _crypto_properties(f["asset"]),
            "evidence": {"occurrences": [{"location": _location(subj)}]},
            "properties": props,
        })
        if subj["kind"] == "endpoint":
            ref = _listener_ref(subj)
            listeners.setdefault(ref, {"subject": subj, "members": []})["members"].append(f"fp:{fp}")

    for ref in sorted(listeners):
        subj = listeners[ref]["subject"]
        props = [_prop("kind", "listener"), _prop("subject", {k: subj[k] for k in ("host", "port", "protocol")})]
        posture = postures.get((subj["host"], subj["port"]))
        if posture:
            props.append(_prop("posture", posture["posture"]))
        svc = svc_of_listener.get((subj["host"], subj["port"]))
        if svc:
            props.append(_prop("service", svc[0]))
            props.append(_prop("service-evidence", svc[1]))
        t13 = tls13.get((subj["host"], subj["port"]))
        if t13:
            props.append(_prop("tls13", {"state": t13["state"], "versions": t13["versions"], "deadline": t13["deadline"],
                                         "event": t13["event"]}))
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": ref,
            "name": f"{subj['protocol'].upper()} {subj['host']}:{subj['port']}",
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                "type": subj["protocol"] if subj["protocol"] in ("tls", "ssh") else "other"}},
            "evidence": {"occurrences": [{"location": f"{subj['host']}:{subj['port']}"}]},
            "properties": props,
        })

    dependencies = [{"ref": ref, "dependsOn": sorted(listeners[ref]["members"])} for ref in sorted(listeners)]
    dependencies += [{"ref": f"fp:{a}", "dependsOn": sorted(f"fp:{b}" for b in bs)} for a, bs in sorted(deps.items())]

    # The chain above the listener: the service, with what the owner supplied about it, and the
    # image it runs. Every service known from a discovered link or a supplied fact is a component.
    services: dict[str, dict] = {}
    for (host, port), (name, ev_id) in svc_of_listener.items():
        s_ = services.setdefault(name, {"listeners": set(), "images": set(), "evidence": set()})
        s_["listeners"].add(f"listener:{host}:{port}")
        s_["evidence"].add(ev_id)
    for image, (name, ev_id) in svc_of_image.items():
        s_ = services.setdefault(name, {"listeners": set(), "images": set(), "evidence": set()})
        s_["images"].add(image)
        s_["evidence"].add(ev_id)
    for name in supplied:
        services.setdefault(name, {"listeners": set(), "images": set(), "evidence": set()})
    image_files: dict[str, list[str]] = {}
    for fp in sorted(comps):
        f = comps[fp]["finding"]
        if f["layer"] == "host" and f["subject"].get("image"):
            ref = f"{f['subject']['image']}@{f['source'].get('subject_digest', '')}"
            image_files.setdefault(ref, []).append(f"fp:{fp}")
    for name in sorted(services):
        s_ = services[name]
        facts = supplied.get(name, {})
        props = [_prop("kind", "service"), _prop("evidence", ",".join(sorted(s_["evidence"])))]
        for kind in ("mission-function", "data-lifetime", "high-value-asset"):
            if kind in facts:
                props.append(_prop({"data-lifetime": "data-lifetime-years"}.get(kind, kind), facts[kind]["value"]))
        props.append(_prop("supplied", [{"name": k, "event": v["event"], "by": v["by"]} for k, v in sorted(facts.items())]))
        if "owner" in facts:
            props.append(_prop("owner", facts["owner"]["value"]))
        if name in priority:
            props.append(_prop("priority", {k: priority[name][k] for k in ("prioritized", "criteria", "event")}))
        if name in migration:
            items = sorted(migration[name], key=lambda i: i["function"])
            props.append(_prop("migration", [{**i, "blockers": blockers.get((name, i["function"]), {})} for i in items]))
            open_items = [i for i in items if i["state"] == "open"]
            if open_items:
                first = min(open_items, key=lambda i: i["deadline"])
                props.append(_prop("queue", first["queue"]))
                props.append(_prop("deadline", first["deadline"]))
            props.append(_prop("state", "open" if open_items else "met"))
        components.append({"type": "application", "bom-ref": f"svc:{name}", "name": name, "properties": props})
        depends = sorted(s_["listeners"]) + sorted(f"img:{i.split('@')[0]}" for i in s_["images"])
        if depends:
            dependencies.append({"ref": f"svc:{name}", "dependsOn": depends})
    for image in sorted(svc_of_image):
        name, ev_id = svc_of_image[image]
        repo, digest = image.split("@", 1)
        components.append({
            "type": "container", "bom-ref": f"img:{repo}", "name": repo, "version": digest,
            "properties": [_prop("kind", "image"), _prop("image", image), _prop("service", name),
                           _prop("evidence", ev_id)],
        })
        files = image_files.get(image, [])
        if files:
            dependencies.append({"ref": f"img:{repo}", "dependsOn": sorted(files)})

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.UUID(hex=head['hash'][:32])}",
        "version": 1,
        "metadata": {
            "timestamp": head["ts"].split(".")[0] + "Z",
            "tools": {"components": [{"type": "application", "name": t, "version": v}
                                     for t, v in sorted(tool_versions.items())]
                      + [{"type": "application", "name": "cbom-workbench", "version": "m0"}]},
            "properties": [
                _prop("projection", label),
                _prop("run", started["payload"]["scope"]["id"] if started["type"] == "run.started" else ""),
                _prop("ledger-head", head["hash"]),
                _prop("ledger-seq", str(head["seq"])),
                _prop("scope-hash", started["payload"].get("scope_hash", "")),
            ],
        },
        "components": components,
        "dependencies": dependencies,
    }
    return bom


BASELINES = {
    "cbomkit": {"cbomkit-theia"},
    "scanners": {"cbomkit-theia", "testssl.sh", "ssh-audit"},
}


def build_all(events: list[dict]) -> dict[str, dict]:
    """The workbench CBOM and both baselines, each validated."""
    out = {"workbench": project(events)}
    for name, tools in BASELINES.items():
        out[f"baseline-{name}"] = project(events, tools=tools, rules=False, label=f"baseline:{name}")
    for name, bom in out.items():
        errors = validate(bom)
        if errors:
            raise ValueError(f"{name} CBOM fails CycloneDX 1.6: " + "; ".join(errors[:5]))
    return out
