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

Two findings with one fingerprint are two claims about one entry (M9). Every
claim is kept: the entry carries them all (`pqch:claims`), the one in force is
chosen by the grade of its evidence (`policy/precedence.yaml`: watched on the
wire, read from a host, parsed from a file, reported in a document, in that
order; the earliest at equal grade), a parameter the claims disagree on is
written as `pqch:dissent` with every value and who said it, and a person's
`claim.resolved` event sets a field over the rule until a `resolution.revoked`
event cites it. Nothing is folded into a list of both and no field changes
type. `project_estate(runs)` projects one document over several runs' ledgers,
each pinned by its head: same runs in, same document out.

Every document is validated against the CycloneDX 1.6.1 JSON schema, vendored
in `schema/` (CycloneDX/specification tag 1.6.1, commit 8a27bfd).
"""

from __future__ import annotations

import json
import uuid
from functools import cache
from importlib import resources

import yaml
from jsonschema import Draft7Validator
from referencing import Registry, Resource

from pqch.common import canonical, hash_object
from pqch.policy import ROOT as _POLICY_ROOT
from pqch.policy import algorithm_ids, classical_strength, family_of, load_families

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


@cache
def _precedence() -> tuple[dict[str, int], str]:
    """The grades in order of precedence, and the pack's id and version, from policy/precedence.yaml."""
    from pqch.policy import ROOT

    doc = yaml.safe_load((ROOT / "policy" / "precedence.yaml").read_text())
    return {g["id"]: i for i, g in enumerate(doc["grades"])}, f"{doc['id']}/{doc['version']}"


def _grade(f: dict) -> str:
    g = (f.get("source") or {}).get("grade")
    if g:
        return g
    # A finding from before the grade was written: graded by its layer, as the pack does.
    return {"wire": "observed-wire", "platform": "observed-host"}.get(f["layer"], "parsed-file")


def _scalar(v) -> bool:
    return not isinstance(v, (dict, list))


@cache
def _families() -> dict:
    return load_families(_POLICY_ROOT / "policy" / "algorithm-families.yaml")


def _x509_signature_name(s: str | None) -> str | None:
    """A tool's spelling of a certificate's signature algorithm to the X.509 name (algorithm-ids.yaml)."""
    if not s:
        return None
    return algorithm_ids()["signature_names"].get(s, s)


def _levels(role: str, name: str, params: dict) -> dict:
    """What a consumer can judge an algorithm by without the workbench's rules: its OID, NIST's
    category for a post-quantum set, and the classical strength its key size gives (SP 800-57)."""
    ids = algorithm_ids()
    out = {}
    fam = family_of(_families(), role, name) if role in ("key-establishment", "signature") else "unknown"
    cs = classical_strength(role, name, fam, params) if role in ("key-establishment", "signature") else None
    if cs is not None:
        out["classicalSecurityLevel"] = cs
    if name in ids["nist_quantum_security_level"]:
        out["nistQuantumSecurityLevel"] = ids["nist_quantum_security_level"][name]
    return out


class _Referenced:
    """Components the standard's reference fields point at and no scanner reported as such: the
    signature algorithm a certificate was signed with, the algorithm of a key, a certificate's public
    key. One per distinct value, named by it, marked `pqch:kind: referenced` and carrying no layer, so
    the scorer and the inventory leave them alone; a consumer's reference resolves inside the document."""

    def __init__(self):
        self.components: dict[str, dict] = {}

    def algorithm(self, name: str, role: str, params: dict | None = None, *, external: bool = True) -> str:
        params = params or {}
        if external:
            self._external_refs = getattr(self, "_external_refs", set())
        label = name + (f"-{params['key_bits']}" if params.get("key_bits") and name in ("RSA", "DSA") else "") \
            + (f"-{params['curve']}" if params.get("curve") else "")
        ref = f"alg:{role}:{label}"
        if ref not in self.components:
            props = {"primitive": _PRIMITIVE.get(role, "other")}
            if role == "key-establishment" and any(k in name for k in _KEM_NAMES):
                props["primitive"] = "kem"
            if params.get("curve"):
                props["curve"] = params["curve"]
            if params.get("key_bits"):
                props["parameterSetIdentifier"] = str(params["key_bits"])
            props.update(_levels(role, name, params))
            cp = {"assetType": "algorithm", "algorithmProperties": props}
            oid = algorithm_ids()["oid"].get(name) or (algorithm_ids()["oid"].get(params.get("curve")) if name == "ECDSA" and params.get("curve") else None)
            if oid:
                cp["oid"] = oid
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": label, "cryptoProperties": cp,
                                    "properties": [_prop("kind", "referenced"), _prop("referenced-as", "algorithm")]}
        if external:
            self._external_refs.add(ref)
        return ref

    def signature(self, x509_name: str) -> str:
        ref = f"alg:signature:{x509_name}"
        if ref not in self.components:
            cp = {"assetType": "algorithm", "algorithmProperties": {"primitive": "signature", "cryptoFunctions": ["sign", "verify"]}}
            oid = algorithm_ids()["oid"].get(x509_name)
            if oid:
                cp["oid"] = oid
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": x509_name, "cryptoProperties": cp,
                                    "properties": [_prop("kind", "referenced"), _prop("referenced-as", "signature-algorithm")]}
        return ref

    def public_key(self, spki: str, family: str, params: dict) -> str:
        """One component per key, by its SPKI hash. Two findings may describe the same key with more or
        less detail (a file read gives the curve, a tool's export does not); the key keeps the most
        detailed algorithm reference seen, whichever finding came first."""
        ref = f"key:spki-sha256:{spki}"
        alg = self.algorithm(family, "signature", params, external=False)
        if ref not in self.components:
            rcm = {"type": "public-key", "id": f"spki-sha256:{spki}", "algorithmRef": alg}
            if isinstance(params.get("key_bits"), int):
                rcm["size"] = params["key_bits"]
            self.components[ref] = {"type": "cryptographic-asset", "bom-ref": ref, "name": f"{family} public key",
                                    "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rcm},
                                    "properties": [_prop("kind", "referenced"), _prop("referenced-as", "public-key"), _prop("spki-sha256", spki)]}
        else:
            rcm = self.components[ref]["cryptoProperties"]["relatedCryptoMaterialProperties"]
            if len(alg) > len(rcm["algorithmRef"]):
                rcm["algorithmRef"] = alg
            if isinstance(params.get("key_bits"), int) and "size" not in rcm:
                rcm["size"] = params["key_bits"]
        return ref

    def prune(self) -> None:
        """An algorithm component nothing references any more (a bare family superseded by one with
        its curve) is dropped, so every referenced component is referenced."""
        used = {c["cryptoProperties"]["relatedCryptoMaterialProperties"].get("algorithmRef")
                for c in self.components.values() if c["cryptoProperties"]["assetType"] == "related-crypto-material"}
        self._external_refs = getattr(self, "_external_refs", set())
        for ref in [r for r, c in self.components.items() if c["properties"][1]["value"] == "algorithm"
                    and r not in used and r not in self._external_refs]:
            del self.components[ref]


def _prop(name: str, value) -> dict:
    if not isinstance(value, str):
        value = canonical(value).decode()
    return {"name": f"pqch:{name}", "value": value}


def _model_label(actor: dict) -> dict | None:
    """What a consumer of the CBOM needs to know of a model that set a fact: which model, on which
    engine and hardware, in which role. None for a rule or a person."""
    if (actor or {}).get("kind") != "model":
        return None
    out = {k: actor[k] for k in ("model", "tier", "role", "hardware", "engine", "served_by") if actor.get(k)}
    # `engine` is the tier's declared engine (data in the inference config); `served_by` is the upstream the
    # endpoint named, a URL. Neither stands in for the other, and a missing one is missing.
    if actor.get("reasoning"):
        out["reasoning"] = True
    return out


@cache
def _spdx_ids() -> frozenset:
    """The SPDX licence ids CycloneDX 1.6 accepts as `license.id`, from the vendored SPDX schema."""
    doc = json.loads(resources.files(__package__).joinpath("schema").joinpath("spdx.schema.json").read_text())
    return frozenset(doc.get("enum") or [])


def _spdx(x: str) -> bool:
    """Whether a licence string is an SPDX id (then `license.id`) or a name an SBOM reported as the
    package carries it (`license.name`): the schema admits only the enum as an id."""
    return x in _spdx_ids()


def _location(subject: dict) -> str:
    if subject["kind"] == "endpoint":
        return f"{subject['host']}:{subject['port']}"
    if subject["kind"] == "file":
        return f"{subject.get('image') or subject.get('host')}:{subject['path']}"
    if subject["kind"] == "client":
        return f"client:{subject['host']}"
    if subject["kind"] == "platform":
        return f"{subject['host']}:{subject['component']}"
    return f"{subject['repo']}@{subject['commit']}:{subject['path']}#L{subject['line']}"


def _platform_components(events: list[dict], comps: dict, listeners: dict) -> tuple[list[dict], list[dict]]:
    """A scanned system as CycloneDX sees hardware: a `device`, its `firmware` with versions, and
    what each depends on. The device holds its listeners, its files and its firmware; the BIOS
    enforces the Secure Boot databases and measures into the TPM; the management controller's
    firmware carries its own configuration, certificates and listeners. From `platform.observed`
    events and the platform layer's findings; nothing here is inferred from a name."""
    scope = events[0]["payload"].get("scope") or {}
    systems = {s["name"]: s for s in scope.get("systems", [])}
    controllers = {c["of"]: c for c in scope.get("controllers", [])}
    facts: dict[str, list[dict]] = {}
    for ev in events:
        if ev["type"] == "platform.observed":
            facts.setdefault(ev["payload"]["system"], []).append({**ev["payload"], "_event": ev["id"]})
    components, dependencies = [], []
    for name in sorted(set(systems) | set(facts)):
        fs = facts.get(name, [])
        device, settings, firmware, evidence = {}, {}, {}, []
        files_fact = next((f for f in fs if f["source"] == "files"), None)
        for f in fs:
            evidence.append(f["_event"])
            for k, v in (f.get("device") or {}).items():
                if v and not device.get(k):
                    device[k] = v
            settings.update({f"{f['source']}:{k}": v for k, v in (f.get("settings") or {}).items() if v is not None})
            for fw in f.get("firmware") or []:
                key = fw["name"]
                cur = firmware.setdefault(key, {"name": key, "version": fw.get("version"), "sources": set(), "enforces": set()})
                cur["sources"].add(f["source"])
                cur["enforces"].update(fw.get("enforces") or [])
                if not cur.get("version"):
                    cur["version"] = fw.get("version")
        ctl_fact = next((f for f in fs if f["source"] == "controller"), None)
        dref = f"device:{name}"
        props = [_prop("kind", "system"), _prop("system", name), _prop("evidence", ",".join(evidence)),
                 _prop("settings", settings)]
        if files_fact:
            props.append(_prop("files", {k: files_fact.get(k) for k in ("files_read", "unreadable", "trust_store",
                                                                         "trust_store_certificates", "read_as_uid")}))
        if ctl_fact:
            props.append(_prop("controller", ctl_fact.get("controller")))
        components.append({"type": "device", "bom-ref": dref, "name": device.get("model") or name,
                           **({"manufacturer": {"name": device["vendor"]}} if device.get("vendor") else {}),
                           "properties": props})
        addresses = set((systems.get(name) or {}).get("addresses") or [])
        ctl = controllers.get(name)
        on_device = [r for r, ln in listeners.items() if ln["subject"]["host"] in addresses]
        files = [f"fp:{fp}" for fp, c in comps.items() if c["finding"]["layer"] == "host"
                 and c["finding"]["subject"].get("host") == name]
        fw_refs = []
        for fwname in sorted(firmware):
            fw = firmware[fwname]
            ref = f"fw:{name}:{fwname}"
            fw_refs.append(ref)
            is_ctl = bool(ctl) and ("Remote Access Controller" in fwname or "iDRAC" in fwname)
            fprops = [_prop("kind", "firmware"), _prop("system", name), _prop("sources", sorted(fw["sources"]))]
            if is_ctl:
                fprops.append(_prop("controller-host", ctl["host"]))
            components.append({"type": "firmware", "bom-ref": ref, "name": fwname,
                               **({"version": str(fw["version"])} if fw.get("version") else {}), "properties": fprops})
            under = []
            if fwname == "BIOS":
                under = [f"fp:{fp}" for fp, c in comps.items() if c["finding"]["layer"] == "platform"
                         and c["finding"]["subject"].get("host") == name
                         and c["finding"]["subject"]["component"].startswith(("secure-boot:", "tpm"))]
            elif is_ctl:
                under = [f"fp:{fp}" for fp, c in comps.items() if c["finding"]["layer"] == "platform"
                         and c["finding"]["subject"].get("host") == name and c["finding"]["subject"]["component"].startswith("bmc:")]
                under += [r for r, ln in listeners.items() if ln["subject"]["host"] == ctl["host"]]
            if under:
                dependencies.append({"ref": ref, "dependsOn": sorted(set(under))})
        depends = sorted(set(fw_refs + on_device + files))
        if depends:
            dependencies.append({"ref": dref, "dependsOn": depends})
    return components, dependencies


def _listener_ref(subject: dict) -> str:
    return f"listener:{subject['host']}:{subject['port']}"


def _crypto_properties(asset: dict, refs: _Referenced | None = None, in_use: str = "true") -> dict:
    """The standard's own fields, filled wherever the finding has the fact (M6): parameter set, curve
    and security levels on an algorithm; the signature algorithm and public key a certificate
    references; a key's algorithm and, when the rules found it unused, its state."""
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
        props.update(_levels(asset["role"], asset["name"], p))
        out = {"assetType": "algorithm", "algorithmProperties": props}
        oid = algorithm_ids()["oid"].get(asset["name"])
        if oid:
            out["oid"] = oid
        return out
    if t == "certificate":
        props = {"certificateFormat": "X.509"}
        for src, dst in (("subject", "subjectName"), ("issuer", "issuerName"),
                         ("not_before", "notValidBefore"), ("not_after", "notValidAfter")):
            if isinstance(p.get(src), str):
                props[dst] = p[src]
        if refs is not None:
            sig = _x509_signature_name(p.get("signature"))
            if sig:
                props["signatureAlgorithmRef"] = refs.signature(sig)
            if isinstance(p.get("spki_sha256"), str) and asset["name"] not in ("unknown", ""):
                props["subjectPublicKeyRef"] = refs.public_key(p["spki_sha256"], asset["name"], p)
        return {"assetType": "certificate", "certificateProperties": props}
    if t == "related-crypto-material":
        kinds = p.get("kind") or ["unknown"]
        kind = kinds[0] if len(kinds) == 1 else "key"
        # CycloneDX 1.6 names the kinds of material it knows; the harness's finer kinds (a
        # keystore, DH parameters) are carried in pqch:parameters and mapped onto the nearest.
        props = {"type": kind if kind in _RCM_TYPES else _RCM_MAP.get(kind, "other")}
        if isinstance(p.get("key_bits"), int):
            props["size"] = p["key_bits"]
        if isinstance(p.get("spki_sha256"), str):
            props["id"] = f"spki-sha256:{p['spki_sha256']}"
        if refs is not None and asset["name"] not in ("unknown", "", "generic-api-key") and \
                asset["name"] in (_families().get("signature") or {}) | (_families().get("key-establishment") or {}):
            role = "signature" if asset["name"] in (_families().get("signature") or {}) else "key-establishment"
            props["algorithmRef"] = refs.algorithm(asset["name"], role, p)
        if in_use == "false":
            props["state"] = "deactivated"      # the rules found no listener serving it (pqch:in-use false)
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

    # Findings, folded by fingerprint: every finding a claim, the one in force by the grade of its
    # evidence and then by its place on the ledger, a person's resolution over both.
    rank, precedence_id = _precedence()
    comps: dict[str, dict] = {}
    finding_fp: dict[str, str] = {}
    tool_versions: dict[str, str] = {}
    resolutions: dict[str, dict[str, dict]] = {}       # fingerprint -> field -> {value, event, basis}
    by_resolution: dict[str, tuple[str, str]] = {}      # resolution event id -> (fingerprint, field)
    for pos, ev in enumerate(events):
        if ev["type"] == "claim.resolved":
            p = ev["payload"]
            resolutions.setdefault(p["fingerprint"], {})[p["field"]] = {"value": p["value"], "event": ev["id"], "basis": p.get("basis")}
            by_resolution[ev["id"]] = (p["fingerprint"], p["field"])
            continue
        if ev["type"] == "resolution.revoked":
            fp_field = by_resolution.get(ev["payload"].get("resolution"))
            if fp_field and fp_field[1] in resolutions.get(fp_field[0], {}):
                del resolutions[fp_field[0]][fp_field[1]]
            continue
        if ev["type"] != "finding.observed":
            continue
        f = ev["payload"]
        if tools is not None and f["source"]["tool"] not in tools:
            continue
        fp = f["fingerprint"]
        finding_fp[ev["id"]] = fp
        tool_versions[f["source"]["tool"]] = f["source"]["version"]
        c = comps.setdefault(fp, {"finding": f, "events": [], "tools": set(), "in_use": None,
                                  "in_use_rule": None, "links": set(), "claims": []})
        c["events"].append(ev["id"])
        c["tools"].add(f["source"]["tool"])
        c["claims"].append({"event": ev["id"], "tool": f["source"]["tool"], "grade": _grade(f), "pos": pos, "finding": f})
    # Identity by the strongest key the evidence has: a claim that names no key identity (an imported
    # entry, whose document carried no SPKI) joins the one identified entry in the same place with the
    # same kind, role and name, when there is exactly one; with two or more it stays apart, a possible
    # same to resolve, never an identity assumed.
    groups: dict[str, list[str]] = {}
    for fp, c in comps.items():
        f = c["finding"]
        groups.setdefault(hash_object({"layer": f["layer"], "subject": f["subject"], "type": f["asset"]["type"],
                                       "role": f["asset"]["role"], "name": f["asset"]["name"]}), []).append(fp)
    for members in groups.values():
        named = [fp for fp in members if comps[fp]["finding"]["asset"].get("identity")]
        anon = [fp for fp in members if not comps[fp]["finding"]["asset"].get("identity")]
        if len(named) != 1 or not anon:
            continue
        keep = comps[named[0]]
        for fp in anon:
            gone = comps.pop(fp)
            keep["events"] += gone["events"]
            keep["tools"] |= gone["tools"]
            keep["claims"] += [{**x, "joined_from": fp} for x in gone["claims"]]
            for eid, mapped in list(finding_fp.items()):
                if mapped == fp:
                    finding_fp[eid] = named[0]
            if fp in resolutions:
                resolutions.setdefault(named[0], {}).update(resolutions.pop(fp))
    for fp, c in comps.items():
        claims = sorted(c["claims"], key=lambda x: (rank.get(x["grade"], len(rank)), x["pos"]))
        c["finding"] = claims[0]["finding"]
        c["in_force"] = {"grade": claims[0]["grade"], "tool": claims[0]["tool"], "event": claims[0]["event"], "decided_by": precedence_id}
        # Dissent: a parameter two claims give different scalar values for, every value kept with its sayer;
        # and a tool's own two values for one parameter, recorded by the normalizer.
        dissent: dict[str, list[dict]] = {}
        for x in claims:
            for k, v in (x["finding"]["asset"].get("parameters") or {}).items():
                if _scalar(v):
                    dissent.setdefault(k, []).append({"value": v, "grade": x["grade"], "tool": x["tool"], "event": x["event"]})
            for k, vs in (x["finding"]["asset"].get("dissent") or {}).items():
                for v in vs:
                    dissent.setdefault(k, []).append({"value": v, "grade": x["grade"], "tool": x["tool"], "event": x["event"], "same_tool": True})
        c["dissent"] = {k: vs for k, vs in dissent.items() if len({canonical(v["value"]) for v in vs}) > 1}
        c["parameters"] = dict(c["finding"]["asset"].get("parameters") or {})
        c["resolved"] = {}
        for field, r in resolutions.get(fp, {}).items():
            c["parameters"][field] = r["value"]
            c["resolved"][field] = r

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
    compat: dict[str, dict] = {}                                       # fingerprint -> status under its pack
    sboms: dict[str, dict] = {}                                        # image repo -> sbom.observed payload
    provides: dict[tuple[str, str], set[str]] = {}                     # (image, library key) -> finding fps it provides
    lib_meta: dict[tuple[str, str], dict] = {}
    for ev in events:
        if ev["type"] == "sbom.observed":
            sboms[ev["payload"]["image"]] = {**ev["payload"], "event": ev["id"]}
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
                     ("state", "queue", "deadline", "deadline_basis")},
                     **{k: p["classification"][k] for k in ("deadline_set_by", "deprecated_after", "disallowed_after")
                        if k in p["classification"]}, "event": ev["id"]})
                continue
            if rid in ("blocker/supplier/1", "blocker/validated-module/1"):
                blockers.setdefault((p["subject"]["service"], p["subject"]["function"]), {})[
                    rid.split("/")[1]] = p["classification"]["state"]
                continue
            if rid == "deadline/tls13/1":
                tls13[(p["subject"]["host"], p["subject"]["port"])] = {**p["classification"], "event": ev["id"]}
                continue
            if rid == "compatibility/entry/1":
                c_ = p["classification"]
                compat[p["subject"]["fingerprint"]] = {"status": c_["status"], "pack": c_["pack"],
                                                       "provisional": c_["provisional"], "basis": p["basis"], "event": ev["id"]}
                continue
            if ev["type"] == "link.asserted" and isinstance(p["from"], str):
                if p["from"] in finding_fp and p["to"] in finding_fp:
                    a, b = finding_fp[p["from"]], finding_fp[p["to"]]
                    comps[a]["links"].add(b)
                    deps.setdefault(a, set()).add(b)
            elif ev["type"] == "link.asserted" and p.get("kind") == "provides" and p["from"].get("kind") == "library":
                key = (p["from"]["image"], p["from"].get("purl") or f"{p['from']['name']}@{p['from'].get('version')}")
                if p["to"] in finding_fp:
                    provides.setdefault(key, set()).add(finding_fp[p["to"]])
                    lib_meta.setdefault(key, {"candidates": p.get("candidates"), "events": []})["events"].append(ev["id"])
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
                    comps[fp]["in_use_by"] = _model_label(ev["actor"])
                    comps[fp]["in_use_agreement"] = p.get("agreement") if comps[fp]["in_use_by"] else None
            elif ev["type"] == "assessment.made" and "posture" in p.get("classification", {}):
                postures[(p["subject"]["host"], p["subject"]["port"])] = p["classification"]

    components = []
    listeners: dict[str, dict] = {}
    refs = _Referenced()
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
            _prop("parameters", c["parameters"]),
            _prop("fingerprint", fp),
            _prop("evidence", ",".join(c["events"])),
            _prop("tools", ",".join(sorted(c["tools"]))),
        ]
        if rules:
            props.append(_prop("grade", c["in_force"]["grade"]))
            if len(c["claims"]) > 1 or c["dissent"] or c["resolved"]:
                props.append(_prop("claims", [{k: x[k] for k in ("event", "tool", "grade", "joined_from") if k in x} for x in c["claims"]]))
                props.append(_prop("in-force", c["in_force"]))
            if c["dissent"]:
                props.append(_prop("dissent", c["dissent"]))
            if c["resolved"]:
                props.append(_prop("resolved", c["resolved"]))
            props.append(_prop("in-use", in_use))
            if c["in_use_rule"]:
                props.append(_prop("in-use-rule", c["in_use_rule"]))
            if c.get("in_use_by"):
                # A model's majority set it (the call-site-read role): the CBOM says so, and by whom.
                props.append(_prop("in-use-by", c["in_use_by"]))
                if c.get("in_use_agreement"):
                    props.append(_prop("in-use-agreement", c["in_use_agreement"]))
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
            if fp in compat:
                props.append(_prop("compatibility", compat[fp]))
        asset_view = {**f["asset"], "parameters": c["parameters"]}
        if f["asset"]["type"] == "certificate" and c["parameters"].get("signature"):
            # The names a policy engine reads (ADR-0007): the X.509 signature algorithm and the key's
            # algorithm, under the consumers' names beside the standard's references.
            x509 = _x509_signature_name(c["parameters"]["signature"])
            props.append(_prop("signature-algorithm", x509))
            props.append({"name": "Signature Algorithm", "value": x509})
            key_label = f["asset"]["name"] + (f"-{c['parameters']['curve']}" if c["parameters"].get("curve") else
                                            f"-{c['parameters']['key_bits']}" if c["parameters"].get("key_bits") else "")
            props.append({"name": "Subject Public Key Algorithm", "value": key_label})
        components.append({
            "type": "cryptographic-asset",
            "bom-ref": f"fp:{fp}",
            "name": f["asset"]["name"],
            "cryptoProperties": _crypto_properties(asset_view, refs if rules else None, in_use),
            "evidence": {"occurrences": [{"location": _location(subj)}]},
            "properties": props,
        })
        if subj["kind"] == "endpoint":
            ref = _listener_ref(subj)
            listeners.setdefault(ref, {"subject": subj, "members": [], "findings": []})
            listeners[ref]["members"].append(f"fp:{fp}")
            listeners[ref]["findings"].append(asset_view)

    for ref in sorted(listeners):
        subj = listeners[ref]["subject"]
        props = [_prop("kind", "listener"), _prop("subject", {k: subj[k] for k in ("host", "port", "protocol")})]
        posture = postures.get((subj["host"], subj["port"]))
        if posture:
            props.append(_prop("posture", posture["posture"]))
        assets = listeners[ref]["findings"]
        protocols = sorted((a for a in assets if a["type"] == "protocol"), key=lambda a: a["name"])
        tls_versions = [a["name"] for a in protocols if a["name"].startswith(("TLS", "SSL"))]
        ssh = next((a for a in protocols if a["name"].startswith("SSH")), None)
        # The protocol as CycloneDX describes it: its type and version, the cipher suites accepted, and
        # a reference to every asset on it; what the standard has no field for goes under the names the
        # consumers read and the pqch: names (ADR-0007).
        pp: dict = {"type": "tls" if (subj["protocol"] in ("tls", "postgres") and tls_versions) or subj["protocol"] == "tls"
                    else "ssh" if subj["protocol"] == "ssh" else "other"}
        if tls_versions:
            pp["version"] = tls_versions[-1].split(" ", 1)[-1]
            suites: dict[str, dict] = {}
            for a in protocols:
                for s in a["parameters"].get("cipher_suites") or []:
                    suites.setdefault(s["name"], {"name": s["name"], "identifiers": [s["id"]]})
            if suites:
                pp["cipherSuites"] = [suites[k] for k in sorted(suites)]
            props.append(_prop("tls-versions", tls_versions))
            schemes = sorted({x for a in protocols for x in a["parameters"].get("signature_schemes") or []})
            if schemes:
                props.append(_prop("tls-signature-schemes", schemes))
        elif ssh:
            pp["version"] = ssh["name"].split(" ", 1)[-1]
            if ssh["parameters"].get("software"):
                props.append(_prop("ssh-software", ssh["parameters"]["software"]))
        groups = sorted({a["name"] for a in assets if a["type"] == "algorithm" and a["role"] == "key-establishment"})
        if groups and pp["type"] == "tls":
            props.append(_prop("tls-groups", groups))
            props.append({"name": "Supported Groups", "value": ", ".join(groups)})
        if ssh:
            for key, pq_name, vendor in (("key_exchange", "ssh-key-exchange", "Key Exchange Algorithm"),
                                         ("host_keys", "ssh-host-key", "Host Key Algorithm"),
                                         ("encryption", "ssh-encryption", "Encryption Algorithm"),
                                         ("mac", "ssh-mac", None)):
                vals = ssh["parameters"].get(key) or []
                if vals:
                    props.append(_prop(pq_name, vals))
                    if vendor:
                        props.append({"name": vendor, "value": ", ".join(vals)})
        pp["cryptoRefArray"] = sorted(listeners[ref]["members"])
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
            "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
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
        for kind in ("mission-function", "data-lifetime", "high-value-asset", "system", "interface", "mission-thread",
                     "classification", "vendor-path", "cost-to-fix"):
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
                if first.get("deadline_set_by"):
                    props.append(_prop("deadline-set-by", first["deadline_set_by"]))
                dep = [i["deprecated_after"] for i in open_items if i.get("deprecated_after")]
                if dep:
                    props.append(_prop("deprecated-after", min(dep)))
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
    # The libraries an image's SBOM says provide cryptography: a capability each, in use only where the
    # rule linked it to something a listener negotiates or serves (CycloneDX 1.6 `provides`).
    for repo in sorted(sboms):
        sb = sboms[repo]
        lib_refs = []
        for lb in sb.get("crypto_libraries") or []:
            key = (repo, lb.get("purl") or f"{lb['name']}@{lb.get('version')}")
            ref = f"lib:{repo}:{key[1]}"
            lib_refs.append(ref)
            provided = sorted(f"fp:{fp}" for fp in provides.get(key, set()))
            props = [_prop("kind", "library"), _prop("image", repo), _prop("sbom-event", sb["event"]),
                     _prop("capability", "present"), _prop("in-use", "true" if provided else "unknown")]
            if lb.get("type"):
                props.append(_prop("package-type", lb["type"]))
            if provided:
                props.append(_prop("provides-count", str(len(provided))))
                props.append(_prop("provides-evidence", ",".join(lib_meta[key]["events"])))
                if (lib_meta[key].get("candidates") or 1) > 1:
                    props.append(_prop("provides-candidates", str(lib_meta[key]["candidates"])))
            comp = {"type": "library", "bom-ref": ref, "name": lb["name"], "properties": props}
            if lb.get("version"):
                comp["version"] = str(lb["version"])
            if lb.get("purl"):
                comp["purl"] = lb["purl"]
            if lb.get("licenses"):
                comp["licenses"] = [{"license": {"id" if _spdx(x) else "name": x}} for x in lb["licenses"] if x]
            components.append(comp)
            if provided:
                dependencies.append({"ref": ref, "provides": provided})
        if lib_refs and f"img:{repo}" in {c["bom-ref"] for c in components}:
            existing = next((d for d in dependencies if d["ref"] == f"img:{repo}"), None)
            if existing:
                existing["dependsOn"] = sorted(set(existing.get("dependsOn", [])) | set(lib_refs))
            else:
                dependencies.append({"ref": f"img:{repo}", "dependsOn": sorted(lib_refs)})

    if tools is None:
        plat, plat_deps = _platform_components(events, comps, listeners)
        components += plat
        dependencies += plat_deps
    # What the references point at, last: resolvable inside the document, outside the scorer's view.
    refs.prune()
    components += [refs.components[k] for k in sorted(refs.components)]

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


def for_consumer(bom: dict) -> dict:
    """The same document for a policy engine that cannot read `pqch:in-use` (ADR-0007): every entry the
    rules found not in use (a retired certificate no listener serves, the key behind it) left out, with
    the dependencies that named them pruned, and the metadata saying how many were dropped and why.
    The full document stays the record; this is a view of it."""
    dropped = {c["bom-ref"] for c in bom["components"]
               if any(p["name"] == "pqch:in-use" and p["value"] == "false" for p in c.get("properties", []))}
    out = json.loads(json.dumps(bom))
    out["components"] = [c for c in out["components"] if c["bom-ref"] not in dropped]
    deps = []
    for d in out.get("dependencies", []):
        if d["ref"] in dropped:
            continue
        kept = {k: [x for x in d[k] if x not in dropped] for k in ("dependsOn", "provides") if k in d}
        kept = {k: v for k, v in kept.items() if v}
        if kept:
            deps.append({"ref": d["ref"], **kept})
    out["dependencies"] = deps
    out["metadata"]["properties"] = [p for p in out["metadata"]["properties"] if p["name"] != "pqch:projection"] + [
        _prop("projection", "workbench-consumer"),
        _prop("consumer-copy", {"dropped": len(dropped), "why": "entries the rules judged not in use (pqch:in-use false) are left out, "
                                                                "because CycloneDX 1.6 has no field a policy engine reads for it"})]
    out["serialNumber"] = f"urn:uuid:{uuid.UUID(hex=hash_object([bom['serialNumber'], sorted(dropped)])[:32])}"
    return out


def project_estate(runs: list) -> dict:
    """One document over several runs' ledgers (a scan, its imports, a later scan): the events in run
    order, each run pinned by its head hash in the metadata, so the same runs give the same document.
    A ledger that does not verify stops the projection."""
    from pqch.ledger import verify

    events, pins = [], []
    for r in runs:
        evs = list(r.ledger.events())
        v = verify(evs)
        if not evs or not v.ok:
            raise ValueError(f"run {r.id}: ledger does not verify ({getattr(v, 'reason', 'empty')})")
        pins.append({"run": r.id, "kind": evs[0]["payload"].get("kind"), "head": evs[-1]["hash"], "seq": evs[-1]["seq"]})
        events.extend(evs)
    bom = project(events, label="estate")
    bom["serialNumber"] = f"urn:uuid:{uuid.UUID(hex=hash_object(pins)[:32])}"
    bom["metadata"]["properties"] = [p for p in bom["metadata"]["properties"] if p["name"] not in ("pqch:ledger-head", "pqch:ledger-seq")]
    bom["metadata"]["properties"].append(_prop("runs", pins))
    return bom


BASELINES = {
    "cbomkit": {"cbomkit-theia"},
    "scanners": {"cbomkit-theia", "testssl.sh", "ssh-audit"},
}


def build_all(events: list[dict]) -> dict[str, dict]:
    """The workbench CBOM and both baselines, each validated."""
    out = {"workbench": project(events)}
    out["workbench-consumer"] = for_consumer(out["workbench"])
    for name, tools in BASELINES.items():
        out[f"baseline-{name}"] = project(events, tools=tools, rules=False, label=f"baseline:{name}")
    for name, bom in out.items():
        errors = validate(bom)
        if errors:
            raise ValueError(f"{name} CBOM fails CycloneDX 1.6: " + "; ".join(errors[:5]))
    return out
