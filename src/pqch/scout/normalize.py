"""Raw scanner output to `pqch.finding/1` (spec/interfaces.md, section 2).

One function per tool. Each takes the raw bytes and the runner's job result
and returns findings, one per fingerprint: entries a tool reports twice for
the same thing (an RSA host key under three SSH names, a key file's private and
public halves) are folded, and their parameters merged.

The same functions serve the workbench and both baselines, so the baselines are
scored on exactly what the tools said, in the same vocabulary.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable

from pqch.common import hash_object, ulid
from pqch.scout import names
from pqch.scout.keys import parse_certificate_pem, spki_sha256_from_der, ssh_fingerprint_from_spki

SCHEMA = "pqch.finding/1"


def fingerprint(layer: str, subject: dict, asset: dict) -> str:
    """SHA-256 of the canonical form of {layer, subject, type, role, name, identity}."""
    return hash_object({"layer": layer, "subject": subject, "type": asset["type"],
                        "role": asset["role"], "name": asset["name"],
                        "identity": asset.get("identity")})


def identity_of(parameters: dict) -> str | None:
    """Which key this is: the public key's SPKI SHA-256, else the OpenSSH fingerprint."""
    spki = parameters.get("spki_sha256")
    if isinstance(spki, str):
        return f"spki-sha256:{spki}"
    ssh = parameters.get("ssh_fingerprint_sha256")
    if isinstance(ssh, str):
        return f"openssh-sha256:{ssh}"
    return None


class _Collector:
    """Entries grouped by place, kind and family, then split by key identity.

    An entry with no identity of its own (a private key, an algorithm read from a
    certificate) joins the one identified entry in its group when there is exactly one;
    otherwise the identity-less entries fold together.
    """

    def __init__(self, job: dict, layer: str, *, subject_digest: str | None = None):
        self.job = job
        self.layer = layer
        self.subject_digest = subject_digest
        self.groups: dict[str, dict[str | None, dict]] = {}

    def add(self, subject: dict, type_: str, role: str, name: str, parameters: dict, excerpt: str) -> None:
        group = hash_object({"subject": subject, "type": type_, "role": role, "name": name})
        ident = identity_of(parameters)
        entries = self.groups.setdefault(group, {})
        if ident in entries:
            f = entries[ident]
            _merge(f["asset"]["parameters"], parameters)
            if excerpt not in f["evidence"]["excerpt"]:
                f["evidence"]["excerpt"] = (f["evidence"]["excerpt"] + "; " + excerpt)[:400]
            return
        job = self.job
        source = {"tool": job["tool"], "version": job["version"], "image_digest": job["image_digest"],
                  "profile": job["profile"]}
        if self.subject_digest:
            source["subject_digest"] = self.subject_digest
        entries[ident] = {
            "schema": SCHEMA,
            "id": ulid(),
            "observed_at": job["ended_at"],
            "layer": self.layer,
            "source": source,
            "subject": subject,
            "asset": {"type": type_, "role": role, "name": name, "parameters": dict(parameters)},
            "evidence": {"raw": job["raw"], "sha256": job["raw_sha256"], "excerpt": excerpt[:400]},
        }

    def findings(self) -> list[dict]:
        out = []
        for entries in self.groups.values():
            named = [k for k in entries if k is not None]
            if None in entries and len(named) == 1:
                anon, f = entries.pop(None), entries[named[0]]
                _merge(f["asset"]["parameters"], anon["asset"]["parameters"])
                f["evidence"]["excerpt"] = (f["evidence"]["excerpt"] + "; " + anon["evidence"]["excerpt"])[:400]
            for ident, f in entries.items():
                if ident is not None:
                    f["asset"]["identity"] = ident
                f["fingerprint"] = fingerprint(self.layer, f["subject"], f["asset"])
                out.append(f)
        return out


def _merge(into: dict, new: dict) -> None:
    for k, v in new.items():
        if k not in into:
            into[k] = v
        elif isinstance(into[k], list) and isinstance(v, list):
            into[k] = sorted(set(into[k]) | set(v))
        elif into[k] != v and not isinstance(into[k], (dict, list)):
            into[k] = sorted({str(into[k]), str(v)})


def _endpoint_subject(job: dict, protocol: str) -> dict:
    t = job["target"]
    s = {"kind": "endpoint", "host": t["host"], "port": t["port"], "protocol": protocol}
    if t.get("sni"):
        s["sni"] = t["sni"]
    return s


# --------------------------------------------------------------- testssl.sh
def testssl(raw: bytes, job: dict) -> list[dict]:
    entries = json.loads(raw)
    # The listener's protocol as the scope names it: `tls`, or the protocol whose upgrade
    # carried the handshake (`postgres`). The finding is about that listener.
    subject = _endpoint_subject(job, job["target"].get("protocol") or "tls")
    c = _Collector(job, "wire")
    by_id = {e["id"]: e for e in entries}
    versions: dict[str, list[str]] = {}
    for e in entries:
        eid, text = e["id"], (e.get("finding") or "").strip()
        if eid == "DH_groups":
            if not text or text.lower().startswith(("no ", "not ")):
                continue
            for name, tool_name in names.dh_groups(text):
                c.add(subject, "algorithm", "key-establishment", name,
                      {"tool_names": [tool_name]}, f"{eid}: {text}")
        elif eid in ("FS_KEMs", "FS_ECDHE_curves"):
            if not text or text.lower().startswith(("no ", "not ")):
                continue
            for tool_name in text.split():
                name = names.TLS_GROUPS.get(tool_name, tool_name)
                c.add(subject, "algorithm", "key-establishment", name,
                      {"tool_names": [tool_name]}, f"{eid}: {text}")
        elif eid.startswith("cipher-") and text.split()[-1:] and text.split()[-1].startswith("TLS_RSA_WITH_"):
            # RSA key transport: the client encrypts the session secret to the server's RSA
            # key. No group is negotiated, so the group lists above never show it.
            parts = text.split()
            c.add(subject, "algorithm", "key-establishment", "RSA",
                  {"mode": "key-transport", "tls_versions": [parts[0]], "suites": [parts[-1]]},
                  f"{eid}: {parts[0]} {parts[-1]}")
        elif eid.startswith("cipher-") and text.split()[:1] and text.split()[0].startswith(("TLSv1", "SSLv")):
            # Every accepted suite names its protocol version first; the versions a listener
            # offers are the set of them. M-26-15 §4 sets a date for TLS 1.3 support.
            versions.setdefault(text.split()[0], []).append(eid)
        if eid == "cert" or eid.startswith("cert <"):
            suffix = eid[4:]
            info = parse_certificate_pem(text)
            family = info.pop("family")
            size = by_id.get("cert_keySize" + suffix, {}).get("finding", "")
            sig = by_id.get("cert_signatureAlgorithm" + suffix, {}).get("finding", "")
            c.add(subject, "certificate", "signature", family, info,
                  f"cert_keySize: {size}; cert_signatureAlgorithm: {sig}")
    for v, ids in sorted(versions.items()):
        name = v.replace("TLSv", "TLS ").replace("SSLv", "SSL ")
        c.add(subject, "protocol", "other", name, {"suites_accepted": len(ids)},
              f"{len(ids)} cipher suites accepted with {v}")
    return c.findings()


# ---------------------------------------------------------------- ssh-audit
def ssh_audit(raw: bytes, job: dict) -> list[dict]:
    doc = json.loads(raw)
    subject = _endpoint_subject(job, "ssh")
    c = _Collector(job, "wire")
    for k in doc.get("kex", []):
        alg = k["algorithm"]
        if names.SSH_KEX_IGNORE.match(alg):
            continue
        name = names.SSH_KEX.get(alg, alg)
        c.add(subject, "algorithm", "key-establishment", name, {"ssh_names": [alg]}, f"kex: {alg}")
    fps = {f["hostkey"]: f["hash"] for f in doc.get("fingerprints", []) if f.get("hash_alg") == "SHA256"}
    fp_by_family = {names.SSH_HOSTKEY.get(h, h): v for h, v in fps.items()}
    for k in doc.get("key", []):
        alg = k["algorithm"]
        family = names.SSH_HOSTKEY.get(alg, alg)
        params: dict = {"ssh_names": [alg]}
        if k.get("keysize"):
            params["key_bits"] = k["keysize"]
        if alg in names.SSH_HOSTKEY_CURVE:
            params["curve"] = names.SSH_HOSTKEY_CURVE[alg]
        if family in fp_by_family:
            params["ssh_fingerprint_sha256"] = fp_by_family[family]
        c.add(subject, "algorithm", "signature", family, params, f"key: {alg}")
    return c.findings()


# ------------------------------------------------------------ cbomkit-theia
_PRIMITIVE_ROLE = {
    "signature": "signature",
    "hash": "hash",
    "pke": "encryption",
    "key-agree": "key-establishment",
    "kem": "key-establishment",
    "mac": "mac",
    "ae": "encryption",
    "block-cipher": "encryption",
    "stream-cipher": "encryption",
}


def theia(raw: bytes, job: dict) -> list[dict]:
    bom = json.loads(raw)
    image, _, digest = job["target"]["image"].partition("@")
    comps = {x.get("bom-ref"): x for x in bom.get("components", []) if x.get("bom-ref")}
    c = _Collector(job, "host", subject_digest=digest or None)
    for comp in bom.get("components", []):
        if comp.get("type") != "cryptographic-asset":
            continue
        cp = comp.get("cryptoProperties", {})
        kind = cp.get("assetType")
        for occ in comp.get("evidence", {}).get("occurrences", []):
            subject = {"kind": "file", "image": image, "path": occ["location"]}
            if kind == "certificate":
                props = cp.get("certificateProperties", {})
                pub = comps.get(props.get("subjectPublicKeyRef"), {})
                sig = comps.get(props.get("signatureAlgorithmRef"), {})
                rcm = pub.get("cryptoProperties", {}).get("relatedCryptoMaterialProperties", {})
                params = {k: v for k, v in {
                    "subject": props.get("subjectName"), "issuer": props.get("issuerName"),
                    "not_before": props.get("notValidBefore"), "not_after": props.get("notValidAfter"),
                    "signature": sig.get("name"), "key_bits": rcm.get("size"),
                }.items() if v is not None}
                if rcm.get("value"):
                    params["spki_sha256"] = spki_sha256_from_der(base64.b64decode(rcm["value"]))
                family = names.key_family(pub.get("name", ""))
                c.add(subject, "certificate", "signature", family, params,
                      f"certificate {comp.get('name')} ({pub.get('name', '?')}, {sig.get('name', '?')})")
            elif kind == "related-crypto-material":
                rcm = cp.get("relatedCryptoMaterialProperties", {})
                params = {"kind": [rcm.get("type", "unknown")]}
                if rcm.get("size"):
                    params["key_bits"] = rcm["size"]
                if rcm.get("value") and rcm.get("type") == "public-key":
                    der = base64.b64decode(rcm["value"])
                    params["spki_sha256"] = spki_sha256_from_der(der)
                    ssh_fp = ssh_fingerprint_from_spki(der)
                    if ssh_fp:
                        params["ssh_fingerprint_sha256"] = ssh_fp
                c.add(subject, "related-crypto-material", "other", names.key_family(comp.get("name", "")),
                      params, f"{rcm.get('type', 'material')} {comp.get('name')}")
            elif kind == "algorithm":
                prim = cp.get("algorithmProperties", {}).get("primitive", "")
                role = _PRIMITIVE_ROLE.get(prim, "other")
                c.add(subject, "algorithm", role, names.algorithm_name(comp.get("name", "unknown")),
                      {"primitive": prim} if prim else {}, f"algorithm {comp.get('name')} ({prim})")
            elif kind == "protocol":
                c.add(subject, "protocol", "other", comp.get("name", "unknown"), {}, f"protocol {comp.get('name')}")
    return c.findings()


# ------------------------------------------------------- pqch image-files
_FILE_ROLE = {"certificate": "signature", "related-crypto-material": "other"}


def imagefiles(raw: bytes, job: dict) -> list[dict]:
    """The harness's own reader (`pqch-image-files/1`): one entry per thing read from a file."""
    doc = json.loads(raw)
    image, _, digest = job["target"]["image"].partition("@")
    c = _Collector(job, "host", subject_digest=digest or None)
    for e in doc.get("entries", []):
        subject = {"kind": "file", "image": image, "path": e["path"]}
        params = dict(e.get("parameters") or {})
        if e["type"] == "related-crypto-material" and "kind" in params and not isinstance(params["kind"], list):
            params["kind"] = [params["kind"]]
        c.add(subject, e["type"], _FILE_ROLE[e["type"]], e["name"], params, e.get("excerpt", ""))
    return c.findings()


NORMALIZERS: dict[str, Callable[[bytes, dict], list[dict]]] = {
    "testssl.sh": testssl,
    "ssh-audit": ssh_audit,
    "cbomkit-theia": theia,
    "pqch-image-files": imagefiles,
}


def normalize(raw: bytes, job: dict) -> list[dict]:
    return NORMALIZERS[job["tool"]](raw, job)
