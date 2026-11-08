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


def _file_subject(job: dict, path: str) -> dict:
    """A file in a scoped image, or in a scoped system's packed paths (its own path, without the
    /scan/root the readers see it under)."""
    t = job["target"]
    if "system" in t:
        p = path.removeprefix("/scan/root") if path.startswith("/scan/root") else path
        return {"kind": "file", "host": t["system"], "path": "/" + p.lstrip("/")}
    return {"kind": "file", "image": t["image"].partition("@")[0], "path": path}


def theia(raw: bytes, job: dict) -> list[dict]:
    bom = json.loads(raw)
    digest = job["target"].get("image", "").partition("@")[2]
    comps = {x.get("bom-ref"): x for x in (bom.get("components") or []) if x.get("bom-ref")}
    c = _Collector(job, "host", subject_digest=digest or None)
    for comp in (bom.get("components") or []):
        if comp.get("type") != "cryptographic-asset":
            continue
        cp = comp.get("cryptoProperties", {})
        kind = cp.get("assetType")
        for occ in comp.get("evidence", {}).get("occurrences", []):
            subject = _file_subject(job, occ["location"])
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
    digest = job["target"].get("image", "").partition("@")[2]
    c = _Collector(job, "host", subject_digest=digest or None)
    for e in doc.get("entries", []):
        subject = _file_subject(job, e["path"])
        params = dict(e.get("parameters") or {})
        if e["type"] == "related-crypto-material" and "kind" in params and not isinstance(params["kind"], list):
            params["kind"] = [params["kind"]]
        c.add(subject, e["type"], _FILE_ROLE[e["type"]], e["name"], params, e.get("excerpt", ""))
    return c.findings()


# ------------------------------------------------- a system's firmware and controller
def _platform(job: dict, component: str) -> dict:
    t = job["target"]
    return {"kind": "platform", "host": t.get("system") or t.get("of") or t.get("controller"), "component": component}


def system_firmware(raw: bytes, job: dict) -> list[dict]:
    """`pqch-system-firmware/1`: each certificate in the Secure Boot databases, and the TPM's banks."""
    doc = json.loads(raw)
    c = _Collector(job, "platform")
    enabled = (doc.get("secure_boot") or {}).get("enabled")
    for label, db in (doc.get("databases") or {}).items():
        for cert in (db or {}).get("certificates", []):
            params = {k: v for k, v in cert.items() if k not in ("key_algorithm",) and v is not None}
            params.update({"database": label, "secure_boot_enabled": enabled, "revoked": label == "dbx"})
            c.add(_platform(job, f"secure-boot:{label}"), "certificate", "signature", cert["key_algorithm"], params,
                  f"{label}: {cert['subject'][:80]} ({cert['key_algorithm']}-{cert.get('key_bits')}, {cert['signature']}, "
                  f"to {cert['not_after'][:10]})")
    for bank in ((doc.get("tpm") or {}).get("pcr_banks") or []):
        name = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "sm3_256": "SM3"}.get(bank, bank)
        c.add(_platform(job, "tpm"), "algorithm", "hash", name, {"tpm_version": doc["tpm"].get("version"), "pcr_bank": bank},
              f"TPM {doc['tpm'].get('version')} PCR bank {bank}")
    return c.findings()


_REDFISH_DATE = "%b %d %H:%M:%S %Y GMT"


def _redfish_date(v: str | None) -> str | None:
    import datetime as _dt
    try:
        return _dt.datetime.strptime(" ".join((v or "").split()), _REDFISH_DATE).replace(tzinfo=_dt.UTC).isoformat()
    except ValueError:
        return None


def controller_attributes(doc: dict) -> dict:
    """The controller's own attribute list, from either a live read or a recording."""
    for p, v in (doc.get("resources") or {}).items():
        if p.endswith("DellAttributes/iDRAC.Embedded.1") and isinstance(v, dict):
            return v.get("Attributes") or {}
    return {}


def controller_redfish(raw: bytes, job: dict) -> list[dict]:
    """`pqch-controller-redfish/1`: what the controller is configured to offer (its SSH and TLS
    settings, SNMP), and the identity certificates it holds. Its listeners' offers on the wire are the
    wire profiles' to record; this is the configuration behind them."""
    doc = json.loads(raw)
    a = controller_attributes(doc)
    c = _Collector(job, "platform")
    for attr, role in (("SSHCrypto.1.KexAlgorithms", "key-establishment"), ("SSHCrypto.1.HostKeyAlgorithms", "signature"),
                       ("SSHCrypto.1.Ciphers", "encryption"), ("SSHCrypto.1.MACs", "mac")):
        for alg in [x for x in str(a.get(attr) or "").split(",") if x]:
            if role == "key-establishment":
                name = names.SSH_KEX.get(alg, alg)
            elif role == "signature":
                name = names.SSH_HOSTKEY.get(alg, alg)
            else:
                name = alg
            c.add(_platform(job, "bmc:ssh-config"), "algorithm", role, name, {"ssh_names": [alg], "configured": True},
                  f"{attr}: {alg}")
    if a.get("WebServer.1.TLSProtocol"):
        c.add(_platform(job, "bmc:https-config"), "protocol", "other", "TLS",
              {"versions_allowed": a.get("WebServer.1.TLSProtocol"),
               "lower_encryption_bit_length": a.get("WebServer.1.LowerEncryptionBitLength"),
               "minimum_bits": a.get("WebServer.1.SSLEncryptionBitLength"),
               "custom_ciphers": a.get("WebServer.1.CustomCipherString") or None, "http_port_open": a.get("WebServer.1.BlockHTTPPort") == "Disabled"},
              f"web server: {a.get('WebServer.1.TLSProtocol')}")
    if a.get("SNMP.1.AgentEnable") == "Enabled":
        proto = a.get("SNMP.1.SNMPProtocol")
        c.add(_platform(job, "bmc:snmp"), "protocol", "other", "SNMP",
              {"versions_accepted": proto, "trap_format": a.get("SNMP.1.TrapFormat"),
               "community_strings_accepted": proto in ("All", "SNMPv1", "SNMPv2c")},
              f"SNMP agent: {proto}, traps {a.get('SNMP.1.TrapFormat')}")
    certs: dict[str, dict] = {}
    for k, v in a.items():
        if k.startswith("SecurityCertificate."):
            parts = k.split(".", 2)
            if len(parts) == 3:
                certs.setdefault(parts[1], {})[parts[2]] = v
    for n, ce in sorted(certs.items()):
        kind = ce.get("CertificateType") or f"certificate-{n}"
        params = {k: v for k, v in {
            "certificate_type": kind,
            "subject": f"CN={ce.get('SubjectCommonName')},OU={ce.get('SubjectOrganizationalUnit')},O={ce.get('SubjectOrganization')}",
            "issuer": f"CN={ce.get('IssuerCommonName')},O={ce.get('IssuerOrganization')}",
            "not_before": _redfish_date(ce.get("CertValidFrom")), "not_after": _redfish_date(ce.get("CertValidTo")),
            "serial": ce.get("SerialNumber"), "expiry_state": ce.get("ExpiryState"),
            "key_reported": False}.items() if v}
        c.add(_platform(job, f"bmc:certificate:{kind.lower()}"), "certificate", "signature", "unknown", params,
              f"{kind}: issued by {ce.get('IssuerCommonName')}, to {str(ce.get('CertValidTo'))[:24]}; the controller does not report the key")
    return c.findings()


def postgres_tls_offer(raw: bytes, job: dict) -> list[dict]:
    """`pqch-postgres-tls-offer/1`: the server's one-byte answer to PostgreSQL's SSLRequest. `N`
    is a refusal: the connection continues in the clear, credentials included."""
    doc = json.loads(raw)
    c = _Collector(job, "wire")
    if doc.get("answer") in ("S", "N"):
        c.add(_endpoint_subject(job, "postgres"), "protocol", "other", "PostgreSQL",
              {"tls_offered": doc["answer"] == "S", "ssl_request_answer": doc["answer"]},
              f"SSLRequest answered {doc['answer']!r}: TLS {'offered' if doc['answer'] == 'S' else 'refused; the connection is in the clear'}")
    return c.findings()


NORMALIZERS: dict[str, Callable[[bytes, dict], list[dict]]] = {
    "pqch-postgres-tls-offer": postgres_tls_offer,
    "testssl.sh": testssl,
    "ssh-audit": ssh_audit,
    "cbomkit-theia": theia,
    "pqch-image-files": imagefiles,
    "pqch-system-files": imagefiles,
    "pqch-system-firmware": system_firmware,
    "pqch-controller-redfish": controller_redfish,
}


def platform_facts(raw: bytes, job: dict) -> dict | None:
    """What a system's firmware or controller says about the system that is not a cryptographic
    asset: its identity, its firmware and their versions, and its security settings. Recorded as a
    `platform.observed` event beside the findings; the CBOM's device and firmware components are
    projected from it."""
    tool = job["tool"]
    if tool not in ("pqch-system-firmware", "pqch-controller-redfish", "pqch-system-files"):
        return None
    doc = json.loads(raw)
    t = job["target"]
    system = t.get("system") or t.get("of")
    if tool == "pqch-system-files":
        return {"system": system, "source": "files", "files_read": doc.get("files_read"),
                "unreadable": doc.get("unreadable", []), "trust_store": doc.get("trust_store"),
                "trust_store_certificates": doc.get("trust_store_certificates"), "read_as_uid": doc.get("read_as_uid")}
    if tool == "pqch-system-firmware":
        dev = doc.get("device") or {}
        fw = [{"name": "BIOS", "version": dev.get("bios_version"), "vendor": dev.get("bios_vendor"), "date": dev.get("bios_date"),
               "enforces": [f"secure-boot:{k}" for k, v in (doc.get("databases") or {}).items() if v]}] if dev.get("bios_version") else []
        tpm = doc.get("tpm")
        return {"system": system, "source": "firmware",
                "device": {"vendor": dev.get("sys_vendor"), "model": dev.get("product_name"), "board": dev.get("board_name")},
                "firmware": fw, "settings": {"secure_boot": (doc.get("secure_boot") or {}).get("enabled"),
                                             "secure_boot_setup_mode": (doc.get("secure_boot") or {}).get("setup_mode"),
                                             "tpm": f"TPM {tpm['version']}" if tpm else None,
                                             "tpm_pcr_banks": (tpm or {}).get("pcr_banks")},
                "dbx_sha256_hashes": doc.get("dbx_sha256_hashes")}
    a = controller_attributes(doc)
    res = doc.get("resources") or {}
    mgr = res.get("/redfish/v1/Managers/iDRAC.Embedded.1") or {}
    inv = []
    for p, v in res.items():
        if "/FirmwareInventory/Installed-" in p and isinstance(v, dict) and v.get("Name"):
            inv.append({"name": v["Name"], "version": v.get("Version"), "id": p.rsplit("/", 1)[-1].split("__")[0]})
    proto = res.get("/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol") or {}
    sb = res.get("/redfish/v1/Systems/System.Embedded.1/SecureBoot") or {}
    bios = (res.get("/redfish/v1/Systems/System.Embedded.1/Bios") or {}).get("Attributes") or {}
    sysres = res.get("/redfish/v1/Systems/System.Embedded.1") or {}
    return {"system": system, "source": "controller", "controller": {
                "host": t.get("controller"), "model": mgr.get("Model"), "firmware_version": mgr.get("FirmwareVersion"),
                "redfish_version": (doc.get("service_root") or {}).get("RedfishVersion"),
                "authenticated": doc.get("authenticated", bool(res)),
                **({"trust": doc["trust"]} if doc.get("trust") else {})},
            "device": {"model": sysres.get("Model"), "vendor": sysres.get("Manufacturer")},
            "firmware": sorted(inv, key=lambda x: x["name"]),
            "settings": {k: v for k, v in {
                "fips_mode": a.get("Security.1.FIPSMode"), "fips_module": a.get("Security.1.FIPSVersion"),
                "protocols_enabled": {k: v.get("ProtocolEnabled") for k, v in proto.items() if isinstance(v, dict) and "ProtocolEnabled" in v} or None,
                "secure_boot": sb.get("SecureBootEnable"), "secure_boot_mode": sb.get("SecureBootMode"),
                "tpm": [{"interface": m.get("InterfaceType"), "firmware": m.get("FirmwareVersion"), "state": (m.get("Status") or {}).get("State")}
                        for m in sysres.get("TrustedModules") or []] or None,
                "tpm_hash": bios.get("Tpm2Algorithm"), "memory_encryption": bios.get("MemoryEncryption"),
                "scv": a.get("SCV.1.CertificateVersion"), "sekm": a.get("SEKM.1.SupportStatus")}.items() if v is not None}}


def normalize(raw: bytes, job: dict) -> list[dict]:
    return NORMALIZERS[job["tool"]](raw, job)
