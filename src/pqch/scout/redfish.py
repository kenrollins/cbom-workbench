"""A server's management controller, read through DMTF Redfish: `pqch-controller-redfish/1`.

GET requests only. The controller's own TLS handshake and certificate are read first, without
credentials; then its service root; then, with the credentials the runner copies into the job's
container (`/scan/controller.env`: REDFISH_USER, REDFISH_PASSWORD), the resources that carry
cryptography, firmware identity and trust anchors. The first refused login stops the read: a
controller locks an account after repeated failures. Credentials are never written to the output,
and neither are the secrets the controller itself holds: the attribute lists are cut to the groups
the normalizer reads, and every field named for a password, passphrase, community string or key is
removed from every resource before the document exists (`sanitize`, which a recording brought in or
sent out must pass through too).

The credentials go to the scoped controller and nowhere else. A link is followed only when it is a
path under /redfish/v1/ on the same host: a link that names a scheme or a host is recorded as
refused and never requested, whatever the controller says.

The resource paths are Dell iDRAC 9's (16th generation); a path a controller does not serve is
recorded with its status, not treated as an error. A recording of an earlier read is the same
document, and is brought into a run as that read's raw output (`pqch scan-system --controller-recording`).

Trust (FR-03). The first handshake is an observation: it sends nothing but a ClientHello and records
the certificate served. Whether the authenticated session that follows trusts that controller is set
in the same per-controller file as the credentials, and recorded in the output's `trust` block, which
the controller's `platform.observed` event carries onto the ledger:

- `REDFISH_TRUST=ca` with `REDFISH_CA_PEM_B64` (a base64 PEM bundle): the session is verified against
  that CA, hostname included.
- `REDFISH_TRUST=pin` with `REDFISH_PIN_SHA256`: the certificate served must be that one, or no
  credential is sent.
- `REDFISH_TRUST=observed`: the session is held to the certificate the observing handshake of this same
  read saw, and its fingerprint is recorded so the operator can set `pin`. This is not trust on first
  use: nothing from an earlier read is consulted, so a controller that serves a new certificate on
  every read is accepted on every read. It stops only a swap between the observation and the session.
- `REDFISH_TRUST=none`, written out: no verification, and `trust.mode` says `none`. The operator's
  stated choice to hand the credentials to whatever answers at the address.
- unset, with credentials present: no credential is sent. The read stops after the service root and
  the output says why (`trust.refused`).

An expired or not-yet-valid certificate fails `ca`, `pin` and `observed` alike (OpenSSL checks the
time of a trust anchor too): the read stops before any credential is sent.

    pqch controller-redfish <host> [--port 443]
"""
from __future__ import annotations

import datetime
import hashlib
import json
import socket
import ssl
import sys
from pathlib import Path

SCHEMA = "pqch-controller-redfish/1"
_OBSERVED: dict[tuple[str, int], bytes] = {}
CRED = Path("/scan/controller.env")
PATHS = [
    "/redfish/v1/Managers/iDRAC.Embedded.1",
    "/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol",
    "/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol/HTTPS/Certificates",
    "/redfish/v1/CertificateService/CertificateLocations",
    "/redfish/v1/UpdateService/FirmwareInventory",
    "/redfish/v1/Systems/System.Embedded.1",
    "/redfish/v1/Systems/System.Embedded.1/SecureBoot",
    "/redfish/v1/Systems/System.Embedded.1/SecureBoot/SecureBootDatabases",
    "/redfish/v1/Systems/System.Embedded.1/Bios",
    "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1",
]
# What is kept from the controller's long attribute list (372 names on the lab's iDRAC 9): the groups
# the normalizer and the platform facts read, and of two groups only the named fields. An allow-list:
# a new firmware's new secret is dropped because nobody listed it, not kept because nobody thought to
# forbid it.
KEEP_GROUPS = ("SSHCrypto", "WebServer", "SecurityCertificate", "SCV", "SEKM")
KEEP_FIELDS = {"Security": ("FIPSMode", "FIPSVersion"), "SNMP": ("AgentEnable", "SNMPProtocol", "TrapFormat")}
# The BIOS attributes that describe the platform's cryptography, by a word in the name.
KEEP_BIOS = ("tpm", "secureboot", "memoryencryption", "memencryption", "fips", "aesni")
# A field of any resource whose name holds one of these is a secret or key material, and is removed
# wherever it is: an account's password or SNMPv3 passphrase, an SNMP community string, the IPMI
# keys, an NTP or SEKM key.
SECRET_WORDS = ("password", "passphrase", "passwd", "community", "secret", "token", "salt", "ipmikey", "encryptionkey",
                "securitykey", "authkey", "authenticationkey", "privkey", "privacykey", "privatekey", "v3key", "accesskey",
                "sessionkey", "kgkey")
MAX_MEMBERS = 200          # of one collection; a controller cannot spend the job's budget on its own links
ATTRIBUTE_LISTS = ("DellAttributes/iDRAC.Embedded.1", "/Bios")


def _secret(name: str) -> bool:
    low = name.lower().replace("_", "").replace("-", "")
    return any(w in low for w in SECRET_WORDS)


def _filtered(attrs: dict, *, bios: bool = False) -> dict:
    """The attributes kept from a controller's or a BIOS's list."""
    out = {}
    for k, v in sorted(attrs.items()):
        if _secret(k):
            continue
        if bios:
            keep = any(w in k.lower() for w in KEEP_BIOS)
        else:
            group, _, rest = k.partition(".")
            field = rest.rpartition(".")[2]
            keep = group in KEEP_GROUPS or field in KEEP_FIELDS.get(group, ())
        if keep:
            out[k] = v
    return out


def _scrub(value, removed: list[str]):
    """A resource with every secret-named field removed, at any depth."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _secret(k):
                removed.append(k)
            else:
                out[k] = _scrub(v, removed)
        return out
    if isinstance(value, list):
        return [_scrub(v, removed) for v in value]
    return value


def sanitize(doc: dict) -> dict:
    """A `pqch-controller-redfish/1` document with nothing in it a controller should keep to
    itself: the one place a live read, a recording brought into a run and a recording sent out are
    all filtered. Attribute lists are cut to the allow-list and secret-named fields are removed from
    every resource. `filtered` counts what went, by name only. Filtering a filtered document changes
    nothing but leaves the counts of the first pass."""
    out = dict(doc)
    resources, dropped, removed = {}, 0, []
    for path, body in (doc.get("resources") or {}).items():
        if isinstance(body, dict) and path.endswith(ATTRIBUTE_LISTS) and isinstance(body.get("Attributes"), dict):
            kept = _filtered(body["Attributes"], bios=path.endswith("/Bios"))
            dropped += len(body["Attributes"]) - len(kept)
            body = {"Attributes": kept}
        resources[path] = _scrub(body, removed)
    out["resources"] = resources
    if "service_root" in out:
        out["service_root"] = _scrub(out["service_root"], removed)
    if dropped or removed or "filtered" not in doc:
        out["filtered"] = {"attributes_dropped": dropped, "secret_fields_removed": len(removed),
                           "secret_field_names": sorted(set(removed))[:50]}
    return out


def own_path(link) -> str | None:
    """A link the reader may follow with the controller's credentials: a path under /redfish/v1/
    on the controller itself. Anything with a scheme or a host, or outside the Redfish tree, is not
    the scoped controller's to send the reader to."""
    from urllib.parse import urlsplit

    if not isinstance(link, str) or not link.startswith("/redfish/v1/") or link.startswith("//") \
            or any(c.isspace() or c == "\\" for c in link):
        return None
    parts = urlsplit(link)
    if parts.scheme or parts.netloc or "/../" in parts.path or parts.path.endswith("/.."):
        return None
    return link


def _body(r) -> dict:
    """A response as the resource it carries; anything else is recorded by its status, not raised."""
    if r.status_code != 200:
        return {"status": r.status_code}
    try:
        body = r.json()
    except ValueError:
        return {"status": 200, "unreadable": "the body is not JSON"}
    return body if isinstance(body, dict) else {"status": 200, "unreadable": "the body is not a JSON object"}


def handshake(host: str, port: int) -> dict:
    """One TLS handshake as this reader's OpenSSL offers it, and the certificate the controller serves."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=15) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        der = s.getpeercert(binary_form=True)
        version, cipher = s.version(), s.cipher()[0]
    _OBSERVED[(host, port)] = der
    c = x509.load_der_x509_certificate(der)
    try:
        k = c.public_key()
    except Exception:       # a key type this library does not load is still a certificate served
        k = None
    fam, bits = ("unknown", None) if k is None else (("RSA", k.key_size) if isinstance(k, rsa.RSAPublicKey) else ("ECDSA", k.key_size)
                 if isinstance(k, ec.EllipticCurvePublicKey) else ("Ed25519", 256) if isinstance(k, ed25519.Ed25519PublicKey)
                 else (type(k).__name__, None))
    return {"version": version, "cipher": cipher, "client_openssl": ssl.OPENSSL_VERSION,
            "certificate": {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                            "key_algorithm": fam, "key_bits": bits, "signature": c.signature_algorithm_oid._name,
                            "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
                            "self_signed": c.subject == c.issuer, "sha256": hashlib.sha256(der).hexdigest()}}


def _settings() -> dict:
    vals = {}
    if not CRED.exists():
        return vals
    for line in CRED.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    return vals


def _credentials() -> tuple[str, str]:
    vals = _settings()
    return vals["REDFISH_USER"], vals["REDFISH_PASSWORD"]


def trust_context(settings: dict, observed_der: bytes) -> tuple[ssl.SSLContext | bool, dict]:
    """The verification for the authenticated session, and the record of it. Raises ValueError when
    the controller served a certificate other than the pinned one."""
    import base64

    mode = (settings.get("REDFISH_TRUST") or "none").strip()
    observed = hashlib.sha256(observed_der).hexdigest()
    rec = {"mode": mode, "observed_sha256": observed}
    if mode == "none":
        return False, rec
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)       # trusts only what is loaded below
    for needs, name in (("ca", "REDFISH_CA_PEM_B64"), ("pin", "REDFISH_PIN_SHA256")):
        if mode == needs and not settings.get(name):
            raise ValueError(f"REDFISH_TRUST is {mode} and {name} is not set")
    if mode == "ca":
        try:
            ca = base64.b64decode(settings["REDFISH_CA_PEM_B64"], validate=True)
            ctx.load_verify_locations(cadata=ca.decode())
        except (ValueError, ssl.SSLError) as e:
            raise ValueError(f"REDFISH_CA_PEM_B64 is not a readable PEM bundle ({type(e).__name__})") from None
        rec["ca_sha256"] = hashlib.sha256(ca).hexdigest()
        return ctx, rec
    if mode == "pin":
        pin = settings["REDFISH_PIN_SHA256"].lower()
        rec["pinned_sha256"] = pin
        if pin != observed:
            raise ValueError(f"the controller served certificate {observed[:16]}…, not the pinned {pin[:16]}…")
    elif mode == "observed":
        rec["pinned_sha256"] = observed
    else:
        raise ValueError(f"REDFISH_TRUST {mode!r} is not one of ca, pin, observed")
    # The served certificate itself is the only trust anchor; a leaf a CA issued is accepted as an anchor too.
    ctx.check_hostname = False
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=observed_der)
    return ctx, rec


def read(host: str, port: int = 443) -> dict:
    return sanitize(_read(host, port))


def _read(host: str, port: int) -> dict:
    import warnings

    import httpx

    warnings.filterwarnings("ignore")
    out = {"schema": SCHEMA, "host": host, "port": port,
           "read_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
           "method": "Redfish GET only", "tls": handshake(host, port), "resources": {}}
    base = f"https://{'[' + host + ']' if ':' in host and not host.startswith('[') else host}:{port}"
    settings = _settings()
    # Credentials are sent only under a trust mode somebody wrote down. With none written, the
    # service root is still read (it carries no credential) and the read stops there.
    undecided = CRED.exists() and not (settings.get("REDFISH_TRUST") or "").strip()
    try:
        verify, out["trust"] = trust_context(settings, _OBSERVED[(host, port)])
    except ValueError as e:
        out["trust"] = {"mode": settings.get("REDFISH_TRUST"), "refused": str(e),
                        "observed_sha256": out["tls"]["certificate"]["sha256"]}
        out["authenticated"] = False
        return out
    with httpx.Client(base_url=base, verify=verify, timeout=60, headers={"Accept": "application/json"},
                      follow_redirects=False) as anon:
        try:
            r = anon.get("/redfish/v1")
        except httpx.ConnectError as e:
            if verify is False:
                raise
            # The session did not verify: stop before any credential is sent, and say why.
            out["trust"]["refused"] = f"{type(e).__name__}: {e}"[:300]
            out["authenticated"] = False
            return out
        out["service_root"] = _body(r)
    if not CRED.exists():
        out["authenticated"] = False
        return out
    if undecided:
        out["trust"] = {"mode": None, "observed_sha256": out["trust"]["observed_sha256"],
                        "refused": "REDFISH_TRUST is not set: the credentials are not sent to a controller nothing verifies. "
                                   "Set ca, pin or observed, or write none to send them unverified"}
        out["authenticated"] = False
        return out
    try:
        user, password = _credentials()
    except KeyError as e:
        out["authenticated"] = False
        out["login_refused"] = f"the credentials file names no {e.args[0]}"
        return out
    refused: list[str] = []

    def follow(c, link) -> dict | None:
        """One link the controller gave, fetched if it is the controller's own path; else recorded."""
        path = own_path(link)
        if path is None:
            if len(refused) < 20:
                refused.append(str(link)[:200])
            return None
        if path not in out["resources"]:
            out["resources"][path] = _body(c.get(path))
        return out["resources"][path]

    # The client never follows a redirect, and every request below is a fixed path or one `follow`
    # passed: the credentials reach the scoped controller's address and port only.
    with httpx.Client(base_url=base, verify=verify, timeout=120, auth=(user, password),
                      headers={"Accept": "application/json"}, follow_redirects=False) as c:
        first = c.get(PATHS[0])
        if first.status_code in (401, 403):
            out["authenticated"] = False
            out["login_refused"] = first.status_code
            return out
        out["authenticated"] = True
        for p in PATHS:
            body = _body(first if p == PATHS[0] else c.get(p))
            out["resources"][p] = body
            members = [m for m in body.get("Members") or [] if isinstance(m, dict) and m.get("@odata.id")]
            if len(members) > MAX_MEMBERS:
                out.setdefault("members_not_followed", {})[p] = len(members) - MAX_MEMBERS
            for m in members[:MAX_MEMBERS]:
                got = follow(c, m["@odata.id"])
                if got and "SecureBootDatabases/" in m["@odata.id"] and "status" not in got:
                    for sub in ("Certificates", "Signatures"):
                        link = (got.get(sub) or {}).get("@odata.id") if isinstance(got.get(sub), dict) else None
                        if link:
                            follow(c, link)
    if refused:
        out["links_refused"] = refused
    return out


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if not args:
        print("usage: pqch controller-redfish <host> [port]", file=sys.stderr)
        return 2
    doc = read(args[0], int(args[1]) if len(args) > 1 else 443)
    json.dump(doc, sys.stdout, indent=1, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
