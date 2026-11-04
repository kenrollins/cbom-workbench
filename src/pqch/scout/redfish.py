"""A server's management controller, read through DMTF Redfish: `pqch-controller-redfish/1`.

GET requests only. The controller's own TLS handshake and certificate are read first, without
credentials; then its service root; then, with the credentials the runner copies into the job's
container (`/scan/controller.env`: REDFISH_USER, REDFISH_PASSWORD), the resources that carry
cryptography, firmware identity and trust anchors. The first refused login stops the read: a
controller locks an account after repeated failures. Credentials are never written to the output.

The resource paths are Dell iDRAC 9's (16th generation); a path a controller does not serve is
recorded with its status, not treated as an error. A recording of an earlier read is the same
document, and is brought into a run as that read's raw output (`pqch scan-system --controller-recording`).

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
# Attribute names kept from the controller's and the BIOS's long attribute lists.
KEEP = ("tls", "cipher", "ssh", "crypt", "cert", "ssl", "fips", "secur", "tpm", "kex", "mac", "hostkey",
        "webserver", "scv", "encrypt", "hash", "sign", "redfish", "ipmi", "snmp", "kmip", "sekm")
DROP = ("password", "community", "authkey", "privkey", "secret", "token")


def _filtered(attrs: dict) -> dict:
    return {k: v for k, v in sorted(attrs.items())
            if any(w in k.lower() for w in KEEP) and not any(w in k.lower() for w in DROP)}


def handshake(host: str, port: int) -> dict:
    """One TLS handshake as this reader's OpenSSL offers it, and the certificate the controller serves."""
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=15) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
        der = s.getpeercert(binary_form=True)
        version, cipher = s.version(), s.cipher()[0]
    c = x509.load_der_x509_certificate(der)
    k = c.public_key()
    fam, bits = (("RSA", k.key_size) if isinstance(k, rsa.RSAPublicKey) else ("ECDSA", k.key_size)
                 if isinstance(k, ec.EllipticCurvePublicKey) else ("Ed25519", 256) if isinstance(k, ed25519.Ed25519PublicKey)
                 else (type(k).__name__, None))
    return {"version": version, "cipher": cipher, "client_openssl": ssl.OPENSSL_VERSION,
            "certificate": {"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                            "key_algorithm": fam, "key_bits": bits, "signature": c.signature_algorithm_oid._name,
                            "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
                            "self_signed": c.subject == c.issuer, "sha256": hashlib.sha256(der).hexdigest()}}


def _credentials() -> tuple[str, str]:
    vals = {}
    for line in CRED.read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    return vals["REDFISH_USER"], vals["REDFISH_PASSWORD"]


def read(host: str, port: int = 443) -> dict:
    import warnings

    import httpx

    warnings.filterwarnings("ignore")
    out = {"schema": SCHEMA, "host": host, "port": port,
           "read_at": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
           "method": "Redfish GET only", "tls": handshake(host, port), "resources": {}}
    base = f"https://{host}:{port}"
    with httpx.Client(base_url=base, verify=False, timeout=60, headers={"Accept": "application/json"}) as anon:
        r = anon.get("/redfish/v1")
        out["service_root"] = r.json() if r.status_code == 200 else {"status": r.status_code}
    if not CRED.exists():
        out["authenticated"] = False
        return out
    user, password = _credentials()
    with httpx.Client(base_url=base, verify=False, timeout=120, auth=(user, password),
                      headers={"Accept": "application/json"}) as c:
        first = c.get(PATHS[0])
        if first.status_code in (401, 403):
            out["authenticated"] = False
            out["login_refused"] = first.status_code
            return out
        out["authenticated"] = True
        for p in PATHS:
            r = first if p == PATHS[0] else c.get(p)
            if r.status_code != 200:
                out["resources"][p] = {"status": r.status_code}
                continue
            body = r.json()
            if p.endswith("DellAttributes/iDRAC.Embedded.1"):
                body = {"Attributes": _filtered(body.get("Attributes", {}))}
            elif p.endswith("/Bios"):
                body = {"Attributes": _filtered(body.get("Attributes", {}))}
            out["resources"][p] = body
            for m in body.get("Members", []) if isinstance(body, dict) else []:
                mp = m.get("@odata.id")
                if not mp:
                    continue
                mr = c.get(mp)
                out["resources"][mp] = mr.json() if mr.status_code == 200 else {"status": mr.status_code}
                if "SecureBootDatabases/" in mp and mr.status_code == 200:
                    for sub in ("Certificates", "Signatures"):
                        link = (mr.json().get(sub) or {}).get("@odata.id")
                        if link:
                            sr = c.get(link)
                            out["resources"][link] = sr.json() if sr.status_code == 200 else {"status": sr.status_code}
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
