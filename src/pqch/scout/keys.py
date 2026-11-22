"""Parsing of keys and certificates that scanners hand back.

These produce the identities that let a finding on the wire be joined to a file
in an image: the SHA-256 of a certificate's SubjectPublicKeyInfo, and the
OpenSSH SHA-256 fingerprint of a host key.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa


def spki_sha256_from_der(spki_der: bytes) -> str:
    return hashlib.sha256(spki_der).hexdigest()


def ssh_fingerprint_from_spki(spki_der: bytes) -> str | None:
    """The OpenSSH `SHA256:` fingerprint (base64, unpadded) of a public key given as SPKI DER."""
    try:
        key = serialization.load_der_public_key(spki_der)
        line = key.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    except Exception:
        return None
    blob = base64.b64decode(line.split()[1])
    return base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


try:  # FIPS 204 signatures: cryptography 46 and later, on OpenSSL 3.5
    from cryptography.hazmat.primitives.asymmetric import mldsa as _mldsa
    _MLDSA = {_mldsa.MLDSA44PublicKey: "ML-DSA-44", _mldsa.MLDSA65PublicKey: "ML-DSA-65",
              _mldsa.MLDSA87PublicKey: "ML-DSA-87"}
except ImportError:  # pragma: no cover - an older library reads the key as unknown
    _MLDSA = {}


def _family_and_params(key) -> tuple[str, dict]:
    if isinstance(key, rsa.RSAPublicKey):
        return "RSA", {"key_bits": key.key_size}
    if isinstance(key, ec.EllipticCurvePublicKey):
        curve = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}.get(key.curve.name, key.curve.name)
        return "ECDSA", {"curve": curve}
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", {}
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", {}
    if isinstance(key, dsa.DSAPublicKey):
        return "DSA", {"key_bits": key.key_size}
    for cls, name in _MLDSA.items():
        if isinstance(key, cls):
            return name, {}
    return "unknown", {}


def _tlv(der: bytes, off: int) -> tuple[int, int, int]:
    """One DER element at `off`: its tag, where its content starts, and where it ends."""
    tag, n = der[off], der[off + 1]
    start = off + 2
    if n & 0x80:
        count = n & 0x7F
        if not 1 <= count <= 4:
            raise ValueError("DER length not readable")
        n = int.from_bytes(der[start:start + count], "big")
        start += count
    if start + n > len(der):
        raise ValueError("DER element runs past its container")
    return tag, start, start + n


def spki_der_from_tbs(tbs: bytes) -> bytes:
    """The SubjectPublicKeyInfo element cut out of a TBSCertificate (RFC 5280 4.1): the seventh
    field, or the sixth when the optional version is absent. For a certificate whose key the library
    cannot load, so its identity is still the hash of the same bytes every other reader hashes."""
    tag, off, end = _tlv(tbs, 0)
    if tag != 0x30:
        raise ValueError("not a TBSCertificate")
    fields = []
    while off < end and len(fields) < 7:
        t, _start, stop = _tlv(tbs, off)
        fields.append((t, off, stop))
        off = stop
    if fields and fields[0][0] == 0xA0:     # [0] EXPLICIT version
        fields = fields[1:]
    if len(fields) < 6 or fields[5][0] != 0x30:
        raise ValueError("no SubjectPublicKeyInfo where one belongs")
    return tbs[fields[5][1]:fields[5][2]]


def _public_key(cert: x509.Certificate) -> tuple[str, dict]:
    """The certificate key's family and parameters, with its SPKI hash. A key type the library does
    not load (a post-quantum or national algorithm newer than it) is not an error: the family is
    `unknown`, the algorithm's OID is kept, and the SPKI is cut from the certificate's own bytes."""
    try:
        key = cert.public_key()
        spki = key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        family, params = _family_and_params(key)
        return family, {**params, "spki_sha256": spki_sha256_from_der(spki)}
    except Exception as e:  # UnsupportedAlgorithm, or a key the library rejects
        params: dict = {"key_parse_error": f"{type(e).__name__}: {e}"[:200]}
        try:
            params["key_algorithm_oid"] = cert.public_key_algorithm_oid.dotted_string
        except Exception:  # noqa: S110 - an older library has no such attribute; the OID stays unrecorded
            pass
        try:
            params["spki_sha256"] = spki_sha256_from_der(spki_der_from_tbs(cert.tbs_certificate_bytes))
        except Exception:  # noqa: S110 - no SPKI identity; the certificate's own hash still identifies it
            pass
        return "unknown", params


def parse_certificate_pem(pem: str) -> dict:
    """What a certificate says about itself, plus the identities used for joining."""
    cert = x509.load_pem_x509_certificate(pem.encode())
    family, params = _public_key(cert)
    try:
        sig = cert.signature_algorithm_oid._name
    except Exception:
        sig = cert.signature_algorithm_oid.dotted_string
    # `openssl req -x509` marks every self-signed certificate CA:TRUE, a server's included;
    # a certificate authority's own certificate also carries keyUsage keyCertSign (RFC 5280
    # 4.2.1.3). `is_ca` is the strict reading; the bare flag is kept beside it.
    try:
        ca_flag = bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        ca_flag = False
    try:
        cert_sign = bool(cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
    except x509.ExtensionNotFound:
        cert_sign = False
    return {
        "family": family,
        **params,
        "signature": sig,
        "is_ca": ca_flag and cert_sign,
        "basic_constraints_ca": ca_flag,
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.subject == cert.issuer,
        "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "serial": format(cert.serial_number, "x"),
        "cert_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }
