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


def parse_certificate_pem(pem: str) -> dict:
    """What a certificate says about itself, plus the identities used for joining."""
    cert = x509.load_pem_x509_certificate(pem.encode())
    spki = cert.public_key().public_bytes(serialization.Encoding.DER,
                                          serialization.PublicFormat.SubjectPublicKeyInfo)
    family, params = _family_and_params(cert.public_key())
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
        "spki_sha256": spki_sha256_from_der(spki),
    }
