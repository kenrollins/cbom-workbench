"""Tool spellings to standard names (agency/answer-key.yaml, "Names").

A name the table does not know is passed through unchanged. An algorithm the
tool did not state is never inferred: a key theia reports only as
`private-key` is named `unknown`.
"""

from __future__ import annotations

import re

TLS_GROUPS = {
    "prime256v1": "secp256r1",
    "secp256r1": "secp256r1",
    "P-256": "secp256r1",
    "secp384r1": "secp384r1",
    "P-384": "secp384r1",
    "secp521r1": "secp521r1",
    "P-521": "secp521r1",
    "X25519": "X25519",
    "x25519": "X25519",
    "X448": "X448",
    "X25519MLKEM768": "X25519MLKEM768",
    "SecP256r1MLKEM768": "SecP256r1MLKEM768",
    "SecP384r1MLKEM1024": "SecP384r1MLKEM1024",
    "x448": "X448",
    "MLKEM512": "ML-KEM-512",
    "MLKEM768": "ML-KEM-768",
    "MLKEM1024": "ML-KEM-1024",
}

# IANA TLS supported-group ids, as a capture sees them, to standard names. Draft and
# vendor ids are named by their draft name; a GREASE value (0x?a?a) is dropped by the caller.
TLS_GROUP_IDS = {
    1: "sect163k1", 2: "sect163r1", 3: "sect163r2", 4: "sect193r1", 5: "sect193r2", 6: "sect233k1",
    7: "sect233r1", 8: "sect239k1", 9: "sect283k1", 10: "sect283r1", 11: "sect409k1", 12: "sect409r1",
    13: "sect571k1", 14: "sect571r1", 15: "secp160k1", 16: "secp160r1", 17: "secp160r2", 18: "secp192k1",
    19: "secp192r1", 20: "secp224k1", 21: "secp224r1", 22: "secp256k1", 23: "secp256r1", 24: "secp384r1",
    25: "secp521r1", 26: "brainpoolP256r1", 27: "brainpoolP384r1", 28: "brainpoolP512r1", 29: "X25519",
    30: "X448", 31: "brainpoolP256r1tls13", 32: "brainpoolP384r1tls13", 33: "brainpoolP512r1tls13",
    256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
    512: "ML-KEM-512", 513: "ML-KEM-768", 514: "ML-KEM-1024",
    4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024",
    25497: "X25519Kyber768Draft00", 25498: "X25519Kyber512Draft00",
}
TLS_VERSION_IDS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def is_grease(n: int) -> bool:
    return (n & 0x0F0F) == 0x0A0A and (n >> 8) == (n & 0xFF)


def tls_group(n: int) -> str:
    """The standard name of a supported-group id; an unknown id is named by its number."""
    return TLS_GROUP_IDS.get(n, f"group-{n}")


SSH_KEX = {
    "curve25519-sha256": "X25519",
    "curve25519-sha256@libssh.org": "X25519",
    "ecdh-sha2-nistp256": "secp256r1",
    "ecdh-sha2-nistp384": "secp384r1",
    "ecdh-sha2-nistp521": "secp521r1",
    "mlkem768x25519-sha256": "X25519MLKEM768",
    "mlkem768nistp256-sha256": "SecP256r1MLKEM768",
    "mlkem1024nistp384-sha384": "SecP384r1MLKEM1024",
    "sntrup761x25519-sha512": "sntrup761x25519",
    "sntrup761x25519-sha512@openssh.com": "sntrup761x25519",
    "diffie-hellman-group1-sha1": "DH-1024",
    "diffie-hellman-group14-sha1": "DH-2048",
    "diffie-hellman-group14-sha256": "DH-2048",
    "diffie-hellman-group16-sha512": "DH-4096",
    "diffie-hellman-group18-sha512": "DH-8192",
    "diffie-hellman-group-exchange-sha1": "DH-GEX",
    "diffie-hellman-group-exchange-sha256": "DH-GEX",
}

# Pseudo-algorithms SSH lists among key exchanges that negotiate nothing.
SSH_KEX_IGNORE = re.compile(r"^(ext-info-[cs]|kex-strict-[cs]-v00@openssh\.com)$")

SSH_HOSTKEY = {
    "ssh-rsa": "RSA",
    "rsa-sha2-256": "RSA",
    "rsa-sha2-512": "RSA",
    "ssh-dss": "DSA",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
    "ssh-ed25519": "Ed25519",
    "ssh-ed448": "Ed448",
}

SSH_HOSTKEY_CURVE = {
    "ecdsa-sha2-nistp256": "P-256",
    "ecdsa-sha2-nistp384": "P-384",
    "ecdsa-sha2-nistp521": "P-521",
}

HASHES = {"SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512", "MD5": "MD5"}


def key_family(name: str) -> str:
    """theia's key names (`RSA-2048`, `ECDSA`, `private-key`) to a key algorithm family."""
    if not name or name in ("private-key", "public-key", "secret-key"):
        return "unknown"
    head = name.split("-")[0].upper()
    return {"RSA": "RSA", "DSA": "DSA", "ECDSA": "ECDSA", "EC": "ECDSA", "ED25519": "Ed25519",
            "ED448": "Ed448"}.get(head, name)


def algorithm_name(name: str) -> str:
    return HASHES.get(name, name)


# testssl.sh names a TLS 1.2 finite-field group by the RFC that defines it, or only by its size.
_OAKLEY_BITS = {"RFC2409/Oakley Group 2": 1024, "RFC3526/Oakley Group 5": 1536, "RFC3526/Oakley Group 14": 2048,
                "RFC3526/Oakley Group 15": 3072, "RFC3526/Oakley Group 16": 4096, "RFC3526/Oakley Group 17": 6144,
                "RFC3526/Oakley Group 18": 8192}


def dh_groups(text: str) -> list[tuple[str, str]]:
    """testssl.sh's `DH_groups` finding as (standard name, tool spelling) pairs.

    The finding is either a list of RFC 7919 names (`ffdhe2048 ffdhe3072`), or one phrase naming
    one group (`RFC3526/Oakley Group 14`, `Unknown DH group (2048 bits)`). A phrase is one group,
    named by its size: splitting it on spaces would invent three.
    """
    text = text.strip()
    if text in _OAKLEY_BITS:
        return [(f"DH-{_OAKLEY_BITS[text]}", text)]
    m = re.search(r"\((\d+) bits\)", text)
    if m:
        return [(f"DH-{m.group(1)}", text)]
    if all(re.fullmatch(r"ffdhe\d+", tok) for tok in text.split()):
        return [(tok, tok) for tok in text.split()]
    return [(text, text)]
