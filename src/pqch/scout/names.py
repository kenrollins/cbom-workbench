"""Tool spellings to standard names (agency/answer-key.yaml, "Names"), read from the alias pack.

A name the table does not know is passed through unchanged. An algorithm the
tool did not state is never inferred: a key theia reports only as
`private-key` is named `unknown`.
"""

from __future__ import annotations

import re

import hashlib
from pathlib import Path

import yaml

# The tables are data (aliases.yaml beside this file, `pqch.alias-pack/1`), loaded once. The module
# keeps the names callers use; nothing here maps a spelling the pack does not hold.
PACK_PATH = Path(__file__).with_name("aliases.yaml")
_raw = PACK_PATH.read_bytes()
_pack = yaml.safe_load(_raw)
if _pack.get("schema") != "pqch.alias-pack/1":
    raise ValueError(f"{PACK_PATH}: expected schema pqch.alias-pack/1")
PACK = {"schema": _pack["schema"], "version": _pack["version"], "sha256": hashlib.sha256(_raw).hexdigest()}
_t = _pack["tables"]
TLS_GROUPS: dict[str, str] = _t["tls_groups"]
# IANA TLS supported-group ids, as a capture sees them; a GREASE value (0x?a?a) is dropped by the caller.
TLS_GROUP_IDS: dict[int, str] = {int(k): v for k, v in _t["tls_group_ids"].items()}
TLS_VERSION_IDS: dict[int, str] = {int(k): v for k, v in _t["tls_version_ids"].items()}
# A protocol version as a tool spells it (testssl.sh's `TLSv1`, Zeek's `TLSv13`) to the standard name.
TLS_VERSION_NAMES: dict[str, str] = _t["tls_version_names"]
# Standard names of key establishment that is post-quantum, alone or in a hybrid, and the group ids
# that carry them: the one definition every rule that counts them reads.
PQ_KEY_ESTABLISHMENT: frozenset[str] = frozenset(_t["pq_key_establishment"])
PQ_GROUP_IDS: frozenset[int] = frozenset(int(k) for k, v in _t["tls_group_ids"].items() if v in PQ_KEY_ESTABLISHMENT)
SSH_KEX: dict[str, str] = _t["ssh_kex"]
SSH_HOSTKEY: dict[str, str] = _t["ssh_hostkey"]
SSH_HOSTKEY_CURVE: dict[str, str] = _t["ssh_hostkey_curve"]
HASHES: dict[str, str] = _t["hashes"]


def provenance() -> dict:
    """The alias pack that named a run's findings: its schema, version and the file's hash."""
    return dict(PACK)


def is_grease(n: int) -> bool:
    return (n & 0x0F0F) == 0x0A0A and (n >> 8) == (n & 0xFF)


def tls_group(n: int) -> str:
    """The standard name of a supported-group id; an unknown id is named by its number."""
    return TLS_GROUP_IDS.get(n, f"group-{n}")


def tls_version_name(spelling: str) -> str:
    """The standard name of a protocol version (`TLS 1.0`) from a tool's spelling (`TLSv1`, `TLSv10`);
    a spelling the pack does not hold passes through unchanged."""
    return TLS_VERSION_NAMES.get(spelling, spelling)


def is_pq_key_establishment(name: str) -> bool:
    """Whether a standard key-establishment name is post-quantum, alone or in a hybrid."""
    return name in PQ_KEY_ESTABLISHMENT


# Pseudo-algorithms SSH lists among key exchanges that negotiate nothing: the pack's list, as the
# pattern callers match a name against.
SSH_KEX_IGNORE = re.compile("^(" + "|".join(re.escape(x) for x in _t["ssh_kex_ignore"]) + ")$")


def key_family(name: str) -> str:
    """A tool's key name (theia's `RSA-2048`, `ECDSA`, `private-key`; a CBOM's `RSA public key`) to a
    key algorithm family. A name that is already a family (`ML-DSA-65`) stays whole."""
    for suffix in (" public key", " private key"):
        if name and name.lower().endswith(suffix):
            name = name[:-len(suffix)].strip()
    if not name or name in ("private-key", "public-key", "secret-key"):
        return "unknown"
    head = name.split("-")[0].upper()
    return {"RSA": "RSA", "DSA": "DSA", "ECDSA": "ECDSA", "EC": "ECDSA", "ED25519": "Ed25519",
            "ED448": "Ed448"}.get(head, name)


def algorithm_name(name: str) -> str:
    """A tool's spelling of an algorithm to the standard name: a hash, a TLS group or an SSH key
    exchange by any spelling the tables know; anything else passes through unchanged."""
    return HASHES.get(name) or TLS_GROUPS.get(name) or SSH_KEX.get(name) or name


# testssl.sh names a TLS 1.2 finite-field group by the RFC that defines it, or only by its size.
_OAKLEY_BITS = {"RFC2409/Oakley Group 2": 1024, "RFC3526/Oakley Group 5": 1536, "RFC3526/Oakley Group 14": 2048,
                "RFC3526/Oakley Group 15": 3072, "RFC3526/Oakley Group 16": 4096, "RFC3526/Oakley Group 17": 6144,
                "RFC3526/Oakley Group 18": 8192}


def dh_groups(text: str) -> list[tuple[str, str]]:
    """testssl.sh's `DH_groups` finding as (standard name, tool spelling) pairs.

    The finding is either a list of RFC 7919 names (`ffdhe2048 ffdhe3072`), or one phrase naming
    one group (`RFC3526/Oakley Group 14`, `Unknown DH group (2048 bits)`). A phrase is one group,
    named by its size: splitting it on spaces would invent three. A fixed prime the tool recognises
    is named `<source>/<group>`: the RFC 7919 primes by their own name (`RFC7919/ffdhe2048`), any
    other by the size its phrase states (`RFC5114/1024-bit DSA group ...`).
    """
    text = text.strip()
    if text in _OAKLEY_BITS:
        return [(f"DH-{_OAKLEY_BITS[text]}", text)]
    m = re.search(r"\((\d+) bits\)", text)
    if m:
        return [(f"DH-{m.group(1)}", text)]
    m = re.fullmatch(r"RFC ?7919/(ffdhe\d+)", text)
    if m:
        return [(m.group(1), text)]
    m = re.fullmatch(r"[^/\s]+/(\d+)-bit\b.*", text)
    if m:
        return [(f"DH-{m.group(1)}", text)]
    if all(re.fullmatch(r"ffdhe\d+", tok) for tok in text.split()):
        return [(tok, tok) for tok in text.split()]
    return [(text, text)]
