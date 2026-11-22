"""Policy packs as data: a memo's requirements, each with the words it is written in.

`load_pack` reads `policy/packs/<id>.yaml` and refuses a pack whose quotes are not in the
source text it names: every `quote` is split at "..." and each part, with whitespace and
hyphenation normalized, must occur in the text in that order. A pack read from a source not
read first-hand (`read_first_hand: false`) carries no text to check against and must say
`verified: false`; the assessor applies no deadline from it. Both packs shipped (OMB M-26-15 and
NSA's CNSA 2.0 FAQ Ver. 2.2) are read first-hand and quote-checked.
"""

from __future__ import annotations

import re
from datetime import date
from functools import cache
from pathlib import Path

import yaml

SCHEMA = "pqch.policy-pack/1"
ROOT = Path(__file__).resolve().parents[3]


def _norm(s: str) -> str:
    s = s.replace("–", "-").replace("—", "-").replace("’", "'").replace("“", '"').replace("”", '"')
    s = re.sub(r"-\s*\n\s*", "-", s)
    return re.sub(r"\s+", " ", s).strip().lower()


def _quotes(obj, path="$"):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in ("quote", "quote_note") and isinstance(v, str):
                yield f"{path}.{k}", v
            else:
                yield from _quotes(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _quotes(v, f"{path}[{i}]")


def check_quotes(pack: dict, text: str) -> list[str]:
    """Every quote's parts, in order, in the source text. Returns the paths that fail."""
    # Page footers and list bullets are layout, not words. Footnote markers stay: a quote that
    # spans one is split at "..." there.
    body = _norm(re.sub(r"Page \d+ of \d+|[\u2022\uf0b7]|^\s*o\s+", " ", text, flags=re.M))
    bad = []
    for where, q in _quotes(pack):
        pos = 0
        for part in [p for p in (x.strip(" .;:") for x in q.split("...")) if p]:
            i = body.find(_norm(part), pos)
            if i < 0:
                bad.append(f"{where}: {part[:60]!r}")
                break
            pos = i + len(part) // 2
    return bad


def load_pack(path: str | Path) -> dict:
    path = Path(path)
    pack = yaml.safe_load(path.read_text())
    if pack.get("schema") != SCHEMA:
        raise ValueError(f"{path}: expected schema {SCHEMA}, found {pack.get('schema')!r}")
    src = pack.get("source") or {}
    if src.get("read_first_hand") is False or src.get("read_first_hand") is None:
        if pack.get("verified") is not False:
            raise ValueError(f"{path}: a pack not read first-hand must say verified: false")
        return pack
    text_path = ROOT / src["text"] if not Path(src["text"]).is_absolute() else Path(src["text"])
    if not text_path.is_file():
        text_path = Path(src["text"])
    bad = check_quotes(pack, text_path.read_text())
    if bad:
        raise ValueError(f"{path}: quotes not found in {src['text']}: " + "; ".join(bad))
    return pack


def load_families(path: str | Path) -> dict:
    doc = yaml.safe_load(Path(path).read_text())
    if doc.get("schema") != "pqch.algorithm-families/1":
        raise ValueError(f"{path}: expected schema pqch.algorithm-families/1")
    return doc


def family_of(families: dict, role: str, name: str) -> str:
    return ((families.get(role) or {}).get(name) or {}).get("family", "unknown")


# A tool's word for "I could not name the algorithm" (scout/normalize.py and scout/names.py write
# `unknown`; the code rules write `unspecified`). It is not an algorithm's name, so no table is asked
# about it: the rules answer `unknown`, never a verdict.
UNIDENTIFIED = frozenset({"", "unknown", "unspecified", "none", "n/a"})

# The family of an algorithm that is post-quantum by design and not a NIST standard (not FIPS 203, 204
# or 205) nor a hybrid with one: OpenSSH's Streamlined NTRU Prime hybrid. Neither a pack's vulnerable
# table nor its resistant list holds it; the rules say exactly that.
PQ_NOT_STANDARDISED = "pq-not-standardised"


def identified(name: str | None) -> bool:
    """Whether a finding's algorithm name is a name at all, and not a tool's placeholder."""
    return isinstance(name, str) and name.strip().lower() not in UNIDENTIFIED


def vulnerability(pack: dict, family: str, role: str) -> tuple[bool | None, str]:
    """Whether a family is quantum-vulnerable under the pack, and the row or rule that says so.
    An asymmetric name the table does not settle is vulnerable by footnote 13; a symmetric one
    is outside the table and returns None. So does an algorithm that is post-quantum by design and
    not a NIST standard: it is not in the memo's table of vulnerable algorithms and not among the
    algorithms the memo calls resistant, so it is not acceptable under the pack (footnote 13: not
    definitively known to be quantum-resistant) and is not called quantum-vulnerable either."""
    qv = pack["quantum_vulnerable"]
    if family in qv["families"]:
        return True, qv["families"][family]["row"]
    if family in qv.get("resistant", {}):
        return False, qv["resistant"][family]["quote"]
    if family == PQ_NOT_STANDARDISED:
        return None, ("post-quantum by design, but not a NIST-standardised algorithm (not FIPS 203, 204 or 205, nor a "
                      "hybrid with one) and not one the pack names: footnote 13 asks that an asymmetric algorithm not "
                      "definitively known to be quantum-resistant be treated as vulnerable, so it is not acceptable "
                      "under the pack; it is not in the table of quantum-vulnerable algorithms")
    if role in ("key-establishment", "signature"):
        return True, qv["families"]["other-asymmetric"]["row"]
    return None, "outside the table: not an asymmetric algorithm"


def sensitive_through(as_of: date, lifetime_years: int) -> int:
    """The last year data handled on `as_of` stays mission-sensitive. Computed."""
    return as_of.year + lifetime_years


# Classical security strength by key size, SP 800-57 Part 1 Rev. 5 Table 2: the IR 8547 rows apply at or
# above 112 bits (128 for EdDSA); below that, SP 800-131A Rev. 2 disallows the key already.
_FF_RSA = ((15360, 256), (7680, 192), (3072, 128), (2048, 112))
_EC = ((512, 256), (384, 192), (256, 128), (224, 112))
# Curve25519 and Curve448, in either use: the curve's strength, not its field size run through the
# table above (a 255-bit field would read as 112). SP 800-186 §3.2.2 and RFC 7748 §4.1 give 128 bits
# for Curve25519 and 224 for Curve448; RFC 8032 the same for Ed25519 and Ed448.
_CURVE_STRENGTH = {"X25519": 128, "Ed25519": 128, "X448": 224, "Ed448": 224}


def classical_strength(fn: str, name: str, family: str, params: dict | None) -> int | None:
    """Bits of classical security a quantum-vulnerable asset provides, from its key size, or None when
    the finding does not carry one. Computed, not measured: the table is SP 800-57's."""
    params = params or {}
    bits = params.get("key_bits")
    if name in _CURVE_STRENGTH:
        return _CURVE_STRENGTH[name]
    # DSA is a finite-field algorithm: its strength is its modulus size L's, the same column of
    # SP 800-57's table as RSA and finite-field DH (1024 gives 80, 2048 gives 112, 3072 gives 128).
    if family in ("rsa-sig", "rsa-kex", "finite-field-dh", "mqv", "dsa"):
        if bits is None:
            m = re.search(r"(?:DH|ffdhe|DSA)-?(\d{3,5})$", name)
            bits = int(m.group(1)) if m else None
        if bits is None:
            return None
        return next((s for k, s in _FF_RSA if bits >= k), 80 if bits >= 1024 else 0)
    if family in ("ecdh", "ecdsa"):
        if bits is None:
            m = (re.search(r"(?:secp|P-|brainpoolP)(\d{3})", name)
                 or re.search(r"(?:secp|P-|brainpoolP)(\d{3})", str(params.get("curve") or "")))
            bits = int(m.group(1)) if m else None
        if bits is None:
            return None
        return next((s for k, s in _EC if bits >= k), 0)
    return None


@cache
def algorithm_ids() -> dict:
    """policy/algorithm-ids.yaml: object identifiers and NIST categories a consumer judges by."""
    doc = yaml.safe_load((ROOT / "policy" / "algorithm-ids.yaml").read_text())
    if doc.get("schema") != "pqch.algorithm-ids/1":
        raise ValueError("policy/algorithm-ids.yaml: expected schema pqch.algorithm-ids/1")
    return doc
