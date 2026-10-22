"""Policy packs as data: a memo's requirements, each with the words it is written in.

`load_pack` reads `policy/packs/<id>.yaml` and refuses a pack whose quotes are not in the
source text it names: every `quote` is split at "..." and each part, with whitespace and
hyphenation normalized, must occur in the text in that order. A pack read from a source not
read first-hand (`read_first_hand: false`) carries no text to check against and must say
`verified: false`; the assessor applies no deadline from it.
"""

from __future__ import annotations

import re
from datetime import date
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


def vulnerability(pack: dict, family: str, role: str) -> tuple[bool | None, str]:
    """Whether a family is quantum-vulnerable under the pack, and the row or rule that says so.
    An asymmetric name the table does not settle is vulnerable by footnote 13; a symmetric one
    is outside the table and returns None."""
    qv = pack["quantum_vulnerable"]
    if family in qv["families"]:
        return True, qv["families"][family]["row"]
    if family in qv.get("resistant", {}):
        return False, qv["resistant"][family]["quote"]
    if role in ("key-establishment", "signature"):
        return True, qv["families"]["other-asymmetric"]["row"]
    return None, "outside the table: not an asymmetric algorithm"


def sensitive_through(as_of: date, lifetime_years: int) -> int:
    """The last year data handled on `as_of` stays mission-sensitive. Computed."""
    return as_of.year + lifetime_years
