"""Conventions shared by every interface (spec/interfaces.md, "Conventions").

Canonical form is RFC 8785. Hashed objects carry no floats, so it reduces to
keys sorted, no insignificant whitespace, non-ASCII characters unescaped. Keys
are sorted by code point; RFC 8785 sorts by UTF-16 code unit, which differs
only for keys outside the Basic Multilingual Plane. Every key in every schema
is ASCII.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import UTC, datetime

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _reject_floats(obj: object, path: str = "$") -> None:
    if isinstance(obj, float):
        raise TypeError(f"float at {path}: hashed objects carry no floating-point numbers")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _reject_floats(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _reject_floats(v, f"{path}[{i}]")


def canonical(obj: object) -> bytes:
    """The RFC 8785 canonical form of a float-free JSON value."""
    _reject_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_object(obj: object) -> str:
    return sha256_hex(canonical(obj))


def utc_now() -> str:
    """RFC 3339, UTC, millisecond precision, `Z` suffix."""
    return format_ts(datetime.now(UTC))


def format_ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parse_ts(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def ms_between(start: str, end: str) -> int:
    return round((parse_ts(end) - parse_ts(start)).total_seconds() * 1000)


def ulid() -> str:
    """A ULID: 48 bits of milliseconds since the epoch, 80 random bits, Crockford base32."""
    value = (time.time_ns() // 1_000_000) << 80 | int.from_bytes(os.urandom(10), "big")
    return "".join(_CROCKFORD[(value >> shift) & 31] for shift in range(125, -1, -5))
