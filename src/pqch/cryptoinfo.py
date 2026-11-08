"""What cryptography protected this ledger: the libraries the harness hashes and verifies with, their
versions, and whether a FIPS provider is active in each (FR-02, the groundwork).

Recorded in every `run.started`, so each ledger names the module its own chain was hashed in. This
module reads state; it changes none. It is not a validation claim: a FIPS provider that is active is
validated only if the certificate covers that build and the algorithms used (lesson 33). Two
OpenSSL builds are in the harness process, and each is reported on its own:

- `hashlib` — the chain's SHA-256 (`pqch.common.sha256_hex`), through the OpenSSL CPython links.
- `cryptography` — checkpoint verification (`pqch.ledger.checkpoints`), through the OpenSSL its wheel
  bundles unless built against the system's.

The checkpoint signer runs in its own container with its own OpenSSL command line; it is not read
from here.
"""

from __future__ import annotations

import platform
import ssl
from pathlib import Path

KERNEL_FIPS = Path("/proc/sys/crypto/fips_enabled")


def _hashlib() -> dict:
    out = {"openssl": ssl.OPENSSL_VERSION, "fips_mode": None}
    try:
        import _hashlib

        out["fips_mode"] = bool(_hashlib.get_fips_mode())
    except (ImportError, AttributeError, ValueError):
        pass
    return out


def _cryptography() -> dict:
    try:
        import cryptography
        from cryptography.hazmat.bindings._rust import openssl as rust_openssl
    except ImportError:
        return {"available": False}
    out = {"version": cryptography.__version__, "openssl": None, "fips_enabled": None}
    try:
        out["openssl"] = rust_openssl.openssl_version_text()
        out["fips_enabled"] = bool(rust_openssl.is_fips_enabled())
    except AttributeError:
        pass
    return out


def _kernel() -> bool | None:
    try:
        return KERNEL_FIPS.read_text().strip() == "1"
    except OSError:
        return None


def provenance() -> dict:
    """The record for `run.started`'s `crypto` field. `None` means the state could not be read."""
    h, c = _hashlib(), _cryptography()
    active = [k for k, v in (("hashlib", h.get("fips_mode")), ("cryptography", c.get("fips_enabled"))) if v]
    return {"python": platform.python_version(), "hashlib": h, "cryptography": c, "kernel_fips": _kernel(),
            "fips_provider_active": active}
