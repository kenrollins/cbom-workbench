"""M8, FR-02 (part): nothing that is not security asks for a hash FIPS mode refuses, and every
ledger names the cryptographic libraries, their versions and whether a FIPS provider is active."""

import ast
import hashlib
import importlib
import warnings
from pathlib import Path

from pqch import cryptoinfo

NOT_APPROVED = {"md5", "sha1"}


def test_no_md5_or_sha1_call_in_the_harness_omits_usedforsecurity():
    bad = []
    for path in Path("src/pqch").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in NOT_APPROVED:
                if not any(k.arg == "usedforsecurity" for k in node.keywords):
                    bad.append(f"{path}:{node.lineno}")
    assert bad == []


def test_the_demo_page_renders_when_md5_refuses_a_security_use(slice_run, monkeypatch):
    real = hashlib.md5

    def fips_md5(*a, usedforsecurity=True, **kw):
        if usedforsecurity:
            raise ValueError("[digital envelope routines] unsupported (FIPS mode)")
        return real(*a, usedforsecurity=False, **kw)

    monkeypatch.setattr(hashlib, "md5", fips_md5)
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        c = TestClient(ui.app)
    assert c.get("/demo").status_code == 200


def test_every_run_started_names_the_crypto_that_protected_its_ledger(slice_run):
    first = next(iter(slice_run.ledger.events()))
    assert first["type"] == "run.started"
    c = first["payload"]["crypto"]
    assert c["hashlib"]["openssl"].startswith(("OpenSSL", "LibreSSL", "BoringSSL"))
    assert isinstance(c["hashlib"]["fips_mode"], bool)
    assert c["cryptography"]["version"] and c["cryptography"]["openssl"]
    assert c["fips_provider_active"] == [k for k in ("hashlib", "cryptography")
                                         if (c["hashlib"]["fips_mode"] if k == "hashlib" else c["cryptography"]["fips_enabled"])]
    assert c["kernel_fips"] in (True, False, None)


def test_an_active_fips_provider_is_reported_by_library(monkeypatch, tmp_path):
    monkeypatch.setattr(cryptoinfo, "_hashlib", lambda: {"openssl": "OpenSSL 3.5.4", "fips_mode": True})
    monkeypatch.setattr(cryptoinfo, "_cryptography", lambda: {"version": "x", "openssl": "OpenSSL 3.5.4", "fips_enabled": False})
    k = tmp_path / "fips_enabled"
    k.write_text("1\n")
    monkeypatch.setattr(cryptoinfo, "KERNEL_FIPS", k)
    p = cryptoinfo.provenance()
    assert p["fips_provider_active"] == ["hashlib"] and p["kernel_fips"] is True
