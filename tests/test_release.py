"""M8, FR-05 (part): a bundle's SHA256SUMS signed with ML-DSA, and a load that refuses sums nothing
outside the bundle vouches for, unless told to and recorded."""

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

from pqch import release


def _load_module():
    spec = importlib.util.spec_from_file_location("bundle_load", Path("bundle/load.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


@pytest.fixture
def bundle(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "manifest.json").write_text("{}\n")
    (out / "SHA256SUMS").write_text(f"{hashlib.sha256(b'{}' + bytes([10])).hexdigest()}  manifest.json\n")
    return out


@pytest.mark.parametrize("alg", ["ML-DSA-65", "ML-DSA-87"])
def test_sums_signed_verify_and_a_changed_byte_does_not(bundle, tmp_path, alg):
    kid = release.keygen(tmp_path / "k", alg)
    assert (tmp_path / "k" / "release.key").stat().st_mode & 0o777 == 0o600
    sig = release.sign(bundle / "SHA256SUMS", tmp_path / "k" / "release.key")
    assert sig["alg"] == alg and sig["key_id"] == kid
    assert release.verify(bundle / "SHA256SUMS", tmp_path / "k" / "release.pub", expect_key_id=kid)["alg"] == alg
    (bundle / "SHA256SUMS").write_text((bundle / "SHA256SUMS").read_text() + "0" * 64 + "  extra\n")
    with pytest.raises(ValueError, match="does not verify"):
        release.verify(bundle / "SHA256SUMS", tmp_path / "k" / "release.pub")


def test_another_key_or_an_unexpected_key_id_is_refused(bundle, tmp_path):
    release.keygen(tmp_path / "a")
    release.keygen(tmp_path / "b")
    release.sign(bundle / "SHA256SUMS", tmp_path / "a" / "release.key")
    with pytest.raises(ValueError, match="not this public key"):
        release.verify(bundle / "SHA256SUMS", tmp_path / "b" / "release.pub")
    with pytest.raises(ValueError, match="not the expected"):
        release.verify(bundle / "SHA256SUMS", tmp_path / "a" / "release.pub", expect_key_id="0" * 64)


def test_the_loader_refuses_sums_nothing_vouches_for(bundle, tmp_path):
    load = _load_module()
    with pytest.raises(SystemExit, match="vouched for by nothing"):
        load.check_sums(bundle, expect_sums=None, sums_pub=None, sums_key_id=None, unverified=False,
                        record=tmp_path / "loads.jsonl")
    assert not (tmp_path / "loads.jsonl").exists()


def test_unverified_loads_and_is_recorded(bundle, tmp_path):
    load = _load_module()
    how = load.check_sums(bundle, expect_sums=None, sums_pub=None, sums_key_id=None, unverified=True,
                          record=tmp_path / "loads.jsonl")
    assert "UNVERIFIED" in how
    rec = json.loads((tmp_path / "loads.jsonl").read_text().splitlines()[-1])
    assert rec["verified"] is False and rec["sums_sha256"] == hashlib.sha256((bundle / "SHA256SUMS").read_bytes()).hexdigest()


def test_the_loader_accepts_the_recorded_hash_or_the_signature(bundle, tmp_path):
    load = _load_module()
    h = hashlib.sha256((bundle / "SHA256SUMS").read_bytes()).hexdigest()
    assert "matches" in load.check_sums(bundle, expect_sums=h, sums_pub=None, sums_key_id=None, unverified=False)
    with pytest.raises(SystemExit, match="not the recorded"):
        load.check_sums(bundle, expect_sums="0" * 64, sums_pub=None, sums_key_id=None, unverified=False)
    kid = release.keygen(tmp_path / "k")
    release.sign(bundle / "SHA256SUMS", tmp_path / "k" / "release.key")
    how = load.check_sums(bundle, expect_sums=None, sums_pub=str(tmp_path / "k" / "release.pub"), sums_key_id=kid,
                          unverified=False)
    assert "signed with ML-DSA-65" in how
