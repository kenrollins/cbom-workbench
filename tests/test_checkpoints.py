"""Signed checkpoints (spike S4). Signing here uses `cryptography`; the OpenSSL path is
exercised by test_openssl_signer where an ML-DSA-capable openssl is on PATH."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from pqch.ledger import verify
from pqch.ledger.checkpoints import verify_signed
from pqch.signer import Signer, SignerError

from .test_ledger import rewrite


class PySigner(Signer):
    """The real Signer, with its one OpenSSL call replaced by `cryptography`."""

    def __init__(self, key_dir, runs_dir):
        super().__init__(key_dir, runs_dir, hardware="test")
        self._key = mldsa.MLDSA65PrivateKey.generate()

    def ensure_key(self):
        self.key_dir.mkdir(parents=True, exist_ok=True)
        self.pub_path.write_bytes(self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def public(self):
        from pqch.signer import key_id
        pem = self.pub_path.read_bytes()
        return {"alg": "ML-DSA-65", "key_id": key_id(pem), "public_key_pem": pem.decode(), "openssl": "none"}

    key = public

    def _sign(self, msg):
        return self._key.sign(msg)


@pytest.fixture
def signer(slice_run, tmp_path):
    s = PySigner(tmp_path / "signer", slice_run.var / "runs")
    s.ensure_key()
    return s


def closed(run, signer):
    run.close(signer)
    return list(run.ledger.events())


def test_a_closed_run_carries_a_checkpoint_over_everything_before_the_close(slice_run, signer):
    events = closed(slice_run, signer)
    assert events[-2]["type"] == "checkpoint.signed" and events[-1]["type"] == "run.closed"
    assert events[-2]["payload"]["through_seq"] == events[-3]["seq"]
    res = verify_signed(events, (slice_run.dir / "ledger.pub").read_bytes(), known=signer.record(slice_run.id))
    assert res.ok and res.checkpoints == 1 and res.unsigned_after == 0, res.error


def test_truncation_behind_a_checkpoint_is_detected(slice_run, signer):
    """It replaces test_truncation_is_not_detected_without_a_checkpoint (M0 review F-28)."""
    events = closed(slice_run, signer)
    lines = slice_run.ledger.path.read_text().splitlines()
    slice_run.ledger.path.write_text("\n".join(lines[:5]) + "\n")
    cut = list(slice_run.ledger.events())
    assert verify(cut).ok                       # the chain alone cannot see it
    res = verify_signed(cut, (slice_run.dir / "ledger.pub").read_bytes(), known=signer.record(slice_run.id))
    assert not res.ok and "removed" in res.error
    assert len(events) > 5


def test_a_rewrite_with_hashes_recomputed_is_detected(slice_run, signer):
    events = closed(slice_run, signer)
    pub = (slice_run.dir / "ledger.pub").read_bytes()
    f = next(e for e in events if e["type"] == "finding.observed" and e["payload"]["asset"]["name"] == "DH-1024")
    kept = [e for e in events if e is not f]
    rewrite(slice_run.ledger, kept)
    res = verify_signed(list(slice_run.ledger.events()), pub)
    # Removing one event shifts every later one; the checkpoint no longer fits wherever it lands.
    assert not res.ok and res.chain_ok and "checkpoint" in res.error


def test_a_forged_checkpoint_is_detected(slice_run, signer):
    events = closed(slice_run, signer)
    pub = (slice_run.dir / "ledger.pub").read_bytes()
    other = PySigner(slice_run.var / "other", slice_run.var / "runs")
    other.ensure_key()
    cp = events[-2]["payload"]
    cp["signature"] = __import__("base64").b64encode(other._sign(b"x")).decode()
    rewrite(slice_run.ledger, events)
    res = verify_signed(list(slice_run.ledger.events()), pub)
    assert not res.ok and "does not verify" in res.error
    res = verify_signed(list(slice_run.ledger.events()), other.pub_path.read_bytes())
    assert not res.ok and "another key" in res.error


def test_a_closed_run_without_a_checkpoint_fails(slice_run, signer):
    slice_run.close()
    res = verify_signed(list(slice_run.ledger.events()), None)
    assert not res.ok and "without a checkpoint" in res.error


def test_events_after_the_last_checkpoint_are_reported_unsigned(slice_run, signer):
    slice_run.checkpoint(signer)
    slice_run.ledger.append("key.committed", {"kind": "human", "id": "t"}, {"n": 1})
    res = verify_signed(list(slice_run.ledger.events()), (slice_run.dir / "ledger.pub").read_bytes())
    assert res.ok and res.unsigned_after == 1


def test_the_signer_refuses_a_ledger_rewritten_behind_its_checkpoint(slice_run, signer):
    events = list(slice_run.ledger.events())
    signer.checkpoint(slice_run.id, events[-1]["seq"])
    rewrite(slice_run.ledger, events[:10])
    with pytest.raises(SignerError, match=r"no longer in the ledger|no event"):
        signer.checkpoint(slice_run.id, 9)


def test_the_signer_refuses_a_chain_that_does_not_verify(slice_run, signer):
    lines = slice_run.ledger.path.read_text().splitlines()
    ev = json.loads(lines[3])
    ev["payload"]["status"] = "edited"
    lines[3] = json.dumps(ev)
    slice_run.ledger.path.write_text("\n".join(lines) + "\n")
    with pytest.raises(SignerError, match="does not verify"):
        signer.checkpoint(slice_run.id, len(lines) - 1)


def _openssl_has_mldsa() -> bool:
    exe = shutil.which("openssl")
    if not exe:
        return False
    out = subprocess.run([exe, "list", "-signature-algorithms"], capture_output=True, text=True).stdout
    return "ML-DSA-65" in out


@pytest.mark.skipif(not _openssl_has_mldsa(), reason="no ML-DSA-capable openssl on PATH (needs OpenSSL 3.5)")
def test_openssl_signer(slice_run, tmp_path):
    s = Signer(tmp_path / "signer", slice_run.var / "runs", hardware="test")
    s.ensure_key()
    events = closed(slice_run, s)
    res = verify_signed(events, Path(slice_run.dir / "ledger.pub").read_bytes(), known=s.record(slice_run.id))
    assert res.ok, res.error
