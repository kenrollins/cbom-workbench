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

    def __init__(self, key_dir, runs_dir, alg="ML-DSA-65"):
        super().__init__(key_dir, runs_dir, hardware="test", alg=alg)
        self._key = {"ML-DSA-65": mldsa.MLDSA65PrivateKey, "ML-DSA-87": mldsa.MLDSA87PrivateKey}[alg].generate()

    def ensure_key(self):
        self.pub_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.pub_path.write_bytes(self._key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))

    def public(self):
        from pqch.signer import key_id
        pem = self.pub_path.read_bytes()
        return {"alg": self.alg, "key_id": key_id(pem), "public_key_pem": pem.decode(), "openssl": "none"}

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


# ---- the checkpoint algorithm, a setting (M8; CNSA 2.0 asks for ML-DSA-87)

def test_ml_dsa_87_checkpoints_are_recorded_and_verify(slice_run, tmp_path):
    s = PySigner(tmp_path / "s87", slice_run.var / "runs", alg="ML-DSA-87")
    s.ensure_key()
    events = closed(slice_run, s)
    cps = [e["payload"] for e in events if e["type"] == "checkpoint.signed"]
    assert cps and {c["alg"] for c in cps} == {"ML-DSA-87"}
    pub = Path(slice_run.dir / "ledger.pub").read_bytes()
    res = verify_signed(events, pub, known=s.record(slice_run.id))
    assert res.ok and res.algs == ["ML-DSA-87"]
    assert verify_signed(events, pub, require_alg="ML-DSA-87").ok
    bad = verify_signed(events, pub, require_alg="ML-DSA-65")
    assert not bad.ok and "ML-DSA-65 is required" in bad.error


def test_the_default_stays_ml_dsa_65_and_a_policy_can_require_87(slice_run, signer):
    events = closed(slice_run, signer)
    pub = Path(slice_run.dir / "ledger.pub").read_bytes()
    assert verify_signed(events, pub).algs == ["ML-DSA-65"]
    res = verify_signed(events, pub, require_alg="ML-DSA-87")
    assert not res.ok and "ML-DSA-87 is required" in res.error


def test_a_checkpoint_whose_named_algorithm_is_not_the_keys_fails(slice_run, signer):
    events = closed(slice_run, signer)
    pub = Path(slice_run.dir / "ledger.pub").read_bytes()
    for alg, msg in (("ML-DSA-87", "says ML-DSA-87, but the key is ML-DSA-65"), ("RSA", "not one of")):
        rewrite(slice_run.ledger, [dict(e, payload={**e["payload"], "alg": alg}) if e["type"] == "checkpoint.signed" else e
                                   for e in events])
        res = verify_signed(list(slice_run.ledger.events()), pub)
        assert not res.ok and msg in res.error, res.error


def test_the_signer_refuses_an_algorithm_it_does_not_allow_and_a_key_of_another(slice_run, tmp_path):
    with pytest.raises(SignerError, match="not one of"):
        Signer(tmp_path / "x", slice_run.var / "runs", alg="ML-DSA-44")
    s65 = PySigner(tmp_path / "k", slice_run.var / "runs")
    s65.ensure_key()
    s87 = Signer(tmp_path / "k", slice_run.var / "runs", alg="ML-DSA-87")
    with pytest.raises(SignerError, match="rotate the key"):
        s87.check_key()


def test_the_checkpoint_schema_admits_both_parameter_sets():
    import json
    doc = json.loads(Path("src/pqch/schemas/checkpoint.json").read_text())
    assert doc["properties"]["alg"]["enum"] == ["ML-DSA-65", "ML-DSA-87"]


def test_a_new_signer_keeps_its_key_and_record_in_a_directory_only_it_can_enter(slice_run, tmp_path):
    import stat
    s = PySigner(tmp_path / "vol", slice_run.var / "runs")
    s.ensure_key()
    s.checkpoint(slice_run.id, len(list(slice_run.ledger.events())) - 1)
    assert s.secret_dir == tmp_path / "vol" / "private"
    assert stat.S_IMODE(s.secret_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(s.record_dir.stat().st_mode) == 0o700


def test_a_key_written_before_the_private_directory_is_used_where_it_is(slice_run, tmp_path):
    vol = tmp_path / "old"
    vol.mkdir()
    (vol / "ledger.key").write_text("legacy")
    s = Signer(vol, slice_run.var / "runs")
    assert s.key_path == vol / "ledger.key" and s.record_dir == vol / "record"
