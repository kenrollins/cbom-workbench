"""The signer: ML-DSA checkpoints over a run's ledger (spec section 3, pqch.checkpoint/1).

The algorithm is a setting (`PQCH_CHECKPOINT_ALG`): ML-DSA-65 by default, ML-DSA-87 allowed, so a
deployment under CNSA 2.0 is a configuration and not a migration. Each checkpoint records the
algorithm it was signed with, and the verifier checks it against the key. A key on the volume of
another algorithm than the setting is refused, never re-used: changing the algorithm is a key
rotation, done deliberately.

It runs as its own service. It holds the signing key on a volume no other
container mounts, has no network and no Docker socket, and reads run ledgers
read-only. It signs only what it has checked itself: the chain up to the
requested event, and that every checkpoint it signed before for the run is
still there. It keeps its own record of what it signed, outside the ledger,
where the service that writes the ledger cannot change it; that record is what
shows a ledger cut back behind a checkpoint.

Signing uses the OpenSSL 3.5 command line. Verification (pqch.ledger.checkpoints)
uses a different implementation, so the two check each other.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from pqch import varmode
from pqch.common import ms_between, sha256_hex, utc_now
from pqch.ledger import Ledger, verify

ALG = "ML-DSA-65"                       # the default
ALLOWED = ("ML-DSA-65", "ML-DSA-87")
SCHEMA = "pqch.checkpoint/1"


# How far, in milliseconds, the ledger's clock may disagree with the signer's before the
# signer refuses. Both run on one host here; the allowance covers the time between the
# harness writing an event and the signer reading it.
SKEW_MS = 2000


def message(through_seq: int, head_hash: str, signed_at: str | None = None) -> bytes:
    """The signed message: the ASCII bytes of
    `pqch.checkpoint/1\\n<through_seq>\\n<head_hash>\\n<signed_at>`.

    A checkpoint written before signer time existed has no `signed_at`, and its message
    is the first three lines only.
    """
    text = f"{SCHEMA}\n{through_seq}\n{head_hash}"
    if signed_at is not None:
        text += f"\n{signed_at}"
    return text.encode("ascii")


def key_alg(public_pem: bytes) -> str | None:
    """The ML-DSA parameter set of a public key, by its type; None for anything else."""
    from cryptography.hazmat.primitives.asymmetric import mldsa

    k = serialization.load_pem_public_key(public_pem)
    for name, cls in (("ML-DSA-44", mldsa.MLDSA44PublicKey), ("ML-DSA-65", mldsa.MLDSA65PublicKey),
                      ("ML-DSA-87", mldsa.MLDSA87PublicKey)):
        if isinstance(k, cls):
            return name
    return None


def key_id(public_pem: bytes) -> str:
    """SHA-256 of the public key in its standard encoding, DER SubjectPublicKeyInfo."""
    der = serialization.load_pem_public_key(public_pem).public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_hex(der)


class SignerError(Exception):
    pass


class Signer:
    def __init__(self, key_dir: str | Path, runs_dir: str | Path, *, openssl: str = "openssl",
                 hardware: str = "unlabelled", alg: str = ALG):
        if alg not in ALLOWED:
            raise SignerError(f"checkpoint algorithm {alg!r} is not one of {', '.join(ALLOWED)}")
        self.alg = alg
        self.key_dir = Path(key_dir)
        self.runs_dir = Path(runs_dir)
        self.openssl = openssl
        self.hardware = hardware
        self._lock = threading.Lock()
        # The key and the record live in a directory only the signer's user can enter (0700). The volume's
        # root comes from the image, world-writable and sticky so any uid can start the signer; a key
        # written there before this directory existed stays where it is and is used as it is.
        legacy = (self.key_dir / "ledger.key").exists()
        self.secret_dir = self.key_dir if legacy else self.key_dir / "private"
        self.key_path = self.secret_dir / "ledger.key"
        self.pub_path = self.secret_dir / "ledger.pub"
        self.record_dir = self.secret_dir / "record"

    def ensure_key(self) -> None:
        if self.key_path.exists():
            self.check_key()
            return
        self.secret_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.secret_dir != self.key_dir:
            self.secret_dir.chmod(0o700)
        old = os.umask(0o077)
        try:
            subprocess.run([self.openssl, "genpkey", "-algorithm", self.alg, "-out", str(self.key_path)],
                           check=True, capture_output=True)
        finally:
            os.umask(old)
        subprocess.run([self.openssl, "pkey", "-in", str(self.key_path), "-pubout", "-out", str(self.pub_path)],
                       check=True, capture_output=True)

    def check_key(self) -> None:
        """The key on the volume is of the configured algorithm, or the signer refuses to start."""
        if not self.pub_path.exists():
            return
        have = key_alg(self.pub_path.read_bytes())
        if have != self.alg:
            raise SignerError(f"the signing key in {self.key_dir} is {have}, but the checkpoint algorithm is set to "
                              f"{self.alg}: rotate the key deliberately; a signer does not switch algorithms silently")

    def public(self) -> dict:
        pem = self.pub_path.read_bytes()
        version = subprocess.run([self.openssl, "version"], capture_output=True, text=True).stdout.strip()
        return {"alg": self.alg, "key_id": key_id(pem), "public_key_pem": pem.decode(), "openssl": version,
                "key_dir_mode": oct(self.secret_dir.stat().st_mode & 0o777)}

    key = public

    def _sign(self, msg: bytes) -> bytes:
        """One ML-DSA signature through the OpenSSL command line. The time includes process start."""
        with tempfile.TemporaryDirectory() as tmp:
            mpath, spath = Path(tmp) / "msg", Path(tmp) / "sig"
            mpath.write_bytes(msg)
            subprocess.run([self.openssl, "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key_path),
                            "-in", str(mpath), "-out", str(spath)], check=True, capture_output=True)
            return spath.read_bytes()

    def record(self, run_id: str) -> list[dict]:
        p = self.record_dir / f"{run_id}.jsonl"
        if not p.exists():
            return []
        return [json.loads(line) for line in p.read_text().splitlines() if line.strip()]

    def checkpoint(self, run_id: str, through_seq: int, *, caller: dict | None = None) -> dict:
        """Sign the chain through `through_seq`. `caller` is the kernel's word on who asked (uid, pid),
        kept in the signer's own record beside what it signed."""
        if not run_id.isalnum():
            raise SignerError("bad run id")
        with self._lock:
            events = list(Ledger(self.runs_dir / run_id / "ledger.jsonl").events())
            if not 0 <= through_seq < len(events):
                raise SignerError(f"the ledger has no event {through_seq}")
            check = verify(events[: through_seq + 1])
            if not check.ok:
                raise SignerError(f"the ledger does not verify through {through_seq}: {check.error}")
            named = events[0]["payload"].get("run")
            if named != run_id:
                # No name is no better than another name: a copy with the name cut out is a copy.
                raise SignerError(f"the ledger names run {named}, not {run_id}: it was copied" if named
                                  else f"the ledger's run.started names no run; it cannot be signed as {run_id}")
            prior_record = self.record(run_id)
            for prior in prior_record:
                s = prior["through_seq"]
                if s >= len(events) or events[s]["hash"] != prior["head_hash"]:
                    raise SignerError(f"an earlier checkpoint, through event {s}, is no longer in the ledger")
            if prior_record and through_seq <= max(p["through_seq"] for p in prior_record):
                raise SignerError(f"a checkpoint through event {max(p['through_seq'] for p in prior_record)} "
                                  f"was already signed; checkpoints only move forward")
            signed_at = utc_now()
            # The signer's own times never run backwards within a run: if its clock stepped
            # back, the new signature carries the last one's time, not an earlier one.
            earlier = [p["signed_at"] for p in prior_record if p.get("signed_at")]
            if earlier and signed_at < max(earlier):
                signed_at = max(earlier)
            # The ledger's timestamps are the writer's; bracket them with the signer's clock.
            for ev in events[: through_seq + 1]:
                if ms_between(signed_at, ev["ts"]) > SKEW_MS:
                    raise SignerError(f"event {ev['seq']} is stamped {ev['ts']}, after the signer's time {signed_at}")
            timed = [p for p in prior_record if p.get("signed_at")]
            if timed:
                last = max(timed, key=lambda p: (p["signed_at"], p["through_seq"]))
                for ev in events[last["through_seq"] + 1: through_seq + 1]:
                    if ms_between(ev["ts"], last["signed_at"]) > SKEW_MS:
                        raise SignerError(f"event {ev['seq']} is stamped {ev['ts']}, before the checkpoint "
                                          f"signed at {last['signed_at']} that it follows")
            head = events[through_seq]["hash"]
            msg = message(through_seq, head, signed_at)
            started = time.monotonic()
            sig = self._sign(msg)
            signing_ms = round((time.monotonic() - started) * 1000)
            cp = {"schema": SCHEMA, "through_seq": through_seq, "head_hash": head, "signed_at": signed_at,
                  "alg": self.alg, "key_id": key_id(self.pub_path.read_bytes()),
                  "signature": base64.b64encode(sig).decode()}
            self.record_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            with (self.record_dir / f"{run_id}.jsonl").open("a") as f:
                varmode.private(self.record_dir / f"{run_id}.jsonl")
                f.write(json.dumps({"through_seq": through_seq, "head_hash": head, "key_id": cp["key_id"],
                                    "signed_at": signed_at, **({"caller": caller} if caller else {})}) + "\n")
            return {"checkpoint": cp, "signing_ms": signing_ms, "hardware": self.hardware}
