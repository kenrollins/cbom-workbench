"""Checking a ledger's signed checkpoints (spec section 3, "Signing checkpoints").

Verification uses the `cryptography` library's ML-DSA, not the OpenSSL command
line the signer signs with, so each implementation checks the other.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

from pqch.common import ms_between, sha256_hex
from pqch.ledger import verify


@dataclass
class SignedVerification:
    ok: bool
    chain_ok: bool
    checkpoints: int = 0
    signed_through: int | None = None
    unsigned_after: int = 0
    events: int = 0
    key_id: str | None = None
    legacy_checkpoints: int = 0
    error: str | None = None
    notes: list[str] = field(default_factory=list)


SKEW_MS = 2000


def _message(through_seq: int, head_hash: str, signed_at: str | None = None) -> bytes:
    text = f"pqch.checkpoint/1\n{through_seq}\n{head_hash}"
    if signed_at is not None:
        text += f"\n{signed_at}"
    return text.encode("ascii")


def verify_signed(events: list, public_pem: bytes | str | None, *, known: list[dict] | None = None) -> SignedVerification:
    """The chain, every checkpoint's signature, and every checkpoint recorded outside the ledger.

    `known` is a list of {through_seq, head_hash} recorded elsewhere — the signer's own
    record, or a hash a reader wrote down. A ledger that no longer holds one of them has
    been cut back or rewritten behind a checkpoint.
    """
    chain = verify(events)
    out = SignedVerification(ok=False, chain_ok=chain.ok, events=chain.count)
    if not chain.ok:
        out.error = f"chain: {chain.error} (event {chain.at_seq})"
        return out
    pub = None
    if public_pem:
        pem = public_pem.encode() if isinstance(public_pem, str) else public_pem
        pub = serialization.load_pem_public_key(pem)
        out.key_id = sha256_hex(pub.public_bytes(serialization.Encoding.DER,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo))
    last_signed: tuple[int, str] | None = None
    for ev in events:
        if ev["type"] != "checkpoint.signed":
            continue
        cp = ev["payload"]
        n = cp["through_seq"]
        if not 0 <= n < ev["seq"]:
            out.error = f"checkpoint at event {ev['seq']} claims to cover event {n}"
            return out
        if events[n]["hash"] != cp["head_hash"]:
            out.error = f"checkpoint at event {ev['seq']}: head hash is not event {n}'s hash"
            return out
        if pub is None:
            out.error = "the ledger has checkpoints and no public key was given"
            return out
        if cp["key_id"] != out.key_id:
            out.error = f"checkpoint at event {ev['seq']} was signed with another key ({cp['key_id'][:12]})"
            return out
        try:
            pub.verify(base64.b64decode(cp["signature"]), _message(n, cp["head_hash"], cp.get("signed_at")))
        except (InvalidSignature, ValueError):
            out.error = f"checkpoint at event {ev['seq']}: the signature does not verify"
            return out
        out.checkpoints += 1
        out.signed_through = n
        t = cp.get("signed_at")
        if t is None:
            out.legacy_checkpoints += 1
            continue
        if last_signed is not None and t < last_signed[1]:
            out.error = f"checkpoint at event {ev['seq']} was signed at {t}, before the previous one"
            return out
        for e in events[: n + 1]:
            if ms_between(t, e["ts"]) > SKEW_MS:
                out.error = f"event {e['seq']} is stamped {e['ts']}, after the signature over it at {t}"
                return out
        if last_signed is not None:
            for e in events[last_signed[0] + 1: n + 1]:
                if ms_between(e["ts"], last_signed[1]) > SKEW_MS:
                    out.error = (f"event {e['seq']} is stamped {e['ts']}, before the checkpoint "
                                 f"signed at {last_signed[1]} that it follows")
                    return out
        last_signed = (n, t)
    if last_signed is not None:
        # The unsigned tail too: nothing after a signature may claim to be older than it.
        for e in events[last_signed[0] + 1:]:
            if ms_between(e["ts"], last_signed[1]) > SKEW_MS:
                out.error = (f"event {e['seq']} is stamped {e['ts']}, before the checkpoint "
                             f"signed at {last_signed[1]} that it follows")
                return out
    for k in known or []:
        n = k["through_seq"]
        if n >= len(events):
            out.error = (f"the ledger ends at event {len(events) - 1}, but a checkpoint through event {n} "
                         f"was signed: events have been removed")
            return out
        if events[n]["hash"] != k["head_hash"]:
            out.error = f"event {n} is not the event a recorded checkpoint signed"
            return out
    last = events[-1] if events else None
    if last and last["type"] == "run.closed":
        prev = events[-2] if len(events) > 1 else None
        if not (prev and prev["type"] == "checkpoint.signed" and prev["payload"]["through_seq"] == prev["seq"] - 1):
            out.error = "the run is closed without a checkpoint over everything before it"
            return out
    covered = out.signed_through if out.signed_through is not None else -1
    # A checkpoint event itself sits after what it covers; it is not an unsigned addition.
    out.unsigned_after = sum(1 for e in events[covered + 1:] if e["type"] not in ("checkpoint.signed", "run.closed"))
    out.ok = True
    return out
