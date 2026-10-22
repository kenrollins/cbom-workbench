"""The ledger: one append-only JSONL file, each event hash-chained to the last.

The system of record (ADR-0001). Everything else — the CBOM, the SQLite index,
the score — is rebuilt from it. See spec/interfaces.md, section 3.
"""

from __future__ import annotations

import fcntl
import json
import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from pqch import schemas
from pqch.common import hash_object, ulid, utc_now

GENESIS = "0" * 64
SCHEMA = "pqch.event/1"


def event_hash(event: dict) -> str:
    """SHA-256 of the canonical form of the event with `hash` removed."""
    return hash_object({k: v for k, v in event.items() if k != "hash"})


class LedgerError(Exception):
    pass


# The actor kinds each event type may carry (spec/interfaces.md, "Event types").
# A type not listed here is accepted from any actor.
ACTORS = {
    "run.started": {"runner"}, "run.closed": {"runner"}, "scan.completed": {"runner"},
    "key.committed": {"human"}, "policy.changed": {"human"}, "service.recreated": {"runner"}, "finding.observed": {"scanner"}, "change.observed": {"scanner"},
    "assessment.made": {"rule", "model"}, "link.asserted": {"rule", "model", "human"},
    "change.proposed": {"rule", "model"}, "rehearsal.completed": {"verifier"}, "matrix.completed": {"verifier"},
    "package.issued": {"rule"}, "import.completed": {"scanner"},
    "reset.requested": {"human"}, "estate.reset": {"runner"},
    "approval.granted": {"human"}, "approval.denied": {"human"}, "change.applied": {"runner"},
    "verdict.issued": {"verifier"}, "queue.enqueued": {"controller"}, "queue.drained": {"controller"},
    "engine.swapped": {"controller"}, "checkpoint.signed": {"controller"}, "trace.completed": {"model"},
    "config.observed": {"scanner"},
}


class Ledger:
    """One ledger file. Appends are serialized with an exclusive lock on the file."""

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def exists(self) -> bool:
        return self.path.exists() and self.path.stat().st_size > 0

    def events(self) -> Iterator[dict]:
        if not self.path.exists():
            return
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        # A line that is not JSON is yielded as itself; verify() fails on it.
                        yield line.rstrip("\n")

    def append(
        self,
        type: str,
        actor: dict,
        payload: dict | None = None,
        *,
        inputs: Iterable[str] = (),
        evidence: Iterable[dict] = (),
        ts: str | None = None,
    ) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a+", encoding="utf-8") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                seq, prev = self._head(f)
                event = {
                    "schema": SCHEMA,
                    "seq": seq,
                    "id": ulid(),
                    "ts": ts or utc_now(),
                    "type": type,
                    "actor": actor,
                    "inputs": list(inputs),
                    "payload": payload or {},
                    "evidence": list(evidence),
                    "prev": prev,
                }
                event["hash"] = event_hash(event)
                schemas.validate(event)
                f.seek(0, os.SEEK_END)
                f.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        return event

    @staticmethod
    def _head(f) -> tuple[int, str]:
        f.seek(0)
        last = None
        for line in f:
            if line.strip():
                last = line
        if last is None:
            return 0, GENESIS
        ev = json.loads(last)
        if ev.get("type") == "run.closed":
            raise LedgerError("the run is closed; nothing more is appended to its ledger")
        return ev["seq"] + 1, ev["hash"]


@dataclass
class Verification:
    ok: bool
    count: int
    head: str
    error: str | None = None
    at_seq: int | None = None


def verify(events: Iterable[dict]) -> Verification:
    """Check a ledger: the chain, each event's shape, and the rules that bind events together.

    It never raises on a bad ledger; anything it cannot read is a failure at that event.
    What it cannot see: events removed from the end, or a ledger rewritten whole with its
    hashes recomputed. Those need a signed checkpoint recorded outside the system.
    """
    prev = GENESIS
    expected = 0
    approved: set[str] = set()
    seen: set[str] = set()
    last_ts = ""
    closed = False
    count = 0

    def bad(error: str, seq) -> Verification:
        return Verification(False, count, prev, error, seq if isinstance(seq, int) else expected)

    for ev in events:
        count += 1
        if not isinstance(ev, dict):
            return bad("line is not a JSON object", expected)
        seq = ev.get("seq")
        if seq != expected or isinstance(seq, bool):
            return bad(f"seq {seq}, expected {expected}", seq)
        if ev.get("prev") != prev:
            return bad("prev does not match the previous hash", seq)
        try:
            if event_hash(ev) != ev.get("hash"):
                return bad("hash does not match the event", seq)
            schemas.validate(ev)
        except TypeError as e:  # a float in a hashed object
            return bad(str(e), seq)
        except Exception as e:  # jsonschema raises its own types
            return bad(f"schema: {e}".splitlines()[0], seq)
        kind, type_, payload = ev["actor"]["kind"], ev["type"], ev["payload"]
        if seq == 0 and type_ != "run.started":
            return bad("event 0 is not run.started", seq)
        if closed:
            return bad("an event after run.closed", seq)
        closed = type_ == "run.closed"
        if type_ in ACTORS and kind not in ACTORS[type_]:
            return bad(f"{type_} from a {kind} actor", seq)
        if ev["id"] in seen:
            return bad("event id already used", seq)
        missing = [i for i in ev["inputs"] if i not in seen]
        if missing:
            return bad(f"input {missing[0]} is not an earlier event", seq)
        if ev["ts"] < last_ts:
            return bad("timestamp is earlier than the previous event's", seq)
        if type_ == "finding.observed":
            a = payload["asset"]
            fp = hash_object({"layer": payload["layer"], "subject": payload["subject"],
                              "type": a["type"], "role": a["role"], "name": a["name"],
                              "identity": a.get("identity")})
            if fp != payload["fingerprint"]:
                return bad("finding fingerprint does not match the finding", seq)
        if type_ in ("approval.granted", "approval.denied", "change.applied") and not payload.get("change_id"):
            return bad(f"{type_} names no change id", seq)
        if type_ == "approval.granted":
            approved.add(payload["change_id"])
        if type_ == "change.applied" and payload["change_id"] not in approved:
            return bad("change.applied without an earlier approval.granted", seq)
        seen.add(ev["id"])
        last_ts = ev["ts"]
        prev = ev["hash"]
        expected += 1
    return Verification(True, count, prev)
