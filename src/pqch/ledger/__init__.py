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
from datetime import datetime
from pathlib import Path

from pqch import schemas, varmode
from pqch.common import hash_object, parse_ts, ulid, utc_now

GENESIS = "0" * 64
SCHEMA = "pqch.event/1"


def event_hash(event: dict) -> str:
    """SHA-256 of the canonical form of the event with `hash` removed."""
    return hash_object({k: v for k, v in event.items() if k != "hash"})


class LedgerError(Exception):
    pass


class HeadMoved(LedgerError):
    """An append that named the event it must follow found another event at the head."""


@dataclass
class Head:
    """The last event of a ledger file, as an append finds it under the lock."""
    seq: int
    hash: str
    id: str
    ts: str
    type: str
    newline: bool      # the file ends in a newline after this event


_BLOCK = 65536


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
    "attestation.recorded": {"human"},
    "claim.resolved": {"human"}, "resolution.revoked": {"human"},
    "gap.recorded": {"rule"}, "gap.filled": {"human"}, "sbom.observed": {"scanner"}, "artefact.destroyed": {"human"},
    "destruction.intended": {"human"},
    "window.opened": {"human"}, "window.closed": {"human"},
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
        # A byte that is not UTF-8 is read as U+FFFD, so the damaged line fails its hash in verify()
        # at that event; reading a bad ledger never raises.
        with self.path.open(encoding="utf-8", errors="replace") as f:
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
        expect_head: str | None = None,
    ) -> dict:
        """Append one event. Everything that depends on the head is decided under the file's lock.

        The event's time is never earlier than the head's: verify() refuses a ledger whose times run
        backwards, so when the clock has stepped back (or a caller's `ts` is older than the head) the
        event carries the head's time and `ts_clamped_from`, the time it would have carried.
        `expect_head` is the id of the event this one must directly follow; with another event at the
        head nothing is written and HeadMoved is raised.
        """
        varmode.mkdir(self.path.parent)
        with self.path.open("a+b") as f:
            varmode.private(self.path)
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                head = self._head(f)
                if head is not None and head.type == "run.closed":
                    raise LedgerError("the run is closed; nothing more is appended to its ledger")
                if expect_head is not None and (head is None or head.id != expect_head):
                    raise HeadMoved(f"the head is event {head.seq if head else None}, not {expect_head}: "
                                    f"another writer appended first")
                stamp = ts or utc_now()
                clamped = None
                try:
                    if head is not None and _time(stamp) < _time(head.ts):
                        clamped, stamp = stamp, head.ts
                except ValueError as e:
                    raise LedgerError(f"a timestamp is not a time ({e}); nothing was appended") from e
                event = {
                    "schema": SCHEMA,
                    "seq": head.seq + 1 if head else 0,
                    "id": ulid(),
                    "ts": stamp,
                    "type": type,
                    "actor": actor,
                    "inputs": list(inputs),
                    "payload": payload or {},
                    "evidence": list(evidence),
                    "prev": head.hash if head else GENESIS,
                }
                if clamped is not None:
                    event["ts_clamped_from"] = clamped
                event["hash"] = event_hash(event)
                schemas.validate(event)
                line = json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n"
                # A whole last event that lost its newline gets it back first, or the two would share a line.
                f.write((b"" if head is None or head.newline else b"\n") + line.encode("utf-8"))
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        return event

    @staticmethod
    def _head(f) -> Head | None:
        """The last event, read from the end of the file: an append costs the last line, not the ledger.

        A last line that is not a whole event (a write cut short, a damaged file) is refused here and
        named by its byte offset. Appending after it would bury it mid-file, and removing it is a
        decision for a person, not for the next writer.
        """
        pos = size = f.seek(0, os.SEEK_END)
        buf = body = b""
        start = 0
        while pos > 0:
            step = min(_BLOCK, pos)
            pos -= step
            f.seek(pos)
            buf = f.read(step) + buf
            body = buf.rstrip(b" \t\r\n")
            start = body.rfind(b"\n") + 1
            if body and (start > 0 or pos == 0):
                break
        if not body:
            return None
        line, offset = body[start:], pos + start
        try:
            ev = json.loads(line.decode("utf-8"))
            if isinstance(ev, dict) and ev.get("hash") == event_hash(ev) and isinstance(ev.get("seq"), int):
                return Head(ev["seq"], ev["hash"], ev["id"], ev["ts"], ev["type"], b"\n" in buf[len(body):])
        except (ValueError, TypeError, KeyError):
            pass
        raise LedgerError(f"the last line of {getattr(f, 'name', 'the ledger')}, at byte {offset} of {size}, is not a whole "
                          f"event: a write was cut short or the file was damaged. Nothing is appended after it")


def _time(ts: str) -> datetime:
    """An event's time, for ordering. Times are compared as times, never as strings: the schema allows
    any number of fractional digits, and '.' sorts below 'Z'."""
    return parse_ts(ts)


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
    last_t: datetime | None = None
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
        try:
            t = _time(ev["ts"])
        except ValueError:
            return bad(f"timestamp {ev['ts']} is not a time", seq)
        if last_t is not None and t < last_t:
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
        last_t = t
        prev = ev["hash"]
        expected += 1
    return Verification(True, count, prev)
