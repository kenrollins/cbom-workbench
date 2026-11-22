"""A run: one ledger file under var/runs/<run-id>/, whose event 0 is the scope."""

from __future__ import annotations

import warnings
from pathlib import Path

from pqch import clock, cryptoinfo, varmode
from pqch import scope as scope_mod
from pqch.common import sha256_hex, ulid
from pqch.ledger import HeadMoved, Ledger, LedgerError

SCHEMAS_IN_USE = ["pqch.event/1", "pqch.finding/1", "pqch.scope/1", "pqch.checkpoint/1", "pqch.verifier/1"]
CLOSE_ATTEMPTS = 5


def _aliases() -> dict:
    """The alias pack that will name this run's findings. Imported here: the scout package imports this module."""
    from pqch.scout import names

    return names.provenance()


class Run:
    def __init__(self, var: str | Path, run_id: str):
        self.var = Path(var)
        self.id = run_id
        self.dir = self.var / "runs" / run_id
        self.ledger = Ledger(self.dir / "ledger.jsonl")

    @classmethod
    def start(cls, var: str | Path, scope: dict, *, runner_scope_hash: str, profile: str,
              runner_id: str = "pqch-runner", kind: str = "scan") -> Run:
        """Open a run. The runner's own hash of the scope it enforces must match ours."""
        ours = scope_mod.scope_hash(scope)
        if ours != runner_scope_hash:
            raise ValueError(f"scope mismatch: harness {ours[:12]}, runner {runner_scope_hash[:12]}")
        run = cls(var, ulid())
        run.ledger.append(
            "run.started",
            {"kind": "runner", "id": runner_id},
            {"run": run.id, "scope": scope, "scope_hash": ours, "profile": profile,
             "schemas": SCHEMAS_IN_USE, "kind": kind, "crypto": cryptoinfo.provenance(),
             "clock": clock.time_source(), "aliases": _aliases()},
        )
        for latest in ("LATEST", f"LATEST_{kind.upper()}"):
            (run.var / "runs" / latest).write_text(run.id + "\n")
            varmode.private(run.var / "runs" / latest)
        return run

    @classmethod
    def start_capture(cls, var: str | Path, scope: dict, *, sensor_id: str = "pqch-capture") -> Run:
        """Open a run of passive capture on an external estate. No runner enforces this scope — nothing
        is sent — so the hash recorded is the harness's own, and the scope must carry the operator's
        authorization and at least one capture point."""
        if scope.get("estate") != "external" or not scope.get("captures"):
            raise ValueError("a capture run needs an external scope with at least one capture point")
        run = cls(var, ulid())
        run.ledger.append(
            "run.started",
            {"kind": "runner", "id": sensor_id},
            {"run": run.id, "scope": scope, "scope_hash": scope_mod.scope_hash(scope), "profile": "capture",
             "schemas": SCHEMAS_IN_USE, "kind": "capture", "crypto": cryptoinfo.provenance(),
             "clock": clock.time_source(), "aliases": _aliases()},
        )
        (run.var / "runs" / "LATEST_CAPTURE").write_text(run.id + "\n")
        varmode.private(run.var / "runs" / "LATEST_CAPTURE")
        return run

    @classmethod
    def latest(cls, var: str | Path, kind: str | None = None) -> Run | None:
        """The latest run, or the latest of one kind (`scan`, `change`)."""
        p = Path(var) / "runs" / (f"LATEST_{kind.upper()}" if kind else "LATEST")
        return cls(var, p.read_text().strip()) if p.exists() else None

    def commit_key(self, key_path: str | Path, *, author: str, commit: str | None = None) -> dict:
        """Record the answer key this run is scored against, by path and hash."""
        data = Path(key_path).read_bytes()
        return self.ledger.append(
            "key.committed",
            {"kind": "human", "id": author},
            {"path": str(key_path), "sha256": sha256_hex(data), "commit": commit},
        )

    def checkpoint(self, signer) -> dict:
        """Have the signer sign everything so far, and record its checkpoint."""
        events = list(self.ledger.events())
        head = events[-1] if events else None
        if not isinstance(head, dict):
            raise LedgerError("the ledger's last line is not an event (a write cut short, or no ledger); "
                              "there is nothing a checkpoint could name")
        res = signer.checkpoint(self.id, head["seq"])
        pub = self.dir / "ledger.pub"
        if not pub.exists():
            pub.write_text(signer.key()["public_key_pem"])
            varmode.private(pub)
        return self.ledger.append(
            "checkpoint.signed", {"kind": "controller", "id": "pqch-signer"},
            {**res["checkpoint"], "signing_ms": res["signing_ms"], "hardware": res["hardware"]},
            inputs=[head["id"]])

    def close(self, signer=None) -> dict:
        """Close the run. With a signer, a checkpoint over everything before the close comes first.

        The signer is called outside the ledger's lock, so another writer can append while it signs.
        `run.closed` is therefore appended only directly after a checkpoint that covers everything
        before itself; when an event got in between, the run is checkpointed again and the close
        retried. A closed ledger takes no more events, so a close that left one outside the last
        checkpoint could never be put right.

        The signer is then told of the close, and keeps it in its own record: `run.closed` is under no
        signature, and without that entry a ledger with its last line removed reads as an open run.
        """
        actor = {"kind": "runner", "id": "pqch-runner"}
        if signer is None:
            return self.ledger.append("run.closed", actor, {})
        for _ in range(CLOSE_ATTEMPTS):
            cp = self.checkpoint(signer)
            if cp["payload"]["through_seq"] != cp["seq"] - 1:
                continue        # an event landed while the signer worked; it is outside this checkpoint
            try:
                closed = self.ledger.append("run.closed", actor, {}, expect_head=cp["id"])
            except HeadMoved:
                continue
            break
        else:
            raise LedgerError(f"run {self.id} was not closed: in {CLOSE_ATTEMPTS} attempts another writer appended "
                              f"between the closing checkpoint and the close each time")
        # A signer without this call (an older service, a test double) leaves the close unrecorded:
        # the ledger is closed either way, and verification is as it was before the call existed.
        record_close = getattr(signer, "closed", None)
        if record_close is not None:
            try:
                record_close(self.id)
            except Exception as e:
                warnings.warn(f"run {self.id} is closed, but the signer did not record the close: {e}", stacklevel=2)
        return closed
