---
id: lesson-83-a-writer-enforces-what-its-verifier-requires
type: lesson
title: "A writer enforces what its verifier requires"
date: 2026-11-21
audience: [engineer, architect]
rung: all
tags: [ledger, verification, evidence]
one_line: "A verifier that refuses a backward timestamp or a fused line, over a writer that checks neither, turns one clock step or one lost newline into a ledger that can never verify again; every condition verify() refuses is a condition append() prevents, under the same lock."
claims:
  - text: "`Ledger.append`, under the file lock, clamps an event's time to the head's when the clock has stepped back and records the time it would have carried as `ts_clamped_from`; refuses with a `LedgerError` naming the byte offset when the last line is not a whole event; and restores a lost trailing newline before writing."
    provenance: "by reading src/pqch/ledger/__init__.py at HEAD; tests/test_ledger.py (test_a_clock_stepped_back_is_clamped_to_the_head_and_said_so, test_a_torn_last_line_refuses_the_append_and_names_where, test_a_whole_last_event_without_its_newline_gets_it_back_before_the_next), passing on xr7620, 2026-11-21"
  - text: "A run closes only directly after a checkpoint that covers everything before the close (`expect_head`), and the signer keeps the close in its own record, so a ledger with its `run.closed` line removed fails against that record and is not signed again."
    provenance: "by reading src/pqch/run.py, src/pqch/ledger/checkpoints.py and src/pqch/signer/service.py (POST /closed) at HEAD; tests/test_checkpoints.py; commit 380b868"
  - text: "The head is read from the end of the file, not by reading the whole ledger: on a scratch copy of a 26 MB ledger the read takes 0.06 to 0.07 ms where the last line is an ordinary event, against 11 to 13 ms before; where the last line is itself 1.4 MB the read takes 47 ms."
    provenance: "measured 2026-11-21 on xr7620 (x86_64), Ledger._head timed over 20 reads at three truncations of the copy; the earlier 11 to 13 ms as recorded in commit 380b868, same host and ledger"
reuse: [whitepaper, runbook]
---

# A writer enforces what its verifier requires

## The rule

List every condition the verifier refuses. For each one, the writer either
makes it impossible or refuses to write. The two lists are kept equal, by a
test, and the writer's checks run inside the same lock that orders the
writes.

## Why

An append-only ledger has two programs: `append()` adds an event, `verify()`
decides whether the whole file can be believed. A verifier grows strict over
time, because every rule added to it closes a way of tampering: times must
not go backward, each line must be one whole event, nothing follows the
close. A writer grows only when something breaks.

The gap between them is a class of event the writer will happily produce and
the verifier will never accept. Two are ordinary accidents:

| What happens | What the writer did | What the verifier does, from then on |
|---|---|---|
| The host clock steps back (a time sync correction) | wrote the earlier time | refuses the ledger: a timestamp before its predecessor's |
| A write is cut short and the last line has no newline | appended the next event onto the same line | refuses the ledger: a line that is not one event |

Neither is tampering. Both are permanent, because the ledger is append-only
and hash-chained: the bad line cannot be edited, and everything after it
chains from it. One correction by the time service makes a system of record
unverifiable for the rest of its life.

The cure belongs in the writer, at the moment it already holds the lock and
has already read the head. It knows the head's time; it can refuse to go
behind it. It can see whether the last line is whole. Neither check needs
anything the writer does not already have.

The same reasoning runs the other way, to what the verifier *cannot* see. A
run's `run.closed` event came after the last signed checkpoint, so nothing
signed covered it. Delete that one line and the file verifies as an open run
that may be appended to. The close has to be recorded where the checkpoints
are: the run closes only directly after a checkpoint that covers everything
before it, and the signer records the close itself.

Reading the head is where the writer's checks cost something. A writer that
finds the head by reading the whole file pays for the ledger's length on
every append. The head is the last line; read it from the end.

## When it applies

Any pair of programs where one produces a record and another judges it:
ledgers and their verifiers, serializers and validators, migrations and
schema checks, an exporter and its importer. It applies most where the
record cannot be repaired after the fact. It does not ask the writer to
repeat cryptographic checks; it asks that the writer never emit what the
verifier is known to reject.

## How to apply it

1. Write the verifier's refusals as a list. For each, write the test "the
   writer, given the situation that would cause this, does not produce it".
2. Prefer a recorded correction to a refusal where the event must still be
   written. A stepped-back clock is clamped to the head's time and the event
   says so:

    ```json
    {"ts": "2026-11-21T10:00:00.000Z", "ts_clamped_from": "2026-11-21T09:59:58.412Z"}
    ```

    The record stays ordered and nothing is hidden.
3. Refuse where correcting would bury damage. A torn last line stops the
   append and names the byte offset; appending after it would put the damage
   mid-file.
4. Make the terminal event depend on the signed state: close only with the
   closing checkpoint at the head, and checkpoint again if another writer got
   in between.
5. Read the head from the end of the file.
6. Before changing a writer or a verifier, run both over every existing
   record and compare the verdicts run by run. A change that alters the
   verdict on an old ledger is a different change from the one intended.

    ```sh
    uv run python -m pytest tests/test_ledger.py tests/test_checkpoints.py
    ```

## Where the claim stops

The clamp keeps order, not truth: an event clamped to the head's time
happened at an unknown moment near it, and `ts_clamped_from` is the stepped
clock's reading, not a corrected one. A ledger damaged before the writer
gained these checks stays unverifiable; the writer refuses to extend it and
does not repair it. Two-process contention on the lock was reasoned about,
not stress-tested.

