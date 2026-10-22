# ADR-0001: The ledger is the system of record; the CBOM is built from it

- **Status:** Accepted
- **Date:** 2026-10-01
- **Amended:** 2026-10-03 — decisions 3 and 5 made precise after design review
  (`docs/fable-review/`, F-03, F-04, F-19)
- **Deciders:** Ken Rollins

## Context

The workbench has several actors — scanners, a code investigator, a rules
engine, a migrator, a human approver — all contributing to one inventory. A
federal reader will ask of any entry: where did this come from, who or what
decided it, and how do you know the change landed. A CBOM file alone records
the state, not the reasons.

## Decision

1. **An append-only JSONL event log is the system of record.** Every finding,
   classification, decision, approval, model swap and verifier verdict is one
   event with an id, a timestamp, an actor, its inputs by reference, and its
   evidence.
2. **Each event carries the hash of the previous event.** Altering any record
   breaks the chain.
3. **Checkpoints are signed with ML-DSA.** A post-quantum migration tool whose
   own audit trail is quantum-vulnerable would be inconsistent. A checkpoint
   is written on every approval, on every verifier verdict, and at close. The
   public key and the latest checkpoint hash are shown in the UI, so a reader
   can record them outside the system. The signature detects alteration by
   anyone without the checkpoint key; it does not defend against the operator
   who holds it, and the UI says so.
4. **The CycloneDX CBOM is a projection.** It is rebuilt from the ledger and
   never edited directly. Fields the standard does not define (owner, approval
   state, deadline, evidence references) live in the ledger and are mapped into
   CycloneDX properties.
5. **Verification is never a model's judgment.** A change is recorded as
   verified only by a verifier event: a wire re-scan, a certificate parse, or a
   compatibility run.
   - **A wire verdict is a pair of probes.** A client offering only the new
     algorithm must succeed, and a client offering only the old one must be
     refused. Both hold: `enforced`. Only the first: `enabled-not-enforced` —
     recorded as its own state, never as a pass.
   - **A verdict is bound to what was scanned.** The event records the target
     address, container id, image digest, served certificate fingerprint,
     scanner image digest, scan start and end times, and the hash of the raw
     output. The scan must start after the apply event; a failed or timed-out
     scan produces no verdict.
   - **A verdict is repeated** after the service is recreated, and confirmed
     by a second witness of a different kind.
   - **A finding class with no verifier is recorded as such**, and counted in
     the receipts.
6. **Nothing is applied without an approval event.**

## Alternatives considered

- **CBOM file as the source of truth.** Simple, but it loses provenance and
  makes change detection a diff of two snapshots rather than a stream.
- **A database as the record.** Queryable, but not portable to the standalone
  target as easily, and not tamper-evident without extra machinery. SQLite is
  used as an index over the ledger, never as the record.
- **Framework-native tracing only.** Useful for debugging; not an evidentiary
  record and not in a format an agency already recognizes.

## Consequences

- Watch mode falls out for free: new events are the deltas.
- Any screen can show "why" by following references back through the ledger.
- The event schema is a public interface and must be versioned from the first
  commit.
- The official minimum elements for a CBOM are still being defined; the mapping
  layer between ledger and CBOM is where that change is absorbed.
