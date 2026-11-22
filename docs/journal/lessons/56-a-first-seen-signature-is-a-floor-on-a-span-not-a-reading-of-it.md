---
id: lesson-56-a-first-seen-signature-is-a-floor-on-a-span-not-a-reading-of-it
type: lesson
title: "A signer's first signature over an event is a floor on the span that starts there, never a reading of it; check a ledger's clock against the bracket, not the floor"
date: 2026-11-04
audience: [engineer, architect]
rung: managed
tags: [verification, policy]
one_line: "An independent signer says when an event existed by (the first signature over it) and when it cannot have existed before (the last signature before it); a span measured from the first-seen time is a lower bound, and a ledger whose own span falls inside that bracket agrees with the signer."
claims:
  - text: "On the demo GB10 a portal change ran 439.3 s from the policy event to the last verdict by the ledger's timestamps, while the signer's first-seen reading gave 149.6 s, because the proposal drafted a records-db change through a model for about five minutes before the first checkpoint was signed over the policy event; the host's clock and the signer container's clock agreed to within one second."
    provenance: "measured 2026-11-04 on a Dell Pro Max GB10, change run 01M6M36JN2GAWHVQ0H624MK5PB, portal change 01M6M36JP9G67E2KNX2Z9QE3GE; `date -u` on the host and in the signer container"
reuse: [whitepaper, runbook]
---

# A signer's first signature over an event is a floor on the span that starts there, never a reading of it; check a ledger's clock against the bracket, not the floor

## The rule

A signed checkpoint says two things about an event: the first checkpoint whose sequence covers it
says the event existed by that signing time, and the last checkpoint before it says the event did not
exist before that time. A span between two events therefore has, by the signer's clock, a floor (first
seen of the end minus first seen of the start) and a ceiling (first seen of the end minus the signature
before the start). The ledger's own span, from its stamped timestamps, is consistent with the signer
when it lies inside that bracket, each end within the allowed skew. A check that compares the ledger's
span to the floor alone reports a disagreement whenever an event waited for its first signature.

## Why

A checkpoint is signed when the writer asks for one, not when each event is written. A proposal that
drafts a change through a model holds its run open for minutes between the policy event and the first
checkpoint, so the signer's first sight of the policy event is late by exactly that wait, and a span
measured from it is short by the same amount. The ledger's timestamp, stamped when the event was
written, is not wrong, and neither is the signer: the two measure different things. The ceiling from
the signature before the event is what bounds a backdated stamp, and that is the end of the bracket a
backdating would cross. The floor catches a stamp set in the future. Both are needed; neither alone is
a reading.

## When it applies

Any ledger with an independent signer whose checkpoints are not one per event: an append-only run
ledger with periodic signatures, a transparency log with batched signed tree heads. It does not apply
where every event is individually countersigned at write time, where first-seen and the stamp
coincide.

## How to apply it

`pqch.migrator.intervals` computes, per change, the ledger span, the signer floor
(`signer_policy_to_verdict_ms`) and the signer ceiling (`signer_policy_to_verdict_max_ms`), and reports
`clocks_disagree_ms` only when the ledger span falls below the floor or above the ceiling by more than
twice the skew allowance. The resolution page shows the time-to-change with both signer readings beside
it; a disagreement replaces the time with the size of the breach. When reading a span from any signed
ledger, quote the bracket, and say which end the stamped value sits near.
