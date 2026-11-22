---
id: lesson-13-bracket-an-event-between-two-signatures
type: lesson
title: "To bound when a logged event happened, sign the log just before it and just after"
date: 2026-10-05
audience: [architect, engineer]
tags: [verification, signatures, agility]
rung: all
one_line: "A timestamped signature over an event shows it existed by then; only an earlier signature that the event is chained after shows it did not exist before."
claims:
  - text: "With a timestamping signer that bracketed the writer's clock only between checkpoints, a policy event stamped one hour in the past was signed, and an event held for 15 s and restamped gave an interval of 47 ms on the writer's clock and 51 ms on the signer's."
    provenance: "measured 2026-10-05, live ML-DSA-65 signer, xr7620 (x86_64); M0B review F-54"
  - text: "With a checkpoint immediately before and after the event, the same change read 55.6 s on the writer's clock and no more than 55.6 s on the signer's; the two extra signatures cost 7 to 12 ms each."
    provenance: "measured 2026-10-05, change run 01M46RCKJZA12PD1REM722YF4F; checkpoint timing from the BRIEF facts table, 2026-10-03"
reuse: [whitepaper, talk]
---

# To bound when a logged event happened, sign the log just before it and just after

## The rule

An interval measured from a log is trustworthy on a second clock only if each
end is bounded on both sides. Have the timestamping signer sign the chain
immediately before the event that starts the interval is written, and again
immediately after. Report the interval as "no more than" the span from the
earlier signature to the first signature over the end event.

## Why

A hash-chained log is signed at checkpoints by a service with its own clock,
which puts its time inside the signed message. It is tempting to read that
time as "when the event happened". It is weaker than that, and the weakness
is one-sided.

A signature over an event proves the event existed when the signature was
made. It is an upper bound on the event's time. It says nothing about how
long the event existed before the signer saw it — the writer can hold it —
and nothing stops the writer stamping it earlier still, if no signature
precedes it. For the end of an interval an upper bound is what is wanted. For
the start it is the wrong bound: a late start makes the interval look short.

The lower bound comes from the chain, not from the signer's clock rule. Each
event is hashed onto everything before it, and a checkpoint is itself an
event containing a signature nobody could have produced earlier. So an event
that follows a checkpoint in the chain was written after that signature was
made. A checkpoint just before the event and one just after pin it between
two times on the signer's clock.

A signer that also refuses events stamped far from its own time catches gross
errors, but only between checkpoints. Before a log's first checkpoint,
nothing is bounded from below.

## When it applies

Any log from which durations are read and shown as a result: time to deploy,
time to remediate, time to respond. It matters when the writer benefits from
the duration being short, or when the reader will quote it.

What it does not bound: the gap between something happening in the world — a
person deciding — and the writer creating the event. Only a signature made by
that person, with a time, closes that.

## How to apply it

- Write a checkpoint immediately before each event that starts a measured
  interval, and immediately after. Start the log with one, over its first
  event.
- Compute the second-clock interval from the last signature *before* the
  start event to the first signature *over* the end event, and label it an
  upper bound.
- Show both readings. When they differ by more than the tolerance allows,
  show neither as a result.
- Have the signer refuse to sign backwards: never a point at or before one it
  has signed, never a time earlier than its last.
- When a log lacks the earlier signature, say so beside the number.
