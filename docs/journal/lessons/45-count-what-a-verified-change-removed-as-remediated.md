---
id: lesson-45-count-what-a-verified-change-removed-as-remediated
type: lesson
title: "Score an inventory against a key that knows about changes: an item a verified change removed is remediated, not missed"
date: 2026-10-22
audience: [engineer]
rung: agile
tags: [cbom, eval]
one_line: "When the estate an answer key describes can be changed, a scan after a verified change no longer sees what the change removed; count each such item as remediated, by the change event that removed it, and take it out of the denominator, or every successful migration reads as a drop in coverage."
claims:
  - text: "On the mini-agency after a verified require change on records-db, the next scan scored 35 of 35 wire items found, with three items moved to remediated (the X25519 and 2048-bit finite-field DH key exchanges and RSA key transport on that listener); scored without the rule, the same scan reads three misses."
    provenance: "measured 2026-10-22, the latest mini-agency scan on the author's deployment; rule in src/pqch/pipeline.py, remediated()"
reuse: [whitepaper, runbook]
---

# Score an inventory against a key that knows about changes: an item a verified change removed is remediated, not missed

## The rule

When a scan follows a verified change, count each answer-key item the change
removed as **remediated**, citing the change, and take it out of the
denominator; count it as missed only if nothing removed it.

## Why

An answer key (the list of everything planted in a test estate, written
before any scan) describes the estate as built. A migration is meant to make
the estate stop matching it: once a listener requires a post-quantum hybrid
key exchange (one that combines a classical and a post-quantum algorithm), the
classical groups it used to accept are gone, and no scan can find them. Scored
naively, the scan "missed" them, and the inventory's coverage drops at the very
moment the migration succeeds. That inverts the measurement: the better the
estate gets, the worse the scanner appears.

The opposite shortcut is as wrong: dropping every unfound item from the
denominator hides real misses. The distinction has to come from evidence: a
change that was approved, applied, and verified by probes (a client offering
only the new algorithm connects, one offering only the old is refused) on that
listener, before the scan.

## When it applies

Any evaluation of discovery against a known truth in an estate that can be
changed: a test range, a lab, a staging copy. It does not apply to items no
change touched, to changes that were enabled but not enforced (the old
algorithm is still accepted, so it should still be found), or after the
estate is reset to its built state, when the key is true again.

## How to apply it

- Key the rule on the change record, not on the absence: the item's
  listener, a verified change with intent *require* before the scan, and no
  reset after that change.
- Report remediated items separately and by the change that removed them, so
  the score reads "35 of 35 found, 3 remediated by change X", not "35 of 38".
- Give the estate a reset to its built state, recorded like any change, so a
  run can start from the key's truth again.
