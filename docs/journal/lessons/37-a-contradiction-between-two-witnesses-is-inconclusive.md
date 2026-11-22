---
id: lesson-37-a-contradiction-between-two-witnesses-is-inconclusive
type: lesson
title: "When a probe claims a handshake the enumerating witness does not find, call the verdict inconclusive and say why; neither side settles it"
date: 2026-10-21
audience: [engineer]
rung: agile
tags: [verification]
one_line: "A verifier that lets its witness only lower a verdict will silently turn a misread probe into a false 'not enforced'; when the negative probe reports a key exchange the witness says the listener does not offer, one of the two misread the listener, and the verdict is inconclusive with the reason, until a person reads the raw output."
claims:
  - text: "A rehearsal of an OpenSSH 10 listener set to the ML-KEM hybrid alone first returned enabled-not-enforced: the probe parser read OpenSSH's debug line 'kex: algorithm: (no match)', printed just before it refuses, as a negotiated key exchange, while ssh-audit found only mlkem768x25519-sha256 offered. With the parser fixed the same rehearsal returned enforced."
    provenance: "measured 2026-10-21, the bastion's twin at 172.16.107.21, change 01M5FHSTW56PACA5CFN660YX7F; the raw output is on the rehearsal's negative probe"
  - text: "Re-deriving all 49 verdicts on the deployment from their raw outputs with the rule added changed none of the honest ones; the 6 that re-derive to another status are the M0B review's deliberate forgeries."
    provenance: "computed 2026-10-21 over every change run under the deployment's var/runs"
reuse: [runbook]
---

# When a probe claims a handshake the enumerating witness does not find, call the verdict inconclusive and say why; neither side settles it

## The rule

When the probe that must be refused reports a key exchange that the
enumerating witness does not find the listener accepting, record the verdict
as `inconclusive`, with that contradiction as the reason. Do not let either
side win.

## Why

A verifier of this kind has two sorts of evidence: probes that sample one
handshake each, and a witness that enumerates what the listener accepts. The
witness is allowed to lower a verdict — if it finds a classical group
accepted, the change is not enforced whatever the probes said — and not to
raise one, because a witness that missed something must not turn a failure
into a pass. That asymmetry is right, and it has a blind side: a probe misread
as *accepted* lowers the verdict to `enabled-not-enforced`, the witness cannot
correct it, and the result looks like a careful, conservative answer.

A probe can be misread in exactly that way. OpenSSH, offered no key exchange
it shares with the server, logs `kex: algorithm: (no match)` and then gives
up; a parser that takes the first `kex: algorithm:` line as the negotiated one
reads a refusal as acceptance. The verdict said the listener still accepted
classical key exchange; the witness said it offered only the hybrid. Both
could not be true.

## When it applies

Any verifier that combines sampling probes with an enumerating witness and
lets the witness only lower the result. It does not apply when the witness
errs or lists nothing; that is its own failure, already inconclusive.

## How to apply it

1. When the negative probe is *accepted*, compare what it negotiated with the
   witness's list. If it is not on the list, the verdict is `inconclusive`,
   and the reason names the algorithm and the disagreement.
2. Read the raw output. Fix whichever reader was wrong, with a test built from
   that raw output.
3. Re-derive every past verdict from its raw outputs with the change, and
   check that no honest verdict moves.
