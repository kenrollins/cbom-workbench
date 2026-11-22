---
id: lesson-41-before-requiring-probe-who-it-shuts-out
type: lesson
title: "Before approving a change that requires post-quantum key establishment, probe each kind of client against a copy with the change; enforced says it landed, not whom it refuses"
date: 2026-10-21
audience: [engineer, architect, leader]
rung: agile
tags: [verification, key-establishment, agility]
one_line: "A require change verified enforced has, by definition, refused every client that cannot offer the hybrid group; measure which kinds those are, against the live listener and a copy with the proposed configuration, and put that table in front of the approver."
claims:
  - text: "For the mini-agency's two pending require changes, a classical TLS 1.3 client, a TLS 1.2 client and a classical-only SSH client were each served today and refused by a copy with the proposed file, while clients able to offer the hybrid group were served by both."
    provenance: "measured 2026-10-21, change run 01M5FHSAWHMY78JV1EJX1YQA87 on the lab deployment; note 08"
reuse: [runbook, customer-question]
---

# Before approving a change that requires post-quantum key establishment, probe each kind of client against a copy with the change; enforced says it landed, not whom it refuses

## The rule

Before a `require` change is approved, run one handshake per kind of client
against the listener as it runs and against a copy with the proposed
configuration, and show the approver which kinds the change shuts out.

## Why

Enforcement is refusal. A listener that requires the hybrid group refuses a
TLS 1.3 client offering only classical groups outright — it does not fall back
— and refuses TLS 1.2, which carries no hybrid group at all. The verifier's
`enforced` verdict is exactly that refusal, so it can only confirm the
breakage, never warn of it. The warning has to come from asking each kind of
client before the change, against a copy, where a refusal costs nothing.

## When it applies

Every change that moves a listener from `enable` to `require`, and any change
that removes an algorithm. It does not apply to `enable`, which adds a choice
and refuses no one — though the matrix shows that too, as "unchanged".

## How to apply it

```sh
pqch change matrix <change-id> --run <change-run>
```

The runner starts the copy in the twin network with the proposed file and
probes it and the live listener with the same client profiles; the result is a
`matrix.completed` event beside the rehearsal, shown on the change. Map the
profiles onto real clients from the estate's own evidence: on a network with
passive capture, the clients that never offered a hybrid group are the ones a
`require` change would refuse.
