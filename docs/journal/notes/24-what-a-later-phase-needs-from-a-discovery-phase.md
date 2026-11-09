---
id: note-24-what-a-later-phase-needs-from-a-discovery-phase
type: note
title: "What does a later phase need from a discovery phase, field by field, and where does each field come from?"
date: 2026-11-09
audience: [leader, architect, engineer]
tags: [cbom, managed, policy]
rung: managed
one_line: "A phase that deploys is planned from a register the discovery phase hands over: one row per step, grouped into the buckets the later phases are scoped by, each row carrying the system, interface, mission thread, owner and classification the owner supplied, the priority and deadline the rules computed, whether the step waits for a supplier, the vendor's path and the owner's cost with its basis, and the CBOM entries the step moves by fingerprint; the workbench writes it from the plan, labels every owner-supplied column as the owner's, and estimates nothing."
claims:
  - text: "On the four-service slice the plan's steps fall into the three buckets a later phase is scoped by with none unplaced: the software replacement in applications and mission, the key-exchange steps in infrastructure and data protection, the certificate authority's root and the reissues in identity, PKI and signing."
    provenance: "measured 2026-11-09, tests/test_register.py over the slice's recorded scanner output, policy/buckets.yaml version 1"
  - text: "The register's cost column sums the owner's cost_to_fix facts once per service and reports the services with no number as uncosted; on the slice that is one service costed and three not."
    provenance: "measured 2026-11-09, same test; the one cost is a planted figure in agency/context.yaml whose basis says so"
reuse: [whitepaper, talk, customer-question]
---

# What does a later phase need from a discovery phase, field by field, and where does each field come from?

## The answer

A discovery phase does not deploy anything. It ends by handing the phases
that do a plan they can be scoped and costed from. The workbench writes that
hand-off as a **register**: one row per plan step, grouped into the buckets the
later phases are organised by, with the facts a planner needs beside each step
and the CBOM entries the step moves named by fingerprint, so every row can be
traced back to the record. Each column comes from one of three places, and the
register says which: the **owner** (typed in, labelled supplied, never
computed), the **rules** (computed from the CBOM and the policy packs, with the
event behind each), or the **plan** itself (the step, its bucket, its order).

The register is available three ways: on the plan page as the "handed to the
next phase" section, as a live download from the run (`register.csv`,
`register.json`), and written beside the run's CBOMs by `pqch plan export`, so
it travels with the record.

<figure class="sketch" markdown>
![A register drawn as a table with its columns in three colours. In ballpoint, from the owner: system, interface, mission thread, owner, classification, impact, data lifetime, vendor path, cost with its basis. In ink, from the rules: priority and its criteria, deadline and what set it, blocked on the supplier, sensitive through. In pencil, from the plan: step, bucket, wave, state, waits for, entries by fingerprint. Above the table three boxes labelled identity PKI and signing, infrastructure and data protection, applications and mission, with the slice's steps sorted into them. A stamp at the bottom reads nothing estimated here.](../img/sketches/24-register-three-sources.svg)
<figcaption>Every column of the register comes from the owner, the rules or the plan, and the register says which; the cost is the owner's number with its basis.</figcaption>
</figure>

## The mechanism

**The owner's facts.** No scan can discover which system of record a service
belongs to, which interface it serves, which mission thread stops when it
does, what classification its enclave carries, what the vendor has said, or
what a fix would cost. These are typed in by the system owner in the context
file, recorded on the ledger as supplied links with a human actor and the
file's hash as evidence, and carried on the service's component with every
other supplied fact under `pqch:supplied` ([note
06](06-how-a-finding-becomes-a-dependency-chain.md) on supplied links; the
scorer never counts one as coverage). The six facts added for an engagement
are `system`, `interface`, `mission_thread`, `classification` (one of
unclassified, cui, confidential, secret, top-secret), `vendor_path` and
`cost_to_fix`. A cost is a mapping of amount, currency and basis, and the
context file refuses a bare number: a figure with no basis is a figure nobody
can check.

**The rules' columns.** Priority and its criteria come from the memo's rule
over the owner's impact, high-value and lifetime facts ([note
07](07-how-a-migration-priority-is-computed.md)); the deadline and the document
that set it from the queue rule; whether the step is blocked on its supplier
from the capability snapshot; the year the data stays sensitive through from
the lifetime and the assessment date. Each is an event on the ledger, and the
plan page shows the event.

**The plan's columns.** The step, its title and why, its wave and due date,
its state (ready, waiting, done) and what it waits for, the CBOM entries it
moves by fingerprint, and its **bucket**.

**The buckets.** Later phases are scoped by kind of work rather than by
service: identity, PKI and signing (certificate authorities and what they
issue, keys, firmware-signing roots and the boot chain); infrastructure and
data protection (key exchange on the wire, the controller's settings, what the
supplier ships for them); applications and mission systems (software that
cannot take post-quantum cryptography and must be replaced or upgraded). A
fourth bucket, inventory, holds the reads the discovery itself still owes (a
path an unprivileged scan could not open). The mapping from a step to a bucket
is a pack, `policy/buckets.yaml`, versioned, by the step's id prefix first and
its kind second; a step no row places is reported as unplaced and counted,
never hidden. On the slice none is.

**The cost.** The register sums the owner's `cost_to_fix` per currency, once
per service, and reports how many services carry no number. It is the owner's
arithmetic, not an estimate: the sum's basis says so, and each addend's basis
travels in its own column. Where a planner wants a model of cost, that model
sits outside the register and cites it.

## Worked example: the four-service slice

| Bucket | Steps on the slice | What they are |
|---|---|---|
| Identity, PKI and signing | the CA's new root and the reissues under it; retiring the unserved certificate | the internal CA that issued the slice's certificates, and the leaves |
| Infrastructure and data protection | offering and then requiring the ML-KEM hybrid on each listener; TLS 1.3 where it is missing | the key-exchange lane of each service |
| Applications and mission systems | replacing the SFTP appliance whose software lists no post-quantum algorithm | the one step nothing configurable can move; its row carries the owner's vendor path and a planted cost of 40,000 USD with its basis |

One service costed, three not; the register says so rather than filling the
blanks. Measured 2026-11-09 in `tests/test_register.py`.

## Scope

- The columns are this project's reading of what a later phase needs. A
  customer's register will have its own; the mechanism is a projection, so a
  different column list is a different projection over the same ledger, as the
  inventory is ([note 01](01-what-is-a-cbom.md)).
- The buckets' names follow the usual three-way split of post-quantum work; a
  programme with a different split edits the pack and the plan regroups.
- The register is as current as the plan: computed from the scan and the
  change runs since when served live, and frozen at its write time when
  exported beside the run. Both say which.
- The vendor's path on a service is the owner's note. A supplier's statement
  about hardware is a different thing, recorded as evidence of its own grade
  ([note 23](23-what-a-suppliers-attestation-can-stand-in-for.md)).
