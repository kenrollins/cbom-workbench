---
title: cbom-workbench
hide:
  - navigation
  - toc
---

# cbom-workbench

!!! tip "The live demo"
    This site is the reading beside a working demonstration.
    **[Open the overview](/)** — NIST's crypto-agility plan with what the workbench does in
    each part — then **[the walkthrough](/walkthrough)**,
    a scan to a change proved on the wire, or **[inside the CBOM](/cbom)**. The tabs under
    *Demo* at the top, and the title, always lead back.

!!! quote ""
    **A cryptography bill of materials, built from evidence and kept on a signed
    ledger, that carries an organization from not knowing what it runs to changing
    an algorithm and proving the change landed — with the role of AI in that work
    measured, not assumed.**

    By **Ken Rollins**, Federal Field CTO — Emerging Technologies at Dell.
    Repository: `cbom-workbench`; the command is `pqch`.

---

A workbench that builds a CBOM from wire, host and code evidence, keeps it
current, and uses it to take a mixed estate from *Opaque* to *Agile* — verified
by re-scan, recorded on a ledger signed with ML-DSA-65. Language models are used
where interpretation is needed and nowhere else, and which model does which role
was decided by measurement against a floor written before the run.

!!! quote ""
    The inventory is not a report. It is the thing the change was made from and
    verified against.

## The clock

Federal policy fixes the dates. The one that shapes this project is the one
nobody can plan against yet.

| Date | What | Source |
|---|---|---|
| 2026-10-22 | Each agency's PQC migration plan due | OMB M-26-15 |
| 2026–2027 | Discovery phase: inventory, assessment, governance | OMB M-26-15 |
| **2027-03-19** | **CISA and NIST publish the minimum elements of a CBOM** | EO 14412 |
| 2030-01-02 | TLS 1.3 everywhere | OMB M-26-15 |
| 2030-12-31 | Key establishment post-quantum on prioritized systems | EO 14412 |
| 2031-12-31 | Digital signatures post-quantum on prioritized systems | EO 14412 |

The inventory is required now; what it must contain is published five months
later. So the workbench keeps every finding with its evidence on a ledger and
treats the CBOM as a projection of that record: when the minimum elements
arrive, meeting them is a new projection, not a new scan
([note 03](notes/03-what-federal-policy-requires-and-when.md)).

## What the demonstration does

A four-service test estate — a classical TLS portal, a hybrid ML-KEM API, an
old OpenSSH and a current one — is scanned, scored against an answer key with
decoys in it, and then changed: the central crypto policy moves the portal to
hybrid key establishment, the change is approved by a person, applied, and
verified on the wire by a pair of probes that no model takes part in. The
elapsed time is on screen, from two clocks.

## Where the models earned their place

Six roles, about 30 labeled items each, a floor per role written before the
run, every call made three times
([note 13](notes/13-where-models-belong.md)).

| Role | Floor | Bound to | Measured | Nearest other arms |
|---|---|---|---|---|
| Read a call site | 27 | Gemma 4 31B on four L4s, reasoning on | 29 of 30, 13.6 s a call | the 120B 29 at 42 s; the 30B with reasoning 28 at 84 s |
| Normalize a tool's spelling | 28 | rules; a model only as a labelled fallback | best 27, four arms | — |
| Classify an algorithm | 28 | Gemma 4 31B on four L4s | 30 of 30, 1.1 s | five arms at 30 |
| Resolve a conflict between layers | 24 of 29 | rules | best 23, with 4 harmful where 2 are allowed | Gemma 31B with reasoning 21 |
| Trace a wire finding to its configuration line | 24 | the 120B reasoning engine on the GB10 | 28 of 30 (Nemotron 3 Super); 27 on the live lane since it changed to Nemotron 3.5 Super VL at medium effort, 12.7 s a call | GPT-OSS 120B 26 with 4 harmful; nothing under 120B above 22 |
| Draft a change plan | 24 | Gemma 4 31B on four L4s | 27 of 30, none harmful, 3.5 s | the 120B 24 at 95 s |

Items correct of 30, measured through the lab gateway in three rounds
(2026-10-07 to 2026-10-16) across fifteen arms: every model the lab holds, on
a desk-side GB10, four L4 GPUs and a second host. One role of six needs a
120B model; the rest run on a 31B model on the L4s at a few seconds a call.
The GB10's reasoning slot changed model on 2026-10-19 (Nemotron 3 Super to
Nemotron 3.5 Super VL at medium-effort thinking); the one role bound to it was
re-measured on the live lane the next day, and the same model's reasoning
setting moved its result more than the change of model did
([lesson 26](lessons/26-name-the-reasoning-setting-beside-the-model.md)).
Each step up is a measured row
([models and hardware](hardware.md)).

## What it is actually about

- **Evidence over inference.** Every entry carries the raw tool output it came
  from, by hash. A model is consulted only where interpretation is needed;
  rules, scanners and parsers do the rest, and a model never decides whether a
  change worked.
- **Enabled is not enforced.** A listener that offers the hybrid group still
  serves every client that does not. The verifier is a pair of probes: a
  hybrid-only client must succeed, and a client offering any classical group
  must be refused.
- **A record that can be checked by someone else.** An append-only ledger,
  hash-chained, with checkpoints signed by a service that holds the key where
  nothing else can read it, and timestamps bracketed by the signer's clock.
- **The honest baseline.** The workbench is scored beside the open-source
  scanners run alone, by layer. At the first rung it finds what they find; what
  it adds is structure, posture and the change.
- **It runs where the inventory belongs.** A map of where an organization is
  weakest, down to the line of code, is not something to send to someone
  else's cloud. Everything here runs on infrastructure the owner holds, and
  what each step up in models or hardware changes is measured, or marked not
  measured.

## What this deliberately does not claim

- **Not that AI solves PQC.** It does not. The models here read call sites,
  classify, and trace a finding to a line; the scanners, rules and probes do
  the work, and two of six roles went back to rules because no model reached
  the floor.
- **Not a replacement for commercial discovery platforms.** Those are fielded
  products with sensors across live estates. This is an open exploration of
  what the CBOM enables once it exists.
- **Not faster than anyone.** The numbers shown are coverage, verification and
  time-to-change, on the hardware and the model they ran on.
- **Not a product.** Nothing here is for sale or supported.

Every number on this site is measured, computed or cited, and says which.

## Start here

| If you want | Read |
|---|---|
| The demonstration, step by step | [Demonstration](demo.md) |
| What a CBOM is, and what policy requires of one | [note 01](notes/01-what-is-a-cbom.md) and [note 03](notes/03-what-federal-policy-requires-and-when.md) |
| What "verified" means, and why a pair of probes | [How it works](how-it-works.md) and [note 08](notes/08-what-verified-means.md) |
| The components, the ledger, who may write what | [Architecture](architecture.md) and [note 12](notes/12-what-an-auditable-record-contains.md) |
| Where the models belong, by measurement | [note 13](notes/13-where-models-belong.md) and [Models and hardware](hardware.md) |
| What the free scanners cover | [note 15](notes/15-what-the-open-source-scanners-cover.md) |
| Standing rules learned the hard way | [Lessons](lessons/index.md) |
