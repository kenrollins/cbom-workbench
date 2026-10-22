---
title: Architecture
---

# Architecture

```text
   SCOUT ─────► INVESTIGATOR ─────► ASSESSOR ─────► MIGRATOR ─────► VERIFIER
 (scanners,      (a model reads      (rules first;    (renders policy;  (paired probes;
  normalizers)    call sites)         a model on       applies only      no model)
                                      conflicts)       what it built)
                                            │
                                   CBOM LEDGER — CycloneDX CBOM + append-only,
                                   hash-chained, signed JSONL event log
```

| Component | What it does | Holds the Docker socket |
|---|---|---|
| **Scout** | Runs the scanners through the runner and normalizes their output into one finding schema | no |
| **Runner** | The one container on the target network with the Docker socket. Accepts named scan profiles only, refuses any target outside the scope file, applies an approved change id, and keeps its own log of every job and every apply where nothing else can write | yes |
| **Investigator** | A model that reads a call site or traces a wire finding to the configuration line behind it, with step and token budgets | no |
| **Assessor** | Rules first — quantum-vulnerable or not, key establishment or signature, deadline, queue; a model only where findings conflict | no |
| **Migrator** | Renders the central crypto policy into each service's configuration, proposes the change with its diff, rollback and the check that will count, and hands it to the runner once approved | no |
| **Verifier** | The paired probes and the witness; a verdict bound to the container and certificate it probed | no |
| **Signer** | Signs ledger checkpoints with ML-DSA-65; holds the key on storage nothing else mounts; no network | no |
| **UI service** | The one page: the scan button, the CBOM with its evidence, the score, the change. Behind the lab's front door | no |

## Who may write what

One process appends to the ledger: the UI service. Every other component
returns a result to it, or refuses. What makes an event trustworthy is stated
per kind, and so is where that trust stops:

- **Runner events** are written from the runner's own job results, and a reader
  checks each apply, recreate and cited probe against the runner's own log — the
  job it was asked for, when it ran, against which container, with what raw
  output.
- **Human events** carry who approved and how they were authenticated: the
  front door's sign-on, believed only on a connection from the front door.
- **Timestamps** are the harness's, held within two seconds of the signer's
  clock on each side of the events a person causes.
- **What remains:** whoever controls the UI process could write an approval no
  person gave. Approvals signed by the approver's own key would close that;
  they are stated and not built.

## One deployment, one bundle

The workbench runs in one lab: an x86_64 server, inference through a gateway
with a scoped key, the test estate beside it on an internal-only bridge. Every
model the lab serves — from the server's own GPUs, from a desk-side GB10 and
from a second GPU host — is reachable through one inference seam, and a role
is given to a model only by measurement. The offline bundle is a feature, not
a second target: every image multi-arch and pinned by digest in a local
registry, so the whole thing loads on another host with the network cut.
What each step up in models or hardware changes is a measured row on the
[models and hardware](hardware.md) page.

## Decisions

Three decisions everything else rests on, each with its record in the
repository: the ledger is the system of record and the CBOM a projection of it
(ADR-0001); one deployment in the lab, with the bundle as a feature and every
model the lab holds in scope by measurement (ADR-0004, superseding ADR-0002); and
the harness changes only an estate it built, handing off a change package
anywhere else (ADR-0003).
