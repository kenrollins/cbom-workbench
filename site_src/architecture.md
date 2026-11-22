---
title: Architecture
---

# Architecture

<figure class="sketch" markdown>
![Five wide bands stacked top to bottom, each with a name and one line: what comes out (the CBOM, the register and plan, changes, answers, gaps); judgement (rules over the evidence; the verifier is probes, no model); the harness (the app, the runner, the signer, the scanners: one job each); models, by role (three tiers, each measured against a floor first); where it runs (any host with Docker; images by digest, nothing fetched). To their right stands one tall column, the ledger, with an arrow into it from every band; inside it, hash-chained events is ringed in red, and signed checkpoints is written below. The heading reads: whatever a layer does is an event on the ledger first; the rest is rebuilt from it.](img/sketches/arch-five-layers.svg)
<figcaption>Five layers of the approach and the ledger beside every one; whatever a layer does is an event first. What each layer holds is in the table below.</figcaption>
</figure>

What each layer holds, from the top:

| Layer | What is in it |
|---|---|
| **What comes out** | Projections, and the people's part. The CBOM in CycloneDX 1.6; the register and plan, steps in order with the owner's facts beside each; changes, approved by a person and probed twice; Ask the CBOM, with its citations checked; the gap queue, naming what was not reached |
| **Judgement** | Rules over the evidence. Policy packs as data, every quote checked against its source; rules that give each entry its status; claims and grades, where the wire outranks a file and a file a statement; supplier statements, reported beside what was observed and never merged with it; the owner's facts, supplied and never computed; the verifier's paired probes, with no model |
| **The harness** | One job each. The app, the only door and the one writer; the runner, which holds the Docker socket; the signer, with no network; the system runner, which reads a host whole; the inference seam, its tiers set in config; the scanners, containers pinned by digest |
| **Models, by role** | Each measured against a floor written first. A fast tier to narrate, name and propose; a deliberate tier to trace, reconcile and answer; an embed tier for Ask's retrieval; and never a finding, a verdict or an approval |
| **Where it runs** | Any host with Docker. Images by digest from an offline bundle, nothing fetched; the one host a run was on, named on every event as recorded; and one option, an isolated scanner on a desktop GPU box |
| **The ledger** | One signed JSONL file per run: the record, not a log. Hash-chained events for every finding, judgement, approval and verdict; checkpoints signed with ML-DSA-65, the key id on each page; projections rebuilt from the events and never edited; and a recording that replays on any host |

The same work as a pipeline of roles, and who does each:

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

Three decisions everything else rests on, each with its architecture decision record (ADR) under
[Decisions](adr/index.md): the ledger is the system of record and the CBOM a projection of it
([ADR-0001](adr/0001-the-ledger-is-the-system-of-record.md)); one deployment in the lab, with the
bundle as a feature and every model the lab holds in scope by measurement
([ADR-0004](adr/0004-one-deployment-in-the-lab.md), superseding ADR-0002); and the harness changes
only an estate it built, handing off a change package anywhere else
([ADR-0003](adr/0003-deployment-shapes.md)). Two more followed: a server is an estate of its own
([ADR-0005](adr/0005-a-server-is-an-estate.md)), and the public copy of this project is a recording,
a record and notes, never a facsimile
([ADR-0006](adr/0006-the-public-site-is-a-recording-a-record-and-notes.md)).
