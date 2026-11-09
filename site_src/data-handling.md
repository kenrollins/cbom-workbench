---
title: Data handling
---

# Data handling

What the workbench keeps, how sensitive it is, where it lives, what mode it is written with, how long
it is kept and how it is destroyed. A CBOM is a map of an estate's weakest cryptography: every
quantum-vulnerable algorithm, with the host and port it was found on. Treat everything below that
carries findings as the agency treats vulnerability information about its own systems; whether that
is controlled unclassified information (the CUI Registry's Information Systems Vulnerability
Information category) is the agency's decision, not the workbench's.

## Modes

Everything under `var/` is written with the process's umask unless the deployment sets
`PQCH_VAR_PRIVATE=1` on every service that writes there. Then every file is created 0600 and every
directory 0700, and `pqch var harden` brings what was written before into line:

```sh
# compose.yaml or an overlay, on the app, runner and signer services
PQCH_VAR_PRIVATE: "1"
# once, for what is already there
docker compose run --rm app pqch var harden
```

It is not the default because one shape reads across users: the kit's system runner writes raw
output as root and the app reads it as the operator's uid. Turn it on where every writer and reader
runs as one uid. The estate's rendered configuration (`agency/generated/`) is not under `var/` and
keeps its mode: the estate's own services read it.

## Marking, retention, roles

Three settings turn the deployment's handling rules into facts the workbench enforces or shows:

- **Marking.** `PQCH_MARKING` (for example `CUI`) puts a banner on every page the app serves,
  writes `pqch:marking` into every document a run writes (the CBOMs, the consumer copy) and adds a
  `marking` column to the register. A marking is applied at creation, as 32 CFR 2002.20 asks; the
  projection itself stays a function of the ledger, and the marking is added where the file is written.
- **Retention.** `pqch retention apply --days N` (or `PQCH_RETENTION_DAYS`) deletes the raw scanner
  output and the written documents of every run older than the period and records each deletion as
  an `artefact.destroyed` event in a run of kind `retention`, with the person and the basis. The
  ledgers stay: they are the record. `--dry-run` lists what would go.
- **Roles and separation of duties** (ADR-0008). `PQCH_APPROVER_GROUP` names the identity
  provider's group an approver must be in, read from the front door's groups header
  (`PQCH_GROUPS_HEADER`, default `X-Forwarded-Groups`) on a trusted connection; every approval
  records the role and groups it rested on. `PQCH_SEPARATION_OF_DUTIES=1` makes the runner refuse an
  apply approved by the person who asked for the change, or approved without the role, and splits
  the page's approve and apply into two requests; the command line then approves only in a labelled
  single-operator mode.
- **Rules of engagement.** `PQCH_REQUIRE_ROE=1` on the runner refuses a scope whose authorization
  does not name the signed rules-of-engagement document by hash (`rules_of_engagement_sha256`).
- **Logs for a collector.** The ledger of every run is JSON lines already. `PQCH_ACCESS_LOG` names a
  file the app appends one line to per request (`pqch.access/1`): the time, the signed-on name, the
  path, the status, how long it took, whether it was a download of a ledger, a CBOM, a register or a
  plan, and the marking. Shipping that file to a collector is the deployment's job.
- **The clock.** Every `run.started` records what the kernel says of the host's clock (`clock`):
  synchronized or not, and the error it estimates, read with a call that changes nothing. An
  unsynchronized clock is recorded, not refused.

## What is kept

| Artefact | Sensitivity | Where | Mode with `PQCH_VAR_PRIVATE=1` | Kept | Destroyed by |
|---|---|---|---|---|---|
| Run ledger: every finding, assessment, approval and verdict | Findings with hosts and ports; who approved what | `var/runs/<run>/ledger.jsonl` | 0600 | Until removed; it is the system of record | Removing the run directory; the CBOM is rebuilt from what remains |
| Ledger public key | Public | `var/runs/<run>/ledger.pub` | 0600 | With the ledger | With the ledger |
| CBOMs (workbench and scanner-only projections) | As the ledger: a projection of it | `var/runs/<run>/*.cdx.json` | 0600 | Rebuilt on demand | Rebuilt or removed with the run |
| Score against an answer key | Test estate only | `var/runs/<run>/score.json` | 0600 | With the run | With the run |
| Raw scanner output | Full detail of every listener and image scanned | `var/raw/<job>.*` | 0600 | Until removed; the ledger holds its SHA-256 | Removing the file; the ledger's hash shows it existed |
| Imported CBOMs | The supplier's findings, and possibly the supplier's licence terms | `var/runs/<run>/imported-*.cdx.json` | 0600 | With the run | With the run |
| Code-layer candidates | Source lines of the scanned repository | `var/runs/<run>/code-candidates.json` | 0600 | With the run | With the run |
| Passive capture logs (Zeek) | Every handshake seen on the mirror: client and server addresses | The capture service's `PQCH_CAPTURE_DIR`, outside `var/` | The capture service's | Rotated `conn` logs pruned once ingested; others until removed | `pqch capture prune` for `conn`; the operator for the rest |
| Recordings of a server's scan (export) | Sanitized: identifiers replaced, MAC addresses and UUIDs scrubbed, leak-checked | The operator's chosen directory | The umask | Until removed | The operator |
| Recorded demo narration and Ask answers | Model output over the CBOM | `var/demo/<run>.json`, `var/ask/<run>.json` | 0600 | Until re-recorded | Removing the file |
| Ask caches (embeddings) | Derived from the CBOM and the site | `var/runs/<run>/ask-index.json`, `var/runs/notes-ask-index.json` | 0600 | Until the text they were built from changes | Removing the file; rebuilt on the next question |
| Scope | The estate's addresses, who authorized the scan, for which system and until when | `var/scope/scope.json` | The operator's | As long as the scan is authorized | The operator; its hash stays in every run's first event |
| Signer key (ML-DSA) | Secret: whoever holds it can sign checkpoints | The signer's volume, `/var/pqch-signer/private/ledger.key` (a key written before that directory existed stays at `/var/pqch-signer/ledger.key`) | 0600 in a 0700 directory | For the life of the key | Removing the volume (`kit/cleanup.sh` does) |
| Signer's record of what it signed | Integrity evidence; names the caller's uid | The signer's volume, `private/record/<run>.jsonl` | 0600 | With the key | With the volume |
| Runner's job and apply logs | Every job and change it ran | The runner's volume, `jobs.jsonl` and the apply log | 0600 | Until removed | Removing the volume |
| Inference keys and controller credentials | Secret | Environment variables named in config; the runner's `PQCH_CONTROLLER_SECRETS` directory | The operator's | As the operator decides | The operator |

## What leaves the box

- **Prompts to a model** carry findings with hosts and ports, source lines, service files and CBOM
  facts. They go only to the inference endpoints in the tier map; on the kit those are engines on the
  same box, reached over its own bridge.
- **Exports** (a server's recording, the public demo) pass through the sanitizer and a leak check that
  deletes the output on any match.
- **The scans themselves** touch only what the scope lists (ADR-0003).
- **Nothing else** is sent by the workbench: it loads no asset from a CDN and makes no update check.

## What the host must provide

- **Encryption at rest** for the disk that holds `var/`, the signer's volume and the capture directory
  (LUKS or the platform's equivalent). The workbench does not encrypt its own files.
- **A time source** (NTP or the platform's), since every event and every signature carries the
  host's clock; the signer refuses a ledger more than two seconds ahead of its own time.

## Where this stops

Retention runs when an operator runs it: nothing is removed on a schedule. Removing a file by hand,
outside `pqch retention apply`, records no event. The access log is a file; sending it to a
collector, and an alert on what it holds, are the deployment's. Accessibility was tested by rule
and by an automated keyboard pass, not by a person with a screen reader (`docs/ACCESSIBILITY.md` in
the repository).
