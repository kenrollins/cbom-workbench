---
id: lesson-65-before-tightening-a-file-mode-find-every-reader
type: lesson
title: "Before making a shared directory's files private, list every process that reads them and the user each runs as"
date: 2026-11-06
audience: [engineer]
rung: all
tags: [agility]
one_line: "Before making a shared directory private, list every reader and the uid each runs as; where writers and readers differ, make the mode a setting."
claims:
  - text: "In the kit, the system runner runs as uid 0 (kit/compose.system.yaml, PQCH_SYSTEM_RUNNER_USER default 0:0) and writes raw scanner output under var/raw, which the app reads as PQCH_UID (default 1000)."
    provenance: "read 2026-11-06 in kit/compose.system.yaml and compose.yaml at branch m8-now"
  - text: "The same runner process also renders the estate's configuration under agency/generated/, which the estate's own services read as their own users; a process-wide umask of 077 would make those files unreadable to them."
    provenance: "read 2026-11-06 in src/pqch/runner/apply.py (policy_dir under agency_dir)"
  - text: "A third reader runs outside the containers: tools/build_public.py reads the deployment's var/runs/ as the user who invokes it, so after pqch var harden it must run as the files' owner."
    provenance: "read 2026-11-08 in tools/build_public.py (the --var reader)"
reuse: [runbook]
---

# Before making a shared directory's files private, find every reader

## The rule

Before a change makes the files under a shared directory 0600 and its directories 0700, list every
process that reads them and the user each one runs as. If they are not all one user, make the private
mode a setting, and turn it on per deployment once they are.

## Why

A file's mode decides who may read it by user and group. 0600 leaves only the owner. That is the right
mode for a ledger, raw scanner output or a CBOM, which together map an estate's weakest cryptography.
But a pipeline split across containers often writes as one user and reads as another. In the
workbench's kit, the system runner runs as root so it can read host keys only root can read. It writes
its raw output under `var/raw`, and the app reads that output as the operator's uid. Written 0600 by
root, it is unreadable to the app (uid 1000 is neither root nor in group 0), so the server scan would
stop at the read. The uids are read from `kit/compose.system.yaml` and `compose.yaml`; the failure was
reasoned from them, not exercised.

<figure class="sketch" markdown>
![Two writers and three readers of the workbench's files: the system runner, as root, writes raw scanner output that the app reads as uid 1000 and the public builder reads as the host user; the same runner writes the estate's rendered configuration, which the estate's services read as their own uids. The red ring is on the 0600 file the uid-1000 reader cannot open.](../img/sketches/65-two-writers-three-readers.svg)
<figcaption>Two writers, three readers, three uids: the file a private mode would close is the one the app needs.</figcaption>
</figure>

Two shortcuts make it worse:

- **A process-wide umask.** It also governs files written for other audiences. The runner renders the
  test estate's configuration, which the estate's services read as their own users.
- **A group-readable mode (0640).** Root's files carry group 0, which the reader is not in.

## When it applies

Any shared volume, bind mount or network share written by more than one service. It does not apply
where one user writes and reads everything; there, private modes cost nothing.

## How to apply it

Change modes at each writer, not with a umask, behind a setting. The workbench's version is
`PQCH_VAR_PRIVATE=1` (`src/pqch/varmode.py`), with a sweep for what was written before:

```sh
PQCH_VAR_PRIVATE=1   # on every service that writes under var/
pqch var harden      # once: directories 0700, files 0600, symlinks not followed
```

Write down which readers you checked, including any that read from the host outside the containers:
here `tools/build_public.py --var`, which runs as the invoking user and, after `pqch var harden`, has
to run as the files' owner. The data-handling page (`site_src/data-handling.md`) states why the setting
is off by default.
