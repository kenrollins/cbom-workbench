---
id: lesson-25-size-the-scanner-network-to-the-parallelism
type: lesson
title: "Size the scanner network's address range to the parallelism, and record a job that never started as its own failure"
date: 2026-10-14
audience: [engineer]
rung: enumerated
tags: [runner, containers, networking, operations]
one_line: "When scanners run as containers on a network with a fixed address range, the range bounds how many can run at once; a job that fails because no address was free must be recorded as a runner failure with its reason, never as a scan the target did not answer."
reuse: [runbook]
---

# Size the scanner network's address range to the parallelism, and record a job that never started as its own failure

## The rule

A network that scanner containers join for the duration of a job has at
least as many free addresses as jobs may run at once, plus the runner's own,
plus a margin for a container that is being torn down while the next starts.
A job whose container could not be created or started is recorded with the
daemon's reason and a status that says the runner failed, distinct from a scan
that ran and found the target unreachable.

## Why

A scanner container on a macvlan or any network with an address pool takes an
address when it starts and gives it back when it is removed. With eight jobs
in flight and seven free addresses, the eighth container fails to start, and
every job that starts while the pool is empty fails the same way in under a
second. Those fast failures look, from the harness's side, like thirteen
listeners that refused to talk: the same status, no raw output, nothing in
the ledger that a reader could tell apart from a host firewall. The daemon's
message — no available IPv4 addresses — was in the runner's stderr tail and
nowhere a page would show it.

The second run, with the pool widened to sixteen addresses, answered for
every listener that was actually up.

## When it applies

Any runner that launches one container per job onto a network with an
explicit address range: macvlan legs into a VLAN, bridges with a small
subnet, anything with `--ip-range`. The tighter the range was drawn for
firewall reasons, the more likely it binds.

## How to apply it

- Set the pool from the runner's worker count: workers + 1 for the runner +
  a margin of a few; `/28` for eight workers.
- Or cap the workers from the pool, and say so in the runner's log.
- Give a job that never ran its own status, carry the daemon's message into
  the ledger event, and show it on the page beside the target, so "the runner
  could not start a scanner" is never read as "the target did not answer".
- When a targeted scan reports many failures of a few hundred milliseconds
  each, read the runner's log before reading anything into the targets.
