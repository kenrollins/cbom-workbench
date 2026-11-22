---
id: lesson-52-a-read-without-privileges-must-list-what-it-could-not-open
type: lesson
title: "An inventory read as an ordinary user must list every path it could not open, and the plan must carry the privileged read as a step"
date: 2026-11-04
audience: [engineer, architect]
rung: enumerated
tags: [discovery, cbom]
one_line: "Reading a server's files without privileges sees the public half of each key pair and none of the private keys; an inventory that drops the unreadable files silently looks complete and is not, so the reader lists them and the plan asks for one privileged, read-only pass."
claims:
  - text: "OpenSSH keeps each host key's public half world-readable and its private half readable by root only (sshd refuses a private host key others can read)."
    provenance: "cited: sshd(8), FILES"
reuse: [runbook, customer-question]
---

# An inventory read as an ordinary user must list every path it could not open

## The rule

When a server's files are read without privileges, record each path that could not be opened beside
what was read, carry the list into the CBOM, and put one privileged, read-only pass in the plan.
Never let an unreadable file disappear from the result.

## Why

On a Unix system a key pair's public half is world-readable and its private half is not: an SSH
host's `.pub` files can be read by anyone, its private keys only by root. A reader running as an
ordinary user therefore finds every public key and no private one, and an inventory built from it
counts the server's keys correctly while missing what they protect: which private keys exist, in what
format, of what size, and whether any sits outside the expected places. Leaving the unreadable files
out makes the partial picture look whole.

## When it applies

Any inventory of files read with less than full privilege: a scan as a service account, a container
without the host's root, a read of a mounted volume. It does not apply where the reader is root on the
system, where nothing is unreadable to it.

## How to apply it

The runner's packer lists every path it cannot open in the archive's manifest; the reader reports the
list; `platform.observed` carries it with the user the read was made as; the CBOM's device component
shows it; and the server's plan adds "read the paths an unprivileged read could not open" as a step
for today.
