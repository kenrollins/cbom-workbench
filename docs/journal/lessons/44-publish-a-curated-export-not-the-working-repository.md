---
id: lesson-44-publish-a-curated-export-not-the-working-repository
type: lesson
title: "Publish a curated export, checked for leaks, not the working repository; and keep the list of what must not leak out of the published tools"
date: 2026-10-22
audience: [engineer, leader]
rung: all
tags: [cbom]
one_line: "A working repository built in a real environment carries that environment in its history, its tests and its notes; publish a fresh tree exported from it, with private passages marked at the source and stripped on export, a scan that refuses the export on any match, and the scan's own patterns kept private."
claims:
  - text: "Before publication, a scan of the working repository's tracked files found internal addresses in 36 lines, the owner's domain in 2, an internal hostname used as a measurement label, and the old project name in 21 places, besides the full history behind them; the export left out 5 kinds of private record and 2 lab-only entries and stripped the marked passages, and its scan found nothing."
    provenance: "measured 2026-10-22 on this repository with tools/export_public.py"
reuse: [runbook]
---

# Publish a curated export, checked for leaks, not the working repository; and keep the list of what must not leak out of the published tools

## The rule

Make the public repository a fresh tree exported from the working one: leave
out the private files, strip passages marked private at the source, scan the
result for anything that must not leak and refuse to write it on any match —
and keep that list of patterns out of the published tools.

## Why

A repository built against a real environment absorbs it: addresses in test
fixtures and configuration examples, hostnames as measurement labels, a
domain in a plan, findings in notes, and all of it again in every commit of
the history. Turning such a repository public publishes the history too, and
rewriting history to clean it is error-prone. An export with one fresh commit
has no history to leak.

A scan only finds what it is told to look for, so the scan's list names the
very things it protects: an internal domain, a username, a product the
environment runs. Published with the tool, it would leak them itself.

## When it applies

Any project developed against a private environment and then shared: a
proof of concept built in a lab, a tool tested against production-like data,
a write-up drawn from a real estate.

## How to apply it

- Mark private passages where they are written (here `<!-- lab -->` blocks,
  `# lab` claim markers and `lab_only: true` entries), so the export does not
  depend on someone remembering them.
- Export from a commit, not the working directory (`git archive`), so what is
  published is what is committed.
- Scan the exported tree and every built page; any match refuses the export.
  Keep the patterns in a private file the tools read.
- Remap private addresses in tests to ranges the environment does not use,
  keeping their relationships, so the tests still mean the same thing.
- Build any public site from the exported tree, so it can hold nothing the
  repository does not.
