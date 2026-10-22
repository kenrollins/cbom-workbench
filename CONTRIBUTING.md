# Contributing

cbom-workbench is a personal exploration project: a working picture of what a cryptography bill of
materials is for once it exists, published so others can read it, run it and argue with it. It is not
a product and has no support commitment, but feedback is the point of publishing it.

## Feedback

[Open an issue](https://github.com/kenrollins/cbom-workbench/issues) for:

- **A wrong claim** — a number, a reading of a standard or a memo, a description of a tool. Every
  number in the pages and the notes is meant to be measured or cited; one that is neither is a defect.
- **A step that fails** — the quickstart in the README and the guide to scanning your own network
  have been run on one machine, the author's.
- **A scanner or CBOM it should read** — the importer scores any tool's CycloneDX CBOM against the
  same answer key; a public sample from a tool not yet tried is welcome.
- **A question** the demo or the notes left unanswered.

## Changes

Pull requests are welcome; for anything larger than a fix, open an issue first. This repository is
generated from a private working copy, so an accepted change is applied there and arrives here with
the next publication, credited in the commit.

What a change needs:

- `uv run ruff check .` and `uv run python -m pytest` pass (CI runs both, and the strict site build).
- **A model never decides whether a change worked.** Verification is a re-scan, a certificate parse
  or a compatibility run.
- **The ledger is the system of record.** The CBOM is rebuilt from it, never edited.
- **A role moves to a model only by measurement**, against a floor written before the run
  (`spikes/s3/`).
- Scanning code touches nothing outside the scope file it is given.
- A new decision gets an ADR in `docs/adr/`; a new finding or rule worth keeping, a note or a lesson
  in `docs/journal/` written to `docs/journal/STYLE.md`.

## Scanning

Scan only networks you own or have written permission to test. The mini-agency in `agency/` exists so
that nothing else needs to be scanned to try the workbench.
