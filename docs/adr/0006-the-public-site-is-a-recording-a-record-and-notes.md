# ADR-0006: The public site is a recording, a record and notes, never a facsimile of the running workbench

- **Status:** Accepted
- **Date:** 2026-11-08
- **Deciders:** Ken Rollins
- **Builds on:** ADR-0001 (the ledger is the system of record), ADR-0004 (one deployment in the lab)

## Context

The workbench runs in one place, the lab, behind a door. What the public sees is a static site on
GitHub Pages, generated from the private repository by `tools/publish.py` and leak-checked. Until
this decision that site rendered eleven of the running application's pages statically from one
recorded run, with every control that needs the workbench disabled and annotated, beside the demo
stage (eight beats, recorded) and the field notes.

That shape grew by accretion. Each page the application gained was given a public rendering, a
recorded fixture, a `public` branch in its template and a note under each dead button: twelve
such branches across the templates by 2026-11-08. Host scans, imported CBOMs and normalization were about to add more.
Two things were wrong with it. The cost of publishing grew with the application's features rather
than with the story it tells, which made the public site a second rendering target for the whole
application, the thing ADR-0004 exists to avoid. And a page that looks interactive and is not
teaches the engineer who checks to distrust the pages that are honest.

The site serves three audiences: a person shown the project on a machine that cannot run it, who
wants a walk-through; a person who checks, who wants the record and the method; and a reader, who
wants the notes. A facsimile of the application serves the first badly and the second worse.

## Decision

The public site is three things, each with a contract and a cost per feature that is a page of
writing, not a port of code:

1. **The demo**: the stage's eight beats, recorded from one run, labelled as recorded, with the
   recorded Ask answers and the ledger's citations re-checked when the page is built. New capability
   enters the public demo only as a beat in that story. The Pages root is the stage.
2. **The record**: the recorded run's own documents, the CBOM, the ledger, the score and the two
   baselines, downloadable with their hashes, and one viewer, *Inside the CBOM*, that opens an entry
   field by field with the evidence behind each field. Data a person can verify, not a user interface.
3. **The notes**: the field notes, with the running workbench shown page by page as screenshots
   captured from the recorded run, under the book's conventions for a marked screenshot. A screenshot
   has no dead button and costs nothing in code.

Four application pages are rendered publicly: `/demo`, `/cbom` (and the entries it and the demo link
to), `/ask` (recorded) and `/about`. The overview, the test agency, the walkthrough, the plan, the
change packages, the imports and the resolve page are not rendered publicly; their templates carry no
`public` branch. The shared header shows only the four in a public build.

## Consequences

- A new feature costs the public site one screenshot and one note, or one beat if it belongs in the
  story; never a static rendering.
- The guarantee that a public page offers no way into the lab moves from branches in every template
  to one list in `tools/build_public.py`, tested.
- The person on the restricted machine loses the feeling of the whole application in the browser,
  and gains pages that are each a recording, a document or a picture: the standard the journal
  already holds itself to.
- The public tooling shrinks rather than grows as the application does.
