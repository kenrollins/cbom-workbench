---
id: lesson-67-publish-a-recording-a-record-and-notes-not-a-facsimile
type: lesson
title: "Publish a running system as a recording, a record and notes; never as a static copy of its pages with the buttons disabled"
date: 2026-11-08
audience: [architect, engineer]
rung: all
tags: [agility, verification]
one_line: "A static copy of a live application's pages costs a fixture, a template branch and a dead-button note per page and grows with the application's features, not with its story; publish a recording, the documents it produced with their hashes, and screenshots in the notes instead."
claims:
  - text: "Before this rule the public copy of the workbench rendered 11 of the application's pages statically (and the CBOM entries they link to), with 12 `public` branches across the templates to hide or disable what needs the running system; after it, 4 pages are rendered (the stage, the CBOM viewer, the recorded answers, About), the 7 branches that remain are all in the shared header and the CBOM viewer, and the dropped pages' templates carry none."
    provenance: "counted 2026-11-08: the page table in tools/build_public.py and `{% if public %}`, `{% if not public`, `{% elif public %}` and `and not public` in src/pqch/ui/templates, at the commits on either side of ADR-0006 (6c969b0 and the one that follows)"
  - text: "The pages not rendered publicly are shown as 7 screenshots captured at 1440 px from the same recorded runs by tools/screenshots.py, 211 to 252 KB each."
    provenance: "measured 2026-11-08, tools/screenshots.py over the lab's curated mini-agency runs, x86_64"
reuse: [whitepaper, talk]
---

# Publish a recording, a record and notes, not a facsimile

## The rule

When a system that runs in one place has to be shown where it cannot run, publish three things and
nothing else: a **recording** of it doing its work, labelled as a recording; the **record** it
produced, as documents with their hashes; and **notes**, with the system's own screens as
screenshots. Do not publish a static copy of its pages with the controls disabled.

## Why

A static copy of a live page is a facsimile: it looks like the application and is not. It costs,
for every page, a recorded fixture to render it from, a branch in the template for what must be
hidden or disabled, a note under each dead control saying so, and a check that nothing private
reached the render. That cost grows with the application's features, so the public copy becomes a
second rendering target for the whole application, maintained in step with the first. And the
facsimile misleads exactly the reader who matters most: the one who checks. A button that does
nothing teaches that reader to distrust the pages that are honest.

The three audiences of such a site want different things, and none of them wants the facsimile. A
person shown the project on a machine that cannot run it wants a walk-through: a recording gives it,
with its date and the hardware it ran on. A person who checks wants the output and the method: the
documents, their hashes and the notes give it, and a verifier they can run gives more than any page.
A reader wants the explanation: the notes, with the screens shown as they were captured, so a
picture never has a dead button.

<figure class="sketch" markdown>
![Three boxes a public site may be made of, a recording, a record and notes, each with what it costs per new feature (one beat, one document row, one screenshot and a note); a fourth box, a facsimile of the application's pages, crossed out, with its cost per feature: a fixture, a template branch, a dead-button note and a leak check](../img/sketches/67-recording-record-notes.svg)
<figcaption>Three things to publish, and the one not to: the facsimile is the only one whose cost grows with the application.</figcaption>
</figure>

## When it applies

Any system that runs behind a door, on an owner's hardware or on data that cannot leave, and has to
be shown outside it: a demonstration published to a static host, a screenshot deck for a restricted
laptop, a paper's artefact. It applies most where the audience includes people who will check. It
does not apply where the public copy *is* the system, served live with its own data, and it does not
forbid one honest viewer over published documents (here, the CBOM opened entry by entry), which is a
document reader, not a facsimile.

## How to apply it

Name the pages the public copy renders in one list, and test that the shared header offers no
other. Generate the record page from the published run at build time, so a document's hash is never
typed by hand. Capture screenshots with a tool from a curated workspace that holds only what may be
published, at a fixed width and scheme, and recapture when a page changes. Write the decision down,
so the next feature is given a beat, a row or a picture, and not a page.

```sh
# the workbench's version (ADR-0006)
tools/build_public.py      # PUBLIC_PAGES: the stage, the CBOM viewer, the recorded answers, About; record_page()
tools/screenshots.py       # the other screens, captured from the curated runs into docs/journal/img/pages/ (the site build copies them in)
site_src/pages.md          # the captions beside them
```
