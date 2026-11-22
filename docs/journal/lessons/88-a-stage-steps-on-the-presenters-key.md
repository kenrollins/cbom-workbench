---
id: lesson-88-a-stage-steps-on-the-presenters-key
type: lesson
title: "A demonstration steps on the presenter's key; a replay on a timer makes the presenter wait for the screen, or talk past it"
date: 2026-11-22
audience: [engineer, architect, leader]
rung: all
tags: [demo, agility]
one_line: "A stage that replays a recorded change at its own speed, or brings its bands and journeys in on timers, puts the screen in charge of the talk. Every beat with more than one thing to show is a list of steps: next shows the next, back takes the last away, the heading says which step of how many, and the beat is left only after its last step."
claims:
  - text: "The workbench's eight-beat stage takes 30 presses from the opening to the record on the mini-agency's data: 3 on the opening, 6 on the architecture (the layers, then five journeys), 3 on the scan, 1 on the CBOM, 8 rows of the plan, 8 steps of a change, 1 on the question and 1 on the record. A key pressed while the stage's document is still being read is ignored."
    provenance: "measured 2026-11-22 in headless Chromium at 1800 x 1000 against the app in console mode on the scan of 2026-11-21, pressing the right arrow and reading the address after each press"
  - text: "The change beat had played the ledger's own timings back compressed to 18 seconds, and showed whichever change run was latest; with the latest run left open it stopped at 'waiting for a person'."
    provenance: "by reading src/pqch/ui/static/demo.js before commit 6d0d0f7 of 2026-11-21, and the owner's capture of the stage that day"
reuse: [talk]
---

# A demonstration steps on the presenter's key; a replay on a timer makes the presenter wait for the screen, or talk past it

## The rule

Anything a demonstration reveals in parts is revealed by the presenter, one
part per key press. The page keeps a list of steps for each beat. Next shows
the next step and leaves the beat only when the last is on the screen; back
takes the last step away before it leaves; the heading says which step of how
many, so the presenter always knows whether more is coming. Nothing that
carries meaning arrives on a timer.

## Why

A replay at its own pace has two failure modes, and a presenter meets both in
one talk. Either the sentence is finished and the screen is not, so the room
watches a progress bar; or the screen has moved on while the sentence was
still about the step before. Neither is visible to the person who built the
page, who knows what is coming and unconsciously waits for it. It shows the
first time someone else presents, or the same person presents to a room that
asks a question in the middle.

A recorded change is the clearest case. Its ledger has real times, a minute
from approval to proof, and playing those times back, even compressed, feels
faithful. But the audience is not there to feel a minute pass. They are there
to see eight things in order: proposed, rehearsed on a copy, approved,
applied, probed, a verdict, recreated, proved again. The times belong on the
screen as numbers beside each step, where they can be read and questioned.

A stepped beat also cannot arrive half-made. The change beat used to show the
latest change run, whatever its state, so a run left waiting for approval
stopped the demonstration at its third card. A stepped beat is drawn from a
change that was carried through, and an approval made live on stage is a
separate, deliberate act with its own key.

## When it applies

Any page presented to a room: a stage, a walkthrough, a slide drawn by
script. It applies to a published static copy as much as to the running
system, since a reader at home is a presenter with an audience of one.

It does not apply to what is real time. A scan actually running may update
by itself, because the audience is watching it happen, and an elapsed clock
may tick. Motion inside one step, a dot travelling a path once after its key
press, is decoration and is fine as long as the step's content is complete
without it and nothing starts by itself.

## How to apply it

1. Give each beat a stepper: a count and a function that draws step *k* from
   any earlier state. Drawing step *k* must not depend on having watched steps
   0 to *k* − 1 animate, or back and a direct jump will show a half-built
   picture.
2. Route every way of moving through one function: the next and back buttons,
   the arrow keys, space and the page keys. A jump (the beat bar, a number, an
   address with the beat's name) goes to a beat's first step; stepping back
   into a beat from the one after it shows its last step, so back always
   undoes the last thing shown. Keep one key for leaving a beat at once.
3. Put "step *k* of *n*" in the heading, where the presenter is looking, and
   check it never overlaps anything fixed to the screen's edge.
4. Keep a still mode that draws every beat's final state at once, for
   screenshots and for checking each beat against its last step
   ([lesson 39](39-a-diagrams-labels-are-claims.md) holds
   what is drawn to the record).
5. Ignore keys until the page's data has loaded. A presenter who presses next
   during a slow load otherwise walks past beats that were never drawn.
6. Count the presses from the first beat to the last in a browser, and write
   the number in the run sheet. A count that changes after an edit is a beat
   that gained or lost a step.

## Scope

The count of 30 is for the mini-agency's eight services and one recorded
change; the plan beat has one step per ranked service, so it grows with the
estate. Whether eight plan rows are too many to step through one by one in a
twenty-minute talk is a judgement about a talk, not measured here; the beat
can be left at any row.
