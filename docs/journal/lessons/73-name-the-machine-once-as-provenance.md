---
id: lesson-73-name-the-machine-once-as-provenance
type: lesson
title: "A demonstration written around one machine goes stale the day the machine leaves; name hardware once, as where a run was recorded, and build the beats on the approach"
date: 2026-11-10
audience: [architect, engineer]
rung: all
tags: [demo, provenance, architecture]
one_line: "A stage whose beats name a box, its chips and its model on every screen is true for one day and one machine. Four days later its recording came from a different host with different models, and three machines were named across eight beats with no reconciliation. The fix is structural: the beats describe the approach, and hardware appears once, as the provenance label on the run the copy shows."
claims:
  - text: "The stage published on 2026-11-09 named a desktop GPU box on its opening, its architecture and its closing beat, with that box's model and runtime in the architecture's model layer, while the copy's own kicker said its numbers were recorded on an x86_64 server and its Ask beat showed an answer from a third host running a different model."
    provenance: "read 2026-11-10 from the published stage's eight beats, screenshotted in headless Chromium at 1600×900"
  - text: "Rebuilt the same day, the stage names hardware in one place per copy, the recorded host from the run's own scan.completed events, and its architecture beat draws the layers from the run's data: the packs the rules read, 8 compatible · 183 not compatible · 11 unknown entries under them, 10 open gaps, 25 register rows, the tiers and roles from the inference config the recording carried."
    provenance: "measured 2026-11-10 against the lab's run 01M6Z41DJB5911EF1Y65K2FBTY in a public-mode copy of the app; the counts are the plan page's own"
reuse: [talk]
---

# A demonstration written around one machine goes stale the day the machine leaves; name hardware once, as where a run was recorded, and build the beats on the approach

## The rule

A recorded demonstration names the machine it ran on **once**, as the
provenance of the run it shows, read from that run's own events. Every other
screen describes the approach: what is collected, what judges it, who
approves, what proves it, and where a model is allowed to speak. A screen that
needs a box's name, chip or model to make its point is making a point about
that box, and it will be wrong the first time the recording comes from
somewhere else.

## Why

A demonstration built for a day on one machine borrows that machine's
specifics for its drama: the chip, the memory, the model served, the path up
to bigger boxes. Those specifics are true that day. The recording the
published copy plays is then remade whenever the estate is re-scanned, on
whatever host did the scan, with whatever models the inference seam bound that
week. Nothing checks that the words on the screens still match the recording,
because the words were typed into the page and the recording is data. The
result here was three hosts named across eight beats, two model names for the
same role, and a hardware roadmap on the closing screen of a project whose
header says it is not a product.

The structural fix is cheaper than a review: let the page read the host from
the run (`scan.completed` carries the hardware label on every job), the model
labels from the recording's engine block, and the counts from the same
projection every other page uses. Then a new recording cannot disagree with
the stage, because the stage has nothing of its own to say about hardware.

## When it applies

Any recorded or static demonstration, deck or page that will outlive the
machine it was first shown on: a demo-day stage, a conference recording, a
published static copy of a dashboard, a README with a screenshot. It applies
with more force when the project's claim is an approach rather than a product,
because every hardware name on a screen reads as a recommendation.

## How to apply it

1. Keep one provenance line per copy, filled from the data: the host the run's
   events name, the engines the recording names, the date it was made.
2. Strip hardware and brand names from every other screen; where a layer of
   the architecture is hardware, say what it must provide (a container
   runtime, images by digest, a local model behind one seam), not which box.
3. Draw the architecture from the run: the packs loaded, the rule's counts, the
   gap queue, the tiers and roles the config bound. A box with a fixed string
   in it is a box that will go stale.
4. Name a specific deployment only as one option, with its proof and its
   limits, in the notes it links to.
5. After each new recording, open the copy and read the screens that still
   carry typed words against the data beside them.

## Where the claim stops

One stage, rebuilt once. The architecture beat still carries typed words for
what each component does; only its counts and labels come from the run. A
typed sentence can still go stale, and lesson 72's rule, read the copy after
every recording, still applies.
