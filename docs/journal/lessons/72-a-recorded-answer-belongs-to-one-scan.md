---
id: lesson-72-a-recorded-answer-belongs-to-one-scan
type: lesson
title: "A recorded model answer belongs to the scan it was asked about; a build that shows a newer scan stops until the answers are recorded again"
date: 2026-11-09
audience: [engineer]
rung: all
tags: [verification, inference]
one_line: "A static copy has no model to call, so it shows what a model said once, recorded against one scan's record. When a newer scan becomes the one the copy shows, the recordings do not follow it, and the page publishes an empty answer unless the build refuses to run without them."
claims:
  - text: "The public copy built on 2026-11-09 showed a scan made that morning, for which no answer and no narration had been recorded; its Ask scene displayed 'no answer was recorded for this question' for every example, and the build, the leak check, the link check and the tests all passed."
    provenance: "measured 2026-11-09: the published stage, and the deployment's ask/ and demo/ folders holding files for the earlier scan only"
  - text: "With six answers and eight narration lines recorded for the new scan, the rebuilt copy's Ask scene shows the answer with 6 of 6 citations found on the ledger; the build now exits with the two commands to run when either recording is missing."
    provenance: "measured 2026-11-09 in headless Chromium against the private preview; tools/build_public.py at commit 93428c4"
reuse: [talk]
---

# A recorded model answer belongs to the scan it was asked about; a build that shows a newer scan stops until the answers are recorded again

## The rule

A **static copy** of a system is a set of files with no service behind them. It
cannot call a model, so anything a model says on it was said once, recorded,
and is shown from the recording. A recording is made against one scan's record
and cites that record's events, so it is stored under that scan's id and is
valid for no other. The build of the copy checks that the scan it is about to
show has its recordings and stops, naming the commands that make them, when it
does not. Publishing without them is a deliberate setting, never the default.

## Why

The step that makes a new scan the latest one and the step that records a
model's answers are separate, and only the first happens on its own. Nothing
fails when the second is skipped: every page builds, every link resolves, no
private name leaks, and the page that should show an answer shows a sentence
saying there is none. Checks that ask whether pages exist cannot see it; only
opening the scene and reading it does. The reader of the published copy is the
one who finds it.

## When it applies

Any published snapshot that carries generated content keyed to the data it was
generated from: recorded model answers, cached summaries, rendered charts,
thumbnails. Whenever the data's identity moves, what was generated for the old
identity is missing for the new one.

## How to apply it

1. Store each recording under the id of the record it cites.
2. In the build, compute the id the copy will show and require a recording for
   it; fail with the exact commands to run.
3. After a build, open the page that shows model output in a browser and read
   it. A count of pages is not a check of their content.
4. Run the recording where it can write. Here the app's container mounts the
   runs and the raw output only, so the recording is made into a scratch folder
   and copied to the deployment's state.

## Where the claim stops

One copy and two kinds of recording. The narration lines are a model's words
recorded once; their accuracy is not checked by a rule the way the answers'
citations are.
