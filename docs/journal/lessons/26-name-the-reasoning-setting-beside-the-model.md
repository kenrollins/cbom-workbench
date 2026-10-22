---
id: lesson-26-name-the-reasoning-setting-beside-the-model
type: lesson
title: "Name the reasoning setting beside the model in every measurement and binding"
date: 2026-10-19
audience: [engineer, architect]
rung: all
tags: [inference, measurement, provenance]
one_line: "A hybrid-reasoning model's result depends on its reasoning switch and effort level as much as on its weights, so a measurement, a table row or a tier binding that names the model without its reasoning setting is incomplete, and a gateway lane that pins the setting is part of the model's name."
claims:
  - text: "The same Nemotron 3.5 Super VL 120B-A12B weights traced a wire finding to its configuration line on 9 of 30 items with thinking off, 26 at medium effort and 21 with full thinking, and resolved 9 and 23 of 29 conflicts between layers with thinking off and at medium effort."
    provenance: "measured 2026-10-16, spike S3 roles R5 and R4, lab GB10 at a 0.62 memory share, three calls per item, majority of three; spikes/s3/results/scored/bake-nemotron-supervl-*/"
  - text: "Between the two 120B models at the same setting the difference on the same role was two items (28 against 26); between one model's settings it was seventeen (9 against 26)."
    provenance: "computed from the same run and the incumbent's arm, spikes/s3/results/scored/bake-nemotron-120b/"
  - text: "Median completion tokens per call on the conflict-resolution role were 21 with thinking off, 904 at medium effort and 3,695 with full thinking, where 12 of 29 calls reached the 900 s timeout."
    provenance: "measured 2026-10-16, same run, role R4"
reuse: [runbook, whitepaper, talk]
---

# Name the reasoning setting beside the model in every measurement and binding

## The rule

Wherever a model is named — a benchmark row, a tier binding in the
inference seam, a gateway lane, a journal claim — name its reasoning
setting with it: thinking on or off, and the effort level if the model has
one. Two numbers for the same model at different settings are numbers for
two different engines. A gateway lane that pins the setting is part of the
model's name, and a change to the lane's default is a rebinding that calls
for a new measurement.

## Why

A hybrid-reasoning model emits a deliberation before its answer, and a flag
in its chat template turns that deliberation on, off or down to a budget. The
flag changes how many tokens the model writes by two orders of magnitude and
changes its accuracy on any task that needs more than one step. In this
project, the same 120B-A12B weights on the same machine at the same memory
share traced a wire finding to its configuration line on 9 of 30 items with
thinking off, 26 at medium effort and 21 with full thinking, where a quarter
of the calls ran past a 900 s timeout. On conflict resolution the spread was
9 to 23 of 29. The gap between two different 120B models at one setting was
two items; the gap between one model's settings was seventeen. The
completion lengths tell the same story: a median of 21 tokens off, 904 at
medium, 3,695 on full.

The setting is also where the gateway can change the engine without
changing its name. A lane that pins thinking off for one caller's benefit
serves every caller on that lane; a default moved from full to medium effort
changes the result of every role bound to the tier. A row that says "the
120B" has not said which of three engines it measured.

## When it applies

Any model with a reasoning switch or an effort level: the Nemotron 3 and
3.5 families, Gemma 4 with thinking, GPT-OSS and its effort levels, Qwen3,
and the hosted models that expose a thinking budget. Through a gateway it
applies twice, because the lane's configuration may pin or override the
setting the caller asked for.

It does not apply to a model with no such switch, but the record still says
so: "reasoning: none" is a setting.

## How to apply it

- The inference seam's tier definition carries a `reasoning` block (on or
  off, and the effort or budget) and a role is bound to a tier with that
  block, never to a model name alone; the frozen `pqch.inference/1` does
  this and every actor on the ledger records the reasoning setting beside
  the model id and the engine.
- A bake-off arm is named for its setting (`-think`, `-nothink`, `-medium`)
  and the setting is in the arm's configuration file, so a result file is
  self-describing.
- A table row that compares models states the setting in the same cell as
  the model, and a successor model is compared with the incumbent at the
  same setting before it is compared at its own default.
- When the gateway's lane changes its default reasoning setting, the roles
  bound to that lane are re-measured against their floors before the change
  is relied on ([lesson 21](21-set-a-floor-before-comparing-models.md)),
  and the measurement records what served the call
  ([lesson 24](24-a-hardware-label-is-a-claim.md)).
