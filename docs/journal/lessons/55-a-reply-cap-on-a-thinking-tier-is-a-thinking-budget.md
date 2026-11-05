---
id: lesson-55-a-reply-cap-on-a-thinking-tier-is-a-thinking-budget
type: lesson
title: "A reply cap on a thinking tier is a thinking budget: set it from the measured tokens of the role's hardest items, and record a cut-off as an empty reply"
date: 2026-11-04
audience: [engineer, architect]
rung: all
tags: [inference, verification]
one_line: "When a role is bound to an engine with reasoning on, the reasoning counts against the reply's token cap; a cap sized for the answer alone returns nothing on the items that need the most thought, and the only safe reading of a cut-off is a wrong reply."
claims:
  - text: "On Nemotron 3.5 Lightning 30B-A3B NVFP4 under vLLM with thinking on, the six S3 roles' completion tokens (thinking plus reply) over the development set, three repeats each, were: call-site read p50 3,323 and p90 6,846; normalization 1,057 and 1,935; classification 2,053 and 4,136 (max 4,179); conflict resolution 11,600 and 16,000 with two of 18 calls cut off at the 16,000 cap; trace-to-cause 2,254 and 12,270; change plan 7,777 and 19,352 with one of 18 cut off at 20,000."
    provenance: "measured 2026-11-04 on a Dell Pro Max GB10 (aarch64), vLLM 0.27.1 with DSpark speculation, spike S3 arm promax-lightning-thinking, spikes/s3/results/dev; a cut-off counted at its cap"
  - text: "All three cut-offs returned an empty body with finish_reason 'length' after 126, 131 and 163 s; the harness's conflict-resolution and classification roles were capped at 4,000 tokens, below the measured p50 of the first and the p90 of the second."
    provenance: "the same run; src/pqch/assessor/explain.py and wiring.py before commit of 2026-11-04"
reuse: [runbook, whitepaper]
---

# A reply cap on a thinking tier is a thinking budget: set it from the measured tokens of the role's hardest items, and record a cut-off as an empty reply

## The rule

When a role is bound to a tier whose engine reasons before it answers, the reply's `max_tokens` is the
budget for the thinking and the answer together. Set it from the measured token use of that role's
hardest items on that engine, at or above the largest value seen, and never from the length of the
answer alone. A reply that stops at the cap is an empty reply: record it with its finish reason, score
it as wrong, and never retry it silently or raise the cap for one call.

## Why

An OpenAI-style completion has one token cap. With a reasoning parser on, the engine writes its
thinking into the same budget before it writes the typed answer, and the parser only separates the two
afterwards. When the budget runs out during the thinking there is no answer at all: the body is empty
and the finish reason says `length`. The thinking is longest on exactly the items that matter, the
ambiguous conflict or the plan with a constraint, so a cap that fits the median item fails the hard
ones. Measured on one engine: conflict resolution thinks for a median of 11,600 tokens and one call in nine
runs past 16,000, so a 4,000-token cap sized for the answer returns nothing on every item; classification's 90th percentile sits at
4,136, just over the same cap, so one call in ten would vanish. A cut-off is a wrong reply, not a
missing one: the rule that the model only interprets still stands, the rule's own answer is shown, and
the empty reply is on the record with its cause.

The budget is for the role's worst call, not its typical one, because the same input does not think
the same length twice: one Ask the CBOM question on the same engine used 2,790 completion tokens on
one run and ran past 16,000 on another, with the same passages shown.

## When it applies

Every role bound with `reasoning: true` in the tier map, on any engine that thinks inside the
completion (vLLM's reasoning parsers, a NIM's reasoning mode). It does not apply to a tier with
thinking off, where the cap bounds the answer alone, nor to a gateway lane that holds the thinking
outside the completion's budget.

## How to apply it

Each role's call site sets `max_tokens` with the measurement beside it. Spike S3's development set
gives the distribution per role and engine, a cut-off counted at its cap:

```sh
for r in r1 r2 r3 r4 r5 r6; do f=spikes/s3/results/dev/<arm>/$r.jsonl; cap=16000; [ $r = r6 ] && cap=20000
  jq -s --argjson cap $cap 'map(if .finish_reason=="length" then $cap else (.usage.completion_tokens // 0) end)
     | sort | {n: length, p50: .[length/2|floor], p90: .[(length*0.9)|floor], max: .[-1]}' -c $f; done
```

The harness's caps are 16,000 for call-site read, classification, conflict resolution, trace-to-cause
and Ask the CBOM, and 20,000 for change plans, the spike's own envelope. A role whose p90 approaches its
cap on a new engine is re-measured before it is bound there; the cap moves only with a row in the
BRIEF's table.
