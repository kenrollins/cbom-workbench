---
id: lesson-63-a-static-copy-of-a-model-page-shows-a-recorded-call-and-checks-it-again
type: lesson
title: "A static copy of a page whose answer comes from a model shows a call made once and labelled, offers only the questions recorded, and runs the rule's check again where it is built"
date: 2026-11-05
audience: [engineer, architect]
rung: structured
tags: [inference, verification]
one_line: "A published, static copy of the workbench has no model to call; its Ask the CBOM page shows the example questions answered once by a real call, labelled with the model, the hardware and the date, and recomputes every citation's verdict against the ledger it is published with, so the verdict a reader sees is never a stored one."
claims:
  - text: "The six example questions on the Ask the CBOM page, recorded against the mini-agency scan the public demo shows, were answered by Nemotron 3.5 Super VL 120B-A12B NVFP4 at medium-effort thinking through the lab gateway in 37 to 91 s a call; every reply finished on its own and every citation passed the rule."
    provenance: "measured 2026-11-05, pqch ask record on run 01M5JFEP7D145D2T38TW0S6631, lab profile ask-cbom bound to the deliberate tier (lab GB10, vLLM 0.32)"
  - text: "On the same run, the twelve-question evaluation set with three repeats per question: Super VL named the expected phrase on 12 of 12 and passed every citation on 12 of 12 (floors 10 and 12), median 55 s a call; Gemma 4 31B with thinking off reached 2 and 3, with 26 of 36 calls cut short of valid JSON at the 1,200-token cap the page sets for a non-thinking call. Retrieval was 10 of 12 for both, under its floor of 11."
    provenance: "measured 2026-11-05, eval/ask/score.py; eval/ask/results/2026-11-05-lab-gateway-supervl-thinking.json and 2026-11-05-lab-gateway-gemma31b-thinking-off.json"
  - text: "The demo stage's eight beats on the public copy: the plan's eight rows narrated once by Gemma 4 31B FP8 with thinking off through the lab gateway, 1.0 to 1.8 s a line; every CBOM entry the stage shows (418 KB of CycloneDX) carried in the page; the hardware named from the scan's own ledger (xr7620, x86_64, on 25 of 25 scan jobs), not from the GB10 the stage was built for."
    provenance: "measured 2026-11-05, pqch demo record on run 01M5JFEP7D145D2T38TW0S6631; pqch.ui.demo.ledger_hardware"
reuse: [runbook, talk]
---

# A static copy of a model page shows a recorded call and checks it again

![Three boxes. The running workbench takes a question, retrieves, calls the model and checks each citation by rule; the record command answers the six examples once, 37 to 91 s each, and keeps the answers beside the run. The recording holds the reply as returned, with the model, the hardware, the date and the tokens. The static page has no model and a disabled question box, says the answer was recorded on 2026-11-05, and runs the rule again at build against the published ledger; a stored verdict is never shown.](../img/sketches/63-a-static-copy-shows-a-recorded-call.svg)

## The rule

When a page whose answer comes from a model is published as a static copy, show answers recorded
from a real call, labelled as recorded with the model, the hardware and the date. Offer only the
questions that were recorded. Store the model's reply, never the verdict on it, and run the check
again where the copy is built.

## Why

A static site cannot call a model, so there are three honest options. A page can go dark, which is
what a link rewritten to "in the live workbench only" amounts to. A page can be removed, which hides
the feature. Or a page can show a real call and say exactly what it is. A recording is evidence of
what one engine said once. Dressed as a live answer, it would claim a capability the copy does not
have.

The check is a different kind of thing. In Ask the CBOM, a rule decides whether each cited ledger event
exists and was among the passages the model was shown (CBOM: the cryptography bill of materials, the
estate's inventory of algorithms, keys, certificates and protocols). The rule is code. It costs nothing
to run again, and it reads the ledger the copy actually publishes. A stored "passes" would still read
"passes" if the published ledger were later trimmed or rebuilt. A recomputed one shows "fails"
instead. So the reply is stored and the verdict is computed where the reader reads it.

The hardware is the same kind of claim. A page that says "on this box" is true where it is served
live. In a copy it must name the hardware the runs themselves recorded, read from their ledger, and
say that the architecture drawn is the design rather than the machine that produced these numbers.

## When it applies

Any page that shows a model's output beside a rule's check of it, published where the model cannot
be reached: a static demonstration site, an offline handout, a screenshot set for a talk. It does not
apply to the running workbench, where every question is a live call. It does not make a recorded
answer a measurement. The role's binding still comes from the evaluation set with its floors and
repeats, and the recording is one call per question.

## How to apply it

Record against the scan run the copy will publish, on the profile whose binding was measured:

```sh
# the deployment's runs, the lab's profile; the key from the app container's environment
PQCH_VAR=/path/to/var PQCH_INFERENCE_CONFIG=/path/to/inference.yaml \
  uv run python -m pqch.cli ask record            # writes var/ask/<run>.json
```

The public build (`tools/build_public.py`) copies the recording for each run it publishes and renders
the Ask page and one page per recorded question in snapshot mode. There the route reads the recording,
calls no model, and passes the stored reply through `pqch.ask.check` against the run's ledger. A run
with no recording gets a page that says so, and a question that was not recorded is answered with
"only the example questions are answered in this copy". Record again whenever the published scan run
changes. A recording is keyed to its run and is ignored for any other.

The demo stage follows the same rule. `pqch demo record` narrates each row of the scan's plan once
through the call the live stage makes and keeps the lines in `var/demo/<run>.json`. In the public build
the stage inlines its whole document: the test agency only, never a server read whole; every CBOM
entry the entry panel shows; the recorded narration; and the Ask beat pointed at the recorded answer
pages. The scan replays from its ledger, the change from the latest change run in which a change landed (a run left
waiting for an approval has nothing to prove), the buttons that would start a scan or
approve a change say they need the running workbench, and the hardware is the label the scan jobs
wrote on the ledger.
