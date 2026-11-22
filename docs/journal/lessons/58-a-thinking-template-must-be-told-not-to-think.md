---
id: lesson-58-a-thinking-template-must-be-told-not-to-think
type: lesson
title: "A model whose chat template thinks by default must be told not to on every plain call, and its reply's shape belongs in the prompt and a validator, not in the engine's grammar"
date: 2026-11-05
audience: [engineer, architect]
rung: all
tags: [inference]
one_line: "Nemotron's chat template reasons unless the request turns it off, so a short plain call spends its whole budget thinking and returns nothing; turn thinking off in the tier's request block, and with thinking off describe the JSON shape in the prompt and validate it, because the engine's structured-output grammar can run a call to its cap."
claims:
  - text: "With the chat template's default, five calls of a one-sentence question at a 120-token cap all returned an empty reply with finish_reason 'length' after 0.9 to 1.1 s; with chat_template_kwargs enable_thinking false, five of five answered in 46 to 78 tokens and 0.6 to 1.1 s."
    provenance: "measured 2026-11-05 on a Dell Pro Max GB10 (aarch64), vLLM 0.27.1 ws/vllm-upstream, Nemotron 3.5 Lightning 30B-A3B NVFP4 + DSpark; spikes/s3/results/2026-11-05-promax-thinking-default-and-grammar.json"
  - text: "With thinking off and a JSON-schema response format at a 400-token cap, four of five calls finished in 64 to 98 tokens and one ran to the cap; with thinking on and the same schema at 4,000 tokens, four of five finished in 567 to 768 tokens and one ran to the cap after 27 s."
    provenance: "the same run"
  - text: "Validated in the seam with the shape in the prompt and one retry, the ask-cbom role with thinking off passed every citation on 12 of 12 evaluation items, three repeats each, at a median of 2.8 s."
    provenance: "measured 2026-11-05, eval/ask/results/2026-11-05-promax-lightning-vllm-thinking-off-v2.json"
reuse: [runbook, whitepaper]
---

# A model whose chat template thinks by default must be told not to on every plain call

## The rule

When an engine serves a model whose chat template reasons by default, as Nemotron 3 and 3.5 do, put
`chat_template_kwargs: {enable_thinking: false}` in the request block of every tier meant to answer
plainly, and let a role that should reason turn it back on. With thinking off, do not rely on the
engine's structured-output grammar. Write the reply's JSON shape into the prompt, parse and validate
the reply in the inference seam (the one module every model call goes through), and retry once.

## Why

A reasoning template writes its thinking first, inside the same token budget as the answer (lesson
55). A plain call sized for a one-line answer therefore ends during the thinking: the content is
empty and the finish reason is `length`, every time. Measured on Nemotron 3.5 Lightning under vLLM
0.27.1, five of five 120-token calls came back empty. The same calls with thinking off answered in
46 to 78 tokens in about a second. On a stage, an empty narration looks like a broken demo, not a
budget problem.

Structured output constrains each token to a grammar. With thinking off on that engine, the grammar
let one call in five run on to its cap without closing the object. The same happened once in five
with thinking on, at 4,000 tokens and 27 s. A prompt that shows the shape, plus a validator and one
retry, gives the same guarantee to the caller. A failure costs one more short call, not a stalled
one: with that arrangement the ask-cbom role passed every citation check on 12 of 12 items at a
median of 2.8 s.

## When it applies

Any model whose template thinks unless told otherwise, on any OpenAI-compatible engine that passes
`chat_template_kwargs` through (vLLM, SGLang, a NIM built on either). It does not apply to a model
without a reasoning template, or to an engine that keeps the thinking outside the completion's
budget. Whether a grammar stalls depends on the engine and its version, so measure it on each new
engine before relying on it.

## How to apply it

In the tier map, the request block rides on every plain call to that tier
(`kit/inference.promax.yaml`):

```yaml
tiers:
  fast:
    request: {chat_template_kwargs: {enable_thinking: false}}
    structured: false          # the shape goes in the prompt; the seam validates, one retry
    reasoning:
      request: {chat_template_kwargs: {enable_thinking: true}}
      structured: true
```

To check an engine, send five plain calls at a small cap and five with the schema, then count the
`length` finishes: `spikes/s3/results/2026-11-05-promax-thinking-default-and-grammar.json` records
the four arms.
