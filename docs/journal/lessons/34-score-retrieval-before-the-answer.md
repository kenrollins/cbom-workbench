---
id: lesson-34-score-retrieval-before-the-answer
type: lesson
title: "Score the retrieval step on its own before scoring a model's answer over it"
date: 2026-10-20
audience: [engineer]
rung: all
tags: [inference, verification]
one_line: "When a model answers from retrieved passages, record what was retrieved with every answer and score whether the passage that settles the question was among it; a faithful model fails every item retrieval misses, and the failure is not the model's."
claims:
  - text: "A job asking a 31B model to explain each migration item's queue from the three nearest passages of a policy pack passed 3 of 14 items; the passage naming the item's queue was retrieved for 3 items, and the model passed all 9 calls on those 3 and cited only passages it was given on all 42."
    provenance: "measured 2026-10-20, explain run 01M5DG1NY5M7E165RF1TCYVSRN; Gemma 4 31B FP8 on four L4s, lab/embed for retrieval; the retrieval and the citations are on each event"
  - text: "On one item retrieval returned another queue's passage, and the model named that queue in all three calls: the job's three harmful answers."
    provenance: "the same run, the broker's key-establishment item"
reuse: [runbook, talk]
---

# Score the retrieval step on its own before scoring a model's answer over it

## The rule

When a model answers from passages a retriever chose, record the retrieved
passages, with their scores, on every answer, and score the retrieval
separately: for each item, was the passage that settles it among those
retrieved. Read the answer's score only alongside that one. Fix whichever step
failed, and measure the fix on items the first round did not see.

## Why

A model that cites only what it is given — the behaviour a design wants — can
answer no better than its retrieval. If the settling passage is missing, a
faithful model either refuses or settles on the nearest passage it has, and a
nearby passage can be a plausible wrong answer. Scored only on the final answer,
that looks like a weak model; a larger model would be bought to fix a ranking
problem. Here the item descriptions named algorithms, the pack's table rows
named algorithms, and the queue passages named dates and functions; retrieval
ranked the table rows first for 11 of 14 items, and the model, given no queue,
named none — or, once, the wrong one it was handed.

Recording the retrieval on the event costs a few integers and makes the
diagnosis a query over the ledger rather than a re-run.

## When it applies

Any retrieval-augmented model job with a checkable answer: an explanation
checked against a rule, a citation checked against a source, an answer
checked against a key. It applies most where the query and the settling
passage use different words for the same thing.

## How to apply it

1. On each answer, record the query and the retrieved passage ids with their
   scores (as integers if the record is hashed).
2. Score two numbers per round: retrieval recall of the settling passage, and
   answer accuracy where retrieval succeeded.
3. Change the retrieval — the query's wording, a filter by the item's
   function, a second index for the passages that settle — and measure it on a
   fresh set of items, against the same floor written before the first round.
