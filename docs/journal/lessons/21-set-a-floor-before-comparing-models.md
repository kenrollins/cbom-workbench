---
id: lesson-21-set-a-floor-before-comparing-models
type: lesson
title: "Set a floor per role before comparing two models, and repeat every call before believing it"
date: 2026-10-08
audience: [architect, engineer]
tags: [inference, verification]
rung: all
one_line: "A model that beats the smaller one is not thereby good enough: each role needs an absolute bar set by what depends on its output, and a reply at temperature 0 is one draw, not an answer."
claims:
  - text: "The larger model beat the smaller one on every one of six roles by a one-sided sign test, and on two of them it still did not reach the floor the role needs; the outcome there is 'neither', not 'use the larger model'."
    provenance: "measured 2026-10-08, spike S3, 216 items, spikes/s3/results/scored/report.json"
  - text: "At temperature 0 the larger model returned different replies to the same prompt on 57 of 178 items and the thinking engine on 50; three calls with a majority made the per-role counts stable."
    provenance: "measured 2026-10-08, same run"
reuse: [whitepaper, talk]
---

# Set a floor per role before comparing two models, and repeat every call before believing it

## The rule

Before running a model bake-off, write down for each role the accuracy below
which its output cannot be used as designed, and how many harmful errors it
may make. Decide "use model B" only when A misses the floor, B clears it, and
B is better on the same items by a stated margin. And score an item by the
majority of several calls, because one call is one draw.

## Why

A comparison answers "which is better". The question a build needs answered
is "is this good enough to act on", and the two come apart in both
directions. A role whose output goes straight into an inventory — a name, a
classification — has to be nearly always right, because nothing downstream
catches a wrong entry; the larger model's 27 of 30 on normalization beat the
smaller model's 23 and still fails that role. A role whose output is
rehearsed and verified before anything depends on it can tolerate more,
because the rehearsal is the check; 24 of 30 change plans verified on the
wire is enough when every plan is rehearsed first.

Without a floor the bake-off always says "use the bigger one", and on a
machine where the bigger one costs a swap and a queue, that answer is
expensive and sometimes wrong. With a floor, the outcome set gains the two
that matter: "neither — redesign the role" and "the small one with reasoning
on is enough".

The repeat is for a different failure. A temperature of 0 is read as
determinism, and it is not: serving engines batch, kernels reorder, and the
same prompt comes back different. On single calls a role's score moves by
several items from one run to the next; on majority-of-three it does not. A
pipeline that acts on one reply without a verifier is acting on noise some of
the time.

## When it applies

Choosing a model per task in any pipeline where tasks differ in what checks
them: inventory fields, classifications, plans, explanations. It applies with
most force on a single machine where the larger model cannot stay resident.
The floors are set by the pipeline, not by the models: a role with a verifier
behind it gets a lower floor than one without.

## How to apply it

1. For each role, write the floor and the harmful-error allowance from what
   consumes the output, and commit them before any model runs.
2. Score a reply against a label or a verifier, never against a model's
   reading of it.
3. Call each item three times; count it correct on a majority; report the
   items whose calls disagreed as a number of its own.
4. Decide per role from the floors first and the pairwise comparison second;
   name the outcome from a closed list that includes "neither".
5. Treat a role that lands "neither" as a design question — a rule, a table,
   a person — not as a reason to try a third model.
