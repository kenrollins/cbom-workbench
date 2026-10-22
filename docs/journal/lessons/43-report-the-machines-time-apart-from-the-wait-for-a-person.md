---
id: lesson-43-report-the-machines-time-apart-from-the-wait-for-a-person
type: lesson
title: "Report a change's time from approval to proof beside its time from policy to proof; the gap is the wait for a person, not the system"
date: 2026-10-22
audience: [engineer, leader]
rung: agile
tags: [agility, verification]
one_line: "Time from the policy decision to the last verdict includes however long the change waited for an approver; shown alone it reads as the system's speed, so headline the approval-to-proof time and give the other as what it is."
claims:
  - text: "The records database's require change took 67.9 s from approval to the last verdict and 7.4 h from the policy event, almost all of it the proposal waiting for the owner's approval."
    provenance: "measured 2026-10-21, change run 01M5FHSAWHMY78JV1EJX1YQA87 on the lab deployment, ledger timestamps"
reuse: [runbook, talk]
---

# Report a change's time from approval to proof beside its time from policy to proof; the gap is the wait for a person, not the system

## The rule

Headline a change's time from approval to its last verdict; give the time from
the policy decision beside it, labelled as including the wait for a person.

## Why

Time-to-change is measured from ledger timestamps: the policy event, the
approval, the verdicts. The span from policy to proof is the honest end-to-end
number, but most of it can be a proposal sitting in a queue — overnight, over a
weekend. Shown alone it reads as the speed of the machinery and buries the
measurement that says how fast an approved change is carried out and proved.
Shown alone, the other hides how long decisions take. Both are true; each
answers a different question.

## When it applies

Any page, report or talk that quotes how long a change took, whenever a person
is in the loop.

## How to apply it

- From `intervals()`: `approval_to_verdict_ms` is the headline;
  `policy_to_verdict_ms` follows, labelled.
- Use units a reader can take in: seconds for the machinery, minutes or hours
  for the wait.
