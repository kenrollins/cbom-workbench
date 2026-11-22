---
id: lesson-12-check-evidence-against-the-question
type: lesson
title: "Check cited evidence against the question it was meant to answer, then derive the conclusion again"
date: 2026-10-05
audience: [architect, engineer]
tags: [verification, agility]
rung: agile
one_line: "That a cited test really ran proves nothing unless it is the test the claim calls for, run after the change, against the thing changed — and the conclusion follows from its raw output."
claims:
  - text: "A verdict of enforced, on a listener that still accepted X25519 and P-256, passed a check that compared each cited probe's hash, times and container with the prober's own log: its negative probe was a genuine job that offered only X448, where the check named thirteen classical groups."
    provenance: "measured 2026-10-05, M0 slice portal, change run 01M46Q2NRZZ08XXARFVECAMRRK, xr7620 (x86_64); M0B review F-55"
  - text: "A verdict whose three probes were copied from a run of the previous day, against another container, passed the same check."
    provenance: "measured 2026-10-05, same run"
  - text: "With the cited job compared to the job the check prescribes, to the time and container of the apply, and with the status recomputed from raw output, both were refused and an honest verdict in the same run passed."
    provenance: "measured 2026-10-05, change run 01M46RA4MF5Q0A9HYVZZY6BKTS"
reuse: [whitepaper, talk, customer-question]
---

# Check cited evidence against the question it was meant to answer, then derive the conclusion again

## The rule

When a conclusion cites evidence held by an independent party, check four
things, not one: that the evidence exists as cited; that it is the evidence
the question calls for; that it was taken after the event it speaks to, from
the thing that event changed; and that the conclusion follows from the raw
material when it is read again.

## Why

A common design for a trustworthy result has one component run the tests and
keep its own log, and another write the conclusion and cite the tests by id.
The reader looks each id up in the log and compares what the conclusion says
about it — output hash, start and end time, target — with what the log says.

That comparison proves the cited tests ran. It does not prove they were the
right tests. Whoever writes the conclusion can usually also ask for tests,
and can ask for one that is bound to come out the way they want. A listener
that accepts two classical key-exchange groups will still refuse a third it
was never configured with; a probe offering only that third group is a real
job, in the log, fresh, against the right container, with a truthful
"refused". Cited as the negative probe of a check that should have offered
every classical group, it supports a verdict that is false.

The same comparison passes evidence lifted from another occasion, if the
conclusion copies the old test's details faithfully: the log does hold that
test, with exactly that hash and those times.

And it leaves the reading of the evidence to the writer. A log that confirms
a scan ran says nothing about whether the scan's output lists two more groups
than the conclusion admits.

## When it applies

Wherever one party attests and another summarizes: test reports that cite CI
jobs, compliance findings that cite scans, change records that cite
verification runs, an agent's report that cites tool calls. It applies with
most force when the summarizer can also start the tests.

It does not replace separating the two parties. If the summarizer can write
the log, none of these checks means anything.

## How to apply it

Have the party that runs tests log, for each one, what it was asked — the
profile and every parameter — as well as what happened. Then, when reading a
conclusion:

| Check | Catches |
|---|---|
| The test is in the log with the same output hash, times and target | Invented or altered evidence |
| No other conclusion cites it | One test used twice |
| Its profile and parameters are exactly what the pre-stated check prescribes | A genuine test of an easier question |
| It started after the logged end of the change it verifies, against what that change produced | Evidence from another occasion |
| The raw output, parsed again by the reader, gives the recorded result, and the results give the conclusion | A misreading, honest or not |

Fix the check before the change, so "what the question calls for" is a matter
of record. Make the decision from parsed results a pure function, so the
reader can call the same code the verifier did. Show nothing as verified when
any row fails, and say "unchecked" for a conclusion that cites nothing.
