---
id: lesson-39-a-diagrams-labels-are-claims
type: lesson
title: "Every label in a diagram of what a system does is a claim; fill it from the record and check each against the record before it is shown"
date: 2026-10-21
audience: [architect, engineer]
rung: all
tags: [cbom, agility, verification]
one_line: "A box that says 'signed', 'by rule' or 'reached' reads as fact, and a framework's boxes invite filling them with what the system ought to do; compute each label from the ledger where it can be computed, and check the rest line by line against the ledger before the page is published."
claims:
reuse: [runbook, talk]
---

# Every label in a diagram of what a system does is a claim; fill it from the record and check each against the record before it is shown

## The rule

Treat every label in an architecture or capability diagram as a factual
claim. Compute it from the record where it can be computed; where it is
prose, check it line by line against the record before the page is shown,
and mark what is partial or absent as such.

## Why

A diagram reads as a statement of fact, and its words are short enough that
nobody stops to ask for the evidence. A framework's diagram adds a pull of its
own: its boxes name what a complete system has — libraries, enforcement,
vulnerability management — and a box left empty looks like a failure, so it
gets filled with what the system ought to do or nearly does. The result is
the brochure the project exists to avoid.

Prose labels drift in a second way. The author knows what the system does on
the estate it was built on and writes that, and a second estate on the same
page — the lab, where the system observes and changes nothing — inherits words
that are true only of the first.

## When it applies

Any page or slide that says what a system does, part by part, and in
particular one laid over a published framework, where the framework's own
labels set the expectation. It applies to the selection of an example too:
"the last change that landed" was, on the record, a review's deliberate
rollback; the example must be filtered for the kind it is meant to show.

## How to apply it

- Compute counts and states from the ledger at render time; never type a
  number into a label.
- For every prose label, name the event, rule or file that makes it true. If
  none can be named, the label is partial or off, and the page says so: the
  overview dims a framework label an estate does not reach and says why on
  hover.
- Select examples by the property they illustrate (here: a landed change
  toward post-quantum, every verdict re-deriving from its raw output), not by
  recency.
- Render the page for each estate it covers and read every box against that
  estate's record.
