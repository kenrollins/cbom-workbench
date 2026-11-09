---
id: lesson-70-a-number-shown-on-two-pages-comes-from-one-projection
type: lesson
title: "A number shown on two pages is computed in one place; a page that counts a rule's events and a page that counts the document's entries will disagree"
date: 2026-11-09
audience: [architect, engineer]
rung: structured
tags: [cbom, verification]
one_line: "A rule judges each observation and the document folds several observations onto one entry, so a count of the rule's events and a count of the document's entries are two different numbers under one label; every page that shows the figure reads it from the same projection, and a test holds the two readers equal."
claims:
  - text: "On the mini-agency's scan of 2026-11-09 the compatibility rule made 227 judgements, 189 of them not compatible, and the CBOM those events project has 221 judged entries, 183 not compatible: six judgements fold onto entries another finding already made. The plan page showed 189 and the CBOM page 183 under the same words."
    provenance: "measured 2026-11-09 on the lab's x86_64 server, run 01M6Z41DJB5911EF1Y65K2FBTY: assessment.made events with rule compatibility/entry/1 against the pqch:compatibility property of workbench.cdx.json"
  - text: "The plan's header now reads the count from the CBOM the same events project, and a test asserts that the plan's four counts equal the CBOM page's on the four-service slice."
    provenance: "cited: src/pqch/planning.py `_compatibility_counts`, tests/test_managed.py, commit a6ecc09"
reuse: [whitepaper, talk]
---

# A number shown on two pages is computed in one place; a page that counts a rule's events and a page that counts the document's entries will disagree

## The rule

Every figure a reader sees under one label is computed by one function over one
projection. Where the record holds both the judgements a rule made and the
document those judgements are written into, the figure is counted from the
document, because the document is what the reader holds, and the second page
calls the first page's function instead of counting again. A test asserts the
two readers give the same numbers.

## Why

A **projection** is a document rebuilt from the record: here the cryptography
bill of materials (CBOM), an inventory of every cryptographic asset, rebuilt
from the ledger of findings. A rule that judges compatibility runs once per
observation. The projection then folds observations onto entries: a certificate
seen on the wire and the same certificate found in a file are one entry, and an
imported claim with no key identity joins the one entry it describes. So the
rule's event count is the number of things observed, and the document's count
is the number of things that exist. Both are true. Under the label "not
compatible" on two pages they are a discrepancy, and a reader who finds 189 on
one page and 183 on another has no reason to trust either.

The defect is invisible to tests that check each page alone. Each page was
right about what it counted. It was found by reading a number off a screenshot
of one page while writing it down from a note built on the other.

<figure class="sketch" markdown>
![On the left, 227 judgements made by the rule, one per observation, 189 of them not compatible. An arrow labelled fold: same asset, one entry. On the right, 221 entries in the document, 183 not compatible. Below: the plan page read the left, the CBOM page read the right; both now read the right.](../img/sketches/70-judgements-fold-onto-entries.svg)
<figcaption>Six judgements fold onto entries that already exist; the figure a reader is shown is the document's.</figcaption>
</figure>

## When it applies

Wherever a system keeps an event log and a document derived from it, and shows
counts from either: findings and assets, alerts and incidents, test results and
requirements, log lines and sessions. It applies with most force after a
deduplication or merge step is added, because that is the moment the two counts
part and nothing fails.

## How to apply it

1. Name the unit a figure counts in the function that computes it: entries, not
   judgements; assets, not findings.
2. Give each figure one function, and have every page, export and command call
   it. A second page never re-derives the count from the events.
3. Write a test that holds the readers equal on recorded data, and one that
   states the inequality that is expected (judgements are at least as many as
   entries), so the difference is documented and not rediscovered.
4. When a written number is checked against a page, check it against every page
   that shows that label.

## Where the claim stops

One figure on two pages of one system. The same event-against-entry difference
may sit behind other counts the pages show; only the compatibility counts were
compared.
