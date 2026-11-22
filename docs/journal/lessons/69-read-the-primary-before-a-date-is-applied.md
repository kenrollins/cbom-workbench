---
id: lesson-69-read-the-primary-before-a-date-is-applied
type: lesson
title: "A policy pack written from secondary summaries is marked unverified and applies no date; the primary is read, hashed and quote-checked before any of its dates or names counts"
date: 2026-11-09
audience: [architect, engineer]
rung: managed
tags: [policy, cbom, managed, cnsa]
one_line: "Summaries of a standard describe the version their authors read; the standard moves on. A pack built from them carries verified: false, sets no deadline and marks every status provisional until the primary document is read first-hand, its hash recorded and every quote in the pack checked against its text by the loader; the CNSA 2.0 pack's five-category timeline, taken from two summaries that agreed, was not in the FAQ's current version at all."
claims:
  - text: "Two secondary summaries of the NSA CNSA 2.0 FAQ, which agreed with each other, gave a per-category timeline (software and firmware signing exclusive by 2030; web browsers, servers and cloud services preferred by 2025 and exclusive by 2033; networking equipment by 2030; operating systems preferred by 2027 and exclusive by 2033; niche equipment preferred by 2030 and exclusive by 2033). The FAQ's Ver. 2.2 (October 2026) has no such table; its Timeframe section gives three dates for all national security systems: 2027-01-01 for new acquisitions, 2030-12-31 for phasing out what cannot support the suite, 2031-12-31 for the mandate."
    provenance: "cited: policy/packs/cnsa-2.0.yaml at commit 3aa22e8 (the summaries' table) against NSA, CNSA 2.0 and Quantum Computing FAQ, Ver. 2.2, Timeframe, read first-hand 2026-11-09, PDF sha256 bc430341…; policy/sources/cnsa-2.0-faq.txt"
  - text: "NSA's site refused the FAQ and the advisory to this project's harness on 2026-10-05, 2026-10-20 and 2026-11-07 (HTTP 403); the owner fetched both in a browser on 2026-11-09, and the loader checks the pack's thirteen quotes against the FAQ's text."
    provenance: "measured 2026-11-09: tests/test_managed.py, the quote check over policy/packs/cnsa-2.0.yaml"
reuse: [whitepaper, talk]
---

# A policy pack written from secondary summaries is marked unverified and applies no date; the primary is read, hashed and quote-checked before any of its dates or names counts

## The rule

A **policy pack** is a standard or memorandum as data: the dates it sets, the
algorithms it names and the systems it governs, each with the words it is
written in. A pack is written from the **primary document** only. Its source
block records the document's URL, version marking, the SHA-256 of the file
read and the date it was read, and the loader refuses the pack if any quote in
it is not found, in order, in the text extracted from that file. When the
primary cannot be obtained, the pack may still be written from secondary
sources so that the scope rule is real (which pack governs which system), but
it says `verified: false`, the assessor applies none of its dates as a
deadline, and every judgement it yields carries *provisional* into its basis
and onto the page. The flag is dropped only by rewriting the pack from the
primary, not by finding a third summary that agrees with the first two.

## Why

Secondary sources describe the version their authors read, and a standard that
is being transitioned to is revised. The CNSA 2.0 FAQ was published in
September 2022 as Ver. 1.0, revised in April 2024 (2.0), December 2024 (2.1)
and October 2026 (2.2). The two summaries this project's pack was first written
from agreed with each other on a five-category timeline with dates from 2025 to
2033, and were both right about the version they described. Ver. 2.2 does not
contain that table. It gives three dates for all of national security systems
and, in the same revision, states positions a summary from 2022 could not have
carried: that a hybrid is compliant only where NSA identified one (IKEv2, not
TLS), that SHA3-384 and SHA3-512 are allowed for a hardware's internal
integrity checks only, that HashML-DSA is not allowed and that no further NIST
standard is planned for the suite. A pack that had applied the summaries'
dates as deadlines would have planned migrations against a table that no
longer existed, with no event on the ledger to say where the dates came from.

Agreement between summaries is not verification. Two summaries that cite the
same version agree because they share a source, not because the source is
current.

<figure class="sketch" markdown>
![Two boxes. On the left, two secondary summaries: five equipment categories with dates from 2025 to 2033, the box struck through, marked verified: false and no deadline applied. On the right, the FAQ Ver. 2.2 of October 2026, read 2026-11-09: three dates, 2027-01-01 required in all new acquisitions, 2030-12-31 what cannot support CNSA 2.0 phased out, 2031-12-31 CNSA 2.0 algorithms mandated; one clock for all of national security systems, every quote checked by the loader.](../img/sketches/69-summaries-against-the-primary.svg)
<figcaption>The timeline two summaries gave, and the one the primary gives; the first was never applied because the pack said so.</figcaption>
</figure>

## When it applies

Whenever a tool encodes a standard, a memorandum, a vendor's deprecation
schedule or a certification list as data that will set a date or a verdict: a
compliance rule, a migration queue, a compatibility tag. It applies with more
force when the primary is hard to obtain, because that is when a summary is
most tempting; a site that refuses an automated client will usually serve a
person with a browser, and the person's download, hashed, is the record.

## How to apply it

1. Write the pack from the primary. Extract its text (`pdftotext -layout`),
   keep the text beside the pack, record the file's SHA-256, its version
   marking and the date read, and quote the passage behind every date and
   every name.
2. Make the loader refuse a quote that is not in the text. A pack that cannot
   quote its source is not a pack.
3. If the primary is refused, write the pack anyway for the scope rule, mark it
   `verified: false`, apply no date from it, and carry *provisional* into every
   judgement it produces, visibly. Record each refusal with its date.
4. When the primary arrives, rewrite the pack from it rather than patching the
   summaries' version, and write down what changed between the two: that
   difference is the measure of what the summaries would have cost.
5. Never rewrite the ledger's earlier judgements. The next assessment of the
   same evidence gives the final statuses; the provisional ones stay on the
   record with their flag.

## Where the claim stops

Checked on one pack and one standard. The FAQ's own version history is read
from its page footers and its revision notes, not from NSA's site index, which
the harness could not reach. The advisory that announced the suite (September
2022, Ver. 1.0) is kept beside the FAQ as a second source; the FAQ is the later
text and governs where they differ.
