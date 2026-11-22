---
id: lesson-38-read-a-standards-status-before-citing-it
type: lesson
title: "Before citing or redrawing a standard, read its status on the publisher's page; cite the current revision by its own identifier"
date: 2026-10-21
audience: [architect, engineer, leader]
rung: all
tags: [policy, agility]
one_line: "A withdrawn publication keeps circulating — in search results, in summaries, in copies saved earlier — so the identifier in hand may not be the one in force; read the status, cite the superseding revision, and say whether the part relied on changed."
claims:
  - text: "NIST CSWP 39, Considerations for Achieving Crypto Agility (December 19, 2025), was withdrawn on 2026-06-29 and superseded in its entirety by CSWP 39-upd1; the update changes one paragraph of §2.3 and leaves Fig. 3, the crypto-agility strategic plan, unchanged."
    provenance: "read first-hand 2026-10-21: the withdrawal notice on the CSWP 39 PDF, and CSWP 39-upd1 (doi:10.6028/NIST.CSWP.39-upd1, PDF sha256 e6b147d2…), Appendix C and p. 22"
reuse: [runbook, whitepaper]
---

# Before citing or redrawing a standard, read its status on the publisher's page; cite the current revision by its own identifier

## The rule

Before a standard, guideline or white paper is cited, quoted or redrawn,
read its status where the publisher keeps it. If it has been withdrawn, cite
the publication that supersedes it, by that publication's own identifier, and
say whether the part relied on changed.

## Why

Publishers withdraw and supersede documents without removing the old copies.
The old PDF stays in search results, in secondary summaries and in files saved
before the change, and its title is often identical to the new one's. NIST
marks a withdrawn publication by prefixing a notice page and by giving the
replacement a suffix such as `-upd1` or `r1`. A citation of the old
identifier points the reader at a document the publisher no longer stands
behind, and for a federal reader that undoes the credibility the citation was
meant to give.

The change may be small. CSWP 39's update rewords one paragraph on the 2031
security-strength transition and leaves the rest, including Fig. 3, as it was.
Saying so is part of the citation: a reader who knows the update exists will
ask whether the figure moved.

## When it applies

Every citation of a standard, a mandate or a guidance document, and in
particular any figure or table redrawn from one, where a reader will compare
the drawing with the source. It applies equally to a document read weeks
earlier and saved: the status is a property of the day it is cited.

It does not replace reading the document. A status page says what is in
force, not what it says.

## How to apply it

- Open the document from the publisher (for NIST, the DOI or `csrc.nist.gov`)
  on the day it is cited; read the first page for a withdrawal notice.
- Cite the identifier in force, with its date and any update date, and the
  DOI.
- In `docs/SOURCES.md`, record the date read, the PDF's hash, the
  superseded identifier, and what the update changed in the part relied on.
