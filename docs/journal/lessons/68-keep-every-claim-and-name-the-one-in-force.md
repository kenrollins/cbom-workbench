---
id: lesson-68-keep-every-claim-and-name-the-one-in-force
type: lesson
title: "When two sources describe one asset, keep every claim, put one in force by the grade of its evidence, and show the rest as dissent; never fold two values into a list"
date: 2026-11-09
audience: [architect, engineer]
rung: structured
tags: [cbom, evidence, agility]
one_line: "An inventory built from several tools gets two values for one field sooner or later; folding them into a list of both changes the field's type and tells the reader nothing, and taking the first silently loses the other. Keep each as a claim with its grade (watched on the wire, read from a host, parsed from a file, reported in a document), project the best-graded one, write the disagreement beside it, and let only a person's recorded resolution override the rule."
claims:
  - text: "Before this rule the normalizer turned two differing scalar values for one parameter into a sorted list of both strings, so a key size could be an integer in one entry and a list in the next; the projection kept the first finding per fingerprint and dropped the rest."
    provenance: "src/pqch/scout/normalize.py `_merge` and src/pqch/cbom/__init__.py's fold at the commit before 2026-11-09 (d417ad6)"
  - text: "On the four-service slice, a second tool's CBOM of the same listeners with two groups misspelled and one certificate's expiry stale folds onto the scan's entries with no duplicate, the stale date is one dissent entry with both values and their grades, and the combined document scores exactly as the scan alone."
    provenance: "measured 2026-11-09, tests/test_claims.py over the slice's recorded scanner output"
reuse: [whitepaper, talk]
---

# When two sources describe one asset, keep every claim, put one in force by the grade of its evidence, and show the rest as dissent; never fold two values into a list

## The rule

Every finding about an entry is a **claim**, and the inventory keeps all of
them. Each claim carries the **grade** of its evidence, from a small ordered
table kept as data: *observed on the wire* (a handshake or probe the harness
made or watched), *observed on the host* (a running system's firmware or
controller answered), *parsed from a file* (a certificate, key or configuration
read), *reported* (a document someone else produced: an imported CBOM, a
supplier's statement). The entry's values come from the best-graded claim, the
earliest on the ledger at equal grade, and the entry says which claim that was
and what decided it. A parameter two claims give different values for is
written as **dissent** beside the entry, every value with its grade, tool and
event; it is shown, not resolved. A person may set a field by a recorded
resolution event, which outranks the rule until a recorded revocation cites it.
No value is ever folded into a list of both, and no field changes type.

## Why

Two tools that read one estate will disagree: a certificate's expiry in a stale
export, a key size one parser reports and another does not, a group spelled
three ways. The two easy answers are both wrong. Folding the values into a
list of both keeps the information but changes the field's type, so a rule that
reads a key size as an integer breaks on the next entry, and a reader is told
only that two values exist, not which to believe. Taking the first finding
loses the other without a trace, so a stale document imported after a fresh
scan can silently overwrite the scan, and nobody can tell afterwards which tool
said what.

Precedence by **grade** rather than by tool is what makes the order
defensible: a handshake the harness watched is better evidence about a
listener than any document's description of it, whoever wrote the document;
and the order is a handful of rows in a versioned file, not a judgement about
vendors buried in code. Writing the dissent beside the entry is what makes the
merge auditable: the reader who checks sees both values, who said each, and
which rule chose, and can overrule it in the open with an event that names its
basis.

Identity is handled the same way: a claim that carries no key identity (an
imported entry whose document had no field for the public key's hash) joins
the one identified entry in the same place with the same kind, role and name;
with two or more such entries it stays apart as a possible match, never an
identity assumed.

## When it applies

Any inventory, cryptographic or not, assembled from more than one source,
and any single source that reports one thing twice. It applies with special
force when documents from outside are brought in: an imported CBOM, a
supplier's statement, a vendor's export. The one exception is a list-valued
field that is a set by nature (the names a tool used for one algorithm), which
unions. It does not apply to presence: a claim that an entry exists which no
other source saw is not a disagreement about a value but a question of whether
the thing is there, and is settled by a fresh scan where the thing is
reachable, not by precedence.

<figure class="sketch" markdown>
![One entry drawn as a box with two claims pinned to it: on the left a claim graded observed on the wire from testssl.sh with a certificate expiry in 2029, on the right a claim graded reported from another scanner's CBOM with the expiry in 2027. An arrow from the left claim into the entry's value is labelled in force by precedence version 1. A slip beside the entry headed dissent lists both values with their grades. Below, two crossed-out alternatives: a list holding both dates, marked type changed, says nothing; and the right claim alone, marked first wins, the other lost. At the bottom a person's resolution event is drawn as a stamp that may override the arrow, with a revocation that lifts it.](../img/sketches/68-two-claims-one-entry.svg)
<figcaption>Two claims on one entry: the better-graded one in force, the other kept as dissent; the list and the silent overwrite crossed out.</figcaption>
</figure>
