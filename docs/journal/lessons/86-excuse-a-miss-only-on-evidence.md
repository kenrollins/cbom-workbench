---
id: lesson-86-excuse-a-miss-only-on-evidence
type: lesson
title: "Excuse a miss only on evidence, and take what is excused out of the count"
date: 2026-11-21
audience: [architect, engineer]
rung: structured
tags: [evaluation, answer-key, verification, cbom]
one_line: "A keyed item a change removed is not a miss, but only when the listener's latest landed change is the one that removed it, the item is not the group that change requires, a copy is declared to carry the change, and the column looked at that listener; and an item set aside leaves the denominator as well as the numerator, so the page cannot print 35/40 beside \"out of the denominator\"."
claims:
  - text: "`pipeline.remediated_rows` moves a missed item to `remediated`, out of `present` and out of the denominator, only when: the listener's latest landed change before the cut-off is a require; the item is a key-establishment algorithm whose name that change's configuration does not keep; for a copy, the change is in the scope's `copy.carries`; and the column holds some component for that listener. A later landed change of any other intent cancels an earlier require, and an estate reset cancels everything before it."
    provenance: "by reading src/pqch/pipeline.py (remediated_changes, remediated_rows) at HEAD, 2026-11-21; tests/test_import_shapes.py (test_only_the_latest_landed_change_excuses_and_never_the_group_it_requires, test_a_copy_is_excused_only_what_it_is_declared_to_carry), passing on xr7620"
  - text: "One function serves a scan, a scan of a copy and an imported document, and `eval/score.py` scores a recorded run through the same entry point the run wrote its score through (`pipeline.score_with_remediation`)."
    provenance: "by reading src/pqch/pipeline.py, src/pqch/scout/imported.py and eval/score.py at HEAD; commit 504aadd"
  - text: "The mini-agency's scan of 2026-11-09 (run 01M6Z41DJB5911EF1Y65K2FBTY) scores 35 of 37 on the wire with 0 false positives: 40 keyed wire items, 3 on records-db set aside as remediated by the change that requires X25519MLKEM768 there, 35 found, and the 2 left keyed out of reach. The score written on 2026-11-09 carried the same 35 found and 3 remediated with a denominator of 40."
    provenance: "measured 2026-11-21 on xr7620 (x86_64): `uv run python eval/score.py <run> --json` over the run and the change runs beside it, read-only; the earlier figure from the run's stored score.json"
reuse: [whitepaper, customer-question]
---

# Excuse a miss only on evidence, and take what is excused out of the count

## The rule

When a scorer sets a missed item aside because the estate legitimately no
longer has it, each such decision rests on a recorded event that says so for
that item, on that listener, as the estate stood at the scan. And an item
set aside leaves the fraction entirely: it is neither found nor missing, so
it is in neither the numerator nor the denominator.

<figure class="sketch" markdown>
![Two timelines for one listener, each ending in an arrow to its result. On the first, a require lands, X25519MLKEM768 only, and a scan follows: what it removed is set aside. On the second, the require lands, then a roll back lands, ringed in red, then the scan: nothing is excused. Under a dashed rule, the arithmetic: 40 keyed less 3 set aside leaves 37 to count.](../img/sketches/86-only-the-latest-landed-change.svg)
<figcaption>Only the latest landed change on a listener can excuse a miss, and what it excuses leaves the denominator; the group the change requires is never excused, and the arithmetic is the mini-agency's key.</figcaption>
</figure>

## Why

An answer key is the written truth about an estate as it was built: for each
listener, the key-establishment and signature algorithms it uses. A migration
changes the estate. Once a change that requires a hybrid key exchange (a
classical and a post-quantum key agreement combined; here X25519MLKEM768)
has landed and been verified on a listener, the classical groups the key
lists for it are gone. A scan that does not find them is right. Scoring them
as misses would punish the scanner for the migration, so the scorer moves
them to a third class, *remediated*.

That is an excuse, and an excuse granted loosely makes a score flatter than
the scan. Each loose condition is a different way to forgive a real miss:

| The loose rule | What it forgives that it should not |
|---|---|
| any require that ever landed on the listener | a listener whose require was later rolled back: the classical groups are back, and not finding them is a miss |
| every missed key-establishment item on the listener | the hybrid group itself, which the change put there and a scan must find |
| a copy of the estate, by the estate's history | changes the copy was never declared to carry |
| any column | a column that holds nothing for that listener: it did not look, so it did not "not find" |

The count is the second half. If three items are set aside and the page
still divides by the key's full count, the fraction says the scan missed
five when it missed two, and the sentence beside it ("three remediated, out
of the denominator") contradicts the number it explains. A reader who checks
the arithmetic stops trusting both.

The mini-agency shows the size of it. Its key has 40 wire items. On the
scan of 2026-11-09, three of records-db's four key-establishment items
(X25519, finite-field Diffie-Hellman and RSA key transport) had been
removed by a landed change that keeps one. The scan found 35, and the
two it did not find are keyed out of reach (a client's offer, a partner's
client certificate). Stated as the rule states it, that is 35 of 37, with 3
remediated and 2 out of reach. Printed over 40 it reads as five misses.

One more condition is about the scorer, not the rule: there must be one of
it. A scan, a scan of a copy and an imported document that each apply their
own version of the excuse cannot be compared, and a command that re-scores a
recorded run must go through the function the run used.

## Why a removed item is set aside at all

When the estate an answer key describes can be changed, a scan made after a
verified change no longer sees what the change removed. Left in the count,
every successful migration reads as a drop in coverage. So the item is counted
as remediated, by the change event that removed it, and reported apart from
what was found: "35 of 37 found, 3 remediated by change X", never three more
misses. The rule is keyed on the change record, not on the absence, which is
what the conditions above enforce. The estate also needs a reset to its built
state, recorded like any change, so a run can start from the key's truth
again; a reset cancels every excuse before it.

## When it applies

Any scoring against a fixed key of a system that is allowed to change:
migrations, patch campaigns, a benchmark whose target is being hardened
while it is measured. It applies to any class that takes an item out of
"missed" for a reason: remediated, out of scope, accepted risk, waived.

## How to apply it

1. Derive the excuse from the ledger, per listener: take the **latest**
   landed change before the cut-off (the scan's start, or for a copy the
   moment the copy was taken); it excuses only if it is a require. A roll
   back, an enable over a require, or an estate reset after it means nothing
   is excused.
2. Excuse by name: only the algorithms the change's rendered configuration
   does not keep. What the change requires stays a present item.
3. For a copy, excuse only a change the copy's scope lists in `carries`
   ([lesson 75](75-score-a-copy-through-an-address-map.md)).
4. Excuse only in a column that holds at least one component for that
   listener.
5. Recompute the count after moving items:

    ```python
    # src/pqch/pipeline.py, remediated_rows
    row["present"] -= len(moved)
    row["denominator"] = row["present"] + row["out_of_reach"]
    ```

6. Record each excused item with the run and change id it rests on, so the
   page can show the evidence beside the class.
7. Keep one function and one entry point, and re-score old runs through it:

    ```sh
    uv run python eval/score.py var/runs/<run-id>
    ```

8. Print the classes with the fraction: found of counted, then how many were
   remediated and how many are out of reach.

## Where the claim stops

The rule covers key-establishment items removed by a require. A certificate
replaced by a change, or an SSH host key retired, has no remediated class
yet and would score as a miss. "Keeps" is read from the names in the
change's rendered configuration; a configuration that removes an algorithm
by a wildcard or a version floor is read only as far as its names go. A
score.json written before the rule keeps the denominator it was written
with until the run is scored again.

