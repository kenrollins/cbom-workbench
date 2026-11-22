---
id: lesson-87-count-a-majority-on-the-one-decision
type: lesson
title: "A majority is counted on the one decision; an optional model step degrades, it does not raise"
date: 2026-11-21
audience: [engineer, architect]
rung: structured
tags: [inference, discovery, verification]
one_line: "Three replies grouped by every field they carry let two that agree on the decision lose to one that does not; the vote is counted on the single question, more than half of the calls made must agree, the descriptive fields are the commonest among those who agreed, and a model call that fails leaves the candidate \"not read\" with the counts and the scan whole."
claims:
  - text: "The call-site-read role's tally sets `in_use` true or false only when more than half of the calls made agree on `is_crypto_use` alone; family and role are then the commonest among the agreeing replies, a tie for the family giving `unspecified` and a tie for the role the rule's own hint; anything else is `in_use: null`, \"not read\", with the counts (`use`, `not_a_use`, `failed`, `of`) on the event and in the basis."
    provenance: "by reading src/pqch/scout/code.py (tally, _commonest) at HEAD, 2026-11-21; tests/test_code_review.py (test_two_of_three_saying_use_is_a_use_whatever_they_call_the_family, test_fewer_than_a_majority_of_the_calls_made_is_not_read, test_a_single_reply_is_not_a_majority_of_three)"
  - text: "Counted as a plurality over (in use, family, role) together, the replies (not a use), (a use, HMAC), (a use, SHA-2) were recorded as not in use, \"1 of 3\", and one surviving reply out of three calls counted as a majority."
    provenance: "commit c5b6ab5, which records the earlier behaviour; reproduced by a reader and confirmed by a second, 2026-11-20"
  - text: "Any failure of a call is one failed call with its reason; the candidate degrades to not read and the run is closed. A timeout or an HTTP error from the client library is not an `OSError` and had ended the scan with its run open."
    provenance: "by reading src/pqch/scout/code.py and src/pqch/inference/__init__.py (CallFailed) at HEAD; commits c5b6ab5 and 894f029"
reuse: [whitepaper, talk]
---

# A majority is counted on the one decision; an optional model step degrades, it does not raise

## The rule

When a model is asked the same question several times and the answers are
voted, vote on the one decision the pipeline acts on, and require more than
half of the calls *made*, not of the replies received. Take any descriptive
fields from the replies on the winning side. And when the step is optional,
its failure is a recorded outcome of that step, never an exception that ends
the work around it.

## Why

A code scan finds candidate call sites by rule: a line that calls a hashing
or signing function. Whether the line is a live cryptographic use, or a
test, a comment or a constant, takes interpretation, so a model role reads
each candidate. Because one reply from a model is a sample, every call is
repeated and the replies are voted.

Each reply carries three fields: is it a use, which algorithm family, in
what role. Grouping whole replies and taking the largest group looks like a
majority vote and is not one:

| Reply | Is it a use | Family |
|---|---|---|
| 1 | no | none |
| 2 | yes | HMAC |
| 3 | yes | SHA-2 |

Grouped by all fields there are three groups of one. A plurality rule picks
one of them, here "no", and records "1 of 3" as agreement. Two of three
replies said the line is a use; they disagreed only about what to call it.
The decision the inventory acts on, in use or not, was settled two to one
the other way. Agreement on a label was allowed to veto agreement on the
fact.

The denominator fails the same way. If two of three calls fail and one
reply comes back, that reply is unanimous among replies and is one of three
calls. A "majority" of what was received rewards an outage with confidence.

The third failure is in the plumbing. The model reading is optional: the
candidate is already on the ledger by rule, and nothing downstream decides a
verdict from the reading. A call that times out should cost that candidate
its reading. If the exception is not the type the code expected, it instead
ends the whole scan, part-way, with its run left open. An optional step that
can take the mandatory steps down with it is not optional.

No model decides whether a change worked anywhere on this path. The reading
labels a candidate; the verifier is a re-scan, a certificate parse or a
compatibility run.

## When it applies

Any repeated model call whose replies are structured and voted:
classification with attributes, extraction with a yes or no gate, a judge
with a verdict and a rationale. It applies to any ensemble, human or
otherwise, where the ballots carry more than the question being decided.

## How to apply it

1. Name the single decision field. Count only that.
2. Require `calls // 2 + 1` on one side, with `calls` the number made:

    ```python
    # src/pqch/scout/code.py, tally
    need = repeats // 2 + 1
    side = True if uses >= need else False if nots >= need else None
    ```

3. Take each descriptive field as the commonest value among the replies on
   the winning side; on a tie, write a neutral value (`unspecified`, or what
   the rule that found the candidate already suggested), not either
   candidate.
4. Make "no majority" a value of its own (`in_use: null`, "not read"), and
   record the counts: for, against, failed, of how many.
5. Wrap each call so that every failure, of whatever exception type, becomes
   one failed call with its reason, and the run is closed whatever a call
   does.
6. Test the split vote, the single surviving reply and the gateway error
   directly; none of them occurs with a healthy model and a fake that always
   answers the same.

## Where the claim stops

A majority of three is a small sample: it removes the single stray reply and
says nothing about a model that is consistently wrong. That is measured
separately, against labelled call sites and a floor written before the run,
and the role's floor was measured with the earlier counting; this entry
reports no score of the corrected tally against the labelled set. The neutral value
on a tied family loses information a larger number of calls would recover.
