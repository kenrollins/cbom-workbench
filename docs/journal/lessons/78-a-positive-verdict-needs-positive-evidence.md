---
id: lesson-78-a-positive-verdict-needs-positive-evidence
type: lesson
title: "A positive verdict needs positive evidence; \"nothing was attributed\" is its own state"
date: 2026-11-21
audience: [leader, architect, engineer]
rung: managed
tags: [policy, cbom, verification, discovery]
one_line: "A rule that answers \"met\" when its list of problems is empty answers \"met\" for everything it never looked at; a migration item with no finding attributed to its service is not-assessed, and a listener on which no key exchange was observed is unobserved, neither compliant nor classical."
claims:
  - text: "A migration item's state is `open` when a vulnerable algorithm was found, `met` only when an acceptable one was observed and nothing unnamed remains, and `not-assessed` otherwise; a service's `pqch:state` in the CBOM is `met` only when every item is."
    provenance: "by reading src/pqch/assessor/managed.py and src/pqch/cbom/__init__.py at HEAD; src/pqch/cbom/fields.yaml (`pqch:state`); tests/test_assess_review.py, passing on xr7620, 2026-11-21"
  - text: "The capture's posture rule calls a listener `unobserved` (basis `none`) when no handshake on it showed a key exchange, counts a hybrid offer and a refusal only on handshakes where one was observed, and calls RSA key transport alone `classical` on the basis of the suite."
    provenance: "by reading src/pqch/scout/capture.py (posture/observed/1) at HEAD; tests/test_capture.py; commit 443c6d6"
reuse: [whitepaper, talk, customer-question]
---

# A positive verdict needs positive evidence; "nothing was attributed" is its own state

## The rule

A rule may say "met", "compliant", "clean" or "refuses it" only when it holds
an observation that says so. When what it holds is an empty list, the answer
is a third state with its own name: not assessed, unobserved. Decide the
empty case of every rule before deciding anything else about it.

## Why

Most rules are written as a search for what is wrong: collect the vulnerable
findings for this service; if there are any, the item is open. The other
branch writes itself, and it is the defect: *otherwise, met*. That branch is
reached two ways that the code cannot tell apart. Either the service was
examined and nothing vulnerable was found, or nothing about the service
reached the rule at all.

The second happens whenever a link upstream is missing. A migration item
belongs to a service; a finding belongs to a listener; the rule joins them
through a link that says which listener serves which service. Where a scan
has no such link (a scan of machines whose container bindings it cannot read,
an imported document, a new estate before its owner's facts are supplied) the
join returns nothing for every service, and every item of every service
reads "met". The inventory beside it can list a dozen vulnerable algorithms
on the same page.

The same shape appears wherever a count is made by subtraction. A passive
capture judges whether a listener refuses a hybrid key exchange (a classical
and a post-quantum key agreement combined, such as X25519MLKEM768) from the
handshakes it saw. A row with no group chosen is one of three things:

| The row | What it says about the listener's key exchange |
|---|---|
| A ClientHello nobody answered | nothing |
| A resumed TLS 1.2 session, no key exchange on the wire | nothing |
| A completed RSA key transport | classical, by the suite |

Subtracting "handshakes with a hybrid chosen" from "all handshakes" counts the
first two as refusals and labels a listener classical that was never seen to
choose anything. Only the third is evidence, and it is evidence of a
different kind from a chosen group.

A wrong "met" is worse than a wrong "open". An open item gets looked at. A
met item leaves the queue, the plan and the reader's attention, and the page
that printed it is the page a leader reads.

## When it applies

Every rule whose output has a favourable value: compliance states, postures,
"no findings", "covered", "verified". It applies to counts as well as
verdicts: a percentage whose numerator is "everything not known to be bad"
has the same empty case. It is the assessor's side of the rule that a
verifier never passes what it could not read
([lesson 85](85-two-absences-are-not-a-match.md)) and the scanner's side of
[lesson 79](79-a-scan-that-did-not-connect-is-not-a-clean-scan.md).

## How to apply it

1. Give every verdict at least three values: the favourable one, the
   unfavourable one, and one that says the rule had nothing to judge. Here
   they are `met`, `open`, `not-assessed`; and `pq`, `mixed`, `classical`,
   `unobserved`.
2. Make the favourable value require a named observation: `met` needs an
   acceptable algorithm observed on the service and no unnamed one left.
3. Roll up strictly: a service is `met` only when every one of its items is;
   one `not-assessed` item makes the service `not-assessed`.
4. Count a refusal as a refusal observed, never as a total less a total.
5. Test the empty case first: run the rule over an estate with no link from
   listeners to services and assert that nothing reads `met`.

    ```sh
    uv run python -m pytest tests/test_assess_review.py tests/test_capture.py
    ```

## Where the claim stops

`not-assessed` says the rule had no finding for the service; it does not say
why. The gap queue ([note 25](../notes/25-how-much-of-an-estates-cryptography-a-tool-can-reach.md))
is where the missing link is named and filled. Runs assessed before the rule
changed keep the events they recorded; a page reading an older run shows what
that run's rule said.

