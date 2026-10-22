---
id: lesson-31-confirm-an-answer-keys-annotations-the-same-way
type: lesson
title: "Confirm every cause an answer key names by changing it, including the ones written as annotations"
date: 2026-10-20
audience: [engineer]
rung: all
tags: [verification, inference]
one_line: "A cause written into an answer key as an aside — a trace, a hint, a why — is a label like any other and needs the same two observations; one the key's author wrote from reading named a commented-out line as the cause of a default, and the first model trace to reach it was right where the key was wrong."
claims:
  - text: "Of nine wire findings the investigator traced on the mini-agency, eight agreed with the answer key's trace annotations and one did not; on inspection the key was wrong: it named a commented-out `ssl_dh_params_file` line as the cause of PostgreSQL's 2048-bit DHE group, which the server supplies by default when no such line is live, as the key's own comment beside the item already said."
    provenance: "measured 2026-10-20, investigate run 01M5CV4QP9K8M4EE4EDTKYRV2H over scan 01M5CTXE9PH6Y2BKPHZPZ9KFK6, lab/reason (Nemotron 3.5 Super VL 120B-A12B, medium-effort thinking) through the lab gateway; agency/answer-key.yaml item records-kex-dh-2048"
  - text: "Two further trace annotations named the file that includes the cause rather than the file that holds it: the portal's groups are set in the rendered policy file nginx.conf includes, not in nginx.conf."
    provenance: "agency/answer-key.yaml items portal-kex-x25519 and portal-kex-secp256r1, read against agency/portal/nginx.conf and agency/generated/portal/tls.conf, 2026-10-20"
reuse: [runbook, talk]
---

# Confirm every cause an answer key names by changing it, including the ones written as annotations

## The rule

An answer key's labels are what it is scored on, and a careful author
confirms each one by observation. The key also tends to carry asides — the
line a finding "comes from", a hint for a future scorer, a reason — written
from reading because nothing is scored on them yet. Treat each of those as a
label the moment anything reads it: confirm it by the same test as the
labels, the behaviour with the named line as written and its absence with
the line changed ([lesson 19](19-confirm-a-cause-by-changing-it.md)), or mark
it unconfirmed. When a model's answer disagrees with an annotation, read the
annotation before scoring the model.

## Why

The labels of a test set are checked because a score rests on them; the
annotations beside them are not, because nothing does. That changes the day
a new role is built that reads them. Here the key's `trace` field, written
at M0 and M1 as a note of where each planted weakness came from, became the
check on the investigator's trace, and three of its entries had never been
tested: two named the file that *includes* the cause rather than the one that
holds it, and one named a commented-out line as the cause of a value the
server supplies by default. The item's own comment, written by the same
author on the same day, stated the default correctly. The two statements sat
a few lines apart in one file and no test compared them.

A model under test that knows the software better than the annotation is
then scored wrong, which is the failure lesson 19 exists to prevent — and it
is more likely on exactly the cases that matter, since defaults, precedence
and included files are where a reader's model of the software is weakest.

## When it applies

Any reference data with fields that are not scored today: a `why`, a `trace`,
a `source`, an expected location. It applies with particular force when the
reference is the key for a planted estate, because the author who planted
the weakness is confident about it and writes from memory. It does not mean
every comment must be tested; it means a field becomes a label when code
reads it, and must be confirmed then, not after a disagreement.

## How to apply it

1. When a new consumer of a reference field is written, list the field's
   values and confirm each by observation before the first scored run; record
   the observation beside the item as the labels' provenance is recorded.
2. Where confirmation is a mutation (change the line, watch the behaviour
   go), reuse the harness that labelled the scored items — here
   `spikes/s3/build_r5.py`'s method — rather than reading.
3. A disagreement between a model and a reference is a question for both.
   Record the model's answer as its claim, re-derive the reference from the
   software's documented behaviour, and correct the key with a dated comment
   when the key was wrong, as `records-kex-dh-2048` now carries.
4. Where no live line sets a behaviour, write the reference as
   `cause: default`, so that a trace naming any line is scored wrong and a
   trace saying default is scored right.
