---
id: note-19-how-a-question-to-the-cbom-is-answered-and-checked
type: note
title: "How is a question to the CBOM answered, and how is the answer checked without asking a model?"
date: 2026-11-04
audience: [architect, engineer]
rung: structured
tags: [cbom, inference, verification]
one_line: "A question is embedded, the nearest components and their chains are handed to a model as passages with their ledger event ids, the typed reply names components and cites events, and a rule checks every citation against the ledger and against what the model was shown; retrieval and the answer are measured apart against floors written first."
claims:
  - text: "Retrieval over one passage per component (250 components of the mini-agency's CBOM, ollama mxbai-embed-large on the GB10), eight nearest by cosine, found every expected component for 9 of 12 questions; adding the chain each hit sits in (its listener, its service) as a rule raised that to 11 of 12 against a floor of 11."
    provenance: "measured 2026-11-04 on the lab GB10, eval/ask/score.py, runs ask-fast (v1) and ask-fast-v2 on scan run 01M6J326QNTAFJW3CQNVR2JFPJ"
  - text: "The Nemotron Nano 9B v2 NIM answered 7 of 12 questions with the expected phrase and passed the citation rule on 10 of 12 (floors 10 and 12), median 22 s a question; Nemotron 3.5 Super VL 120B-A12B at medium-effort thinking under vLLM answered 10 of 12 and passed on 10 of 12 without the chain rule (median 57 s) and 11 of 12 and 9 of 12 with it (median 34 s), with other jobs on the GPU throughout."
    provenance: "measured 2026-11-04 on the lab GB10; eval/ask results ask-fast-v2, ask-deliberate (v1) and ask-deliberate-v2; three repeats per question"
  - text: "Of the citation failures seen, none was a passing invented id: the rule caught event ids that were not in the ledger, a component hash or bom-ref cited as an event, component refs written with a prefix, and three replies cut short of valid JSON by a 4,000-token budget the model's thinking shared; the spellings became normalization rules and the budget was raised, and an invented id stays a failure the page shows."
    provenance: "computed 2026-11-04 from the eval records (ask-fast, ask-fast-v2, ask-deliberate, ask-deliberate-v2)"
reuse: [whitepaper, talk, customer-question]
---

# How is a question to the CBOM answered, and how is the answer checked without asking a model?

## The answer

A question in plain words is embedded; the eight components whose passages lie nearest to it, and the
chain each sits in (an asset's listener, a listener's service), are handed to a model as numbered
passages, each with the ledger event ids that are its evidence. The model returns a typed reply: the
answer, the components it rests on, the event ids it cites. A rule then checks each citation: the event
must exist in the ledger, and it must belong to a passage the model was shown; a component must be one
it was shown. The page prints the answer, each citation with its verdict, and the passages. The model
never decides whether it cited well. Retrieval and the answer are measured separately against floors
written before the first run.

## The concept

A CBOM (cryptography bill of materials: the inventory of an estate's algorithms, keys, certificates and
protocols, with where each was found) is a document, and a document can be asked questions. The risk in
letting a model answer is that it answers from what it knows rather than from the document, and names
things the document does not hold. Two things close that gap: the model sees only passages built from the
CBOM, and every claim it makes about provenance is checked by code against the ledger the CBOM was
built from. The ledger (an append-only, hash-chained record of every finding, assessment and decision,
from which the CBOM is rebuilt) is what makes the check possible: every fact in the CBOM has an event
behind it, so a citation is a thing that can be looked up.

## The mechanism

1. **Passages.** One per component, built from the same anatomy the CBOM page shows: kind, label,
   bom-ref, every field and value, what it depends on and what depends on it, and the sorted set of
   ledger event ids behind those fields. Embedded once per CBOM (the `embed` tier) and cached beside the
   run.
2. **Retrieval.** The question is embedded as a query; the eight nearest passages by cosine are taken.
   Then a rule adds, for each hit, its parents two hops up the CBOM's dependency graph. A question about
   a service is usually answered by the assets that make it what it is, and the assets are what the
   embedding finds; the chain brings the service along so the model can name it.
3. **The answer.** Role `ask-cbom`, one call through the inference seam with a JSON schema on the reply:
   `answer`, `components` (bom-refs), `citations` (event ids), `not_in_passages`. The system prompt says
   what an event id looks like and that a component's hash is not one.
4. **The check.** For each citation: in the ledger, and among the shown passages' events. For each
   component: among the shown. A hash of a shown component cited as an event is read as a component
   naming; a ref written `bom-ref: X`, `/bom-ref X` or `[n]` is normalized. Anything else that fails is
   shown as failing, and the page says the answer is unsupported.

The ledger is not written: a question is not an event of the estate.

## Worked example

Question: *Which SSH listener still offers the 1024-bit Diffie-Hellman group?* The nearest passages are
the DH-1024, DH-2048 and DH-GEX wire assets on `172.16.106.20:22` and the listener itself; the chain adds
the `bastion` service. The reply names `listener:172.16.106.20:22`, cites the finding events behind the
DH-1024 asset, and passes. Asked the same on the first version of the page, the Nano NIM cited the
DH-2048 asset's hash as an event: the rule marked it failing, which is the page working as intended.

## What the measurement says

| Part | Floor (of 12) | Nano 9B NIM | Super VL 120B, medium effort, without the chain rule | Super VL, with it |
|---|---|---|---|---|
| Retrieval, recall@8 | 11 | 11 (with the rule) | 9 | 10 |
| Answer contains the expected phrase, all three repeats | 10 | 7 | 10 | 11 |
| Every citation passes, all three repeats | 12 | 10 | 10 | 9 |
| Median latency a question | — | 22 s | 57 s | 34 s |

Neither arm clears all three floors on 2026-11-04. The larger model answers correctly; the citation
floor is total by design and three questions missed it: invented event ids near real ones (caught),
bom-refs given as citations (now read as component namings), and one question whose three replies were
cut short of valid JSON by a 4,000-token budget shared with the model's thinking (the budget is now
8,000). Retrieval reached its floor on one run and missed by one on the next: the embedding of a
question is not bit-stable across runs on this engine, and the eighth nearest passage can change. The role is bound to the deliberate tier as the best measured arm, below floor, and
the page shows every verdict (`kit/inference.yaml`).

## What follows

An agency can let a model answer questions about its inventory on its own machine, if the answer is
grounded in passages from the inventory and every citation is checked by code against the record the
inventory came from. The check is cheap and exact; the model's quality shows up as answers the check
marks unsupported, not as answers that mislead. A floor written first says when the page is usable.

## Scope

Twelve questions on one estate, written from the answer key, three repeats, two engines on one GB10.
Not a benchmark of retrieval methods; not a measure of the page on a real estate's CBOM; the question
set is small and will grow. Lesson 34 holds: retrieval is scored on its own before the model is blamed.

## References

- `src/pqch/ask` (passages, index, retrieval, the check), `eval/ask/README.md` (the floors, written
  2026-11-04 before the first run), `eval/ask/items.jsonl`.
- Lesson 34 (score retrieval on its own first), lesson 49 (what an engine decides for itself).
