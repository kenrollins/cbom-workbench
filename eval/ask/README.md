# Ask the CBOM — the floor, written before the first run (2026-11-04)

A question box whose answers are grounded in the CBOM and cite ledger events. Two parts, scored
separately, retrieval first (journal lesson 34):

1. **Retrieval** (`src/pqch/ask`, the `embed` tier): the question is embedded, every component's
   passage is embedded once per CBOM, and the eight nearest passages are given to the model.
   Scored on its own: for each item, the share of its expected components among the eight.
2. **The answer** (role `ask-cbom`): a typed reply — the answer, the components it rests on, and the
   ledger events it cites — made only from the passages given. Every citation is checked by a rule
   against the ledger: the event must exist, and it must be among the events of a passage the model
   was shown. The page shows each citation's verdict; the model never decides whether it cited well.

## Items

`items.jsonl`: 12 questions about the mini-agency's CBOM, each with the components (`bom-ref`s) a
correct answer rests on and, for the answer check, a phrase the answer must contain. Written from the
answer key and the estate as built, before any retrieval ran.

## Floors (of 12)

| Part | Floor | Why |
|---|---|---|
| Retrieval, recall@8 | 11 of 12 items with every expected component among the eight | The model cannot cite what it was not shown; a miss here is an unanswerable question |
| Answer: contains the expected phrase | 10 of 12 | A wrong answer with a correct citation misleads less than the reverse, but a page that is wrong one time in six is not usable |
| Citations: every citation passes the rule | 12 of 12 | An invented event id is the one failure the page must never show; a rule catches it, so the floor is total |

An arm clears when all three hold over three repeats of every item (the scorer's rule). The result,
with the engine and the hardware, goes in the BRIEF's table and in the journal.

## Results

`results/<date>-<box>-<engine>[-chain-rule].json`: the scorer's summary and every record. The first two
runs of each engine on 2026-11-04 were made before and after the chain rule in retrieval (note 19).
