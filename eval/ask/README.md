# Ask the CBOM — the floor, written before the first run (2026-11-04)

A question box whose answers are grounded in the CBOM and cite ledger events. Two parts, scored
separately, retrieval first (journal lesson 34):

1. **Retrieval** (`src/pqch/ask`, the `embed` tier): the question is embedded, every component's
   passage is embedded once per CBOM, and the eight nearest passages are given to the model.
   Scored on its own: for each item, the share of its expected components among the eight.
2. **The answer** (role `ask-cbom`): a typed reply — the answer, the components it rests on, and the
   ledger events it cites — made only from the passages given. Every citation is checked by a rule
   against the ledger: the event must exist, it must be among the events of a passage the model
   was shown, and that passage must be a component the reply names or one within two dependencies of
   it (since 2026-11-21; recomputed over the twelve recorded example answers with no model called,
   all twelve still pass). An answer that cites nothing fails the rule. The page shows each
   citation's verdict; the model never decides whether it cited well.

## Items

`items.jsonl`: 12 questions about the mini-agency's CBOM, each with the components (`bom-ref`s) a
correct answer rests on and, for the answer check, a phrase the answer must contain. Written from the
answer key and the estate as built, before any retrieval ran.

**Unanswerable items (added 2026-11-21, not yet run on any engine).** Four more questions,
`ask-13` to `ask-16`, ask for something the mini-agency's CBOM does not hold (two of them are the
spreadsheet's rows for systems the estate does not have). The only right reply sets
`not_in_passages` and cites nothing; the scorer counts an item as `declined` when every repeat does.
The floor, written before any run: all four. An arm clears only with it. The eight result files
below were made before these items existed and say nothing about them.

**What the phrases do not show.** Three phrases are weak and are kept as they were, so the recorded
runs stay comparable: `api` (ask-09) and `5432` (ask-05) are close to the question's own words, and
ask-02 passes on the group's name without any of its four listeners. The scorer now also reports
`named`: on how many items an expected component was among the reply's components on every repeat.
It becomes a floor only after it has been measured once.

**What three repeats show.** Every call is made at temperature 0, so on a deterministic engine three
repeats are close to one sample: they catch an engine that is not deterministic (a cut-off, a
timeout, a reply that differs under load), not the spread of a sampled answer.

## Floors (of 12)

| Part | Floor | Why |
|---|---|---|
| Retrieval, recall@8 | 11 of 12 items with every expected component among the eight | The model cannot cite what it was not shown; a miss here is an unanswerable question |
| Answer: contains the expected phrase | 10 of 12 | A wrong answer with a correct citation misleads less than the reverse, but a page that is wrong one time in six is not usable |
| Citations: every citation passes the rule | 12 of 12 | An invented event id is the one failure the page must never show; a rule catches it, so the floor is total |

An arm clears when all three hold over three repeats of every item and every unanswerable item is
declined (the scorer's rule). The result, with the engine and the hardware, goes in the BRIEF's
table and in the journal.

**No arm has cleared.** In all eight result files `clears` is false; the best (2026-11-05, Super VL
with thinking) holds phrase 12 and citations 12 with retrieval 10 against its floor of 11. The two
retrieval misses are the same items on three different embedding models (ask-02 needs four listeners
among the eight; ask-04 is a host-file fact on a service), which points at the passages, not at the
answering model. The role is nevertheless bound in the deployments that show the question box:
below its floor, with every citation's verdict on the page (BRIEF; `eval/role-cards.yaml`). That is
an exception to "a role moves to a model only by measurement", stated here so it is not read as a
cleared floor.

## Results

`results/<date>-<box>-<engine>[-chain-rule].json`: the scorer's summary and every record. The first two
runs of each engine on 2026-11-04 were made before and after the chain rule in retrieval (note 19).
