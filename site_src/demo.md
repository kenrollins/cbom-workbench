---
title: Demonstration
---

# The demonstration

The spine is the crypto-agility maturity model. Each rung is a question the
agency can now answer, and each is a screen.

| Rung | What the agency has | What the CBOM answers | Passes when |
|---|---|---|---|
| **Opaque** | A stale spreadsheet | Nothing reliable | — (the starting point) |
| **Enumerated** | Scanner output | Where is quantum-vulnerable cryptography? | Coverage by layer is scored against the key, with decoys not flagged |
| **Structured** | A CBOM with dependencies | What depends on it, and how long must the data stay secret? | Every discovered link resolves to a ledger event with evidence; supplied links are labelled as supplied |
| **Managed** | Owners, priorities, approvals | What first? What is blocked on a supplier? What changed since yesterday? | Every key item has an owner, a queue, a blocker state and the rule id that put it there |
| **Agile** | Change as routine | If policy changes, how fast can we respond, and did it land? | Time-to-change is under the limit and every affected endpoint has a verdict |

## The opening 90 seconds

Inside the opening there is no model call and no engine swap: anything a model
produced was produced earlier, is read back from the ledger, and carries its
ledger timestamp on screen. Each step is marked.

1. **The spreadsheet.** "This is most inventories today." *(static)*
2. **One button.** Targeted scans run against the test estate; the list fills.
   *(live — targeted checks with a per-endpoint time budget; image scans
   replayed from the ledger)*
3. **The list folds into a CBOM.** One entry opens: the chain from the wire
   finding to the file holding the key, the evidence for each link. *(replayed)*
4. **The priority view.** Two queues, and the reason each item sits where it
   does. *(live — rules over OMB M-26-15, quoted)*
5. **A policy change is approved.** The configuration regenerates, the wire is
   re-scanned by a hybrid-only and a classical-only probe, and the elapsed time
   is on screen. *(live)*
6. **The receipts.** Coverage against the answer key, the two baselines beside
   the workbench, and the ledger entry for the change just made.

## What is built today

Every step of the opening runs on the eight-service mini-agency, live in the lab
at [the walkthrough](/walkthrough). Measured on the lab's x86_64 server:

| | |
|---|---|
| A scan of the estate | 25 runner jobs; 206 s with every image scanned, about 100 s with image scans replayed; wire 38 of 40 keyed items found, images 20 of 20, no decoy flagged, the posture of all 9 listeners correct |
| The scanners run alone | the same 38 on the wire, 14 of 20 in images with both image decoys flagged, no posture |
| The queues | 7 of 8 services prioritized by the memo's criteria; 14 migration items open, 7 of them blocked on their supplier |
| A trace to the cause | one per listener on the 120B reasoning engine, a median of 27.6 s, eight of nine agreeing with the answer key and the ninth correcting it |
| A policy change, rendered by rule and verified twice on the wire | 55.6 s from the policy event to the last verdict on the four-service slice |
| A change drafted by a model and rehearsed on a copy before approval | the records database: drafted from its CBOM entries in about 5 s a reply, rehearsed `enforced` in 33 to 37 s |

The source of each number is the facts table in the repository's `BRIEF.md`,
which names the run.

## The walkthrough

After the opening, the same path at full depth and live: a full scan, an
investigator trace run from cold on the larger model with its ledger event and
measured time, a policy change that moves from `enabled-not-enforced` to
`enforced` through a compatibility matrix, a change event arriving in Watch
mode, and the table of which roles need which model and what each step up in
models or hardware was measured to change. The waits are part of the
demonstration, labelled with the engine and the machine that produced them.
Built so far: the full scan, the investigator's trace, watch mode, and changes
drafted by a model and rehearsed on a copy; the compatibility matrix and the
three applies of the build plan's M3 are not.
