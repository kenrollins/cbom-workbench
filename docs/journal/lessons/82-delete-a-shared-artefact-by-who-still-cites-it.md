---
id: lesson-82-delete-a-shared-artefact-by-who-still-cites-it
type: lesson
title: "Delete a shared artefact by who still cites it, and record the intent before the act"
date: 2026-11-21
audience: [engineer, architect]
rung: managed
tags: [evidence, ledger, retention]
one_line: "Retention that deletes what an expired run cites deletes evidence a younger run cites too; a file goes only when no run outside the pass cites it, a path is resolved and must lie inside the store, the key a kept ledger verifies with stays, and the intent goes on the ledger before the first unlink."
claims:
  - text: "`pqch retention apply` deletes a raw output only when no run outside the pass cites it, comparing resolved paths, and names the ones it kept in `kept_cited`; an evidence ref that resolves outside `var/raw` is refused and reported, never unlinked; `ledger.jsonl` and `ledger.pub` are kept; a run whose ledger does not verify, or whose first event has no readable time, is skipped and reported."
    provenance: "by reading src/pqch/retention.py at HEAD; tests/test_handling.py (the five retention tests), passing on xr7620, 2026-11-21"
  - text: "A `destruction.intended` event with the paths goes on the retention run's ledger before any file is unlinked, and `artefact.destroyed` with what actually went after; a pass cut short leaves the intent, and the next pass records what the interrupted one destroyed."
    provenance: "by reading src/pqch/retention.py; tests/test_handling.py::test_a_retention_pass_cut_short_leaves_its_intent_and_the_next_pass_records_what_went"
  - text: "The event schema places no constraint on an evidence ref, so a ledger carrying a ref with `..` in it is appended and verifies; containment is retention's check to make."
    provenance: "reproduced in a scratch store by two readers, 2026-11-20 and 21; by reading the docstring of src/pqch/retention.py"
reuse: [runbook, whitepaper]
---

# Delete a shared artefact by who still cites it, and record the intent before the act

## The rule

Before deleting anything that more than one record can point at, ask who else
points at it, and keep it while anyone outside the deletion does. Resolve
every path and require it to lie inside the store being cleaned. Never delete
what the surviving record needs in order to be checked. Write what is about
to be destroyed on the ledger first, and what was destroyed after.

## Why

A retention policy is stated per run: artefacts of a run older than N days
are destroyed, its ledger is kept. The obvious implementation walks each
expired run's ledger, collects the files it cites as evidence, and deletes
them. That is correct only if every file belongs to exactly one run.

Raw scanner output does not. It is stored once, by content, and cited by
every run that used it: the scan that produced it, a replay of that scan
under new rules, a re-score. The first retention pass whose cut-off falls
between two such runs deletes the file out from under the younger one. The
younger run's ledger still verifies, its evidence hashes now point at
nothing, and no event anywhere says that run lost anything. The destruction
record names only the old run.

Three more defects sit in the same few lines, each a deletion decided from
too little:

- **A ref is a string, and a string can climb.** An evidence reference is
  whatever a ledger says it is. Filtering on a prefix (`var/raw/…`) and
  unlinking the unresolved path follows `var/raw/../runs/<another run>/ledger.jsonl`
  to another run's system of record. Such a ledger is not corrupt: the event
  schema does not constrain the string, so it appends and verifies.
- **"Everything but the ledger" forgets the key.** A signed ledger is checked
  against the public key beside it. Delete the key with the documents and the
  ledger that was kept can no longer be verified offline.
- **Act, then record.** If the files go first and the event second, a pass
  interrupted between the two has destroyed evidence with no record that it
  did.

## When it applies

Retention, garbage collection, cache eviction, cleanup jobs: any deletion
driven by one owner's list over storage that is shared or content-addressed.
It applies whenever the list of what to delete is itself read from data that
something else wrote.

## How to apply it

1. Build the set of everything still cited by every record that is **not**
   being destroyed, including records of kinds retention never touches, and
   subtract it. Compare resolved paths, not reference strings.
2. Resolve each candidate and require it to be inside the store's resolved
   root; refuse and report anything else. Do not unlink a refused path "to be
   safe".
3. Keep, by name, what the surviving record is checked with:

    ```python
    # src/pqch/retention.py
    KEEP = ("ledger.jsonl", "ledger.pub")
    ```

4. Skip and report any run whose ledger does not verify or whose first event
   cannot be read, and go on to the next; one bad run must not stop the pass
   or be acted on.
5. Bracket the act on the ledger: `destruction.intended` with the paths, the
   unlinks, `artefact.destroyed` with what actually went. On the next pass,
   reconcile any intent left without its second event.
6. Say in the output what was kept because another run cites it, what was
   refused and what was skipped; an operator reading "destroyed 40 files"
   should also read "kept 3, still cited".
7. Dry-run first, and read the kept list.

    ```sh
    pqch retention apply --days 30 --dry-run
    ```

## Where the claim stops

"Still cited" is computed from the ledgers in the deployment at the time of
the pass. A run archived elsewhere that cites the same output is not seen. A
file kept because a younger run cites it is destroyed only when that run in
turn expires, so the retention period is a floor on a shared file's life, not
its length.

