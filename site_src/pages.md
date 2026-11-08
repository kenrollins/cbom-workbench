---
title: Page by page
---

# The workbench, page by page

<!-- Screenshots captured by tools/screenshots.py from the lab's recorded mini-agency runs, at 1440 px wide,
     light scheme; recapture them when a page changes. Captions describe; every number is on the page itself. -->

The published copy of this project is a recording, a record and these notes (ADR-0006): the
[stage](/) plays eight beats recorded from one run, [inside the CBOM](/cbom) opens that run's
document, and [the record](record.md) holds its ledger, CBOM and score. The running workbench has
more screens than those. They are shown here as they were captured from the same recorded runs,
rather than copied as pages whose buttons do nothing. Each is one screen as a reader in the lab sees
it; what lies below the fold is described under the picture.

## The overview

![The overview: NIST's crypto-agility plan drawn as NIST draws it, each box filled with what the workbench does in that part and the count read live from the ledgers; the CBOM is the information repository in the middle](img/pages/overview.png)

NIST CSWP 39's picture of crypto agility, with the workbench's own counts in each box, read from the
ledgers when the page is shown. Each box opens to the page behind it. Above the drawing: a switch
between the test agency and the servers read whole, a link to the plan, and the story of one
weakness followed from the scan that found it to the scan that shows it gone, step by step around
the loop.

## The test agency

![The test agency page: the eight services of the mini-agency, each with the software it runs, the listeners it exposes and what was planted in it, read from the estate's own files](img/pages/test-agency.png)

The eight services the demonstration scans, read from the estate's own compose files and
configuration: a benefits portal, a partner API, an inter-agency gateway already post-quantum, a
records database and its SFTP drop, a message queue, a case-management application and an
administrators' jump host. For each, what was planted in it and where the answer key expects it to be
found. This is the estate the record's score is measured against.

## The walkthrough

![The walkthrough: the clock the project runs against, drawn from the facts table, then the stale spreadsheet of six rows that is most inventories today, the first of the sections that go from the sheet to a plan](img/pages/walkthrough.png)

Top to bottom, the path from a stale spreadsheet to a plan: the clock, the sheet, the scan button
and its progress, the list that folds into a CBOM, one entry opened to its evidence, the queues from
OMB M-26-15 with the memo quoted beside each, and the receipts against the answer key with the two
baselines beside the workbench. In the lab the scan runs when the button is pressed; the stage plays
the same path as a recording.

## The plan

![The plan: the six-row spreadsheet planned from beside the plan computed from the CBOM, then the plan drawn as lanes per service with dependencies between steps, from now to 2030 to 2031](img/pages/plan.png)

What the CBOM says depends on what, what comes first and in what order, computed by rules from the
scan every time the page is shown. Left, the spreadsheet planned from: independent rows, nothing
behind two of them. Right, the plan from the CBOM: steps tied to the entries they move, the
dependencies that tie services together, what must wait. Below, the lanes: one per service, the
certificate authority and the estate-wide work in lanes of their own, a line for each dependency. A
step opens to why it is there and the fields it was computed from; a what-if frees what waited on an
assumed step.

## Change packages

![Change packages: one per migration item blocked on its supplier, each stating why no configuration change can move it, with the evidence and what would unblock it](img/pages/packages.png)

For each item that no configuration change can move, because the software lists no post-quantum
algorithm for that function, a package: the evidence from the capability snapshot, the item's queue
and deadline, and what would unblock it. These are the items that start now, since replacement takes
procurement time.

## Imports

![Imports: another tool's CycloneDX CBOM brought in as evidence on a run of its own and scored against the same answer key as the workbench's scan](img/pages/imports.png)

Bring your own scanner: any tool's CycloneDX CBOM, imported as evidence on a run of its own, its
assets named by the workbench's normalizers, and scored against the same answer key by layer, so a
vendor's inventory and the workbench's can be compared on the same estate.

## Resolve

![Resolve: a policy change proposed from the CBOM, rehearsed on a copy of the service, awaiting a person's approval, then applied and verified on the wire by a pair of probes](img/pages/resolve.png)

A change from proposal to verdict: the policy event, the configuration rendered from it, the
rehearsal on a copy of the service, the approval by a person signed on to the workbench, the apply,
and the verifier's two probes, a hybrid-only client that must succeed and a classical-only client
that must be refused. Every step is a ledger event; no model takes part in the verdict.

## Not shown

Hosts, the servers read whole below their operating system, and the lab's own network: both carry
the owner's hardware identifiers and addresses and stay with the deployment
([note 20](notes/20-how-a-server-is-inventoried-and-planned-as-an-estate.md) describes the first in
general form).
