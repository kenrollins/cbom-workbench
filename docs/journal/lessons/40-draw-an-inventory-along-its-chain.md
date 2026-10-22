---
id: lesson-40-draw-an-inventory-along-its-chain
type: lesson
title: "Draw a cryptographic inventory in columns along its dependency chain, not as a force-directed graph"
date: 2026-10-21
audience: [engineer, architect]
rung: structured
tags: [cbom]
one_line: "A CBOM already has an order — service, listener or image, asset, file — so draw each link of that chain as a column, one service's chain at a time, and group bulk files by directory; a force layout throws that order away and, unbounded, drifts nodes off the canvas."
claims:
  - text: "On the mini-agency's latest scan, the estate map holds 8 services, 9 listeners, 8 images and the assets and files behind them; drawn as a force layout, most nodes settled outside the visible canvas, and the portal's image alone held about two dozen package-signing keys that no listener serves, which grouped by directory become two entries."
    provenance: "observed 2026-10-21 on the deployment's walkthrough page, scan run 01M5FYXR40S3FRWW9NXYVA5A7K"
reuse: [runbook, talk]
---

# Draw a cryptographic inventory in columns along its dependency chain, not as a force-directed graph

## The rule

Draw a CBOM as columns that follow its dependency chain — the system a
person knows, the service, its listeners and images, the cryptographic assets,
the files they come from — with one service's chain shown to the end at a
time, and group a directory's files into one entry when there are more than a
few.

## Why

A CBOM is not a general graph. Its dependencies run one way, and that
direction is the explanation a reader needs: this row of the spreadsheet is
this service, which listens here, negotiates this key exchange, and is served
from this file. A force-directed layout places nodes by repulsion and
attraction, so it discards the direction, and a reader has to rebuild it by
tracing lines. Without a force that keeps nodes inside the canvas it also
scatters them out of view, and the figure reads as isolated dots.

Volume hides the chain in a second way. A base image carries a package
manager's signing keys; each is real cryptographic material and a CBOM entry,
and none is served by anything. Listed one per row they outnumber everything
the service actually uses.

## When it applies

Any view of an inventory whose relations have a direction: a CBOM, an SBOM's
dependency tree, a data-flow inventory. It does not apply where the relations
have no order, such as which clients talk to which servers, where a network
layout is the honest picture.

## How to apply it

- One column per link of the chain, with a heading saying what it is.
- Order the first column by what the reader brings (the spreadsheet's rows),
  and keep rows with no evidence visible and marked.
- Show every service; draw the assets and files of the one in focus, and let
  a click move the focus.
- Group files no asset points to by directory above a small threshold, and
  list them in the detail panel.
- Position by column and row; never simulate a layout for structured data.
- Where the estate has no spreadsheet or service names — a network observed,
  not built — start the chain from where the listener is: subnet, host,
  listener, then its entries. The columns change; the direction does not.
- Put the view where the CBOM is opened, for every estate, not inside one
  walkthrough.
