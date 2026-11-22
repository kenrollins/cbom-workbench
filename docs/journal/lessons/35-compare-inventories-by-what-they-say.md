---
id: lesson-35-compare-inventories-by-what-they-say
type: lesson
title: "Compare two inventories by the identity of each observation and by what it says, leaving out references to the records behind it"
date: 2026-10-21
audience: [engineer]
rung: managed
tags: [cbom, discovery]
one_line: "A component's reference should be a hash of what was observed, so the same thing seen twice is the same entry; and a comparison should strip the event ids an entry cites, which are new on every scan, or every scan of an unchanged estate looks like change."
claims:
  - text: "Two CBOMs from consecutive scans of the unchanged eight-service estate first compared as 20 of 254 components changed; every difference was an event id inside a property value. With event references left out, they compare as 254 unchanged."
    provenance: "measured 2026-10-21, scan runs 01M5DFXYNNG08S8ADTDF48WYFE and 01M5DG85J78FF3FVG3GDH26SWZ; src/pqch/cbom/anatomy.py, diff"
reuse: [runbook]
---

# Compare two inventories by the identity of each observation and by what it says, leaving out references to the records behind it

## The rule

Give each inventory entry a reference derived from what was observed — the
layer, the place, the kind of asset, its name and the key — so the same
observation in two scans has the same reference. Compare two inventories by
that reference, and compare each entry's content with every reference to the
record behind it removed: event ids, run ids, timestamps of the scan.

## Why

An entry that carries its evidence names the events it rests on, and a new
scan writes new events for the same observation. Those ids are correct, and
they are noise to a comparison: they change on every scan whether or not
anything in the estate did. Left in, they turn every scan into a report of
change, and a watch mode built on it re-examines everything or nothing
useful. A reference made from a counter or from the order of discovery has
the opposite fault: the same observation gets a new reference when anything
before it changes, and an unchanged entry looks removed and re-added.

## When it applies

Any comparison of two snapshots of an inventory or a bill of materials whose
entries cite their evidence: change detection, drift reports, "what changed
since yesterday". It does not apply to an audit of the evidence itself,
where the event ids are the point.

## How to apply it

1. Make the reference a hash of the observation's identity fields, and test
   that two scans of the same estate produce the same references.
2. Before comparing content, drop fields that only point at evidence
   (`evidence` lists, `*-evidence` properties, `event` keys inside structured
   values), recursively.
3. Test the comparison on two scans of an estate known to be unchanged: the
   expected result is no change, and anything else is a bug.
