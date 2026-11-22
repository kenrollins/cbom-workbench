---
id: lesson-76-read-another-tools-document-in-its-own-shape
type: lesson
title: "Read another tool's document in its own shape before scoring it; a reader's blind spot is otherwise recorded as the tool's score"
date: 2026-11-21
audience: [architect, engineer]
rung: structured
tags: [cbom, discovery, evaluation, interoperability]
one_line: "A CBOM arrives as components-as-assets placed by host:port or as components-as-listeners with the facts in properties and the place as src=; an importer that reads one shape scores the other at zero, and the zero is its own. The reader chooses per component, counts what it sets aside by reason, and is held by a round trip of its own writer's document."
claims:
  - text: "`pqch import` reads two shapes, chosen per component: an asset component (an algorithm, certificate or key) placed by the `host:port` of its occurrence, and a listener component (one protocol component per server) whose facts are in the properties `Supported Groups`, `Key Exchange Algorithm` and `Host Key Algorithm` and whose place is the `src=<server>:<port>` of its occurrence. A certificate's key family is read through `subjectPublicKeyRef` and that key's `algorithmRef`, then a `Subject Public Key Algorithm` property, then its own name."
    provenance: "by reading src/pqch/scout/imported.py (_asset, _is_listener_shape, _listener_shape, locate) at HEAD, 2026-11-21"
  - text: "A component located by its destination is a client and is counted (`client_side`), not placed; a component that exists only to be referenced, a listener summary, one with no location and one outside the scope are each counted under their own name in `left_out`; a claim under a name no alias table knows is listed as `unrecognised`, not charged as a false positive."
    provenance: "by reading src/pqch/scout/imported.py (run_import, recognised) at HEAD; tests/test_import_shapes.py (6 tests, passing on xr7620, 2026-11-21)"
  - text: "A scored run's own CBOM, imported, covers the same keyed items as the scan that made it with 0 false positives."
    provenance: "tests/test_import_shapes.py::test_the_workbenchs_own_document_scores_as_the_scan_that_made_it, on the fixture slice, xr7620, 2026-11-21"
reuse: [whitepaper, customer-question]
---

# Read another tool's document in its own shape before scoring it; a reader's blind spot is otherwise recorded as the tool's score

## The rule

Before another tool's cryptography bill of materials (CBOM: an inventory of
the algorithms, keys, certificates and protocols a system uses) is scored
against an answer key, open the document and find out how it says *what* and
*where*. Read it in that shape. Count everything the reader sets aside, by
reason. And hold the reader with a round trip: the workbench's own CBOM,
imported, must score exactly as the scan that wrote it.

<figure class="sketch" markdown>
![Two documents on the left, each a box. The first, components as assets, lists algorithm X25519, a certificate that points to its key and through it to RSA, and an occurrence at 192.0.2.10:443. The second, components as listeners, lists Supported Groups: x25519, Host Key Algorithm: RSA-2048 and src=192.0.2.10:443. An arrow from each meets at a slip, ringed in red, that says the reader chooses by shape, and one arrow leaves it for a box headed the same findings: 192.0.2.10:443, key establishment X25519, signature RSA.](../img/sketches/76-two-shapes-one-reader.svg)
<figcaption>Two shapes of the same inventory become the same findings when the reader chooses by shape, component by component; the addresses are invented, and a component placed by its destination is a client, counted and not placed.</figcaption>
</figure>

## Why

CycloneDX 1.6 fixes the fields of a cryptographic asset. It does not fix what
a component *is*. Two shapes are both valid and both in use:

| | Components as assets | Components as listeners |
|---|---|---|
| One component is | an algorithm, a certificate, a key | a protocol endpoint, one per server |
| The fact is in | the component's name and its typed fields | properties: `Supported Groups`, `Key Exchange Algorithm`, `Host Key Algorithm` |
| The place is | an occurrence, `host:port` | an occurrence, `src=<server>:<port>, dst=<client>, …` |
| A certificate's key | a separate component, reached by `subjectPublicKeyRef` then `algorithmRef` | a `Subject Public Key Algorithm` property |
| Written by | a scanner that asks each listener what it accepts | a passive sensor that watches conversations |

An importer written beside one writer learns that writer's shape and nothing
else. Given the other shape it finds no `host:port` and no algorithm
component, places nothing, and reports a score of zero with every component
"unplaced". Nothing fails: the document is valid, the importer ran, the score
is a number. The number then goes into a comparison as a statement about the
other tool, when it is a statement about the reader.

The reader's own writer is not exempt. A certificate component is named for
what it is; its key's family lives one reference away. A reader that takes the
family from the nearest name reads the referenced key component's name, "RSA
public key", as an algorithm nobody keyed, so each certificate becomes one
miss and one false positive. A document's own author can be misread by the
tool that wrote it, and only a round trip shows it.

Three things a reader sets aside are not errors and must not look like them:

- **A client.** A component located by its *destination* describes what a
  client offered to a server in scope. It is true and it is not a property of
  the listener. It is counted as client-side and not placed.
- **A component that exists to be referenced**, and the writer's own listener
  summaries. Counted as referenced and as listeners.
- **A claim under a name no alias table knows.** An answer key cannot call a
  name wrong that the reader could not recognise; it is listed as
  unrecognised and is not a false positive.

What is left as "unplaced" is then what it says: a component with a location
the scope does not hold, or none.

## When it applies

Whenever one tool reads a document another wrote: importing a second tool's
CBOM to score it, handing a CBOM to a policy engine, merging inventories. It
applies with most force when the result is a comparison, because the reader's
miss lands on the other side of the table.

It does not make two shapes say the same thing. A scanner's listener lists
what the server *accepted when offered*; a passive sensor's lists what
clients and the server *selected* in the period it watched. The import
records which (`--observed`, `--conditions`, `--window`), and a comparison
states it beside the score.

## How to apply it

1. Read the document before the importer does: for ten components, write down
   the type, where the algorithm is named, and what the occurrence's location
   string looks like.
2. Choose the reading per component, by its shape, not per document; real
   documents mix them.
3. Follow references before reading names: a certificate to its key, a key to
   its algorithm.
4. Report what was not placed under separate counts (client-side, referenced,
   listener summaries, no location, out of scope, repeated) and list
   unrecognised names apart from false positives.
5. Keep the round trip as a test:

    ```sh
    uv run python -m pytest tests/test_import_shapes.py
    ```

    It projects a scored run, imports the run's own CBOM, and asserts the same
    covered items and no false positive.
6. Score the import through the entry point a scan is scored through, so an
   item a landed change removed is set aside for both
   ([lesson 86](86-excuse-a-miss-only-on-evidence.md)).

## Where the claim stops

Two shapes are read, the two met so far; a third will again place nothing
until it is read, and the counts in `left_out` are how that shows.

