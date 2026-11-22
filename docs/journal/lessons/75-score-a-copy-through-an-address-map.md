---
id: lesson-75-score-a-copy-through-an-address-map
type: lesson
title: "Score a copy of an estate through an address map on the copy's scope, never through an edited key; judge a remediated item by when the copy was taken"
date: 2026-11-15
audience: [architect, engineer]
rung: structured
tags: [cbom, discovery, evaluation, answer-key, scope]
one_line: "When two tools must inventory the same machines, the estate is copied to a network both can see and re-addressed; the copy's scope names each listener's original, the scorer maps addresses back at matching time, the one key stays the source of truth, and the copy's CBOM keeps the addresses a sensor there sees. A change the estate applied counts as remediated in the copy only if it was verified before the copy was taken."
claims:
  - text: "A scope may declare itself a copy: `copy` (what it copies, when it was taken, the applied changes it carries) and `copy_of` on every listener. The scorer builds the address map from the scope, maps each wire component's and listener's address before matching, and records the map in the score; the run is kind `scan-copy`, with the scan window on the ledger as `window.opened` and `window.closed`."
    provenance: "src/pqch/score.py (address_map, score_run), src/pqch/pipeline.py (scan_copy, remediated_changes, remediated_rows), src/pqch/schemas/scope.json, spec/interfaces.md; tests/test_copy.py, 2026-11-15; the remediated rule as it stands from 2026-11-21, tests/test_import_shapes.py"
  - text: "On the fixture slice re-addressed to another network, the copy scores 22/23 wire items with 0 false positives and 4/4 postures through the map, the same as the slice itself; unmapped, the same CBOM matches 0 items."
    provenance: "tests/test_copy.py, 2026-11-15"
  - text: "Another tool's CBOM of the copy, imported under the copy's scope (`pqch import --scope`), is scored through the same map and the score records it; under the estate's own scope the same document places no listener."
    provenance: "src/pqch/scout/imported.py (run_import), src/pqch/cli.py; tests/test_copy.py, 2026-11-16"
reuse: [whitepaper, customer-question]
---

# Score a copy of an estate through an address map on the copy's scope, never through an edited key; judge a remediated item by when the copy was taken

## The rule

When an estate is copied to another network so that a second tool can
inventory the same machines in the same state, keep **one answer key**, with
the estate's own addresses. Put the correspondence on the copy's scope — the
scope declares what it copies and when the copy was taken, and every listener
names the original it is a copy of — and let the scorer map addresses back at
matching time. Never edit the key for the copy, and never re-address the
copy's CBOM: the CBOM says what a sensor on that network sees. A keyed item the
estate removed by an applied change counts as remediated in the copy only when
the change was verified **before the copy was taken**, not before the scan,
and the copy's scope declares that it carries that change.

<figure class="sketch" markdown>
![On the left the answer key, holding the estate's address for one listener, portal at 172.16.106.10; on the right the copy's CBOM, holding the copy's address for the same listener, portal at n.n.n.101; between them, ringed in red, the copy's scope, on which copy_of names the original, and an arrow from the copy's address to the key's labelled mapped at scoring. Below, a timeline: the change lands on 2026-10-22, the copy is taken on 2026-11-01, the copy is scanned on 2026-11-15; a bracket from the change to the day the copy was taken says that what landed before the copy was taken is remediated in the copy too.](../img/sketches/75-one-key-two-addresses.svg)
<figcaption>One key, two networks: the map lives on the copy's scope and is applied at scoring; the cut-off for a remediated item is the day the copy was taken.</figcaption>
</figure>

## Why

An answer key is the written truth about one built estate: for every listener,
the key establishment and signature algorithms it uses, the decoys that look
present but are not, and the items no tool can reach. It is committed by hash
before a run, and a run is scored only against the key whose hash it recorded.
A second copy of the key, edited to the copy's addresses, is a second truth: it
has its own hash, drifts when the first is corrected, and leaves a reader
unable to say which number came from which key. One key, one hash, one source.

The copy's CBOM has the opposite constraint. It is the document another tool's
inventory is compared with, and that tool sees the copy at the copy's
addresses. A CBOM re-addressed to the estate's would describe machines the
sensor never saw. So the CBOM keeps the copy's addresses, and the join between
the two address spaces happens in exactly one place, at scoring, from a table
the run itself carries: the scope recorded in its first ledger event. The score
records the map it used, so the number is reproducible from the run directory
alone.

The cut-off follows from what a copy is. A frozen copy carries the estate as it
stood when the copy was taken: any change applied before then, and nothing
after. The estate's own scorer sets a missed key-establishment item aside as
remediated when the listener's latest landed change before the scan began
requires the replacement and does not keep that item, no reset followed, and
the column holds some component for the listener; what is set aside leaves
the denominator ([lesson 86](86-excuse-a-miss-only-on-evidence.md)). For a
copy, "before the scan began" is wrong in both directions: a change landed
after the copy was taken is not in the copy, and a reset of the estate after
the copy was taken does not undo what the copy carries. The right instant is
the copy's `taken` time, and the scope states it. The scope also lists the
changes the copy carries (`carries`), and only a listed change excuses
anything in the copy: the estate's history is evidence about the copy only
as far as the copy's own declaration reaches.

## When it applies

Any evaluation where two tools must see the same machines in the same state
and one of them cannot reach the estate where it lives: a wire sensor that
needs a switch port it can mirror, a vendor appliance that must sit on a
network of its own, a reference target kept frozen while the estate is
changed. It applies to a copy of a scored estate; a copy of an estate with no
answer key is an external scan like any other, and gains nothing from the
mapping.

It does not apply when the copy is rebuilt rather than copied: certificates
and host keys are generated at build time, so a rebuilt copy is a different
estate with the same names, and its fingerprints will not match. Check the
copy's fingerprints against the estate's before trusting any comparison.

## How to apply it

1. **Freeze the copy and record when.** Export the running images unchanged
   (not a rebuild), checksum them, and note the export time; that is `taken`.
   Record the applied changes the copy carries, by change id.
2. **Write the copy's scope** as an external, unowned estate with the owner's
   authorization, and on it:

    ```json
    "copy": {"of": "mini-agency", "taken": "2026-11-01T13:36:50Z",
             "carries": ["01M5FHSTVRHX7QPN6KMTDV89Y9"]},
    "endpoints": [
      {"host": "n.n.n.101", "port": 443, "transport": "tcp", "protocol": "tls",
       "sni": "portal.agency.test", "service": "portal",
       "copy_of": {"host": "172.16.106.10"}},
      ...
    ]
    ```

    A scope short of any of this — not external, no `copy`, a listener with no
    `copy_of` — is refused by `pqch scan-copy`, so a plain external scan cannot
    be mistaken for a scored copy.
3. **Give the copy its own runner** on the copy's network, with that scope and
   no ability to apply anything: the same image and job set, its own socket
   and log, one leg on the target network. Nothing about the copy is changed
   by scanning it.
4. **Scan in a declared window.** `pqch scan-copy --key agency/answer-key.yaml
   --runner-socket … --sources "…"` commits the key, writes `window.opened`
   with the addresses the scans come from, runs the wire jobs, writes
   `window.closed`, and scores through the map. The window matters when
   another tool watches the same wire: its inventory will show the scanner's
   handshakes as client profiles, and the two timestamps let a reader
   separate them from real clients.
5. **Read the score's `copy` block** for the map and the facts it rested on,
   and compare the copy's wire entries with the estate's own run by host, port,
   type, role and name, after mapping. Any difference is a finding about the
   copy or the network, not about the tools; then check the fingerprints.
6. **Score the other tool's document through the same map.** `pqch import
   <its CBOM> --scope <the copy's scope> --key …` places its listeners at the
   copy's addresses and scores them against the key's originals, recording
   the map in its `import.completed` event; under the estate's own scope the
   same document places nothing, which is the check that the right scope was
   given.

## Where the claim stops

The map is one-to-one on (host, port). An estate copied behind a port
translator, where several originals share one address, needs a map keyed on
the port too; the schema allows a `copy_of.port`, and the scorer honours it,
but that case has not been run. The window is the operator's statement of
where the scans come from; nothing checks it against the packets.
