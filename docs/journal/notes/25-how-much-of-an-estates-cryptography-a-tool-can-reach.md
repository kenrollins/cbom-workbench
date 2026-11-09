---
id: note-25-how-much-of-an-estates-cryptography-a-tool-can-reach
type: note
title: "How much of an estate's cryptography can a tool reach, by asset class, and how is the rest kept from disappearing into a coverage figure?"
date: 2026-11-09
audience: [leader, architect, engineer]
tags: [cbom, evidence, enumerated, managed]
rung: enumerated
one_line: "Every gap a discovery leaves — a key file not opened, a listener no scan reached, a service nobody described, a path unreadable to the scan's user, a controller certificate whose key the controller does not report, a model no supplier has attested — is written on the ledger as its own event with a stable id, the asset class it falls in, the reason and what would fill it; a person closes one by citing evidence, and coverage per asset class is counted from reached against reached plus open gaps, so the figure can only rise by evidence."
claims:
  - text: "On the four-service slice the gap rule records one gap: a private key file whose algorithm no reader identified; its listeners are 4 of 4 reached and its services 4 of 4 described."
    provenance: "measured 2026-11-09, tests/test_gaps.py over the slice's recorded scanner output"
  - text: "On a synthetic server read whole with no supplier's statement, the rule records three gaps: an unreadable path, the controller's listener no job reached, and the absence of a supplier's statement for the model, which counts every reported firmware as unreached (0 of 3); with the example statement recorded, the firmware class reads 2 of 3, the one gap the drive the statement does not name."
    provenance: "measured 2026-11-09, tests/test_gaps.py with the illustrative attestation"
  - text: "A gap's id is the hash of its kind and subject, so the same gap on a later scan is the same gap, and a fill recorded against it stands on the later scan too."
    provenance: "the design, src/pqch/assessor/gaps.py; tested in tests/test_gaps.py"
reuse: [whitepaper, talk, customer-question]
---

# How much of an estate's cryptography can a tool reach, by asset class, and how is the rest kept from disappearing into a coverage figure?

## The answer

No tool reaches all of it, and every discovery phase knows this: a phase that
scopes one plans for manual gap-fill of what the tools cannot see, by asset
class. The question is what happens to those gaps between the scan and
the person. In most tools they become a percentage, and a percentage is a
place for a gap to hide. The workbench writes each gap down instead. At the
end of a run's rules, `gap/record/1` appends one `gap.recorded` event per gap,
with the kind, the asset class, the exact subject, the reason in words, and
what would fill it. The CBOM page lists them as a queue; `pqch gap list` prints
them; a person closes one with `pqch gap fill`, which records a `gap.filled`
event citing the evidence brought (a run on this deployment and an event on
it, both checked to exist) and the basis in words. Coverage per asset class is
then a count, reached against reached plus open gaps, and it moves only when a
gap is recorded or filled.

<figure class="sketch" markdown>
![A row of asset-class boxes, listeners, entries, key files, services, firmware, controller, each with a reached count over a total and a small number of gaps beside it, drawn as slips pinned under the box. Below, one slip enlarged: a gap with its id, kind key file not opened, the file's path, the reason the reader could not open it, and what fills it, a privileged read or the owner's statement. An arrow from a document labelled evidence, run and event, to the slip, stamped filled, with the person's name and basis. A note says the id is the hash of kind and subject, so the next scan's same gap is already filled.](../img/sketches/25-gaps-as-a-queue.svg)
<figcaption>Gaps as slips under each asset class, not as a percentage; one filled by evidence a person brought, and the fill holds on the next scan.</figcaption>
</figure>

## The mechanism

**The kinds.** The rule knows nine kinds of gap, each with the class it falls
in and what fills it:

| Kind | Class | Why it is a gap | What fills it |
|---|---|---|---|
| key file not opened | key files | the reader found a key or keystore it could not open (permissions, encryption) | a privileged read-only read, or the owner's statement of the key's algorithm and size |
| algorithm unidentified | entries | an entry names no algorithm any table places | the material opened by a reader that can name it, or the owner's statement |
| listener not scanned | listeners | the scope names it and no job ran against it | a scan that reaches it |
| scan failed | listeners | every job on it ended other than ok | the job run again once its cause is removed |
| no owner's facts | services | the scope names the service and nobody supplied its facts | the system owner's facts in the context file |
| unreadable path | key files | a path the scan's user could not read on a server | a privileged read-only read |
| controller certificate key unknown | controller | the controller reports the certificate's issuer and dates and not its key | the supplier's statement of the algorithms behind the controller's identities |
| no supplier's statement | firmware | no attestation names the model | the supplier's attestation (`pqch attest`, [note 23](23-what-a-suppliers-attestation-can-stand-in-for.md)) |
| firmware not attested | firmware | the server reports a firmware the statement does not name | the statement extended to it |

**Why an event and not a count.** A gap recorded as an event has a subject a
person can act on and an id that persists. Its id is the hash of its kind and
subject, not of the run, so the same unread key on the next scan is the same
gap; a fill recorded against it holds. Each recorded gap names the finding or
scan event it rests on in its inputs, so the queue is traceable like every
other projection. A run on which the rule found nothing still carries the
rule's own assessment event with zero counts, so a page can tell "no gaps"
from "nobody looked".

**Why filling needs evidence.** `pqch gap fill` refuses a gap nobody
recorded, a run that is not on this deployment, and an event that is not on
the run it names. What it records is a person's judgement that the cited
evidence fills the gap, with their name and basis; it does not change the
inventory, which is a projection of the evidence itself. If the evidence is a
supplier's statement, the statement is already on the ledger as reported
evidence; if it is a later scan that read the file, that scan's finding is in
the CBOM. The fill is the record that someone looked and closed the loop.

**Why coverage is counted from the queue.** For each class the page shows
*reached* against *reached plus open gaps*. Listeners: endpoints in the scope
with a successful scan against those without. Entries: fingerprints judged
against those whose algorithm is unidentified. Key files: files read against
paths unreadable and keys not opened. Services: those with supplied facts
against those without. Firmware: reported firmware the supplier has named
against those it has not; with no statement at all, none is reached.
Controller: certificates with a known key against those without. A class with
nothing to count is not shown. The figure cannot be improved by a scan that
sees less; it can only rise when a gap is recorded as filled or a later scan
reaches what the earlier one did not.

## Worked example

The four-service slice records one gap: a private key file whose algorithm
no reader identified, an entry gap; its four listeners and four services are
all reached. Filled by citing an attestation run (as the owner's statement of
the key would be), the entries class reads 100 percent and the gap is listed
as filled with the person's name, the run cited and the basis. A later scan
of the same estate records the same id, so the fill stands.

A synthetic server read whole, with one unreadable path and no supplier's
statement, records three: the path, the controller's listener no job reached,
and the missing statement, which counts the three reported firmware as zero of
three reached. With the example statement recorded, a fresh read of the same
server records one gap in that class, the drive the statement does not name,
and the class reads two of three.

Measured 2026-11-09 in `tests/test_gaps.py`. The full mini-agency's and the
lab's numbers appear on their CBOM pages after their next scan; a run assessed
before the rule existed says so rather than showing zero.

## Scope

- The nine kinds are what the workbench's own evidence can tell it is missing.
  A gap it cannot detect (a device not in the scope at all) is a scope
  question, not a queue entry; the scope's authorization and the capture's
  summary are where that is answered.
- Coverage per class is this project's definition and is stated on the page.
  It is not a statement about the estate's cryptography as a whole, only about
  what the scope asked for and what was reached.
- The fill is a person's record and carries their name; the workbench does not
  judge whether the evidence suffices, it records that someone did.
