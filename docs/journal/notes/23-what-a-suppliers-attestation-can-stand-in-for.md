---
id: note-23-what-a-suppliers-attestation-can-stand-in-for
type: note
title: "What can a supplier's attestation stand in for in a CBOM, and what can it not?"
date: 2026-11-09
audience: [leader, architect, engineer]
tags: [cbom, platform, evidence, managed]
rung: structured
one_line: "The hardware half of an inventory — what signs a firmware image, which modules a controller carries, whether the installed version has a route to post-quantum algorithms — is the supplier's to state; the workbench takes such a statement in as reported evidence on a ledger of its own, joins it to a scanned server by model and firmware version, shows the two beside each other with every disagreement visible, and never lets it become a finding or outrank what the server showed."
claims:
  - text: "Of the firmware a scanned server reports through its controller, the workbench's own readers establish the name and version of each, the Secure Boot databases' certificates, the TPM's banks and the controller's TLS, SSH and settings; they cannot establish the algorithm a firmware image is signed with, the modules a controller's firmware carries, or whether a later version will carry post-quantum algorithms."
    provenance: "the readers' scope, ADR-0005 and note 20; measured on the lab's server 2026-11-04 (lab-only detail withheld)"
  - text: "On the example statement and a synthetic server reporting three firmware, the join records one firmware at the attested version, one at another version, one the statement names that the server does not report, and one the server reports that the statement does not name."
    provenance: "measured 2026-11-09, tests/test_attest.py, agency/attestations/example-supplier.yaml (illustrative, no real vendor)"
  - text: "A supplier's statement about a product is evidence about the product, not about the server: it says what version 2.4.0 is signed with, not which version this server runs; the server says that, and when the two disagree the inventory holds a conflict, not a fact."
    provenance: "the design, spec/interfaces.md `attestation.recorded` and `attestation/match/1`"
reuse: [whitepaper, talk, customer-question]
---

# What can a supplier's attestation stand in for in a CBOM, and what can it not?

## The answer

A server's cryptography is not all reachable by a reader. A scan sees its
listeners; its own files can be read; its firmware's Secure Boot databases and
TPM banks can be read; its management controller answers Redfish with its
firmware inventory, settings and certificates ([note
20](20-how-a-server-is-inventoried-and-planned-as-an-estate.md)). What no
reader reaches is what the supplier built in: the algorithm each firmware
image is **signed** with, the cryptographic **modules** inside a controller's
firmware and whether any is validated, and the **route** from the installed
version to one that carries post-quantum algorithms, if there is one. Those
are the facts a discovery phase is told to fill by hand, and they are the facts
the risk register needs most: an update path or a replacement is the
difference between a firmware release and a hardware refresh.

The workbench takes them from the supplier, as a statement, and keeps the
statement in its place. A `pqch.attestation/1` document names the supplier,
the date, and for each product (vendor and model as the firmware reports them)
each firmware by name and version with what signs it, what its listeners offer,
its post-quantum roadmap and one of four supportability words: `update`,
`replace`, `end-of-life`, `no-statement`. `pqch attest` records it on a run of
its own as `attestation.recorded` events graded **reported**, keyed by the
document's hash, so the same document twice is a no-op and a revised one a new
claim with the old one still on the record. Nothing in it becomes a finding.

Then it is **joined**, not merged. For every closed system scan whose device
is the product, the run records `attestation/match/1`: firmware by firmware,
the version the server reported beside the version the statement is about,
and whether they agree. The hosts page shows the supportability words per
server, the server's CBOM page shows the statement beside the scan in one
table, and the server's plan writes the supplier's answer onto the steps that
wait for the supplier. The server's CBOM itself is unchanged: it is a
projection of what the server showed, and the statement is another document
about the same hardware.

<figure class="sketch" markdown>
![Two columns joined in the middle. Left, observed: what the server showed to the readers, listed as firmware names and versions, Secure Boot databases, TPM banks, the controller's TLS and SSH and settings. Right, reported: what the supplier states about the model, listed as the signing algorithm of each firmware, the modules and their validation, the post-quantum roadmap and a supportability word. The join between them is labelled model and firmware version. Under the join, four outcomes with the example's counts: same version 1, another version 1, named but not reported 1, reported but not named 1. A note says the right column never crosses into the left: reported stays reported.](../img/sketches/23-observed-and-reported.svg)
<figcaption>Observed on the left, reported on the right, joined by model and version; the example's four outcomes counted; the right column never becomes a finding.</figcaption>
</figure>

## The mechanism

**What the statement can stand in for.** Three things the readers cannot
reach, and nothing else:

1. *What signs a firmware image.* The platform verifies a signature before it
   runs the image; the algorithm and key size behind that signature are the
   supplier's, invisible from inside the running system. The statement names
   them per firmware and version.
2. *The modules inside a firmware.* A controller's HTTPS and SSH are served
   by a library in its firmware; whether that library is a validated module
   (and under which CMVP certificate) is a supplier's fact. The statement lists
   the modules and their certificate numbers, or `null` where none.
3. *The route forward.* Whether the installed firmware will receive a
   post-quantum signing root, an ML-KEM hybrid in its listeners, or nothing;
   in which version and by when. The statement carries the algorithms, the
   version, a date or `null`, and the supportability word.

**What it cannot stand in for.** Anything the server itself shows. The
installed firmware version is the server's to report, and the statement is
matched to it, never substituted for it: a statement about version 2.4.0 joined
to a server at 2.3.1 is shown as a disagreement, with both numbers, and the
plan's supplier step says so in words ("version 2.4.0, not the installed
2.3.1"). What a listener accepts on the wire is measured by the targeted scan;
the statement's list of what the controller offers is shown beside it and
settles nothing when they differ. Which certificates the Secure Boot databases
hold is read from the firmware's variables; the statement's chain is a claim
about what ships, not about what is on this board after years of updates. A
statement marked `illustrative: true` stands in for nothing at all: every page
that shows it says it is a worked example and not the supplier's own.

**Why reported is a grade and not a source.** The ledger already distinguishes
who observed a finding (the tool, its version, the raw output's hash). A
statement differs in kind: the workbench did not watch it being made and cannot
reproduce it. It is therefore graded `reported` and kept on a run of its own,
where a reader can verify the chain, read the document, and see the hash that
ties each event to it. When the estate projection over many runs lands (M9),
the grade is what decides precedence: observed on the wire, observed on the
host, parsed from a file, reported in a document, in that order, and never by
vendor or tool. Until then the join is at the pages, and the server's CBOM
stays a pure function of the server's run.

**Why the join is by model and version and nothing finer.** A supplier states
facts per model and firmware version, because that is the unit it ships and
signs. A service tag or serial would join to one server, but the statement is
not about one server, and the recording export replaces such identifiers in
any case. Model and vendor are compared case-insensitively with whitespace
collapsed, because a firmware's `product_name` and a controller's `Model` do
not always agree on either; firmware names likewise. A version of `any` covers
every version of that firmware on that model, for a statement that is about
the product line rather than a release.

## Worked example

The repository's example statement (`agency/attestations/example-supplier.yaml`,
an invented supplier and product, marked illustrative) names three firmware on
one model: a BIOS at 2.4.0 signed with RSA-3072 and SHA-256, with an LMS and
ML-DSA-87 signing root planned for 3.0.0 in 2028 and supportability `update`;
a management controller at any version offering X25519 and the NIST curves,
with an ML-KEM hybrid on the roadmap and no date; and a network adapter signed
with RSA-2048 and `no-statement`. Joined to a server reporting a BIOS at 2.3.1,
the controller at 7.1.0 and an NVMe drive:

| Firmware | The server reports | The statement is about | Outcome |
|---|---|---|---|
| BIOS | 2.3.1 | 2.4.0 | another version: shown, not resolved |
| the controller | 7.1.0 | any | the same: the statement applies |
| the network adapter | not reported | any | named but not reported |
| the NVMe drive | 1.2 | not named | reported but not named: a gap for the supplier |

The plan's supplier step for the controller then reads, after its own reason,
"The supplier's statement (…, illustrative; reported, not observed) says of the
installed version: supportability update; X25519MLKEM768 in version 8.0.0, no
date given". The step is still the plan's; the supplier's words are attached to
it, labelled, and the step's due date does not move for them.

Measured 2026-11-09 in `tests/test_attest.py`; the example is not a real
vendor's statement and the lab's own server has none recorded.

## Scope

- The format is this project's; a supplier's real statement will arrive as a
  PDF or a spreadsheet and be transcribed into it, and the transcription is the
  operator's act, recorded as the `human` actor on the event.
- Supportability is the supplier's word, not a judgement: `update` means the
  supplier says an update exists or is planned, not that it has shipped or
  that the operator can install it.
- The join reads the latest matching statement. Two suppliers' statements
  about one model (an OEM's and a component maker's) are not yet combined;
  M9's conflict rules are where that belongs.
- The statement does not yet reach the CBOM entry's compatibility status
  ([note 22](22-what-compatible-means-entry-by-entry.md)); it will when the
  estate projection can carry a reported claim beside an observed one.
