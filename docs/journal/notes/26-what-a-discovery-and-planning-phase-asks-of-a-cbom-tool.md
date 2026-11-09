---
id: note-26-what-a-discovery-and-planning-phase-asks-of-a-cbom-tool
type: note
title: "What does a discovery-and-planning phase ask of a CBOM tool, and what does this one answer, measured?"
date: 2026-11-09
audience: [leader, architect, engineer]
tags: [cbom, policy, managed, verification]
rung: all
one_line: "The phase most organisations start with discovers every piece of cryptography, records it in a CBOM, tags each entry against the policy that governs it, maps what is not compatible to its system and owner, prices the risk and hands a plan to the phases that deploy; against that list the workbench answers nine of ten asks from the ledger on the mini-agency (313 components, 183 not compatible, 10 gaps recorded, 25 steps in three buckets), and the one it does not, a proof in a commercial consumer, is named and waiting."
claims:
  - text: "On the mini-agency's scan of 2026-11-09 (run 01M6Z41DJB5911EF1Y65K2FBTY, 897 ledger events, 313 CBOM components), the entry rule tags 8 entries compatible, 183 not compatible, 11 unknown and 19 outside the pack under OMB M-26-15; in use, 8, 173, 11 and 17."
    provenance: "measured 2026-11-09 on the lab's x86_64 server, harness at 29cb4cb, from the run's workbench.cdx.json"
  - text: "The same scan records 10 gaps (9 entries whose algorithm no table places, 1 key file the reader could not open) and reaches 9 of 9 listeners, 8 of 8 services, 217 of 227 entries and 141 of 142 key files."
    provenance: "measured 2026-11-09, the run's gap.recorded events and pqch gap list"
  - text: "Eight images' SBOMs (19 to 221 packages each) name 43 libraries that provide cryptography; 13 are linked to something a listener negotiates or serves and 30 are present with nothing observed using them."
    provenance: "measured 2026-11-09, the run's sbom.observed events and library components"
  - text: "The plan from the same run has 25 steps in three buckets, 9 in identity, PKI and signing, 12 in infrastructure and data protection, 4 in applications and mission systems; two services carry an owner's cost, 160,000 USD together, planted; five carry none."
    provenance: "measured 2026-11-09, the run's register.json"
  - text: "Seventeen entries carry more than one claim and nine a parameter the claims disagree on, every one kept; the consumer copy leaves out the 12 entries the rules judged not in use."
    provenance: "measured 2026-11-09, the run's workbench.cdx.json and workbench-consumer.cdx.json"
reuse: [whitepaper, talk, customer-question]
---

# What does a discovery-and-planning phase ask of a CBOM tool, and what does this one answer, measured?

## The answer

The phase an organisation starts its post-quantum work with is not a
migration. It is a discovery and a plan: find every piece of cryptography in
scope, record it in a cryptography bill of materials, decide what is not
compatible with the policy that governs the system, map each such item to its
system, interface, mission thread and owner, build a risk register, and hand
the phases that deploy a schedule and a cost. It deploys nothing. Its
deliverables are the CBOM, the compatibility assessment, the dependency map,
the register and the plan; its gaps are what no tool could see, filled by
hand; its hardware half is the supplier's to attest.

Ten asks follow from that, and the table below says what the workbench
answers for each, measured on the mini-agency on 2026-11-09, and where the
answer stops. The workbench is a research project and an exploration, not a
product (BRIEF); what it offers such a phase is the method, the record and the
instruments, each one checkable.

| What the phase asks | What the workbench answers | Measured on the mini-agency | Where it stops |
|---|---|---|---|
| Where the CBOM lives and who maintains it | A signed, append-only ledger is the record; the CBOM is a projection rebuilt from it; approvals, resolutions and fills are events on it ([note 12](12-what-an-auditable-record-contains.md)) | 897 events, 313 components, same ledger same document | one deployment, one owner's ledger; roles by setting (ADR-0008) |
| Discovery across the asset classes | Wire, host, code and platform readers; the SBOM beside them; any tool's CBOM imported and scored ([note 15](15-what-the-open-source-scanners-cover.md)) | 35 of 35 keyed wire items; 8 images' SBOMs, 43 crypto libraries, 13 in use | HSMs and crypto modules by attestation only; the code layer one repository |
| Every entry tagged against the governing policy | `compatibility/entry/1`: compatible, not compatible, unknown, outside the pack, provisional under a pack not read first-hand ([note 22](22-what-compatible-means-entry-by-entry.md)) | 8 / 183 / 11 / 19; in use 8 / 173 / 11 / 17 | CNSA 2.0 provisional until the primary documents are read |
| Vendor supportability on the hardware | A supplier's attestation as reported evidence, joined by model and firmware version, never a finding; modules looked up in the CMVP snapshot ([note 23](23-what-a-suppliers-attestation-can-stand-in-for.md)) | an illustrative statement; the lab's server has none recorded | no real supplier's statement yet |
| The dependency map | The plan's shared dependencies: the certificate authority, the library build, the shared key, the client trust anchor ([note 17](17-how-a-cbom-becomes-a-migration-plan.md)) | 25 steps, 4 shared dependencies | the lab's and a server's plans have their own rules |
| System, interface, mission thread, owner, classification per item | Owner-supplied facts, labelled supplied, on the service component and every register row ([note 24](24-what-a-later-phase-needs-from-a-discovery-phase.md)) | 8 services with all four; none invented | typed in; the owner's inventory is the source |
| A risk register with impact, exposure, vendor path and cost | The register: priority and its criteria, deadline and what set it, blocked on the supplier, the vendor's path and the cost as the owner's words, summed once per service | 25 rows; 160,000 USD across 2 services, 5 uncosted | nothing is estimated; a cost model sits outside and cites it |
| The plan grouped for the later phases | `policy/buckets.yaml`: identity, PKI and signing; infrastructure and data protection; applications and mission; none unplaced | 9 / 12 / 4 / 0 | the split is one programme's; the pack is edited for another |
| What no tool could see | `gap/record/1`: each gap an event with a stable id, its class, reason and what fills it; coverage per class counted from it ([note 25](25-how-much-of-an-estates-cryptography-a-tool-can-reach.md)) | 10 gaps; listeners 9 of 9, services 8 of 8, entries 217 of 227, key files 141 of 142 | the nine kinds are what the evidence can tell it is missing |
| A CBOM a policy engine can read | The standard's fields filled with references that resolve, the consumers' names beside the workbench's, a consumer copy without the retired material (ADR-0007) | 24 referenced components; 12 entries left out of the consumer copy | the re-upload to a commercial engine is not yet done |

## The mechanism, in one pass through the pages

A reader shown the workbench follows the phase's own order:

1. **The test agency**, so the answer key is on the table before the tool is:
   eight services, every weakness planted, decoys in every layer.
2. **Inside the CBOM**: the document's counts, then every entry tagged under
   its pack with unknown counted apart; the claims kept where two tools
   described one entry; the gap queue with coverage per class; one entry opened
   field by field with the evidence behind each field, the referenced
   signature algorithm and public key among them; the same record projected as
   an inventory.
3. **The plan**: the steps, the shared dependencies drawn, what comes first
   and why, and at the end the hand-off: the three buckets and the register
   to download.
4. **Hosts**, for the hardware half: a server read whole, the supplier's
   statement beside what the server showed, the modules against the CMVP
   snapshot, and the firmware the statement does not name as gaps.
5. **Imports**: a vendor's CBOM of the same estate scored against the key, and
   the scan and its imports projected as one document with every disagreement
   shown.
6. **The ledger**, last: the events behind every number above, hash-chained
   and signed, with the record page listing each document and its hash.

The waits, the numbers and the engines are labelled as the stage labels them;
nothing in the pass is a model's judgement of whether a thing worked.

## What this changed about the claim

The BRIEF's claim is about taking the mini-agency from Opaque to Agile with a
CBOM built from evidence and verified by re-scan, with the models' roles
measured. A discovery-and-planning phase stops before Agile: it asks for the
Structured and Managed rungs done thoroughly and handed over, and it asks
three things the claim did not name: that every entry be judged under a
policy with the unknowns kept apart, that what no tool could see be written
down rather than averaged away, and that the supplier's part of the inventory
be taken in as evidence of its own grade. All three are now rules on the
ledger, and each is measured above. The claim's own clauses are untouched by
them: the score, the baselines, the verifier and the roles table read the
same.

## Scope

- The numbers are the mini-agency's, a planted estate with an answer key.
  The lab's own estate and its server are read the same way; their numbers
  are the owner's and stay off the public copy.
- Four answers are complete in mechanism and waiting on an outside party for
  their proof: a real supplier's statement, the CNSA 2.0 primary documents, a
  commercial engine to re-upload into, and a second real server for the SSH
  route.
- The workbench is not the tool such a phase would accredit; it is the method
  and the record shown working, with every number traceable to an event. The
  gaps between that and an accreditation are the federal readiness rows in
  the plan, three of which became settings on 2026-11-09 (marking, retention,
  roles and separation of duties).
