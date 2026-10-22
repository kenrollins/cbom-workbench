---
id: note-03-what-federal-policy-requires-and-when
type: note
title: "What does federal policy require, and by when?"
date: 2026-10-20
audience: [leader, architect, engineer]
tags: [policy, cbom, discovery, managed]
rung: all
one_line: "Executive Order 14412 and OMB M-26-15 require an inventory now, post-quantum key establishment on prioritized systems by the end of 2030 and signatures by the end of 2031 — and the minimum elements of the inventory itself are not published until 2027-03-19, which is why this project builds a record and projects the CBOM from it."
claims:
  - text: "OMB M-26-15, dated 2026-06-24, requires each agency's PQC Migration Plan within 120 days, 2026-10-22; it does not apply to national security systems."
    provenance: "cited: OMB M-26-15 §1 and §3.B, read first-hand 2026-10-03; the date computed"
  - text: "M-26-15 phases migration: discovery 2026–2027, pilots 2027–2028, prioritized key-establishment migration 2028–2030, signature migration 2031, full migration 2035; TLS 1.3 support no later than 2030-01-02."
    provenance: "cited: OMB M-26-15 §3.D and §4"
  - text: "Executive Order 14412 (2026-06-22) sets post-quantum key establishment on HVAs and high-impact systems by December 31, 2030 and digital signatures by December 31, 2031, and directs CISA and NIST to publish the minimum elements of a CBOM within 270 days, 2027-03-19."
    provenance: "cited: EO 14412 as recorded in BRIEF.md's facts table, read through a summarizing tool on 2026-10-03 — check the quotations against the published order before reuse; the 270-day date computed"
  - text: "M-26-15 requires a central CBOM populated from software composition analysis, static and dynamic testing, and network scanning."
    provenance: "cited: OMB M-26-15 Appendix A §6, read first-hand 2026-10-03"
  - text: "CNSA 2.0 requires new national security system acquisitions to be compliant from 2027-01-01."
    provenance: "secondary: summaries of the NSA CNSA 2.0 FAQ that agree with one another; NSA's site refused the primary document on 2026-10-05 and 2026-10-20, so it was not read first-hand"
reuse: [whitepaper, talk, customer-question]
---

# What does federal policy require, and by when?

## The answer

Two documents set the clock for United States federal civilian agencies.
Executive Order 14412 (2026-06-22) requires post-quantum key establishment on
high-value assets and high-impact systems by the end of 2030 and post-quantum
digital signatures on them by the end of 2031, and directs CISA and NIST to
publish the *minimum elements* of a cryptography bill of materials (CBOM)
within 270 days, which is 2027-03-19. OMB memorandum M-26-15 (2026-06-24)
turns the order into a programme: a migration plan from each agency within
120 days (2026-10-22), a discovery phase through 2027 in which the inventory is
built, and a central CBOM fed from three kinds of evidence. The inventory is
therefore required before anyone has said what it must contain. That gap —
five months between the discovery phase starting and the minimum elements
appearing, and the risk that an inventory built to one shape is measured
against another — is the reason this project keeps every finding with its
evidence on a ledger and treats the CBOM as a projection of that record.
National security systems are on a separate clock, CNSA 2.0, with new
acquisitions compliant from 2027-01-01.

## The concept

Post-quantum cryptography (PQC) replaces the public-key algorithms a large
quantum computer could break — RSA, Diffie-Hellman and elliptic-curve
schemes — with algorithms NIST standardized in 2024: ML-KEM (FIPS 203) for key
establishment and ML-DSA (FIPS 204) for signatures. Key establishment comes
first because traffic recorded today can be decrypted later once the key
exchange is broken ("harvest now, decrypt later"); a signature forged later
does not retroactively undo anything signed today.

A CBOM is the inventory of an organization's cryptography: every algorithm,
key, certificate and protocol in use, where it was found and what depends on
it, in the CycloneDX format ([note 01](01-what-is-a-cbom.md)). A high-value
asset (HVA) is a federal system designated as such for the information it
holds or the function it serves; a high-impact system is one whose loss would
have severe effect under FIPS 199. M-26-15 adds systems with highly sensitive
data and any the agency judges particularly exposed. These are the systems the
dates apply to; everything else is Phase 5.

## The dates

| Date | What | Source | What it asks of an inventory |
|---|---|---|---|
| 2026-06-22 | EO 14412 signed | EO 14412 | — |
| 2026-10-22 | Each agency's PQC Migration Plan due to OMB and ONCD | M-26-15 §1 | The plan names an inventory approach before the inventory exists |
| 2026–2027 | Phase 1: strategy, planning and discovery — inventory, assessment, governance, accountable officials | M-26-15 §3.D | The inventory is built in this window |
| 2027-01-01 | New national security system acquisitions CNSA 2.0 compliant | NSA CNSA 2.0 FAQ, through secondary summaries; the primary refused the download on 2026-10-05 and 2026-10-20 and was not read | A separate clock for a separate community |
| **2027-03-19** | **CISA and NIST publish the minimum elements of a CBOM** | EO 14412 (270 days) | Until then, "a CBOM" means CycloneDX 1.6 plus whatever an agency or vendor adds; after it, an inventory is measured against a published list |
| 2027–2028 | Phase 2: pilots and early migration of prioritized systems | M-26-15 §3.D | The inventory must say what first: owners, deadlines, blockers |
| 2028–2030 | Phase 3: prioritized migration of key establishment | M-26-15 §3.D | The first queue |
| 2030-01-02 | TLS 1.3 supported | M-26-15 §4 | Hybrid key establishment in TLS is a TLS 1.3 mechanism; a listener on 1.2 alone cannot offer ML-KEM |
| 2030-12-31 | Key establishment post-quantum on HVAs and high-impact systems | EO 14412; M-26-15 Phase 3 | The first queue closes |
| 2031 / 2031-12-31 | Phase 4: signatures post-quantum on the same systems | M-26-15; EO 14412 | The second queue; it waits on validated modules and certificate chains |
| 2035 | Phase 5: full migration of remaining systems | M-26-15 §3.D | — |

Two further requirements shape what the inventory has to hold. M-26-15
Appendix A §6 says the central CBOM is populated from software composition
analysis, static and dynamic testing of code, and network scanning — the three
evidence layers this project calls code, host and wire. And on enforcement it
says devices must be configurable to use *only* acceptable algorithms: an
inventory that records what a listener offers, but not whether it still
accepts the old algorithm, cannot show that requirement met
([note 08](08-what-verified-means.md)).

## What the gap means for how an inventory is built

The minimum elements are a list that does not exist yet. Three ways to build
an inventory in the meantime:

| Approach | When the minimum elements arrive |
|---|---|
| A spreadsheet or a document edited to today's best guess | Re-collected by hand against the new list; nothing in it can show where its rows came from |
| A CBOM document written directly by scanners | Re-scanned, and anything the scanners did not keep — the raw output, the rule that linked two findings — is gone |
| A ledger of findings with their evidence, the CBOM projected from it | Re-projected: the same record, a new shape, no re-scan. Fields the list does not ask for are dropped from the projection and kept in the record |

The third is this project's design (ADR-0001 in the repository, *the ledger is
the system of record*):
the ledger is the system of record, the CBOM is rebuilt from it, and the CBOM
carries more than any minimum is likely to ask — dependencies, data lifetime,
the evidence hash for every entry, the listener's posture, the verifier verdict
for every change. The bet is that the published minimum will be a subset of
these, and the way to find out which is to hold them all and project.

The same gap is why the project starts now rather than waiting for the list.
The discovery phase is this year and next; an agency that waits for the
minimum elements before building an inventory arrives at the pilots phase
with nothing to pilot.

## Scope

Covered: the dates and requirements in EO 14412 and OMB M-26-15 as they bear
on a cryptographic inventory, and CNSA 2.0's acquisition date. M-26-15 was
read first-hand (again on 2026-10-20, from the PDF with sha256 515af704…).
CNSA 2.0 was not: NSA's site refused its FAQ and advisory on 2026-10-05 and
2026-10-20, and its date here is from secondary summaries that agree. EO 14412 was read through a summarizing tool on 2026-10-03;
its quotations in the repository's facts table should be checked against the
published order before they are reused in anything public.

Not covered: what the minimum elements will turn out to be; agency-specific
plans; how the dates apply to systems outside the prioritized categories
beyond Phase 5; national security systems in any detail
(planned as note 11).

## References

- Executive Order 14412 (2026-06-22) — the deadlines and the direction to
  CISA and NIST on the minimum elements of a CBOM.
- OMB M-26-15, *Execution of the Migration to Post-Quantum Cryptography*
  (2026-06-24) — §1 the plan, §3.D the phases, §4 TLS 1.3, Appendix A §6 the
  central CBOM and its three evidence sources.
- NSA, CNSA 2.0 FAQ — the national security system dates; not read first-hand (refused twice), the date taken from secondary summaries.
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA).
- `BRIEF.md` in the repository, "The clock" and the facts table — every date
  above with its provenance.
- Related notes: [what a CBOM is](01-what-is-a-cbom.md);
  [what "verified" means](08-what-verified-means.md).
