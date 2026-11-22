---
id: note-21-what-a-federal-authorization-asks-of-a-cbom-tool-itself
type: note
title: "What does a federal authorization ask of a CBOM tool itself, and where does the workbench stand?"
date: 2026-11-06
audience: [leader, architect, engineer]
tags: [policy, cbom, inference, verification, managed]
rung: all
one_line: "An agency authorizes a CBOM tool as a system of its own, against the same controls as any other; the workbench's foundation (a signed ledger, the CBOM projected from it, a scope the runner enforces, images by digest, models by measurement, verification by probe) is what an assessor looks for, and the three things that would stop an authorization today are all in the shell around it: one owner with no roles, its own cryptography in no validated module, and plain HTTP to the page and the models."
claims:
  - text: "A review of the workbench at commit f3f2621 against what an agency asks before authorizing a tool on its network found thirteen findings: three that block an authorization as it stands, seven an assessor opens at once, three that strengthen a case already made; none requires the ledger, the projection or the scope to be rebuilt."
    provenance: "reviewed 2026-11-06 at f3f2621; a reading of the code and configuration against NIST SP 800-53 Rev. 5 controls, not an assessment by test"
  - text: "In the CMVP snapshot of 2026-10-20, the OpenSSL FIPS Provider (certificate 4985) lists no post-quantum algorithm; the Chainguard FIPS Provider for OpenSSL (certificate 5523, validated 2026-09-15) lists ML-DSA, ML-KEM and SLH-DSA."
    provenance: "cited: policy/snapshots/cmvp-2026-10-20.json, from the NIST CMVP pages, read 2026-10-20"
  - text: "NIST IR 8547, finalized 2026-10-27, deprecates every quantum-vulnerable signature and key-establishment scheme at or above 112 bits after 2030 and disallows it after 2035."
    provenance: "cited: NIST IR 8547 (final) Tables 2 and 4, read first-hand 2026-11-06"
  - text: "Syft 1.33.0 over the harness image found 309 packages; every one carries a name, a version and a package URL, 95% a dependency relationship, 58% a licence, 56% a producer and none a hash."
    provenance: "measured 2026-11-06 on x86_64, tools/sbom.py over an image built from branch m8-now; the element list from CISA's minimum elements as summarized, not read first-hand"
  - text: "OMB M-26-05 (2026-01-23) rescinded the government-wide secure software attestation requirement of M-22-18 and leaves each agency free to require a current SBOM on request."
    provenance: "secondary: law-firm summaries that agree with one another, read 2026-11-06; the memorandum itself not read"
reuse: [whitepaper, talk, customer-question]
---

# What does a federal authorization ask of a CBOM tool itself, and where does the workbench stand?

## The answer

An agency authorizes a cryptographic inventory tool the way it authorizes any
system on its network. It holds the tool to the controls of NIST SP 800-53
under its Risk Management Framework, and adds the policies that bear on
software, cryptography, artificial intelligence and accessibility. The tool's
purpose earns no exemption. A tool that judges an estate's cryptography is
judged on its own first.

Read against those controls, the workbench's foundation is what an assessor
looks for:

- a signed, hash-chained record
- the CBOM rebuilt from it
- scanning bounded by a scope the runner enforces
- images by digest
- models used only where measured
- changes verified by probe

The three findings that would stop an authorization today are all in the shell
around that foundation:

- one owner with no roles, so a person can propose and approve their own change
- the workbench's own cryptography running in no validated module
- plain HTTP to the page, and to the models unless a deployment turns on the
  seam's TLS requirement

None of them requires the foundation to be rebuilt.

<figure class="sketch" markdown>
![Two columns. Left, the foundation, every item ticked: a hash-chained ledger with ML-DSA checkpoints, the CBOM rebuilt from it, scans bounded by a scope file, images by digest and an offline bundle, rules first and models by measurement, verified by probes and never a model. Right, the shell: thirteen findings, the three P0 ringed in red — who may act (one owner, no roles), its own cryptography in no validated module, plain HTTP to the page and the models — then seven P1 and three P2.](../img/sketches/21-foundation-and-shell.svg)
<figcaption>The review of 2026-11-06: nothing underneath fails; the three blockers are in the shell.</figcaption>
</figure>

## The concept

A **cryptography bill of materials (CBOM)** is the inventory of an
organization's cryptography: every algorithm, key, certificate and protocol in
use, where it was found and what depends on it, in the CycloneDX format.

An **authorization to operate (ATO)** is an agency official's decision to
accept the risk of running a system, after an assessment against a baseline of
controls chosen for the system's impact level. A cryptographic inventory tool
is usually assessed at **moderate** impact: what it holds is a map of the
estate's weakest cryptography, and it can change production configuration.

Five bodies of requirement apply, beside the security baseline:

| Requirement | What it asks of the tool |
|---|---|
| FIPS 140-3 (through SP 800-53 SC-13) | Cryptography that protects federal information runs in a module the Cryptographic Module Validation Program (CMVP) has validated, for the algorithm used, with that module active |
| OMB M-26-05 and CISA's 2026 SBOM minimum elements | An agency may require a current SBOM of the software; what one must hold |
| OMB M-25-21 | Each AI use inventoried; whether any is high-impact decided; minimum practices for those that are |
| Section 508 | The interface meets WCAG AA; an Accessibility Conformance Report for procurement |
| Supply-chain exclusion orders (FASCSA) | No excluded product, including AI models: DHS's order 2026-01 excludes DeepSeek and products built on it from civilian systems |

## The mechanism: what an assessor reads

An assessor reads a tool the way a reviewer reads a design. Who can act, and
how is it recorded? What protects the data in transit, at rest and in the
record? What runs with privilege? What can the vendor show about the software
itself? Where does a model decide something?

The workbench answers each of those from its record (ADR-0001: the ledger is
the system of record). That makes its gaps unusually easy to see: each is a
place where the record is right but the thing around it is not.

| Question | What holds | What would stop an authorization |
|---|---|---|
| Who may act? | Every approval is an event naming the person and how they were authenticated, covered by a signed checkpoint before the runner applies anything; the scope names the system, the person and role who authorized it, and a window the runner enforces | No roles: any signed-on person may propose, approve and apply, and the page approves and applies in one request (P0) |
| What protects the record? | SHA-256 chain; ML-DSA checkpoints (ML-DSA-65, or ML-DSA-87 by setting) from a signer with no network that keeps its own record, with each caller's uid from the kernel; every ledger names the cryptographic libraries and FIPS state it was written under | The signing and hashing run in OpenSSL builds with no validated FIPS provider active (P0) |
| What protects the traffic? | Internal-only bridges with explicit subnets; the inference seam can require TLS with a named CA and record how each call travelled; management-controller sessions can be held to a CA, a pin, or the certificate the same read observed (not yet to one an earlier read saw) | The page itself is plain HTTP, and the TLS requirements are settings a deployment has to turn on (P0 until it does) |
| What runs with privilege? | The runner refuses anything outside its fixed, digest-pinned profiles and the scope; the capture service is fully confined; the harness services hold no capability and cannot gain one, and wire-probe jobs run with none (set in the compose files and the runner; not yet exercised in a running stack) | The runner's Docker socket is root on the host, and the jobs that read archives keep Docker's default capabilities (P1) |
| What can be shown about the software? | Images by digest, an offline bundle checked blob by blob and its sums signed with ML-DSA, an SBOM of the harness image on demand, a licence table, CI actions pinned by commit with a dependency audit | No CBOM of the workbench by its own pipeline yet; the SBOM carries no component hash (P1) |
| Where does a model decide? | Only in roles measured against a floor written first, each with a card; every call recorded with model, engine, hardware and prompt hash; a model-set fact in the CBOM says which model set it; the seam can refuse a model of an origin not on the allowlist; no model verifies a change | The allowlist works only once each model's origin is declared in the config (P1) |
| Is the content current? | Policy packs as data, every passage cited; NIST IR 8547 beside M-26-15, each deadline naming the source that set it | CNSA 2.0 still read second-hand (P1) |

The checkpoint algorithm adds one point. For the ledger's integrity to count
under SC-13, ML-DSA has to be on the module's certificate. The OpenSSL FIPS
Provider's certificate 4985 lists no post-quantum algorithm. In the CMVP
snapshot of 2026-10-20, one OpenSSL provider does: Chainguard's, certificate
5523, validated 2026-09-15. A post-quantum audit trail and a validated one are,
for now, a choice of base image.

## Worked example: the approval of one change

A change to the portal's key exchange on the four-service slice follows this
path: it is proposed, a person approves it, the runner applies it, and paired
probes verify it (a model-drafted change is also rehearsed on a twin first).
Today it fails an assessor on one point.

- **What passes.** The ledger shows the proposal, the rehearsal, the approval
  with the approver's name and how they were authenticated, a checkpoint signed
  either side of the approval, the apply, and two verdicts.
- **What fails.** Nothing on that record, and nothing in the runner, stops the
  person who asked for the proposal from approving it, in the same request
  that applies it.

The change that passes keeps the whole path:

- the approval event records the role and the authentication context from the
  identity provider
- the runner refuses an approval by the requester
- the apply becomes a separate act

The ledger gains three fields and the runner three refusals. Separation of
duties is a property the record can then prove, not one the operator promises.

## What follows

- **Review the tool before building on it.** The cheapest moment to find that
  a foundation cannot pass is before a customer depends on it. Here it can,
  and the work is in the shell, ordered as milestone M8 of the plan.
- **Hold the tool to its own standard.** A CBOM tool should produce its own
  SBOM and CBOM, sign its releases with the algorithm it recommends, and run
  that algorithm in a module validated for it. Each is a demonstration as well
  as a control. An SBOM tool's output is not yet a minimum-elements SBOM:
  Syft over the workbench's image names every package but hashes none of
  them, and finds a producer for only 56% and a licence for 58%.
- **Make each requirement a setting before making it a default.** A check
  that refuses plain HTTP, an expired controller certificate or an unpinned
  image changes a running deployment the day it ships. Shipped as a setting,
  recorded when used, it can be turned on deployment by deployment.
- **Label every fact a model produced.** The record already says which facts
  a model made. The CBOM a consumer reads has to say so too, or an agency
  cannot complete its AI inventory from it.
- **Check origin in the seam, not in a comment.** A model of excluded origin
  is one configuration change away on any shared inference host. The seam that
  binds tiers to models is the place to refuse it.
- **Ask the customer four things first:**
  - whether the system is a national security system, which brings CNSA 2.0
    and NSA approval of the workbench's own cryptography (CNSSP 15)
  - the impact level
  - the identity provider and the claims it sends
  - the inventory template they file

## Scope

Covered: the findings, the workbench at commit `f3f2621`; the table's "what
holds" column, branch `m8-now` after milestone M8's first part (2026-11-06) and
its review (2026-11-08), not yet merged or deployed; its configurations for the
lab and for one box, read against SP 800-53 Rev. 5 controls at a moderate baseline,
FIPS 140-3 through the repository's own CMVP snapshot, NIST IR 8547 (read
first-hand), and OMB M-26-05, M-25-21, the FASCSA order and CISA's 2026 SBOM
minimum elements through summaries that agree with one another.

Not covered:

- no control was tested and no running service was probed
- no penetration test, and no assessment under SP 800-53A
- FedRAMP, which applies only to a hosted offering
- Department of Defense impact levels and STIGs, which a defense customer
  makes mandatory

The findings with their evidence are kept privately with the plan; this note
states what holds generally.

## References

- NIST SP 800-53 Rev. 5 — the controls named above (AC-5 separation of duties,
  CM-3 change control, SC-8 transmission, SC-13 cryptographic protection,
  AU-9 protection of audit information, SR-4 provenance).
- FIPS 140-3 and the CMVP validated modules list — what counts as validated
  cryptography; certificates 4985 and 5523 as recorded in the repository's
  snapshot.
- NIST IR 8547 (final, 2026-10-27) — the 2030 deprecation and 2035
  disallowance of every quantum-vulnerable family.
- OMB M-26-05 (2026-01-23) — attestation rescinded; SBOM on request.
- CISA, *2026 Minimum Elements for a Software Bill of Materials*
  (2026-07-29) — what an SBOM must hold.
- OMB M-25-21 — AI use-case inventory and minimum practices for high-impact AI.
- DHS FASCSA exclusion and removal order 2026-01 — DeepSeek and products built
  on it.
- Section 508 (36 CFR 1194) and WCAG — accessibility.
- Related notes: [what federal policy requires, and by when](03-what-federal-policy-requires-and-when.md);
  [what an auditable record contains](12-what-an-auditable-record-contains.md);
  [where models belong](13-where-models-belong.md).
