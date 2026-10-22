---
id: note-07-how-a-migration-priority-is-computed
type: note
title: "How is a migration priority computed?"
date: 2026-10-20
audience: [leader, architect, engineer]
tags: [policy, managed, cbom, verification]
rung: managed
one_line: "A migration priority is computed, not chosen: a rule reads the memo's own criteria against the owner's facts to decide whether a system is prioritized, reads the memo's table to decide which of its algorithms are quantum-vulnerable, and places each system's key establishment and signatures in the queue the memo names with its date — and two more rules, each resting on a dated measurement, say whether the change is blocked on a supplier or on a validated module."
claims:
  - text: "On the eight-service mini-agency, OMB M-26-15's criteria prioritize seven of eight services — three by high impact, high-value status and data lifetime, four by data lifetime alone — leaving the administrative jump host, whose data stays sensitive for one year, to the 2035 queue."
    provenance: "measured 2026-10-20, scan run 01M5DFXYNNG08S8ADTDF48WYFE on the xr7620 (x86_64); rule priority/m-26-15/1 over agency/context.yaml (planted, supplied facts)"
  - text: "Fourteen migration items are open and two met: six in the key-establishment queue due 2030-12-31, six in the signature queue due in 2031, two in the 2035 queue; the post-quantum gateway meets both functions. Three of the open key-establishment items offer the hybrid group beside a classical one, enabled and not enforced."
    provenance: "the same run; rule queue/m-26-15/1 over policy/packs/m-26-15.yaml"
  - text: "Seven of the fourteen open items are blocked on their supplier: the runtimes of OpenSSH 6.6, Java 8 and RabbitMQ 4 on Erlang/OTP 27 list no post-quantum algorithm in either function, and OpenSSH 10 lists ML-KEM key exchange but no post-quantum host-key algorithm. Erlang/OTP 27 links OpenSSL 3.5.9, which has ML-KEM; its own TLS stack lists no ML-KEM group."
    provenance: "measured 2026-10-20, tools/probe_capabilities.py, each image run with --network none; raw outputs under eval/capabilities/2026-10-20/ with their hashes"
  - text: "Of 92 active FIPS 140 certificates whose module name or vendor matches OpenSSL, Java, Erlang or OpenSSH, one lists ML-KEM among its approved algorithms and two list ML-DSA; the OpenSSL project's own validated provider (certificate 4985) lists neither, and no Java, Erlang or OpenSSH module lists either."
    provenance: "NIST CMVP search and certificate pages read 2026-10-20 by tools/cmvp_snapshot.py; policy/snapshots/cmvp-2026-10-20.json carries every page's SHA-256"
  - text: "A model asked to explain each open item's queue from three retrieved passages of the pack passed 3 of 14 items against a floor of 13, with 3 harmful calls of 42; retrieval missed the item's queue passage in 11 of 14, and the model passed 9 of 9 calls where it was retrieved. The role is unbound."
    provenance: "measured 2026-10-20, explain run 01M5DG1NY5M7E165RF1TCYVSRN; Gemma 4 31B FP8 on the xr7620's four L4s (gateway lane vllm/gemma-4-31b-l4, thinking off), lab/embed for retrieval; median 3.2 s a call; floor of 13 of 14, written before the first call"
  - text: "OMB M-26-15 prioritizes a high-impact system, a High Value Asset, and a system with data expected to remain mission-sensitive in 2030; it puts key establishment for prioritized systems in Phase 3 (2028–2030, with mitigation by December 31, 2030), signatures in Phase 4 (2031), the rest by 2035, and TLS 1.3 support no later than January 2, 2030."
    provenance: "cited: OMB M-26-15 §3.A, §3.C.2, §3.D and §4, read first-hand 2026-10-20 from the PDF with sha256 515af704…; policy/sources/m-26-15.txt"
  - text: "For the seven items blocked on their supplier, a rule issues one change package each — why no configuration change can do it, with the runtime's own list by path and hash; the memo's replacement clause; the CBOM entries covered (19 in all, by fingerprint); and the check that will count once replaced. One has an upgrade path the estate already holds: OpenSSH 6.6 on the SFTP drop lists no post-quantum key exchange, while OpenSSH 10.0 on the jump host lists mlkem768x25519-sha256."
    provenance: "computed 2026-10-21 on the xr7620 (x86_64): package run 01M5G36BJANYEKWVTHDVNQ98YE over scan run 01M5FYXR40S3FRWW9NXYVA5A7K; capability snapshot policy/snapshots/capabilities-2026-10-20.json"
reuse: [whitepaper, talk, customer-question]
---

# How is a migration priority computed?

## The answer

A migration priority answers two questions for each system: does it come
first, and by when must each kind of cryptography it uses be post-quantum.
Both answers are in OMB M-26-15, the memorandum that governs federal civilian
agencies' migration, and both can be computed. The memo names the systems to
prioritize — a high-impact system, a High Value Asset, a system whose data is
expected to remain mission-sensitive in 2030 — and the queues: key
establishment for prioritized systems by the end of 2030, signatures in 2031,
everything else by 2035, and TLS 1.3 support by January 2, 2030. A rule reads
those criteria against facts the system owner supplies, reads the memo's table
of quantum-vulnerable algorithms against what was found, and places each
system's key establishment and its signatures in a queue with a date. Two
further rules say what stands in the way: whether the system's software can
offer a post-quantum algorithm at all, and whether a validated cryptographic
module that does so exists. Each is a rule over a dated measurement, and each
cites the words it rests on.

## The concept

Three ideas carry the computation.

**Prioritization is the memo's, not the tool's.** An inventory tool that ranks
by its own score invents a policy. M-26-15 §3.C.2 already says which systems
come first, so the rule is a reading of that list: a system is prioritized when
any criterion holds, and the record says which.

**Two clocks, because two attacks.** Key establishment protects confidentiality
now: traffic recorded today can be decrypted once the key exchange that
protected it is broken ("harvest now, decrypt later"). A signature protects
authenticity at the moment it is checked, and a forgery needs a working
quantum computer at that moment. So the memo moves key establishment first and
signatures a year later, and a system appears in two queues, one per function.

**A blocker is a state with evidence, not a note.** "We can't, the vendor
doesn't support it" is the most common reason a migration stalls, and the
least often checked. Asking the software's own runtime what it can do turns
the claim into a measurement; asking NIST's list of validated modules what
they cover turns the second common claim — "we must use a validated module and
none supports it" — into one too.

## The mechanism

**The pack.** The memo is carried as data, `policy/packs/m-26-15.yaml`: the
criteria, the table's rows, the queues with their sections and dates, the
replacement and enforcement clauses. Each entry carries the memo's own words.
The loader refuses the pack if any quote does not occur, in order, in the text
extracted from the memo's PDF, whose SHA-256 the pack records; a paraphrase
does not load. A date the memo states is `stated`; a date it gives only as a
year (Phase 4, "2031") is carried as the year's end and marked `computed`.

**The rules.**

| Rule | Decides | From |
|---|---|---|
| `quantum/vulnerable/1` | Per algorithm name: its family and whether the memo's table makes it quantum-vulnerable. A name the table does not list is vulnerable when asymmetric, by the table's footnote 13 | `policy/algorithm-families.yaml`, the pack's table |
| `pack/scope/1` | Which policy governs a service: M-26-15 unless the owner marks it a national security system (§3.B) | the owner's fact |
| `priority/m-26-15/1` | Which of §3.C.2's criteria hold | the owner's facts: FIPS 199 impact, high-value status, data lifetime |
| `queue/m-26-15/1` | Per service and function, the vulnerable algorithms it still offers or holds in use, the queue and the deadline; `met` when none | the findings joined to the service by the dependency chain |
| `deadline/tls13/1` | Per TLS listener, whether TLS 1.3 was offered | the TLS versions of the cipher suites the listener accepted |
| `blocker/supplier/1` | Whether the software can offer a post-quantum algorithm in that function at all; when not, the item is marked for replacement (§3.C.3) | the capability snapshot |
| `blocker/validated-module/1` | Whether a validated module is in use, available, or does not exist for the library and algorithm | the CMVP snapshot |

The data-lifetime criterion is computed: data handled on the assessment date
stays sensitive until that date plus its lifetime, and the criterion holds when
that reaches 2030.

**The two snapshots.** The capability snapshot runs each image with no network
and its entry point replaced, and asks the runtime for its own list:
`openssl list -kem-algorithms`, `ssh -Q kex`, Erlang's `ssl:groups()`, the
classes in the Java runtime. Where an image ships no tool that can list its
library's algorithms — the nginx images ship no `openssl` command — the probe
records the library package and checks it is the same build as an image whose
capability was observed on the wire. The CMVP snapshot reads NIST's search for
active certificates and each certificate page's list of approved algorithms,
and keeps every page's hash. Both are files in the repository with a date in
their name; a rule never reaches the network.

**The record.** Every result is an `assessment.made` event naming its inputs —
the supplied facts, the findings, the item — and its source: the pack, the
PDF's hash, the section. The CBOM carries the result on each service component
(`pqch:owner`, `pqch:queue`, `pqch:deadline`, `pqch:state`, `pqch:migration`
with the blockers) and on each asset (`pqch:family`,
`pqch:quantum-vulnerable`). The page shows a decision record per open item:
owner, queue and date, why it is there, its blockers, and the approval state
of any change that answers it.

## Worked example

The mini-agency on 2026-10-20 (scan run `01M5DFXYNNG08S8ADTDF48WYFE`):

| Service | Prioritized by | Key establishment | Signatures | Blockers |
|---|---|---|---|---|
| records-db | high impact, HVA, lifetime | kex-2030: DH-2048, RSA key transport and X25519 beside the hybrid group | sig-2031 | none from the supplier; a validated module with ML-KEM exists and is not in use |
| sftp-legacy | high impact, HVA, lifetime | kex-2030: DH-1024 and six more | sig-2031: DSA, ECDSA, Ed25519, RSA | supplier: OpenSSH 6.6 has no post-quantum algorithm; replace |
| pq-gateway | high impact, HVA, lifetime | met: X25519MLKEM768 only | met: ML-DSA-65 only | — |
| queue | lifetime (7 years) | kex-2030; TLS 1.2 only, so also tls13-2030 | sig-2031 | supplier: Erlang/OTP 27's TLS lists no ML-KEM group, though it links OpenSSL 3.5.9 |
| legacy-app | lifetime | kex-2030; TLS 1.2 only | sig-2031 | supplier: Java 8 has neither ML-KEM nor ML-DSA |
| portal, api | lifetime | kex-2030 | sig-2031 | none from the supplier |
| bastion | none (data sensitive for one year) | remaining-2035 | remaining-2035 | supplier, signatures only: OpenSSH 10 has ML-KEM key exchange and no post-quantum host key |

Two rows show what the blocker rules are for. The queue's broker runs on an
Erlang/OTP whose cryptographic library has ML-KEM, and a reader of its package
list would call it ready; its TLS stack does not offer the group, so the item
is blocked on the supplier. The records database is not blocked on its supplier
— PostgreSQL 18 on OpenSSL 3.5 lists ML-KEM and ML-DSA — and is configured to
offer the hybrid group, but it still accepts X25519, finite-field
Diffie-Hellman and RSA key transport, so its item stays open: enabled is not
enforced (Appendix A §5).

**A model does not decide any of this, and on this pack does not yet explain it
either.** The plan gave one job to a model: retrieve the pack's passages for an
item and explain, in plain words, why the item sits in its queue, with the queue
it names checked against the rule that placed it there. The floor was written
before the first call: every open item passes by the majority of three calls,
one excepted, and no call names another queue. The job reached 3 of 14 items,
with three harmful calls, at 3.2 s a call on Gemma 4 31B on four L4s. Retrieval,
not the model, failed: the item's description named algorithms, so the three
nearest passages were rows of the memo's table, and the queue's own passage was
among them for only 3 items; on those three the model passed all nine calls. On
the broker's key-establishment item retrieval returned the TLS 1.3 queue's
passage, and the model named that queue. The role is unbound; the page shows
the rule's basis alone ([lesson 34](../lessons/34-score-retrieval-before-the-answer.md)).

## What follows

- **Carry the policy as quotes a loader checks.** A rule that says "the memo
  requires X" is only as good as the reading behind it; a pack whose every rule
  is the memo's own words, refused when a word is wrong, can be audited by
  anyone holding the PDF.
- **Ask the runtime, not the package list.** A library that supports an
  algorithm is not a protocol stack that offers it; measure what the software
  will negotiate before calling a blocker a supplier's
  ([lesson 32](../lessons/32-ask-the-runtime-what-it-supports.md)).
- **A validated module is a property of the certificate, not of the library's
  version.** The OpenSSL project's own validated provider covers neither ML-KEM
  nor ML-DSA, while one vendor's validated rebuild of it covers both; a module
  shipped and not activated is not in use
  ([lesson 33](../lessons/33-read-a-validated-modules-certificate-for-the-algorithm.md)).
- **Most of the work is blocked or waiting.** On this estate half the open
  items are blocked on a supplier, and no item is in a validated module today.
  A migration plan that lists systems without these two states lists work that
  cannot start.

## When no configuration change is possible: the package

A blocked item has nothing to render, draft or rehearse, but it still needs a
record an owner can act on. The workbench issues a **change package** per
blocked item, written by a rule (`package/supplier/1`) from the ledger and the
snapshot, never by a model:

| Field | What it holds |
|---|---|
| Why no configuration change | The blocker's basis and the runtime's own list of what it supports, by path and SHA-256 |
| What would unblock it | Any service in the same snapshot running the same product that does list an algorithm for the function — an upgrade path the estate already holds — or none |
| What the memo says | §3.C.3, quoted: such systems "must be identified and given priority for replacement or decommissioning" |
| The CBOM entries it covers | Each entry on the service's listeners for the function, by fingerprint, with the files it is served from |
| The test that will count | The verifier check that applies once the software is replaced |
| Rollback, rehearsal | None, and `not rehearsed`: nothing is applied |

On the mini-agency the seven packages cover 19 CBOM entries on four services.
Six have no upgrade path in the estate. The seventh does: the SFTP drop's
OpenSSH 6.6 lists no post-quantum key exchange, while the jump host's OpenSSH
10.0 lists `mlkem768x25519-sha256` — an upgrade, then a one-line configuration
change of the kind the jump host's own change already rehearsed. In NIST's
crypto-agility plan (CSWP 39-upd1, Fig. 3) this is the *mitigation* output
beside *migration*.

## Scope

Covered: the eight-service mini-agency, its planted owner's facts, M-26-15 read
first-hand, the capability of each image's runtime measured on 2026-10-20, and
NIST's CMVP active certificates matching OpenSSL, Java, Erlang and OpenSSH on
the same day. Not covered: CNSA 2.0, whose primary documents NSA's site refused
twice; it is carried unverified and governs no service here. Not examined: the
validated software version on each certificate (in each Security Policy, not
read), modules in process, products in CISA's product-category list (§3.C.4),
client-side support, and whether a supplier's next release adds what is
missing. Deadlines are the memo's; an agency's own plan may set earlier ones.

## References

- OMB M-26-15, *Execution of the Migration to Post-Quantum Cryptography*
  (2026-06-24) — §3.A, §3.C.2 to §3.C.4, §3.D, §4, Appendix A §2, §3, §5;
  `policy/sources/m-26-15.txt`.
- NIST CMVP, validated modules search and certificate pages — the validated
  module states; `policy/snapshots/cmvp-2026-10-20.json`.
- `policy/packs/m-26-15.yaml`, `src/pqch/policy/`, `src/pqch/assessor/managed.py`
  — the pack, its loader and the rules.
- Related notes: [what federal policy requires](03-what-federal-policy-requires-and-when.md);
  [how a finding becomes a dependency chain](06-how-a-finding-becomes-a-dependency-chain.md);
  [where models belong](13-where-models-belong.md).
