---
id: note-22-what-compatible-means-entry-by-entry
type: note
title: "What does \"compatible\" mean for one CBOM entry, and what cannot be told from the evidence?"
date: 2026-11-09
audience: [leader, architect, engineer]
tags: [policy, cbom, managed, cnsa]
rung: managed
one_line: "Every entry in the CBOM carries one of four statuses under the policy pack that governs its service — compatible, not compatible, unknown, outside the pack — judged by a rule from the pack's own table and the entry's algorithm, with unknown counted on its own so that a gap in the evidence is never reported as a pass, and every status from a pack not read first-hand marked provisional; both packs shipped are read first-hand, so none is."
claims:
  - text: "On the four-service slice of the mini-agency (47 entries), the rule tags 2 compatible, 39 not compatible, 1 unknown and 5 outside the pack under OMB M-26-15; counting entries in use only, 2, 34, 1 and 4."
    provenance: "measured 2026-11-09 on x86_64 from the slice's recorded scanner output (tests/fixtures), rule compatibility/entry/1 at the commit that introduced it; tests/test_managed.py reproduces the counts"
  - text: "The one unknown entry on the slice is a private key file the reader could not open, so its algorithm is not identified; the five outside the pack are hashes (SHA-1, SHA-256), which the memo's table does not name, and the two SSH listeners' protocol entries."
    provenance: "measured, same run; the entries' bases are on the CBOM page"
  - text: "OMB M-26-15 names what is quantum-resistant (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, and a hybrid in which both parts must be broken) and what is quantum-vulnerable (its Appendix A table and footnote 13); it names no symmetric algorithm or hash as acceptable or not."
    provenance: "cited: OMB M-26-15 Appendix A §1, §2 and footnote 13, read first-hand 2026-10-20 (policy/packs/m-26-15.yaml quotes it)"
  - text: "CNSA 2.0 names one algorithm per function at one parameter set: ML-KEM-1024 for key establishment, ML-DSA-87 for signatures in any use case, LMS and XMSS for signing firmware and software only, AES-256, and SHA-384 or SHA-512; SHA3-384 and SHA3-512 for a hardware's internal integrity checks only; and a hybrid is compliant only where NSA identified one, which it has for IKEv2 and not for TLS."
    provenance: "cited: NSA, CNSA 2.0 and Quantum Computing FAQ, Ver. 2.2 (October 2026), the suite's table and the Hybrids and composites section, read first-hand 2026-11-09 from the PDF with sha256 bc430341…; policy/sources/cnsa-2.0-faq.txt, every quote in policy/packs/cnsa-2.0.yaml checked against it by the loader"
reuse: [whitepaper, talk, customer-question]
---

# What does "compatible" mean for one CBOM entry, and what cannot be told from the evidence?

## The answer

A discovery phase ends with every entry in the inventory tagged against the
policy that governs the system it belongs to: compatible, not compatible, or
unknown, with the vendor's supportability noted where it is known. The
workbench makes that tag a rule's judgement on the ledger, one per entry, and
adds a fourth state the three leave out: *outside the pack*, for an entry the
policy says nothing about. The four together cover every entry, so a count of
compatible entries is never inflated by the ones nobody judged, and a count of
unknowns is a measured gap rather than a silent pass.

The rule is `compatibility/entry/1`. It runs once per entry (one per finding
fingerprint, so an asset two tools both saw is judged once), under the pack
that governs the entry's service: OMB M-26-15 for an agency's information
system, CNSA 2.0 for a service the owner marks a national security system. The
judgement names the pack, the section, the algorithm's family, the basis in the
pack's own words, and whether it is provisional. The CBOM carries it as the
`pqch:compatibility` property, the inventory projection as three columns, and
the CBOM page and the plan as four counts.

<figure class="sketch" markdown>
![Four boxes an entry can land in under a policy pack. Compatible: the algorithm's family is one the pack calls resistant, or its name is one the pack lists for that function. Not compatible: the pack's table or footnote makes it vulnerable, or the pack names another algorithm for the function. Unknown: the entry names no algorithm a table places, or the pack does not place the name; counted on its own. Outside the pack: a hash, a symmetric algorithm or a protocol version the pack says nothing about. The slice's counts beside each: 2, 39, 1, 5; in use 2, 34, 1, 4. Below, what the same entries are under CNSA 2.0, read first-hand from the FAQ.](../img/sketches/22-four-statuses.svg)
<figcaption>Four statuses, and the slice's 47 entries sorted into them under M-26-15; unknown is a count, not a pass.</figcaption>
</figure>

## The mechanism

**What the entry is judged on.** The CBOM names every asset by a normalized
algorithm name (`X25519`, `RSA`, `ML-DSA-65`, `SHA-256`) and a role: key
establishment, signature, encryption, hash. A certificate is judged by the
algorithm of the key it certifies, which is what signs with it. A key file is
judged by its algorithm, looked up first in the signature table and then in key
establishment. RSA seen in an encryption role is RSA key transport, judged as
key establishment. A protocol version (TLS 1.2, TLS 1.3) is not an algorithm
and is outside the pack; the TLS 1.3 obligation is a rule of its own
(`deadline/tls13/1`, [note 03](03-what-federal-policy-requires-and-when.md)).

**How M-26-15 decides.** The memo's pack carries two lists from its Appendix A:
the quantum-resistant algorithms (§1: FIPS 203, 204, 205, and a hybrid whose
classical and post-quantum parts must both be broken) and the quantum-vulnerable
table (§2) with footnote 13, which asks that any asymmetric algorithm not
definitively known to be quantum-resistant be treated as vulnerable. So an
asymmetric entry is compatible when its family is on the resistant list and not
compatible otherwise, footnote 13 included: Ed25519 and OpenSSH's
`sntrup761x25519` are not compatible under this pack because the memo does not
name them resistant, not because anyone has broken them. The memo says nothing
of AES or SHA-2, so a hash or a symmetric algorithm is outside the pack.

**How CNSA 2.0 decides.** The suite names one algorithm per function at one
parameter set. Its pack lists them by function, and the rule compares names:
ML-KEM-1024 is compatible for key establishment and ML-KEM-768 is not, so the
hybrid `X25519MLKEM768` that M-26-15 accepts is not compatible under CNSA 2.0,
and ML-DSA-65 is not where ML-DSA-87 is required. SHA-256 is not compatible
where the suite names SHA-384 and SHA-512. A hybrid whose post-quantum part is
the suite's own (`SecP384r1MLKEM1024`) is unknown, a count and not a verdict:
the FAQ says a hybrid is compliant only where NSA identified one, names one for
IKEv2 and none for TLS, so the pack lists it as unsettled. LMS and XMSS are in
the suite for signing firmware and software only, and SHA3-384 and SHA3-512 for
a hardware's internal integrity checks only. The rule reads where the entry is:
on the platform layer (a system's firmware, its Secure Boot databases, its
management controller) those names are compatible; a SHA-3 hash on the wire or
in a file is not compatible; and an LMS or XMSS key in a file is unknown,
because the evidence does not say what the key signs. The pack was read
first-hand from the FAQ (Ver. 2.2, October 2026) on 2026-11-09, after NSA's site
had refused the download to the harness three times; every quote in it is
checked against the FAQ's text by the loader, and no status is provisional. A
pack that is not read first-hand says `verified: false`, and the rule copies
that into each judgement's basis and into the page's heading until it is; when
such a pack is corrected the next assessment of the same ledger gives the final
statuses, and the ledger's events are not rewritten.

**Why unknown is a state and not a default.** The slice has one entry the rule
cannot judge: a private key file the reader could not open, whose algorithm is
therefore not identified. A rule that folded it into "compatible" would be
reporting a pass with no evidence; one that folded it into "not compatible"
would be scheduling work nobody can scope. Either way the number would be
wrong. Kept apart, the unknowns are the manual gap-fill queue a discovery phase
plans for: each is an entry to open by hand, a vendor to ask, or a reader to
improve.

**Why outside-the-pack is a state too.** A pack is a document's words as data,
and the rule may say only what the document says. M-26-15 governs asymmetric
cryptography; it does not bless SHA-256 or AES-128, and a tag of "compatible"
on them under that pack would be a claim the memo never makes. The fourth state
says so. Under CNSA 2.0, which does name a hash and a symmetric algorithm, the
same SHA-256 entry is not compatible, and the two packs' counts differ for that
reason alone.

**Vendor supportability.** The tag a discovery phase wants beside each
not-compatible entry is whether the vendor has a path: an update, a replacement,
or no statement. That fact does not come from the wire or the host; it is a
supplier's attestation, imported as graded evidence and joined to the entry by
model and version. It is the next item in the plan (M10, supplier
attestations), and until it lands the status stands alone.

## Worked example: the four-service slice

| Status | All entries | In use | What they are |
|---|---|---|---|
| compatible | 2 | 2 | the hybrid `X25519MLKEM768` on two listeners |
| not compatible | 39 | 34 | RSA, ECDSA and DSA keys and certificates; X25519, the NIST curves and finite-field DH groups; Ed25519 and `sntrup761x25519` by footnote 13 |
| unknown | 1 | 1 | one private key file the reader could not open |
| outside the pack | 5 | 4 | SHA-1 and SHA-256, which the memo's table does not name; the two SSH listeners' protocol entries |

The five entries that are not in use and not compatible are the retired
certificate and the keys behind it, which no listener serves ([note
06](06-how-a-finding-becomes-a-dependency-chain.md) on in-use). They are in
the inventory, tagged, and excluded from the migration's count by the in-use
judgement, not by the compatibility one; a reader who wants them back in the
count has both numbers.

Measured 2026-11-09 on x86_64 from the slice's recorded scanner output, at the
commit that introduced the rule; `tests/test_managed.py` reproduces the counts.

## Scope

- The rule judges algorithm names and key algorithms. It does not judge key
  sizes against a pack's parameter conditions beyond what the name carries;
  the IR 8547 key-size check lives in the queue rule ([note
  07](07-how-a-migration-priority-is-computed.md)), and a 1024-bit RSA key is
  not compatible for the same reason a 4096-bit one is.
- Under CNSA 2.0 an entry's application is read from its layer and nothing
  finer: a firmware entry counts as firmware signing or a hardware integrity
  check, and an LMS or XMSS key outside firmware is unknown until someone says
  what it signs. No LMS, XMSS or SHA-3 entry exists in the mini-agency, so the
  rule is tested on constructed entries, not measured on a scan.
- A pack read first-hand (M-26-15, IR 8547) is checked quote by quote against
  its source text when it loads; the compatibility block adds no quote of its
  own and rests on the resistant and vulnerable lists the pack already carries.
- The counts above are the slice's. The full mini-agency's counts appear on
  its CBOM page after the next scan; a run recorded before the rule existed
  shows no counts, since its ledger holds no such judgements and the
  projection invents none.
