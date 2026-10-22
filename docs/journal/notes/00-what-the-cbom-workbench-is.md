---
id: note-00-what-the-cbom-workbench-is
type: note
title: "What is the CBOM workbench, and what has it shown so far?"
date: 2026-10-20
audience: [leader, architect, engineer]
tags: [cbom, discovery, verification, agility, policy]
rung: all
one_line: "A working example of how a cryptographic inventory, built from evidence and kept on a signed ledger, carries an organization from not knowing what it runs to changing an algorithm and proving the change landed."
claims:
  - text: "On a four-service test estate, the workbench finds 22 of 23 wire items and 7 of 10 host items in the answer key, flags no decoy, and states the posture of all 4 listeners correctly."
    provenance: "measured 2026-10-03, M0 slice, xr7620 (x86_64), scored by eval/score.py against agency/answer-key.yaml"
  - text: "The same open-source scanners run with no harness find the same 22 and 7, flag the one host decoy, and state no posture. CBOMkit's image scanner alone finds 0 of 23 on the wire."
    provenance: "measured 2026-10-03, same run, same scorer"
  - text: "A policy change that requires hybrid key establishment on one TLS listener is applied and verified in 63 seconds from the policy event and 63 seconds from approval, two verdicts included."
    provenance: "measured 2026-10-03, M0 slice, xr7620 (x86_64), from ledger timestamps; change run 01M422Y6WP5TNB65NPFFEWNAK4"
  - text: "With a person approving through the page, the same path took 69.4 s from the policy event and 65.6 s from approval."
    provenance: "measured 2026-10-04, M0 slice, xr7620 (x86_64); change 01M43EN2B4ZVTSKAPG0WZTNZXT"
  - text: "The slice, the harness and every scanner start from an offline bundle — eight images for x86_64 and arm64 in a local registry, 611 MB — in 8.7 s, with no image fetched from elsewhere; a live scan through them scores as above, and a policy change is applied and verified on that estate with the bundle's registry stopped, in 62.0 s."
    provenance: "measured 2026-10-05, xr7620 (x86_64), harness at commit 9e45a6a; bundle/README.md; change run 01M46RP7WVRMW1EXNKM4D762P2"
  - text: "With a signature on each side of the policy event and the approval, a change measured 55.6 s on the ledger's clock and no more than 55.6 s on the signing service's."
    provenance: "measured 2026-10-05, xr7620 (x86_64); change run 01M46RCKJZA12PD1REM722YF4F"
  - text: "Every scanner and probe the harness uses ran as arm64 under emulation and gave the same results as on x86_64; Zeek's packet capture does not run under emulation."
    provenance: "measured 2026-10-04, xr7620 under qemu-user; spike S2"
  - text: "On the eight-service estate — nine listeners, 40 keyed wire items, 20 keyed image items — the three scanners alone find 38 of 40 on the wire and 14 of 20 in images while flagging both image decoys; the workbench finds the same 38 and 20 of 20, flags neither decoy, and states all nine listener postures correctly. The two wire misses are keyed out of reach."
    provenance: "measured 2026-10-19, run 01M5AS1BSKH8SQN8XN6NCFE1E5, xr7620 (x86_64), eval/score.py against agency/answer-key.yaml (sha256 f07f8b59…), harness at 63475e9"
  - text: "The whole estate scans in 206 s with every job running at once: cbomkit-theia takes 75 to 136 s per image, the harness's own file reader 1 to 8 s per image, and the records database 94 s through PostgreSQL's TLS upgrade."
    provenance: "measured 2026-10-19, same run, 25 runner jobs, from the ledger's scan.completed events"
  - text: "On the eight-service estate every one of nine listeners has a complete dependency chain: 17 service links discovered by rule on the runner's binding records and 24 owner-supplied facts for eight services, each labelled supplied; the key's five supplied items are all carried and labelled, coverage is unchanged; 188 of 220 CBOM entries have no verifier; three conflicts are settled by rule."
    provenance: "measured 2026-10-20, runs 01M5CTXE9PH6Y2BKPHZPZ9KFK6 and 01M5D07C5R46RQZR1EWECAM7CE, xr7620 (x86_64); score.json and the ledgers' rule events"
  - text: "The investigator traced nine wire findings, one per listener, on the live lab/reason lane in a median of 27.6 s each (23 to 89 s, 2 to 4 steps); eight agreed with the key and the ninth was right where the key was wrong."
    provenance: "measured 2026-10-20, investigate run 01M5CV4QP9K8M4EE4EDTKYRV2H; lesson 31"
  - text: "Under OMB M-26-15, read as quotes the loader checks against the memo, the eight-service estate has 7 prioritized services, 14 open migration items (6 key establishment by 2030-12-31, 6 signatures in 2031, 2 by 2035) and 2 met; 7 open items are blocked on their supplier, and none runs in a validated module."
    provenance: "measured 2026-10-20, scan run 01M5DFXYNNG08S8ADTDF48WYFE; policy/snapshots/ capabilities and CMVP snapshots of the same day"
  - text: "OMB M-26-15 requires key establishment on prioritized systems to be post-quantum by 2030 and digital signatures by 2031."
    provenance: "cited: OMB M-26-15, sections 3.C.2 and 3.D"
reuse: [whitepaper, talk, customer-question]
---

# What is the CBOM workbench, and what has it shown so far?

## The answer

cbom-workbench (its command is `pqch`) is a worked
example, in running code, of what a cryptographic inventory is for. It builds a cryptography bill of materials (CBOM) — a
structured list of every algorithm, key, certificate and protocol an
organization runs, with where each one was found — from three kinds of
evidence, and then uses that inventory to do the thing the inventory exists
for: change an algorithm across an estate and prove, by re-scanning, that the
change landed. Every finding, decision, approval and verification is an event
on an append-only, signed ledger, and the CBOM is rebuilt from that ledger.
Its first page draws NIST's crypto-agility plan (CSWP 39-upd1, Fig. 3) with
what the workbench does in each part: the CBOM is the plan's information
repository, between the tools that fill it and the engine that ranks what to
change ([note 16](16-what-a-cbom-makes-possible.md)). Its centre is the
plan the CBOM makes possible: what depends on what, what comes first, and in
what order the changes have to go
([note 17](17-how-a-cbom-becomes-a-migration-plan.md)).

It is an exploration shared freely, not a product. Its three arguments are
that the inventory is the tool the migration is made from and checked against,
not a report to file; that the place of a language model in that work is
something to measure role by role, not assume; and that this work can run on
hardware an organization holds, because a map of where its cryptography is
weakest is not something to send elsewhere. It is being built now because
federal policy requires the inventory now, and the minimum elements of a
federal CBOM are not published until 2027-03-19
([note 03](03-what-federal-policy-requires-and-when.md)): a record built with
its evidence can be projected into whatever is asked for later.

So far it has shown the path end to end on a small test estate: scan,
inventory, score against an answer key, change policy, apply, verify on the
wire — and, since 2026-10-19, the inventory half on an estate twice the size,
with a database that still accepts RSA key transport, a broker, a legacy Java
service, a post-quantum gateway and an internal certificate authority. The
numbers are below, with what each one does and does not establish.

## The concept: five rungs

Post-quantum migration means replacing the public-key algorithms a large
quantum computer could break — RSA, elliptic-curve Diffie-Hellman, ECDSA — with
the algorithms NIST standardized in 2024: ML-KEM (FIPS 203) for key
establishment, and ML-DSA (FIPS 204) for signatures. Key establishment is
urgent first, because traffic recorded today can be decrypted later once the
key exchange is broken ("harvest now, decrypt later"). United States federal
policy sets dates: OMB M-26-15 puts key establishment on prioritized systems
in a phase ending 2030, and digital signatures in 2031.

An organization cannot migrate what it cannot see. The project is organized
around a maturity ladder in which each rung is a question the organization can
now answer:

| Rung | What the organization has | The question it can answer |
|---|---|---|
| Opaque | A hand-kept spreadsheet | None reliably |
| Enumerated | Scanner output | Where is quantum-vulnerable cryptography? |
| Structured | A CBOM with dependencies | What depends on it? |
| Managed | Owners, priorities, approvals | What first, what is blocked, what changed? |
| Agile | Change as routine | If policy changes, how fast can we respond, and did it land? |

Crypto agility — the top rung — is the ability to change an algorithm by
changing policy, without re-engineering each system. The project treats it as
something to measure: the time from a policy change to a verified result.

## The mechanism

Three ideas hold the design together.

**Agents propose, verifiers dispose.** Scanners, rules and, where
interpretation is needed, a language model produce findings and proposed
changes. Whether a change worked is never a model's judgement. It is decided by
a verifier that re-scans: one client that offers only the new algorithm must
succeed, and one that offers only the old ones must be refused. A listener
that accepts both has the new algorithm *enabled*, not *enforced*, and that is
recorded as its own state.

**The ledger remembers.** Every event is one line in an append-only file,
each line carrying the hash of the one before it. Checkpoints over the file
are signed with ML-DSA-65 by a separate signer service. The CBOM, the score
and every screen are computed from the ledger and can be deleted and rebuilt.

**Models earn their place by measurement.** Six roles, a floor per role
written before the run, every call repeated, fifteen arms across every model
the lab holds: one role needs a 120B model, three run on a 31B model on four
L4s (one of them with reasoning on), two went back to rules because no arm reached
the floor ([note 13](13-where-models-belong.md)). What each step up in
models or hardware changes is a measured row or is marked not measured.

The parts, as built today:

| Part | What it does | Uses a model |
|---|---|---|
| Scope | A file listing the only addresses, ports and images that may be touched | No |
| Runner | The one container that holds the Docker socket; runs named scan profiles and approved changes, and refuses anything outside the scope | No |
| Scout | Runs testssl.sh (through PostgreSQL's TLS upgrade where the scope says so) and ssh-audit against listeners, cbomkit-theia and the harness's own reader of key material against images; normalizes their output to one finding format | No |
| Rules | Link a certificate seen on the wire to the file that holds its key; link a listener and its image to the service the scope names, on the runner's record of the container it found; judge whether a certificate in an image is served, leaving a certificate authority's alone; state each listener's posture; name the verifier that could confirm a change to each class of entry; settle each conflict between a file and the wire | No |
| Owner's facts | Mission function, data lifetime and high-value status per service, typed into one file and recorded as supplied links with a human actor; labelled supplied in the CBOM, never coverage | No |
| Managed rules | Read OMB M-26-15, carried as quotes the loader checks against the memo, to decide which algorithms are quantum-vulnerable, which systems are prioritized, which queue each system's key establishment and signatures wait in and by when, and whether TLS 1.3 is offered; record supplier and validated-module blockers from two dated snapshots | No |
| Watch | Records each scan's configuration manifest and what changed since the previous scan; sends only new findings and changed items to the model jobs | No |
| Investigator | Traces a wire finding to the configuration line that causes it, through three typed tools over the service's build files under step and token budgets; recorded as the model's claim with the engine, the settings and the time | Yes — the one role that needs the 120B |
| Scorer | Compares a CBOM with an answer key, by layer, beside two baselines | No |
| Migrator | Renders a central policy into a service's configuration and proposes the difference as a change | No |
| Verifier | Paired probes and a second witness; issues `enforced`, `enabled-not-enforced`, `not-landed` or `inconclusive` | No, by rule |
| Signer | Signs ledger checkpoints; holds the key where nothing else can read it | No |
| Inference seam | One place that knows where a model lives; code asks for a tier or a role, never a model | Yes — the investigator's trace; a typed classification, used by no rule; a conflict explanation where a deployment binds the role (the lab does not) |

## The estate at M1: eight services, scored

On 2026-10-19 the estate grew to eight services and nine listeners: the
slice below, a PostgreSQL 18 records database reached through its TLS
upgrade, a RabbitMQ 4 queue, a Tomcat 8.5 application on Java 8, a gateway
with an ML-DSA-65 certificate and the hybrid group only, a client-certificate
listener on the API, and an internal certificate authority that issued three
of the certificates. The answer key holds 73 items; every wire claim was
probed by hand before the key was committed. The scanners alone and the
workbench, by layer:

| Layer | Keyed | Scanners alone | Workbench | What differs |
|---|---|---|---|---|
| Wire | 40 (2 out of reach) | 38, no false positive | 38, no false positive | nothing: the wire is the scanners' |
| Image | 20, 2 decoys | 14; both decoys flagged | 20; no decoy flagged | the harness's own file reader (an ML-DSA certificate and key, a PKCS#12 keystore, DSA and Ed25519 host keys) and the rules (two unserved certificates marked not in use, two CA certificates left alone) |
| Posture | 9 listeners | not stated | 9 of 9 | a rule over both layers |

The delta over the scanners is where the design said it would be: the host
layer and the structure, not the wire. The one listener that accepts RSA key
transport, the records database, is found only because its scan speaks
PostgreSQL's upgrade and enumerates cipher suites; a plain TLS scan of its
port reports nothing ([lesson 29](../lessons/29-a-plain-tls-scan-of-an-upgrade-port-is-silent.md)).

## Worked example: the four-service slice

The test estate is a "mini-agency" in which every weakness is planted, so an
answer key can say exactly what a perfect inventory holds. The first slice is
four containers on an isolated network:

| Service | Listener | Planted posture |
|---|---|---|
| portal | TLS | Classical: X25519 and P-256 key exchange, RSA-2048 certificate |
| api | TLS | Mixed: the hybrid group X25519MLKEM768 offered, X25519 still accepted, ECDSA P-256 certificate |
| sftp-legacy | SSH | Classical and old: OpenSSH 6.6, key exchange down to 1024-bit Diffie-Hellman, a DSA host key |
| bastion | SSH | Mixed: OpenSSH 10.0, hybrid ML-KEM key exchange first, X25519 still accepted, classical host keys |

A hybrid group combines a classical exchange with a post-quantum one, so the
session is safe if either holds.

The answer key holds 36 items: 22 on the wire and 10 in images that a good
inventory should find, 2 decoys that look like findings and are not, 1 real
item no scan can reach (what a service offers when it connects *out*), and 1
fact that can only be typed in. It was committed before any scanner code was
written.

The full test estate is eight services, these four among them, with a key of
74 items (58 to find, 9 decoys, 2 out of reach, 5 supplied); the demo's
[test agency](https://kenrollins.github.io/cbom-workbench/agency/) page shows
each service and what was planted in it. The slice's key is kept, frozen, in
`eval/answer-keys/mini-agency-m0.yaml`, and the scores below are the slice's.

**Enumerated and Structured.** One scan, scored (measured 2026-10-03, xr7620,
x86_64):

| Layer | CBOMkit's image scanner alone | All scanners, no harness | Workbench |
|---|---|---|---|
| Wire | 0 of 23 | 22 of 23 | 22 of 23 |
| Host (images) | 7 of 10, decoy flagged | 7 of 10, decoy flagged | 7 of 10, decoy not flagged |
| Listener posture | not stated | not stated | 4 of 4 |

The denominators count the unreachable item, so the wire layer cannot reach
23 of 23 by design. A targeted wire scan takes 27 to 46 s for a TLS listener
and 2 to 3 s for an SSH one; an image scan takes 71 to 96 s.

**Agile.** The portal's key-exchange groups come from one policy file. Changing
that file from "classical" to "require hybrid" produces a proposed change with
its diff and the exact check that will count as verified. After approval the
runner applies it, and the verifier probes the listener, then probes it again
after the service is recreated. Measured on the same machine: 63.4 s from the
policy event to the last verdict, 62.9 s from approval, with the verdict
`enforced` both times. With a person approving through the page, 69.4 s and
65.6 s. Nearly all of that time is the second-witness scan, 21 to 31 s per
verdict; the paired probes take about one second each. Each interval is
reported twice: from the harness's own timestamps, and as an upper bound from
the times a separate signing service puts inside its signatures — the last
signature before the policy event to the first over the verdict (55.6 s and
"no more than 55.6 s" on a later change). A change is shown as verified, with
a time, only when the runner's own log of its jobs and applies bears the
ledger out; the three changes above predate that log and are shown as
unchecked.

**Off the network.** Everything above — the slice, the harness, the scanners —
starts from an offline bundle: eight images for both x86_64 and arm64, by
digest, in a local registry on disk, 611 MB. With the bundle's images deleted
first, it started in 8.7 s, every image came from the bundle, a live scan
scored as above, and a policy change was applied and verified with the
bundle's registry stopped. Every scanner and probe has also run as arm64
under emulation with the same results. The host's own route to the internet
has not been cut; that is the rehearsal on a second host.

## What follows

- **At the first rung, a harness adds structure, not coverage.** On this
  estate the workbench finds exactly what the scanners find. What it adds is
  the link from a wire finding to the file holding the key, the judgement
  that a certificate sitting in an image is not served, and a stated posture
  per listener. Anyone presenting this work should say so in those words.
- **The baseline matters.** Measured against CBOMkit alone, any tool that scans
  the network looks transformative, because CBOMkit does not scan networks.
  The honest bar is all the open-source scanners run together with no harness.
- **Verification is where the value concentrates.** An inventory can be
  approximately right and still be useful. A statement that a change landed
  cannot. Most of the engineering effort, and most of the defects found in
  review, were in the verifier and in who is allowed to write what.
- **Time-to-change is a measurable property.** About a minute on one service
  is a starting figure for one estate, not a benchmark.

## Scope

What this note's numbers cover: the four-service slice for the change path
(one changed listener) and the eight-service estate for coverage — TLS, TLS
behind PostgreSQL's upgrade, and SSH; wire and image evidence — on an x86_64
lab server, with the slice also run as arm64 under emulation. The code layer
is not yet scanned on either. A separate set of targets measured what each scanner
can see beyond the slice — databases and brokers over TLS, a
client-certificate listener, an ML-DSA certificate
([note 15](15-what-the-open-source-scanners-cover.md)).

Which model each of the pipeline's six roles needs is measured, on every
model the lab holds ([note 13](13-where-models-belong.md)): tracing a wire
finding to its configuration line needs a 120B model; drafting a change
plan, reading a call site and classifying an algorithm run on a 31B model on
four L4s, the call-site read with reasoning on; naming a tool's spelling and
resolving a conflict between layers go back to rules. A successor to the
120B, measured in the same slot, did not displace it; the same model's
reasoning setting moved its result more than the change of model did.

Since 2026-10-20 the inventory is Structured: every listener on the
eight-service estate has a complete dependency chain — listener, certificate,
service, mission function, data lifetime — with each discovered link resting
on named ledger events and each supplied link labelled
([note 06](06-how-a-finding-becomes-a-dependency-chain.md)); 188 of its 220
entries are recorded as having no verifier; its three file-versus-wire
conflicts are settled by rule; and the investigator traced one finding per
listener to its configuration line, eight of nine agreeing with the key and
the ninth correcting it.

Since the same evening it is Managed: OMB M-26-15 is carried as data, each
rule in the memo's own words, and the assessor places each service's key
establishment and signatures in the memo's queues with their dates — 14 items
open, 2 met, 7 blocked on a supplier whose software cannot offer
post-quantum cryptography, none yet in a validated module — and shows a
decision record per item ([note 07](07-how-a-migration-priority-is-computed.md)).
Watch mode records what changed between scans and re-examines only that.
Since 2026-10-21 the CBOM itself is on its own page: the document's makeup,
any entry field by field with the standard's fields and the project's told
apart and each traced to its ledger event, what a model was given from the
entry and what it answered, the CBOM against the previous scan's, and a
second projection of the same ledger rebuilt in milliseconds with no scan
([note 01](01-what-is-a-cbom.md)). And a model now drafts the change for
software the harness has no renderer for, from the CBOM's entries and the
trace; the draft is rehearsed on a copy of the service before anyone can
approve it, and a verifier with a fourth, TLS 1.2 probe decides whether it
holds ([note 16](16-what-a-cbom-makes-possible.md)). The first, for the records
database, was rehearsed `enforced` and waits for approval. The
one model job tried for the rung, a plain-words explanation of each item's
queue, fell below its floor and is not used.

What is not yet built or measured: the code layer (no source scanner runs yet, so the key's code-layer
decoy is untested); client-side posture; the full twelve-service estate; the
bundle loaded on a second host with the network cut.

Where trust stops today: approvals are written by the harness process on the
strength of a sign-on at the front door, not signed by the approver. The
ledger's timestamps are the harness's clock, bracketed within two seconds by
the signing service's; a verdict is re-derived from the runner's own log and
raw output before it is shown as verified. What neither covers is how long a
person's decision waited before the harness recorded it. The limits are
stated on the page.

The mini-agency is the only estate the workbench changes; a network of one's
own can be scanned and planned, never changed
([the guide](https://kenrollins.github.io/cbom-workbench/site/your-own-network/)).
This is a personal research project, not
a Dell product, reference architecture or supported offering.

## References

- `BRIEF.md` in the repository — the claim, the facts table with provenance
  for every number above, and the alternatives rejected.
- `agency/answer-key.yaml` — the 36 keyed items and the matching rules.
- `docs/fable-review/M0-review.md`, `M0A-review.md` — what was attacked, what
  held and what broke.
- OMB M-26-15, *Execution of the Migration to Post-Quantum Cryptography* —
  the phases and dates.
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA) — the algorithms.
- OWASP CycloneDX, *Authoritative Guide to CBOM* — the CBOM format the
  inventory is written in (version 1.6).
- Related notes: [what federal policy requires, and by when](03-what-federal-policy-requires-and-when.md);
  [what "verified" means](08-what-verified-means.md);
  [what an auditable record contains](12-what-an-auditable-record-contains.md);
  [what the open-source scanners cover](15-what-the-open-source-scanners-cover.md).
