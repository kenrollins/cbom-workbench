---
id: note-16-what-a-cbom-makes-possible
type: note
title: "What does a CBOM make possible once it exists?"
date: 2026-10-21
audience: [leader, architect, engineer]
tags: [cbom, agility, inference, verification, managed]
rung: all
one_line: "A CBOM whose entries carry their evidence and their chain can be projected into any field list without a new scan, compared between scans to see what changed, read against a policy to say what comes first, and handed to a model as the context for its work — and because the same entry is what the result is checked against, the model can draft the change and a verifier, not the model, can prove it landed."
claims:
  - text: "For the records database, the CBOM held 7 entries for its listener; the queue rule put its key establishment in the 2030 queue with no supplier blocker; the investigator had traced its 2048-bit DHE to the server's default; Gemma 4 31B on four L4s drafted the change from those entries, the trace and the service's files in 3 of 3 usable replies of about 5 s each; and the draft, rehearsed on a copy of the service, was enforced on all four probes in 33 s."
    provenance: "measured 2026-10-21 on the xr7620 (x86_64): scan run 01M5FG9BJBCD7B6WNSM209P8XR, trace 01M5D12XTD7PTEK05BA8Y7YM70 (Nemotron 3.5 Super VL on the lab GB10), change run 01M5FGP0R99EF496M74YYJYNBD"
  - text: "The plan most easily written for the same intent — the hybrid group alone — refuses every classical-only TLS 1.3 client and still accepts DHE and RSA key transport over TLS 1.2; the verifier's TLS 1.2 probe is what tells the two apart."
    provenance: "measured 2026-10-21 by hand on a copy on the twin network; lesson 36"
  - text: "A flat inventory of 62 rows rebuilds from the same ledger in 19 ms with no scan, and two CBOMs of an unchanged estate compare as 254 components unchanged."
    provenance: "measured 2026-10-21; note 01"
  - text: "Laid over NIST CSWP 39-upd1 Fig. 3, the mini-agency reaches every region of the plan — governance, assets, management tools, the information repository, the risk engine, the measures, mitigation and migration — with 17 of the figure's 22 labelled boxes fully reached, 2 in part and 3 not (partner ecosystem, data discovery, zero trust); the lab estate reaches assets, tools and the repository in part and has no migration, because the workbench changes nothing it did not build."
    provenance: "computed 2026-10-21 from the deployment's ledgers by src/pqch/ui/agility.py; the per-label states are data in that module"
  - text: "One weakness followed from finding to fixed — records-db's classical key exchange, removed by a change that requires the hybrid group — takes thirteen steps through five of the plan's regions: two by a model (tracing the finding to its cause, drafting the edit), three recording a person's decision (the owner's facts, the policy, the approval), the rest by scanners, rules, the runner and probes; every step reads from or writes to the CBOM, and the scan after the change shows X25519, 2048-bit DH and RSA key transport gone from the listener."
    provenance: "read 2026-10-23 from the deployment's ledgers by src/pqch/ui/agility.py: scan 01M5FHJHNTJVRPMZ09KQ7YN9TM, trace in investigate run 01M5D11HXJZ4GDAV7KJBYD1CVX, change run 01M5FHSAWHMY78JV1EJX1YQA87, scan 01M5JFEP7D145D2T38TW0S6631"
reuse: [whitepaper, talk, customer-question]
---

# What does a CBOM make possible once it exists?

## The answer

An inventory that is a list can be read. A CBOM whose entries carry their
evidence, sit in a dependency chain and are rebuilt from a record can be
*used*, in four ways a spreadsheet cannot be. It can be projected again into
whatever field list is asked for, without a new scan. It can be compared with
yesterday's to say what changed. It can be read against a policy to say what
comes first and what blocks it. And it can be handed to a language model as
the context for its work — which entry, on which listener, of which service,
served from which file, with what evidence — so that a model can trace a
weakness to the line that causes it and draft the change. The same entry is
then what the result is checked against: a verifier probes the listener the
entry names and decides, with no model in that decision, whether the change
landed.

## The concept

A model asked "make this database post-quantum" with nothing else will write
something plausible about the software in general. Given the entry, it is
asked something narrower and checkable: this listener at this address accepts
these key exchanges, seen by this tool; the service's files are these; this
line causes this one; this is the only file you may edit and these are the
only lines that file may hold. The CBOM supplies the facts, the policy the
intent, and the verifier the test. The model supplies the one thing none of
them can: reading a configuration it has not seen before and writing the
change.

That division is the project's measured position on models
([note 13](13-where-models-belong.md)): a role goes to a model when a model
reached a floor on it, and never the role of deciding whether a change
worked.

## The mechanism

| What the CBOM enables | How | Where it is shown |
|---|---|---|
| Projection | A field list is a data file; the record is rebuilt and projected in milliseconds | the CBOM page, section 3 |
| Comparison | An observation's reference is its fingerprint; event references are left out | the CBOM page, section 4; watch mode |
| Prioritization | The policy pack's rules over the entries and the owner's supplied facts | the queues ([note 07](07-how-a-migration-priority-is-computed.md)) |
| A model's context | The entry, its chain to the service, the service's files | the trace and the draft, on each entry and each proposal |
| Proof | The entry's listener, probed four ways, on a copy before approval and on the estate after | the change section ([note 08](08-what-verified-means.md)) |

**The path for a service with no renderer.** For software the harness can
render by rule, a rule writes the change. For the rest, which is most of a real
estate, the `change-plan` role drafts it:

1. The context is the CBOM: the listener's entries from the latest scan, the
   investigator's trace where there is one, and the service's build files with
   line numbers.
2. The model is told one file is editable — a policy file the service reads
   last — and which lines the runner will write in it. Three calls are made and
   all are recorded; the first usable reply is the proposal, with the model as
   its actor.
3. The runner starts a copy of the service from the scope's image on an
   internal twin network with the proposed file, and the change's own check runs
   against the copy.
4. Only a rehearsal that meets the intent opens the way to approval. A person
   approves; the runner applies, refusing any model's proposal that has no such
   rehearsal in the ledger and in its own log; the verifier probes the estate,
   the service is recreated, and the verifier probes again.

## Worked example

The records database, PostgreSQL 18 behind its TLS upgrade, holds benefits
records with a 75-year lifetime. Its CBOM entries on 2026-10-21 (scan run
`01M5FG9BJBCD7B6WNSM209P8XR`) show it offering the hybrid group X25519MLKEM768
first and still accepting X25519, 2048-bit finite-field Diffie-Hellman and RSA
key transport; its RSA certificate's key is the file `/etc/pg-tls/server.crt`.
The queue rule placed its key establishment in the queue due 2030-12-31, not
blocked on its supplier (PostgreSQL on OpenSSL 3.5 lists ML-KEM), with a
validated module available and not in use. The investigator had traced the DHE
group to the server's default — no live line sets it — on Nemotron 3.5 Super VL.

The policy for the listener was set to *require*. Gemma 4 31B on four L4s,
given those seven entries, the trace and the four build files, drafted the
same change in three replies of about 5 s each:

```
--- agency/generated/records-db/tls.conf
+ssl_groups = 'X25519MLKEM768'
+ssl_min_protocol_version = 'TLSv1.3'
```

The minimum protocol is what matters: TLS 1.3 carries no RSA key transport and
no finite-field DHE. Rehearsed on a copy at `172.16.107.30`, the change was
`enforced` in 33 s: the hybrid-only client accepted, a client offering every
classical group refused, the witness finding only X25519MLKEM768, and a TLS 1.2
handshake refused.

The counterexample is the plan that sets only the groups. On a copy with that
file, a client offering every classical group over TLS 1.3 was refused —
which, read alone, says "enforced" — while a TLS 1.2 client completed a
handshake with DHE-RSA, and another with RSA key transport
([lesson 36](../lessons/36-probe-tls-1-2-apart-when-requiring-post-quantum.md)).
A model that wrote that plan, or a person, would have been told it worked by a
weaker check.

Two changes now wait for the owner's approval, in one change run
(`01M5FHSAWHMY78JV1EJX1YQA87` on the deployment): the records database's,
drafted again under the scope regenerated that afternoon and rehearsed
`enforced` in 37 s, and the jump host's SSH key exchange, which a rule renders
into one line (`KexAlgorithms mlkem768x25519-sha256`) and which rehearsed
`enforced` on a copy — an ML-KEM-only client agreed a key exchange, a client
offering every other one was refused, ssh-audit found only the hybrid. A model
drafts where spike S3 measured the role; OpenSSH had no change-plan items in
the spike and needs no interpretation, so a rule writes it. Neither change has
been applied to the estate.

## Where the CBOM sits in NIST's crypto-agility plan

NIST's white paper on crypto agility (CSWP 39-upd1, December 2025, updated
June 2026) draws the plan an organization needs in order to change its
cryptography repeatedly, as its Fig. 3. *Crypto agility*, in the paper's words,
"describes the capabilities needed to replace and adapt cryptographic
algorithms in protocols, applications, software, hardware, firmware, and
infrastructures while preserving security and ongoing operations" (§1). The figure has five regions inside a loop:
**governance** (standards, mandates, supply chains, threats, policies,
stakeholders); **assets** (code, libraries, applications, files, protocols,
systems); **management tools** that discover, assess, configure and enforce;
**data-centric risk management** — an information repository feeding a risk
analysis and prioritization engine feeding dashboards and measures; and the
two outcomes it informs, **mitigation** and **migration**, which feed back to
the tools.

A CBOM is that information repository. It is also what the other regions
need from each other: the tools write to it, the engine reads it with the
policy, the outcome is checked against it. The workbench's first page draws
the figure, credited and with NIST's own labels, and fills each region with
what the workbench does there, read from the ledgers at render time:

| NIST region | The workbench, on the mini-agency | Who acts |
|---|---|---|
| Governance | OMB M-26-15 as a policy pack checked against the memo's text; the crypto policy; the owner's facts per service | person, rule |
| Assets | services, listeners and images from the scans; call sites in one pinned repository | scanner |
| Management tools | testssl.sh, ssh-audit, cbomkit-theia and the workbench's readers; rules; the runner; the verifier | scanner, rule, model (the trace, the call-site read), verifier |
| Information repository | the hash-chained, ML-DSA-65-signed ledger and the CycloneDX 1.6 CBOM rebuilt from it | rule |
| Risk analysis and prioritization engine | the queue, priority and blocker rules; conflicts settled by rule | rule, model (explaining a conflict; a name the table lacks) |
| Monitoring and measures | the receipts: coverage against the key, changes landed, time-to-change | verifier |
| Mitigation | items whose software cannot take post-quantum cryptography, marked for replacement | rule |
| Migration | a change proposed, rehearsed on a copy, approved, applied and verified twice | model (the draft), person, verifier |

Each of the figure's
labels is lit, half-lit or dim for the estate shown, with the reason, so the
frame doubles as a gap analysis.

The figure also carries one weakness through the loop, step by step, as the
ledgers recorded it. A scan finds records-db accepting X25519, 2048-bit
finite-field Diffie-Hellman and RSA key transport. Rules link the listener to
the service, and the owner's facts (a 75-year data lifetime, a high-value
asset) attach to it. The OMB M-26-15 rules then put it in the 2030
key-establishment queue as a prioritized system. A model traces one finding
to its cause, and a second model drafts the edit from the CBOM's findings and
the files the CBOM links to the service. The edit is rehearsed on a copy, the
copy is tried against each kind of client, a person approves, the runner
applies it, and probes prove it on the wire twice. The next scan's CBOM shows
the classical groups gone, with the signature queue still open, which is the
plan's next step for the service. At each step the page says what the CBOM
contributes. The models act in two steps of thirteen and never decide whether
the change worked.

## What follows

- **Build the record before the model.** The model's work here is a few
  seconds; what makes it usable is that the question it is asked comes from an
  inventory with evidence and a chain, and that its answer is checked by
  something that is not a model.
- **Constrain what a model may write, not what it may think.** One editable
  file, a fixed set of lines, a runner that refuses anything else. The model is
  free to read everything and to be wrong; it cannot write a line the service
  would load and the shape does not allow.
- **Rehearse before approval.** An approver who sees a draft beside its
  rehearsal verdict is approving a measured result, not a model's suggestion.
- **Make the verifier stricter than the plan.** The test that matters is the one
  the easiest wrong plan would pass.

## Scope

Covered: the mini-agency; one model-drafted change, for one PostgreSQL
listener, rehearsed on a copy; the projection and comparison shown on the CBOM
page. Not yet measured: the change applied to the estate and verified there,
which waits for approval; drafts for OpenSSH and the other services; how often
drafts are usable across many services. The `change-plan` role's floor was
measured on spike S3's thirty items with the same prompt and no paragraph
naming an editable file; each draft here is checked by rehearsal, not by that
measurement.

## References

- NIST CSWP 39-upd1, *Considerations for Achieving Crypto Agility: Strategies
  and Practices* (Barker et al., December 19, 2025, updated June 29, 2026),
  Fig. 3 — the plan the overview page redraws; doi:10.6028/NIST.CSWP.39-upd1.
- [Note 01](01-what-is-a-cbom.md) — an entry, field by field.
- [Note 07](07-how-a-migration-priority-is-computed.md) — the queues and blockers.
- [Note 08](08-what-verified-means.md) — what verified means, the four probes.
- [Note 13](13-where-models-belong.md) — which model does which role, measured.
- `src/pqch/migrator/plan.py`, `src/pqch/runner/apply.py` — the draft and the rehearsal.
