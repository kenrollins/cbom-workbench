---
id: note-17-how-a-cbom-becomes-a-migration-plan
type: note
title: "How does a CBOM become a migration plan, and why can't a list of systems?"
date: 2026-10-22
audience: [leader, architect, engineer]
tags: [cbom, agility, managed, policy]
rung: managed
one_line: "A migration plan is an order, and the order comes from what the estate shares — a certificate authority whose leaves must follow its root, a library build several services run, one key on two listeners, clients the agency does not control — which a CBOM records and a list of systems does not; on the mini-agency the CBOM yields 26 steps, 15 of them waiting on another, from six rows that say nothing about each other."
claims:
  - text: "From the mini-agency's CBOM and the M-26-15 policy pack, rules compute 26 migration steps over 34 CBOM entries, with 4 shared dependencies and 15 steps that wait for another step; the agency's spreadsheet has 6 rows, 2 with nothing behind them, and none for 4 of the 8 services."
    provenance: "computed 2026-10-22 by src/pqch/planning.py from scan run 01M5FYXR40S3FRWW9NXYVA5A7K and the deployment's change runs; agency SHEET in src/pqch/ui/app.py"
  - text: "One internal certificate authority issues the certificates of three services, and two of them run software that lists no post-quantum signature; so the CA's ML-DSA root waits on two replacements, and the three reissued certificates wait on the root."
    provenance: "same computation: the CA identified by basicConstraints in the workbench's own reading of each image, leaves by their issuer on the wire, blockers from the capability snapshot of 2026-10-20"
  - text: "Three services run one library build; on it two already negotiate X25519MLKEM768, so for the third the hybrid group is a setting, not an upgrade."
    provenance: "same computation; policy/snapshots/capabilities-2026-10-20.json same-build groups and the scan's posture rule"
reuse: [whitepaper, talk, customer-question]
---

# How does a CBOM become a migration plan, and why can't a list of systems?

## The answer

A migration plan is an order of work, and the order is set by what the parts
of an estate share. A certificate authority's new root has to be in place, and
verifiable everywhere it is held, before any certificate it issues can move.
Software that cannot take the new algorithms has to be replaced before
anything that depends on it. A server is offered a post-quantum key exchange
before it is required to use one, and required only when its clients can
follow. A list of systems — the spreadsheet most agencies start from — names
each system once and says nothing about what connects them. A CBOM records
exactly those connections: which authority issued which certificate, which key
sits on which listener, which build a service runs, what each listener
accepts. From it, with the policy's deadlines, the order can be computed
rather than guessed. Being able to compute the next change, and the one after
it, from the record is what crypto agility rests on.

## The concept

Three questions turn an inventory into a plan:

- **What depends on what.** A shared thing has a blast radius: change it and
  everything tied to it changes too, or breaks.
- **What comes first.** OMB M-26-15 prioritizes high-impact systems, High Value
  Assets, and data still sensitive in 2030. Among those, the longer data must
  stay secret, the sooner its key exchange matters: traffic recorded today is
  decrypted once the key exchange that protected it falls (harvest now,
  decrypt later).
- **In what order.** The dependencies set a partial order; deadlines and
  priority break ties.

## The mechanism

The workbench computes the plan by rules each time it is shown, from the latest
scan's ledger and every change run since. No model orders it.

| Kind of dependency | Found in the CBOM by | What it does to the order |
|---|---|---|
| Certificate authority | a certificate file whose basicConstraints mark it a CA, and the issuer of each served certificate | new root first, distributed to every service holding the old one; then every leaf |
| Library build | the runtime's own list of what it supports, per image, and which images share a build | one service negotiating the hybrid group proves the build can: for the rest it is a setting |
| Shared key | the same public key (SPKI hash) served on more than one listener | one step for all of them |
| Clients' trust anchor | a CA file the service uses to verify clients, issuing none of the estate's certificates | the clients' migration sets the pace of the service's |
| Supplier block | the software lists no post-quantum algorithm for the function | procurement, started now |

Each step carries its deadline, the steps it waits for and unblocks, the CBOM
entries it moves, the CBOM fields it was computed from, and its state: done
when a change with the step's intent landed after the scan.

## Worked example

On the mini-agency, eight services and the M-26-15 pack give 26 steps over 34
CBOM entries. Four dependencies tie them together, and 15 steps wait on
another:

- The internal CA issues the certificates of the records database, the message
  queue and the case-management application. The queue and the application run
  software that lists no post-quantum signature. So their replacement comes
  first, then the CA's ML-DSA root, then all three certificates at once. A plan
  that reissued each certificate on its own schedule would leave two services
  unable to verify their own chain.
- The portal, the partner API and the post-quantum gateway run one OpenSSL
  build, on which the API and the gateway already negotiate X25519MLKEM768. For
  the portal the hybrid group is a setting, not an upgrade.
- The API serves one key on ports 443 and 8443; reissuing for one leaves the
  other serving the old key.
- The API also verifies client certificates against a partner CA whose keys its
  partners hold, so the partners' reissue sets the pace of its signature work.
- The SFTP drop runs OpenSSH 6.6, which lists no post-quantum key exchange,
  while the jump host's OpenSSH 10.0 does: its first step is an upgrade the
  estate has already proved, not a procurement.

The records database's `require` change, applied and verified twice after the
scan, shows as done.

## What if

Any step can be taken as done and the plan recomputed: the steps it frees are
shown. Taking the queue's replacement as done frees its TLS 1.3 step; taking
both the queue's and the case-management application's frees the internal
CA's new root as well. Nothing is recorded; the assumption lives in the
address. It is how a planner tests which piece of procurement unlocks the most.

## What follows

- **Plan from connections, not rows.** The work that takes longest — replacing
  software, moving a CA — is invisible in a list of systems and unavoidable in a
  CBOM.
- **Start procurement now.** Items no setting can move have the longest lead
  time and the same deadlines.
- **Measure clients before requiring.** Every `require` is an order: offered,
  clients measured, then required.

## Scope

Covered: the mini-agency, its supplied owner's facts, the M-26-15 pack, the
capability snapshot of 2026-10-20. The dependency kinds are those this estate
holds; others — a hardware module, a firmware root, a partner's own CA chain —
are not modelled. Lead times are not estimated: "now" means only that the
step depends on nothing else.

## References

- OMB M-26-15 §3.C.2 (prioritization), §3.C.3 (replacement), §4 (TLS 1.3).
- [Note 06](06-how-a-finding-becomes-a-dependency-chain.md) — the chains the plan rests on.
- [Note 07](07-how-a-migration-priority-is-computed.md) — the queues and blockers.
- [Note 16](16-what-a-cbom-makes-possible.md) — the CBOM as the information repository of NIST's plan.
- `src/pqch/planning.py` — the rules.
