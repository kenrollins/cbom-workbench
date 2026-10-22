---
id: note-12-what-an-auditable-record-contains
type: note
title: "What does an auditable record of agent work contain?"
date: 2026-10-05
audience: [leader, architect, engineer]
tags: [cbom, verification, signatures]
rung: all
one_line: "An append-only event log in which each event names its actor, its inputs and its evidence, is chained by hash, and is checkpointed with a post-quantum signature by a party that is not the writer — plus a plain statement of what that does not prove."
claims:
  - text: "An ML-DSA-65 signature is 3,309 bytes. OpenSSL 3.5.7 signs in 0.88 ms and verifies in 0.16 ms; a checkpoint through the signer's command-line path takes 5 to 11 ms."
    provenance: "measured 2026-10-03, xr7620 (x86_64), harness image (Debian 13, OpenSSL 3.5.7), openssl speed and 20 checkpoints over run 01M416HVH3A1ZE2MFBNFDY1RR5"
  - text: "A hash chain alone accepts a ledger with its last events removed, and a ledger rewritten whole with hashes recomputed."
    provenance: "measured 2026-10-03, tamper suite over a real run's ledger; M0 review F-28"
  - text: "Checked against the signer's key and its record of what it signed, truncation behind a checkpoint, an edited event, a recomputed rewrite and a re-signing with another key each fail."
    provenance: "measured 2026-10-03, nine tamper cases over change run 01M4189RVMMBREE31W3RY39WGJ; M0A review"
  - text: "From the files alone, a ledger rewritten and re-signed with another key, with the public-key file beside it replaced, verifies."
    provenance: "measured 2026-10-03, same suite; M0A review F-48"
  - text: "With the signer's own time in each checkpoint, the ledger's clock and the signer's gave the same time-to-change, to 0.1 s, on a live change."
    provenance: "measured 2026-10-04, M0 slice, xr7620 (x86_64), change run 01M43FZ7534ZF48DH0ZB9FMZWC"
  - text: "Before a run's first checkpoint nothing bounded a timestamp from below: a policy event stamped one hour in the past was signed, and one held 15 s and restamped gave 47 ms on the writer's clock and 51 ms on the signer's with 15.05 s elapsed. With a signature before the event and one after, a change measured 55.6 s on the writer's clock and no more than 55.6 s on the signer's."
    provenance: "measured 2026-10-05, live signer, xr7620 (x86_64); M0B review F-54; change run 01M46RCKJZA12PD1REM722YF4F"
  - text: "With the signer's clock up to 2 s fast or slow the two readings of an interval agreed within 10 ms; an hour off either way, the signer refused to sign."
    provenance: "measured 2026-10-05, a local copy of the signer with its clock offset, nine cases"
reuse: [whitepaper, talk, customer-question]
---

# What does an auditable record of agent work contain?

## The answer

A record that lets a third party ask "where did this come from, who decided
it, and how do you know it happened" needs five things:

1. **Events, not state.** One entry per thing that happened, appended and
   never edited.
2. **Provenance in every event.** Who or what acted, which earlier events it
   acted on, and the raw evidence by reference and hash.
3. **A chain.** Each event carries the hash of the one before, so an edit,
   a removal from the middle or a reordering is evident.
4. **Signed checkpoints, made by a party that is not the writer,** and a copy
   of the latest one kept somewhere the writer cannot reach.
5. **A stated boundary.** What the signatures prove, what they do not, and
   whose word each kind of event rests on.

The inventory, the scores and every screen are then computed from the record,
and can be thrown away and rebuilt.

## The concept: the record is the system, the inventory is a view

A cryptography bill of materials (CBOM) describes a state: these algorithms,
keys and certificates, in these places. On its own it cannot say why an entry
is there, what changed since yesterday, or whether a fix was checked. When
several actors contribute — scanners, rules, a language model, a person
approving, a tool applying a change — the questions an auditor asks are about
the sequence, not the state.

So the system of record here is a ledger: an append-only file of events. The
CBOM is a projection of it, a pure function with no clock and no randomness:
the same events give the same bytes.

## The mechanism

**One event.**

```json
{
  "schema": "pqch.event/1",
  "seq": 42,
  "id": "01M4…",
  "ts": "2026-10-03T16:07:06.448Z",
  "type": "approval.granted",
  "actor": {"kind": "human", "id": "…"},
  "inputs": ["01M4…"],
  "payload": {},
  "evidence": [{"ref": "var/raw/01M4….json", "sha256": "…"}],
  "prev": "…",
  "hash": "…"
}
```

`inputs` names the events this one was derived from; following them backward
answers "why". `evidence` points at raw tool output by path and hash. `hash`
is the SHA-256 of the event's canonical form; `prev` is the previous event's
`hash`. An event a model contributed to names the model, its tier and the
hardware it ran on in `actor`.

**What makes a chain valid, beyond its hashes.** Anyone who can write the file
can recompute every hash, so the hashes prove only internal consistency. A
ledger must also make sense: it starts with the event that states the scope;
ids are unique; `inputs` name earlier events; timestamps do not go backward;
each event type comes only from the kind of actor allowed to produce it (a
verdict from a verifier, an approval from a person); a change is applied only
after it is approved; nothing follows the closing event.

**Signed checkpoints.** A checkpoint signs the ASCII message
`pqch.checkpoint/1\n<sequence number>\n<hash of that event>\n<signer's time>`
with ML-DSA-65, the post-quantum signature algorithm of FIPS 204. A migration
tool whose own audit trail relied on a quantum-vulnerable signature would
undercut itself. A checkpoint is written after every proposal, every approval
and every verification verdict, before a run is closed — and immediately
before each of the two events a person causes, the policy change and the
approval.

**Who signs.** A separate signer service holds the key on storage nothing else
mounts, with no network. It signs only after verifying the chain itself, and
only if every checkpoint it signed earlier for that run is still present. It
keeps its own list of what it signed. That list is what reveals truncation: a
ledger that ends before a checkpoint the signer remembers has lost events. It
also refuses a ledger whose first event names another run, or no run, so a
ledger copied under a new run id is not signed a second time. It signs only
forward, and its own times never run backwards within a run.

**Time from someone other than the writer.** The writer stamps every event
with its own clock, so intervals computed from those stamps — time-to-change,
for one — rest on the writer's word. The signer puts its own UTC time in each
checkpoint, inside the signed message, and uses it to bracket the writer's
stamps: no event may claim a time later than the signature over it, and none
after a checkpoint may claim a time before it, within a stated tolerance (two
seconds here, where both run on one host).

A signature over an event says the event existed *by* then. That bounds the
end of an interval and not its start: an event can be written, held, and
shown to the signer late, or stamped an hour early if nothing was signed
before it. The lower bound comes from the chain. An event is hashed onto
everything before it, so an event that follows a checkpoint in the chain was
written after that signature was made. An event is therefore bracketed when a
checkpoint is written just before it and another just after — which is why
the policy change and the approval each get one on both sides.
Time-to-change on the signer's clock is then an upper bound: from the last
signature before the policy event to the first signature over the verdict.
On a live change the two readings were 55.6 s and "no more than 55.6 s". When
they differ by more than twice the tolerance, neither is shown.

**Who writes.** One process appends to a ledger. Other parties return results
to it. The tool that applies changes — the only one with control of the
container runtime — reads the ledger itself before acting, and proceeds only
if it finds the proposal, a later approval whose diff is exactly what would be
applied, and a signed checkpoint covering that approval. It keeps its own log
of every job it ran and every change it applied. The page compares the ledger
with that log: each probe a verification verdict cites must be a job in the
runner's log with the same output hash, the same times and the same container,
cited by no other verdict; it must be the job the check prescribes, started
after the runner's own record of the apply, against the container that apply
created; and its raw output must give the verdict's status when parsed again.
A change the runner's record does not bear out is shown with no verified
status and no time-to-change.

## Worked example

A change run from the test estate, 15 events, 5 checkpoints: scope, policy
change, proposal, approval, checkpoint, apply, verdict, checkpoint, recreate,
verdict, checkpoint, a further check, checkpoint, closing checkpoint, close.

Tampering with a copy, checked two ways:

| Tamper | Chain only | With the signer's key and record |
|---|---|---|
| Edit one event | fails | fails |
| Remove an event from the middle | fails | fails |
| Remove the last events | **passes** | fails: "a checkpoint through event 6 was signed; events have been removed" |
| Change a verdict, recompute every hash | **passes** | fails: the checkpoint's hash no longer matches |
| The same, then re-sign every checkpoint with a new key | **passes** | fails: signed with another key |
| The same, and replace the public-key file beside the ledger; verify from the files alone | — | **passes** |

The last row is the important one. A public key stored next to the thing it
verifies is not an independent check.

Cost, on an x86_64 lab server: 0.88 ms to sign and 0.16 ms to verify; 5 to 11
ms per checkpoint including starting the signing process. Signing is not what
limits how often to checkpoint.

## What follows

- **Record two short values outside the system:** the signer's key id and the
  latest checkpoint's hash. With them, anyone holding the public key can
  detect alteration of anything at or before that checkpoint. Without them,
  verification from files is a consistency check.
- **A signature proves integrity since signing, not truth at signing.** The
  signer attests that the chain was well formed when it signed. If the writing
  process recorded an approval nobody gave, the checkpoint over it is still
  valid.
- **Say whose word each event rests on.** Here: scan results and applied
  changes rest on the runner and can be cross-checked against its log;
  approvals rest on a sign-on at the front door, accepted only from the front
  door's address; verdicts are written by the harness and re-derived by the
  reader from the runner's log and raw output; timestamps are the harness's
  clock, bracketed by the signer's.
- **For agent systems generally:** the same structure answers "what did the
  model decide?" precisely. A model appears as an actor on specific events,
  with its inputs, and never on a verification.

## Scope

Covered: the event format, hash chain, validity rules, ML-DSA-65 checkpoints
and their verification, as built and attacked on the four-service test estate
on x86_64. The same image passes its checkpoint tests built for arm64 under
emulation; no timing from that is given.

Not covered, and open: approvals are not signed by the approver's own key, so
whoever controls the writing process, or can connect from the front door's
address, can record one. No signature shows how long a person's decision
waited before the writer recorded it. A writer can leave out the checkpoint
before an event; the reader then reports only when the signer first saw it.
The signer's time bounds the writer's clock to
within its tolerance; it does not make the signer's own clock right. Events after
the latest checkpoint are unsigned. The signature gives no protection against
whoever holds the signing key. Key rotation and long-term archival are not
addressed.

## References

- ADR-0001, *The ledger is the system of record* — the decision and its
  alternatives.
- `spec/interfaces.md`, section 3 — the event, the validity rules, the
  checkpoint, and "Who writes the ledger".
- `docs/fable-review/M0-review.md` F-27, F-28; `M0A-review.md` F-45 to F-48 —
  the attacks and their results.
- FIPS 204 — ML-DSA.
- OWASP CycloneDX, *Authoritative Guide to CBOM* — the format of the
  projection.
- Related: [lesson 07, the verification key comes from outside the ledger](../lessons/07-verification-key-from-outside-the-ledger.md);
  [lesson 04, an identity header only from the proxy](../lessons/04-identity-header-only-from-the-proxy.md).
