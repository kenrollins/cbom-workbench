---
id: note-06-how-a-finding-becomes-a-dependency-chain
type: note
title: "How does a finding become a dependency chain?"
date: 2026-10-20
audience: [architect, engineer]
tags: [cbom, discovery, verification]
rung: structured
one_line: "A finding becomes a chain when each link above it — the certificate it rides on, the service that serves it, the mission function and data lifetime behind that service — is either a rule's assertion resting on named ledger events or a fact the owner typed in and the record labels as supplied; the chain is complete when no link is missing, and it never counts a supplied link as something discovered."
claims:
  - text: "On the eight-service mini-agency, every one of nine listeners has a complete chain: 17 service links discovered by rule (nine listener-to-service, eight image-to-service), each resting on the runner's record of the container it found at the address, and 24 facts supplied by the owner for eight services, each labelled supplied; the five supplied items the answer key lists are all carried and labelled, and coverage is unchanged by them."
    provenance: "measured 2026-10-20, run 01M5CTXE9PH6Y2BKPHZPZ9KFK6 on the xr7620 (x86_64), harness at e742741; score.json against agency/answer-key.yaml"
  - text: "188 of the 220 entries in the same CBOM have no verifier that could confirm a change to them: every host entry (141 keys and other material, 21 certificates, 31 algorithms read from files) and the six SSH host-key algorithms on the wire; 25 key-establishment entries have the paired-probe verifier and 7 served certificates the certificate parse."
    provenance: "the same run; rule verifier/class/1 over policy/verifiers.yaml; counted by eval/score.py"
  - text: "Three conflicts between a file in an image and what its listener serves were settled by rule: two retired certificates no listener serves (the wire is in force, reason not-served) and one ML-DSA-65 certificate that cbomkit-theia reported nothing for while the harness's reader parsed it (the parse is in force, reason tool-limit). No model took part."
    provenance: "the same deployment, the scan run after the rule was corrected for CA files (2026-10-20); events of rule conflict/resolve/1"
reuse: [whitepaper, talk, customer-question]
---

# How does a finding become a dependency chain?

## The answer

A finding is one observation: a tool saw this algorithm, certificate or key
at this place. It becomes a dependency chain when the record can say what the
observation rides on and what rides on it, link by link, and can show for
each link how it knows. In this workbench a chain for a wire entry has five
links above the observation: the listener it was seen on, the certificate or
host key that listener serves, the service that serves the listener, the
mission function that service carries, and how long the data it handles must
stay secret. The first three are *discovered*: a rule asserts each from
evidence already on the ledger and names the events it rests on. The last two,
and whether the service is a high-value asset, are *supplied*: typed in by
the system owner, because no scan can see a mission, and recorded with a
human actor and the label `supplied`. A chain is complete when every link is
present. A supplied link is never counted as coverage, and the CBOM carries
the label on every one, so a reader can tell at a glance which parts of the
chain the evidence found and which parts a person said.

## The concept

The five rungs of the maturity model ask five questions, and the Structured
rung asks two: *what depends on this*, and *how long must the data stay
secret*. The first is what makes an inventory usable for migration — a
certificate is changed on a listener, a listener belongs to a service, and a
service is what an agency can take down, schedule and own. The second is what
sets the order: traffic recorded today can be decrypted once the key exchange
that protected it is broken, so a service whose data must stay confidential
for seventy-five years is in a different queue from one whose data is stale
in a year, whatever the two listeners look like on the wire. OMB M-26-15's
prioritization criteria — high-impact systems, high-value assets, highly
sensitive data — are properties of systems and data, not of cipher suites.

Nothing on the wire or in an image says what a service is for or how long its
data lives. Those facts come from the organization. The design question is
how to carry them beside the evidence without letting them pass for evidence,
and the answer here is the same one the ledger gives for everything else:
every link is an event with an actor, and the actor's kind is what it is. A
rule's link names the events it was computed from. A person's link names the
file it was typed in, with the file's hash.

## The mechanism

**The discovered links.** Three rules, each recording `link.asserted` events
with a `rule` actor and `status: discovered`:

| Link | Rule | Evidence the link rests on |
|---|---|---|
| served certificate → file in the image | `link/public-key/1` | The SHA-256 of the public key (SubjectPublicKeyInfo, or the OpenSSH fingerprint for a host key) is the same in the wire finding and the file finding; both findings' events are the link's inputs |
| listener → service | `link/service/1` | The scope, generated from the estate's compose file, names the service for the listener; and the runner's record of the scan (`binding/scope/1`) says a container at that address ran the scope's image for the whole scan. The binding event is the link's input. A listener that was not bound gets no service link, and the chain says why |
| image → service | `link/service/1` | The same binding events: the container found serving the service's listener runs this image |

The listener itself rests on the `scan.completed` event, which carries the
tool, its version and image digest, and the raw output by path and hash
([note 12](12-what-an-auditable-record-contains.md)).

**The supplied links.** The owner's facts live in one file, `agency/context.yaml`:

```yaml
# agency/context.yaml
schema: pqch.context/1
supplied_by: the system owner
services:
  records-db:
    mission_function: benefits records
    data_lifetime_years: 75
    high_value_asset: true
```

For each service the scope names, each fact becomes a `link.asserted` event
with a `human` actor (the operator who ran the scan), `status: supplied`, the
file's path and SHA-256 as `source`, and the same file in the event's
`evidence` list. A service in the file that the scope does not name gets no
event; a service the scope names with no entry in the file gets a chain
whose last links are marked missing.

**The projection.** The CBOM, rebuilt from these events, carries the chain as
components and dependencies in CycloneDX's own terms: an `application`
component per service, which depends on its listeners and on a `container`
component per image; the container depends on the files found in it; a
listener depends on the assets it negotiates and serves; a served certificate
depends on the file holding its key. The supplied facts are properties of the
service component — `pqch:mission-function`, `pqch:data-lifetime-years`,
`pqch:high-value-asset` — and a `pqch:supplied` property lists each one with
the event that carries it and who supplied it. The scorer reads that list: a
supplied item in the answer key counts as *carried* only when the service
component holds the fact and labels it; a fact carried without the label is
reported as a defect, and no supplied item is ever coverage.

**Two more rules that make a chain honest.** `verifier/class/1` records, for
each class of finding present (layer, asset type, role), which verifier could
confirm a change to it — the paired probes for key establishment on the wire,
the certificate parse for a served certificate, none for anything read from
a file — and the CBOM carries the kind on each entry as `pqch:verifiable-by`.
`conflict/resolve/1` settles each disagreement between what a file says and
what the wire shows, in the vocabulary spike S3 labelled: *not-served* when no
listener of the image serves the file and every precondition for saying so
holds (every listener scanned, bound to the scope's image, every served
certificate found in the image); *tool-limit* when one tool parsed a
certificate from a file and another reported nothing for it; *cannot-tell*
otherwise, with what is missing named. A model may explain a conflict beside
the rule's answer; it never settles one ([note 13](13-where-models-belong.md)).

## Worked example

The portal's X25519 key-exchange entry, from the eight-service estate scanned
on 2026-10-20 (run `01M5CTXE9PH6Y2BKPHZPZ9KFK6`):

| Link | Status | What it rests on |
|---|---|---|
| listener TLS 172.16.106.10:443 | discovered | `scan.completed`: testssl.sh 3.2.4, raw output by hash |
| certificate RSA (2048) | discovered | the wire finding; `link/public-key/1` to `/etc/nginx/tls/portal.crt` in `pqch-agency/portal` by SubjectPublicKeyInfo hash |
| service portal | discovered | `link/service/1`: the scope names `portal` for the listener; `binding/scope/1` found container `pqch-agency-portal-1` running the scope's image for the whole scan |
| mission function: benefits enrollment | supplied | `link.asserted` by the operator; `agency/context.yaml` sha256 recorded |
| data lifetime: 10 years | supplied | the same |
| high-value asset: no | supplied | the same |

The same image holds a second certificate, `/etc/ssl/legacy/portal-2019.crt`,
that no listener serves. Its chain stops at the image: the file is linked to
the service through the image, marked not in use by `in-use/not-served/1`, and
the conflict between the file and the wire is settled by `conflict/resolve/1`
as *wire, not-served*, with the in-use event and the served certificate's
finding as inputs. The records database's chain carries a 75-year data
lifetime and high-value status; its listener is mixed (hybrid key exchange
offered, classical still accepted, RSA key transport too), and that pair of
facts is what the Managed rung will turn into a place in the first queue.

On the page, each listener shows its chain as a list, one link per line with
its status and the event behind it, and each entry shows which verifier could
confirm a change to it. The receipts panel counts the chains complete, the
service links discovered, the facts supplied and labelled, the entries with
no verifier, and the conflicts by outcome.

## What follows

- **Discovered and supplied are different colours of the same record.** An
  inventory that mixes what it found with what it was told cannot be audited;
  one that refuses to carry what it was told cannot be used for
  prioritization. Carry both, label every supplied link, and never let a
  supplied fact raise a coverage score.
- **The service link is where a wire scan meets the organization's map.** It
  rests on something the runner observed — the container at the address and
  the image it ran — not on a name in a spreadsheet. On an estate the harness
  did not build, the equivalent evidence is whatever the operator's own
  deployment record can show; without it, the link is supplied and labelled so.
- **Most of an inventory has no verifier.** On this estate 188 of 220 entries
  are files in images or SSH host-key algorithms, for which no change can yet
  be shown to have landed by a probe. Saying so per entry is what keeps the
  Agile rung's claim — time-to-change, verified — honest about what it covers.
- **Conflicts are rules' work.** Every conflict on this ledger was settled by
  a rule from evidence the ledger already held; the one measured role a model
  was given for this never reached its floor ([note 13](13-where-models-belong.md)).
  The reasons that need a configuration layer — a default applying, a line
  overridden, a stale file — are not decided yet, because no configuration
  scan runs yet.

## Scope

Covered: the eight-service mini-agency, nine listeners (TLS, TLS behind
PostgreSQL's upgrade, SSH), eight images, on an x86_64 lab server; the chain
from a wire or image entry up to the owner's facts. Links are discovered from
wire and image evidence only; no source or configuration scan contributes a
link yet, so a chain stops at the file holding a key and does not reach the
line of code or configuration that selects it (the investigator's trace is a
model's claim recorded beside the chain, not a link in it). The owner's facts
are the mini-agency's planted ones.
The Managed rung — owners, deadlines, queues
computed from the lifetime and the posture — is not built.

## References

- `spec/interfaces.md` §3 — the `link.asserted` event, its subject forms and
  the supplied form; the CBOM projection's components and dependencies.
- `src/pqch/assessor/chains.py`, `verifiers.py`, `conflicts.py` — the rules.
- `agency/context.yaml`, `policy/verifiers.yaml` — the owner's facts and the
  verifier table, both data.
- `BRIEF.md`, "The story: five rungs" — the Structured rung's pass condition
  this note answers to.
- OMB M-26-15 §3.A and Appendix A §6 — prioritization criteria and the
  reason data lifetime sets the order.
- Related notes: [what is a CBOM](01-what-is-a-cbom.md);
  [what an auditable record contains](12-what-an-auditable-record-contains.md);
  [where models belong](13-where-models-belong.md).
