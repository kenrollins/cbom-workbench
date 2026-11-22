---
id: lesson-05-penalize-what-an-inventory-invents
type: lesson
title: "Score an inventory for what it invents, and put a decoy in every layer it is scored on"
date: 2026-10-04
audience: [architect, engineer]
tags: [cbom, discovery]
rung: enumerated
one_line: "A coverage score with no penalty for unplanted claims is maximized by claiming everything; count claims the answer key does not hold as false positives, and never show an untested decoy as avoided."
claims:
  - text: "A CBOM with 180 invented components — every algorithm name on every listener — scored 22 of 23 on the wire with no false positives."
    provenance: "measured 2026-10-03, eval scorer before the change, M0 slice; M0 review F-32"
  - text: "A decoy in a layer no scanner covered was displayed as \"decoys flagged 0 of 1\" in all three columns."
    provenance: "measured 2026-10-03, same scorer; M0 review F-34"
  - text: "One unserved certificate produced six inventory components; marking only the certificate as not in use left its RSA-1024 key and SHA1-RSA algorithm in the inventory."
    provenance: "measured 2026-10-03, M0 slice portal image; M0 review F-33"
reuse: [whitepaper, customer-question]
---

# Score an inventory for what it invents, and put a decoy in every layer it is scored on

## The rule

When an inventory is scored against an answer key, a claim the key does not
hold counts against it; each scored layer contains at least one decoy; and a
layer nothing scanned is reported as not scanned.

## Why

A cryptography bill of materials (CBOM) is scored against an answer key for
*coverage* — how much of what is there it found — and *false positives* — how
much it reported that is not there. If false positives are counted only as
"decoys flagged", three things go wrong.

- **Over-claiming is free.** With no decoy in a layer, nothing reported there
  can be wrong. A scanner that asserts every algorithm on every endpoint
  reaches full coverage with a clean record. Measured: 180 invented
  components, including "ML-KEM-1024 on a classical web server", cost
  nothing; they were filed as "outside the key's scope".
- **An untested trap looks like a pass.** A decoy in a layer that was never
  scanned is "not flagged" by every tool. Shown as 0 of 1 in green, it reads
  as discrimination. It is absence.
- **A decoy is suppressed in part.** Scanners emit several components per
  file: the certificate, its public key, its signature algorithm, its hash. A
  key that matches the decoy only by one component type credits a tool for
  avoiding it while the rest remain in the inventory for a reader to find.

An answer key for a planted estate is *exact* for the class of thing it
covers. That exactness is what allows "not in the key" to mean "wrong".

## When it applies

Any evaluation of a discovery tool against planted truth: cryptographic
inventories, vulnerability scanners, secret scanners, software bills of
materials. It applies with most force when comparing a tool against baselines,
where a lenient scorer flatters whichever column reports more.

It does not apply to findings genuinely outside the key's stated scope — here,
symmetric ciphers and hashes — which are counted separately and neither
credited nor penalized.

## How to apply it

State the key's scope in its header, then score in four bins:

| Bin | Counted as |
|---|---|
| Matches a *present* item | covered |
| Matches a *decoy*, and is reported as in use | false positive |
| In the key's scope, on a keyed subject, matches nothing | false positive ("unplanted claim"), listed by name |
| Outside the key's scope | unkeyed: shown, not scored |

Match a decoy by its *location*, whatever component type the tool emitted.
Give every layer a decoy of its own kind: an unserved certificate in an
image; a weak cipher in a commented-out line of configuration; on the wire, a
group a listener advertises and then refuses to negotiate. Report a layer in
which a column holds no component as "not scanned — N decoys untested".
Finally, test the scorer itself: feed it an inventory that claims everything,
and one that claims nothing, and check that neither scores well.

Write the key, and commit it, before the scanner it scores exists. An honest
key includes items the tool cannot reach, kept in the denominator.
