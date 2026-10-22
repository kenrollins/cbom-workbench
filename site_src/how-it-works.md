---
title: How It Works
---

# How it works

## Evidence first, a model only where interpretation is needed

Three layers of evidence feed one inventory:

| Layer | Tools | What they see |
|---|---|---|
| Wire | testssl.sh, ssh-audit, OpenSSL probes; Zeek beside a client | What a listener accepts: protocol versions, key-exchange groups, RSA key transport, the served certificate; what a client offers |
| Host | cbomkit-theia on container images | Certificates, keys and configuration files in the image |
| Code | CBOMkit's source scanners (Java, Python, Go); an Opengrep rule pack for Ruby | Call sites |

Each tool's output is normalized into one finding schema and appended to the
ledger with the raw output's hash. Rules link findings across layers — the
certificate served on the wire to the file in the image that holds it — and
state a posture per listener. A model is called for the things that need
reading: a call site, an unfamiliar spelling, a conflict between findings.
Which of those roles needs the larger of the two models is decided by
measurement ([spike S3](https://github.com/kenrollins/cbom-workbench/tree/main/spikes/s3)),
not assumption.

## Enabled is not enforced

Adding the hybrid group to a server changes nothing for a client that does not
offer it. A scanner that offers the hybrid group sees it negotiated and reports
success; the server's posture toward every other client is unchanged. So the
verifier runs a pair:

| Hybrid-only client | Classical-only client | Status |
|---|---|---|
| accepted | refused | `enforced` |
| accepted | accepted | `enabled-not-enforced` — a real state, not a pass |
| refused | — | `not-landed` |

The classical-only probe offers *every* classical group a client could offer,
not the two the server used to be configured with: a listener set to the
hybrid group and P-384 passed a probe that refused only X25519 and P-256
([lesson 01](lessons/01-refuse-every-classical-group.md)). A second tool of a
different kind enumerates what the listener accepts and can only lower the
verdict. Each probe records the container it reached, and the check is repeated
after the service is recreated. No model takes part.
[Note 08](notes/08-what-verified-means.md) has the full mechanism.

## The ledger is the system of record

Every finding, link, approval, applied change and verdict is an event:
hash-chained to the one before, naming its actor, its inputs and its evidence.
The CBOM is a projection of the ledger and can be deleted and rebuilt. A
separate signer service checkpoints the chain with ML-DSA-65, keeps its own
record of what it signed, and puts its own time in each signature, so that
events cannot be cut from the end, rewritten behind a checkpoint, or stamped
with a time the signer did not see. The runner — the only component that can
touch the estate — applies a change only after reading the ledger itself and
finding the approval under a signature. [Note 12](notes/12-what-an-auditable-record-contains.md)
describes the record and what was tried against it.

## Scored against an answer key, beside the scanners run alone

The test estate is built with every weakness planted, so the answer key is
exact: items that are present, decoys that look like findings and are not,
items that are real and out of reach, and items that were typed in rather than
discovered. The workbench is scored by layer beside two baselines: CBOMkit
alone, and all the scanners run alone with no harness. At the first rung the
workbench finds exactly what the scanners find; what it adds is the link from
a wire finding to the file holding the key, the judgement that a certificate
sitting in an image is not served, and a stated posture per listener
([note 15](notes/15-what-the-open-source-scanners-cover.md)).
