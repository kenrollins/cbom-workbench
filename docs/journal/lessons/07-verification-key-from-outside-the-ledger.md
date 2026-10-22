---
id: lesson-07-verification-key-from-outside-the-ledger
type: lesson
title: "Take the key that verifies a signed log from somewhere other than the log"
date: 2026-10-04
audience: [leader, architect, engineer]
tags: [verification, signatures]
rung: all
one_line: "A public key stored beside the data it verifies can be replaced along with it; record the key's id and the latest signed checkpoint somewhere the writer cannot reach."
claims:
  - text: "A copy of a real ledger with a verdict altered, every checkpoint re-signed with a new ML-DSA-65 key, and the adjacent public-key file replaced, verified from the files alone."
    provenance: "measured 2026-10-03, change run 01M4189RVMMBREE31W3RY39WGJ; M0A review F-48"
  - text: "A ledger cut back to its first checkpoint verified from the files alone, and failed when checked against the signer's own record of the checkpoints it had signed."
    provenance: "measured 2026-10-03, same run"
reuse: [whitepaper, talk, customer-question]
---

# Take the key that verifies a signed log from somewhere other than the log

## The rule

A signed log is verified with a public key, and against a latest checkpoint,
that were obtained independently of the log's own files. Verification that
used only what sits beside the log reports that plainly.

## Why

A tamper-evident log chains each entry to the one before by hash and signs
checkpoints over the chain. The signature says: whoever held the private key
attested to this state. Two things are needed to use it, and both are easy to
keep in the wrong place.

- **The public key.** It is convenient to store it next to the log so a
  reader has everything in one directory. But a party able to rewrite the log
  can rewrite that file too: alter the entries, recompute the hashes, sign new
  checkpoints with a key of their own, and replace the public key. Every
  check then passes, because the log is being verified against itself.
- **The latest checkpoint.** A signature covers everything up to a point and
  nothing after. A log truncated back to an earlier checkpoint is a valid,
  shorter log. Only someone who knows a later checkpoint existed can tell.

Both were measured on a real ledger. Checked against the signing service's
own key and its own list of what it had signed, each tamper failed. Checked
from the files alone, a full rewrite with a swapped key passed, and so did a
truncation.

This is not a weakness of the signature algorithm. ML-DSA-65 (FIPS 204), a
post-quantum signature scheme, did exactly what a signature does. The trust
anchor was in the wrong place.

## When it applies

Any signed or hash-chained record meant to be checked later by someone other
than its writer: audit logs, software attestations, transparency logs,
inventories with provenance. It applies with most force when the record is
exported — sent to an auditor, archived, moved to another machine.

## How to apply it

Publish two short values out of band each time they change, where the log's
writer cannot alter them — a ticket, a printed report, a second system:

- the **key id**: the SHA-256 of the public key in its standard encoding;
- the **latest checkpoint**: its sequence number and the hash it signed.

Then verify with them:

```sh
pqch ledger verify --signed ledger.jsonl \
  --key-id 69d4ea57…16f2 \
  --known checkpoints.json      # [{"through_seq": 12, "head_hash": "…"}]
```

Have the tool warn, in its output and not only its documentation, when the
key was taken from beside the log and checked against nothing. Have the
signer keep its own record of what it signed, apart from the log, and refuse
to sign a log from which one of its earlier checkpoints has disappeared. Show
the key id and the latest checkpoint on screen so a reader can copy them
down.

State the limits beside the result: a signature proves the log has not
changed since signing, not that what was written was true; entries after the
latest checkpoint are unsigned; and nothing here protects against the holder
of the signing key.
