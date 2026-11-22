---
id: lesson-08-identify-a-key-by-its-public-key-hash
type: lesson
title: "Identify a key in an inventory by the hash of its public key, not by where it was found"
date: 2026-10-04
audience: [architect, engineer]
tags: [cbom, discovery]
rung: structured
one_line: "\"An RSA certificate at this address\" cannot tell a renewed certificate from the old one, and an image digest in the location makes every rebuild look like a new estate; put the public key's hash in the identity and keep build identifiers out of it."
claims:
  - text: "With identity defined as layer, location, type, role and algorithm family, an RSA-1024 and an RSA-2048 certificate at one location had the same fingerprint, and every image-layer fingerprint changed when an image was rebuilt or saved and loaded."
    provenance: "by construction of the fingerprint, and measured digests, 2026-10-03; M0 review F-37"
  - text: "With the public key's SHA-256 in the identity and the image named by repository, all 45 fingerprints on the four-service slice were identical before and after a rebuild of one image."
    provenance: "measured 2026-10-03, M0 slice, runs 01M4168SBEYRZCGMK66K12JV3G and 01M422Q34TCDFE7NT1N80DGGMQ"
  - text: "The same hash joins a certificate seen in a TLS handshake to the file that holds it in an image."
    provenance: "measured 2026-10-03, M0 slice, rule link/public-key/1, four links"
reuse: [whitepaper, customer-question]
---

# Identify a key in an inventory by the hash of its public key, not by where it was found

## The rule

An inventory entry for a key or certificate is identified by where it is,
what kind of thing it is, *and* the hash of its public key. Identifiers that
change on every build — image digests, container ids — are recorded with the
entry and kept out of its identity.

## Why

A cryptography bill of materials (CBOM) is re-scanned, and each re-scan is
compared with the last to answer "what changed?". That comparison needs a
stable identity for each entry: a fingerprint under which the same thing seen
twice is one entry and a different thing is another. Two natural choices each
fail in one direction.

- **Too coarse.** "Wire, this address and port, a certificate, RSA." A
  certificate replaced by another RSA certificate — a renewal, a larger key,
  an attacker's substitute — has the same fingerprint. So does a host key
  regenerated at a different size. The comparison reports no change.
- **Too fine.** "Image `portal@sha256:d7ba…`, this path, a certificate, RSA."
  The digest changes on every rebuild, and on a save and load. Every entry in
  the image becomes new, and the comparison reports that everything changed.

The public key is the stable thing. The SHA-256 of its SubjectPublicKeyInfo
(the standard encoding of an algorithm identifier and key) is the same
wherever the key appears — in a served certificate, in a file, across
rebuilds — and different for any other key.

It does a second job. The same hash, computed from a handshake and from a
file, is what proves they are the same certificate. That is the first link of
a dependency chain, made by arithmetic, with no model and no naming
convention.

## When it applies

Asymmetric keys and certificates in any inventory that is compared over time
or joined across sources. It applies less cleanly in three cases:

- A private key file with no public half alongside has no identity a file
  scanner can compute; a regenerated key there looks unchanged.
- An SSH host key seen on the wire is commonly identified by its OpenSSH
  fingerprint, a hash of a different encoding of the same key. Convert to one
  form before comparing across layers.
- Algorithms with no key — a negotiated group, a hash — have no identity, and
  place plus name is their whole fingerprint.

## How to apply it

```json
"subject": {"kind": "file", "image": "agency/portal", "path": "/etc/nginx/tls/portal.crt"},
"source":  {"subject_digest": "sha256:d7ba…"},
"asset":   {"type": "certificate", "role": "signature", "name": "RSA",
            "identity": "spki-sha256:e028e2ea…"}
```

Fingerprint = SHA-256 of the canonical form of
`{layer, subject, type, role, name, identity}`, with `identity` null when
there is none. Compute the key hash with any X.509 library:

```python
spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
identity = "spki-sha256:" + hashlib.sha256(spki).hexdigest()
```

Test both directions: swap a key for another of the same family and confirm
the fingerprint changes; rebuild the image with the same keys and confirm no
fingerprint does. Settle this before anything compares re-scans; changing the
meaning of an identity later invalidates every record that used the old one.
