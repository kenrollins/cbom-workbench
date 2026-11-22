---
id: lesson-15-check-a-bundles-blobs-and-anchor-its-checksums
type: lesson
title: "Hash every blob in an offline bundle's registry before serving it, and keep the checksum file's own hash somewhere else"
date: 2026-10-05
audience: [architect, engineer]
tags: [verification]
rung: all
one_line: "A registry serves what is on disk without checking it, a client does not re-fetch what it holds, and a checksum file edited together with what it lists still passes."
claims:
  - text: "With one bit flipped in a layer, a distribution 3.0.0 registry served the damaged bytes under the original digest; skopeo, with no local store, refused them; Docker 29.1.5 with the layer already in its store pulled successfully twice without fetching it."
    provenance: "measured 2026-10-05, a copy of the project's bundle registry, xr7620 (x86_64); M0B review F-58"
  - text: "A loader that checked five listed files against SHA256SUMS accepted a manifest naming another image once the manifest's line in SHA256SUMS was edited too."
    provenance: "measured 2026-10-05, a copy of the bundle's small files"
  - text: "Hashing all 216 blobs of a 611 MB bundle is part of an 8.7 s load and start."
    provenance: "measured 2026-10-05, bundle/load.py, xr7620 (x86_64)"
reuse: [whitepaper, customer-question]
---

# Hash every blob in an offline bundle's registry before serving it, and keep the checksum file's own hash somewhere else

## The rule

An offline bundle that carries a container registry's data directory is
checked in two steps before use: every blob is hashed and compared with the
SHA-256 it is named by, and the bundle's checksum file is compared with a
hash that did not travel with the bundle.

## Why

Three behaviours, each reasonable alone, add up to no check at all.

- **The registry trusts its disk.** Blobs are stored under their SHA-256, and
  the registry serves the file at that path. It does not hash it on the way
  out.
- **The client trusts its store.** A client verifies the digest of what it
  downloads — and downloads nothing it already holds. On a machine that has
  seen the image before, a pull "succeeds" without reading the damaged blob.
  The damage surfaces later, on another machine, or after a prune.
- **A checksum file beside the data is self-consistent, not authentic.**
  Anyone who can change a listed file can change its line. This is the same
  mistake as keeping a public key beside the log it verifies
  ([lesson 07](07-verification-key-from-outside-the-ledger.md)).

Content addressing makes the first check free of any extra file: the name is
the checksum. Only one value needs to be carried separately.

## When it applies

Air-gapped delivery of images by registry directory, mirrored registries
restored from backup, any content-addressed store moved as files. It applies
whether the concern is a failing disk, a truncated copy or deliberate change;
the second step is for the last.

## How to apply it

```python
# bundle/load.py — before the registry is started
for data in sorted(registry.glob("docker/registry/v2/blobs/sha256/*/*/data")):
    if sha256_of(data) != data.parent.name:
        raise SystemExit(f"registry blob {data.parent.name[:16]}… does not hash to its name")
```

- At build, print the SHA-256 of the checksum file and record it where the
  bundle's carrier cannot reach: a ticket, the receiving team's notes, a
  signed message.
- At load, require it: `bundle/load.py --expect-sums <hash>`. Without it,
  print that the bundle was checked against nothing but itself.
- Test the loader on a machine with an empty image store before relying on
  "every image came from the bundle"; on a warm machine a pull event names
  the registry and may have fetched nothing.
