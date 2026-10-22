---
id: lesson-09-time-a-scanner-on-the-bare-base-image
type: lesson
title: "Time a file scanner on the bare base image first; symlinks, not size, can set its cost"
date: 2026-10-04
audience: [engineer]
tags: [discovery]
rung: enumerated
one_line: "cbomkit-theia's secrets plugin reads a file's contents once for every symlink that points to it, so a BusyBox-based image costs it about 94 s whatever its size; measure the base before blaming the image."
claims:
  - text: "cbomkit-theia 1.1.2's secrets plugin took 94.8 s of a 94.6 s scan of a 4.6 MB nginx image; the certificates, OpenSSL-configuration and problematic-CA plugins took 0.9 to 1.5 s each."
    provenance: "measured 2026-10-04, xr7620 (x86_64), each plugin run alone on the M0 portal image"
  - text: "A bare alpine:3.22 image took 93.7 s; an image of 4 MB of random files took 1.6 s."
    provenance: "measured 2026-10-04, same host and tool"
  - text: "One 800 KB file took 1.1 s alone, 18.4 s with 50 symlinks to it, and 69.8 s with 200."
    provenance: "measured 2026-10-04, same host and tool, synthetic images"
  - text: "alpine:3.22 holds 304 symlinks to its 808,712-byte BusyBox binary."
    provenance: "counted 2026-10-04 in the pinned image"
  - text: "The plugin used one core at about 100% and about 60 MB of memory throughout; --ignore patterns did not shorten it."
    provenance: "measured 2026-10-04, docker stats during the scan"
reuse: [talk, customer-question]
---

# Time a file scanner on the bare base image first; symlinks, not size, can set its cost

## The rule

Before tuning or budgeting an image scanner, time it on the bare base image
the estate is built from, and on a synthetic image of the same size. If the
base alone is slow, the cost is in the base's structure — usually its
symlinks — not in anything the estate added.

## Why

A file scanner reads every file in an image and matches its contents against
patterns. Its cost should follow the bytes it reads. In cbomkit-theia 1.1.2,
the plugin that looks for secrets and private keys took 94.8 s of a 94.6 s
scan of a 4.6 MB image — every other plugin together took about three
seconds — and it was CPU-bound on one core the whole time.

The image's size did not explain it: 4 MB of random files took 1.6 s. A bare
`alpine:3.22`, with nothing added, took 93.7 s. The difference is structure.
Alpine's command-line tools are one BusyBox binary of about 800 KB with 304
symlinks pointing to it, one per command. The plugin reads the target's
contents once *per symlink*. Measured directly: one 800 KB file took 1.1 s
alone, 18.4 s with 50 symlinks to it, 69.8 s with 200 — linear in the number
of links. 304 links × about 0.3 s each is the 94 s.

So every Alpine-based image costs this plugin about a minute and a half before
the scanner reaches anything the estate put there. Its `--ignore` patterns did
not change the time.

## When it applies

Any scanner that walks a container filesystem: secret scanners, SBOM and
CBOM tools, malware scanners. Bases that link many names to one binary —
BusyBox (Alpine), toybox, multi-call Go binaries — or that keep many
alternatives symlinks are where to look. It does not apply to scanners that
read package databases rather than files.

Under emulation the effect multiplies: the same scans took 633 to 837 s per
image as arm64 under qemu-user.

## How to apply it

```sh
docker save alpine:3.22 -o base.tar
time docker run --rm --network none -v "$PWD:/scan:ro" \
  ghcr.io/cbomkit/cbomkit-theia:<pinned> image -p secrets docker-archive:/scan/base.tar
```

Then run each plugin alone (`-p certificates`, `-p secrets`, …) on the real
image to find which one carries the cost. Count symlinks per target:

```sh
docker run --rm IMAGE sh -c 'find / -xdev -type l -exec readlink {} \; | sort | uniq -c | sort -rn | head'
```

Where image results change only when an image does, scan once per image
digest and replay the result, which is what this project does. Report the
finding upstream with the synthetic reproduction: one file, N symlinks.
