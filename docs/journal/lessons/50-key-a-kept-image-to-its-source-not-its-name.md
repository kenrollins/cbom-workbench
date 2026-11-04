---
id: lesson-50-key-a-kept-image-to-its-source-not-its-name
type: lesson
title: "When a bundle keeps an image from one build to the next, key it to a hash of its build context, never to its name"
date: 2026-11-04
audience: [engineer]
rung: all
tags: [verification, discovery]
one_line: "A bundle that reuses an image by name will carry a stale service for as long as the name stays the same; the kept image must be keyed to what it was built from, and the test that catches it is scoring the bundle-started estate against the answer key."
claims:
  - text: "The offline bundle built on 2026-11-04 carried the mini-agency's api image from 2026-10-05, without the partner listener on 8443 and its CA file added on 2026-10-19, because the builder kept any image whose name it already held; two live scans from that bundle scored wire 35 of 40 and host 19 of 20, and the same scan after a forced rebuild scored 38 of 40 and 20 of 20."
    provenance: "measured 2026-11-04 on the lab GB10: runs 01M6J326QNTAFJW3CQNVR2JFPJ, 01M6J3PHTFJFANMPJ3K5ARQQX1 (stale api image) and 01M6J41JHM771T1JA0AWZZDAPC (rebuilt); bundle/build.py before and after the change"
reuse: [runbook]
---

# When a bundle keeps an image from one build to the next, key it to a hash of its build context, never to its name

## The rule

A bundle builder that reuses an image already in the bundle must decide "already built" by a hash of the
image's build context (every file's path and content), recorded in the manifest beside the image, and
rebuild when the hash differs. The image's name and tag say nothing about what it was built from.

## Why

Keeping images is right for a test estate whose every build makes new keys and certificates: rebuilding
it needlessly changes the estate under the answer key. But "keep if the name exists" keeps forever. The
mini-agency's api service gained a second listener on 2026-10-19; the bundle, first built on 2026-10-05,
kept the api image by name on every build after, and a scan started from that bundle could not find
what the source had added. All of its jobs reported `ok`: a scanner that cannot connect to a listener that
does not exist records a finding of its own, not a failure. The defect showed only as a lower score against
the answer key, which is the one check that knows what should be there.

## When it applies

Any build that caches an artefact across runs by a stable name: a bundle, an image cache, a wheelhouse,
a generated fixture. It does not apply to artefacts that must be rebuilt every time (the harness image,
which must be the source as it stands) or to artefacts fetched by digest, which are keyed already.

## How to apply it

`bundle/build.py` records `source_hash` per built image in `manifest.json` and keeps an image only while
the hash of its context matches; `--rebuild` forces every slice image. After any bundle build, start the
estate from the bundle and run one scan: the answer-key score (wire, host, posture, false positives) must
match the score of the estate built from source. A bundle whose score is lower carries something stale.
