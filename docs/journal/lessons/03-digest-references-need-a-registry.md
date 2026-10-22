---
id: lesson-03-digest-references-need-a-registry
type: lesson
title: "Carry a registry in an offline bundle; `docker save` and `docker load` do not preserve digest references"
date: 2026-10-04
audience: [engineer]
tags: [discovery]
rung: all
one_line: "An image saved by digest loads back as an untagged id, and an image saved by tag loads back under a new digest; an air-gapped bundle that pins by digest needs a local registry, filled registry-to-registry with every platform."
claims:
  - text: "Three scanner images saved as repo@sha256:… and loaded on the same daemon came back as untagged image ids; containers pinned to those references failed with \"No such image\"."
    provenance: "measured 2026-10-03, Docker 29.1.5 with the containerd image store, xr7620 (x86_64); run 01M40YH61ZS2Z7CAKNR8A7TRKA records the failed scans"
  - text: "A locally built image saved by tag for one platform and loaded back kept its tag and changed its repository digest."
    provenance: "measured 2026-10-03, same host; portal image digest b5d8ade… before, d7bafe8… after"
  - text: "Pushing an image whose index was pulled for two of its platforms changed its digest from 6d5dee75… to 1e3ea107…; Docker reported that only the single-platform image it held was pushed."
    provenance: "measured 2026-10-04, Docker 29, positronsecurity/ssh-audit"
  - text: "A bundle of 8 images for linux/amd64 and linux/arm64 in a local registry was 608 MB; with every image the deployment used removed, the slice and harness started from it in 8.9 s, the daemon reported eight pulls all from the local registry, and a live scan scored as before."
    provenance: "measured 2026-10-04, xr7620 (x86_64); bundle/README.md, run 01M43PBXACRFGEXMS7DJZXYKJY"
  - text: "Anonymous reads from Docker Hub were refused with 429 Too Many Requests for most of an afternoon of building and checking images on the lab host."
    provenance: "observed 2026-10-04, spike S1 and the bundle build"
reuse: [talk, customer-question]
---

# Carry a registry in an offline bundle; `docker save` and `docker load` do not preserve digest references

## The rule

A bundle that must start with no network, and whose images are pinned by
digest, carries a registry with its data directory, filled registry-to-registry
with every platform of each image, and is tested by removing every image and
starting from the bundle alone.

## Why

Pinning an image by digest (`repo@sha256:…`) is how a deployment runs exactly
the bytes that were tested; a digest names the content, not a place. Three
ways of moving images lose it:

- **`docker save` by digest.** The image comes back from `docker load` as an
  untagged id. The bytes are present and nothing can start them by the
  reference that pins them: "No such image".
- **`docker save` by tag.** The tag survives; the repository digest changes,
  because the saved form drops the multi-platform index the original digest
  named. Any record of "this service runs digest X" is stale after the load.
- **`docker push` of an image pulled for some of its platforms.** Docker pushes
  only what it holds and builds a new index for it, under a new digest.

A registry stores manifests and indexes by digest and serves them unchanged,
so a reference that resolved when the bundle was built resolves when it is
loaded. Two tools fill it without losing a digest: a multi-platform build
pushed straight to it (`docker buildx build --platform … --push`), and a
registry-to-registry copy of every platform (`skopeo copy --all`). Check each
digest after the copy; refuse the bundle if one changed.

The registry's own image is the one thing saved with `docker save` — by tag,
which does survive — once per architecture.

Built and tested this way, a bundle of eight images for two platforms was 608
MB; with every image the deployment uses deleted, the system started from it
in 8.9 s, every pull the daemon reported came from the local registry, and a
live scan through it scored as before.

One more reason to build the bundle early: anonymous reads from Docker Hub are
rate-limited, and on a shared lab address they were refused for most of an
afternoon. A bundle built ahead of time is also what makes a build repeatable
on a bad day.

## When it applies

Air-gapped or offline deployments of anything pinned by digest — scanners,
verifiers, services whose image identity is itself evidence. It does not apply
to a bundle whose images are referenced by tag and whose digests are never
compared; there `save` and `load` are enough.

## How to apply it

```sh
# build time, online: a registry with its data on disk
docker run -d --name bundle-registry -p 127.0.0.1:15000:5000 \
  -v "$PWD/bundle/out/registry:/var/lib/registry" ghcr.io/distribution/distribution:3.0.0
# your own images, every platform, straight in
docker buildx build --platform linux/amd64,linux/arm64 -t 127.0.0.1:15000/agency/portal:m0 --push agency/portal
# third-party images, every platform, digest unchanged
skopeo copy --all --dest-tls-verify=false \
  docker://ghcr.io/testssl/testssl.sh@sha256:DIGEST docker://REGISTRY_IP:5000/testssl/testssl.sh:pinned
# the registry's own image, by tag, per architecture
docker save --platform linux/arm64 -o bundle/out/registry-image.arm64.tar ghcr.io/distribution/distribution:3.0.0
```

At run time: load the registry image, start it read-only on its data, pull
each image by digest from it, start with `--pull never`. Point the
deployment's configuration at the registry-qualified digests and regenerate
anything that records image digests after the load. Test by deleting the
images first and recording the daemon's image events: every pull should name
the local registry. Say what the test did not do — here, the host's own route
to the internet was not cut.

The project's scripts: `bundle/build.py`, `bundle/load.py`.
