# Spike S1 — arm64 images for every planned mini-agency image

Written 2026-10-04, before the check was run.

## Question

Does every image the mini-agency and the harness plan to use publish a
`linux/arm64` build, so the GB10 subset can be built from them?

## Pass criterion

S1 passes when every image in `images.yaml` that is marked `gb10: true`
publishes a `linux/arm64` manifest at the pinned reference, read from the
registry with `docker buildx imagetools inspect`. An image marked
`gb10: false` is lab-only; it passes when it names an arm64 stand-in that
itself passes. Any `gb10: true` image without an arm64 manifest fails S1 and
must be replaced or moved to lab-only, with the reason in the BRIEF's "what one
GB10 does" table.

What S1 does not claim: that an image *runs* on arm64. A manifest is not a
run. The slice's images, the harness and the scanners have run under qemu
emulation (M0 done-criteria); the services planned for M1 have not.

## Method

```sh
uv run python spikes/s1/check.py      # writes spikes/s1/results.json
```

The script reads `images.yaml`, inspects each reference, records every
platform it publishes and the index digest, and applies the criterion above.

## Results

**Not decided yet.** The first run, 2026-10-04 13:14 UTC, printed: 25 of 28
pass; `centos:6` and `debian:jessie` publish no arm64 build and pass as
lab-only through their stand-ins (`centos:7`, `debian:stretch`, which do);
`docker:29-cli`, `positronsecurity/ssh-audit` and `registry:2` could not be
read because Docker Hub answered 429 Too Many Requests. Re-run at 14:46 UTC to
read those three, Docker Hub refused 20 of the 28 and the results file of the
first run was overwritten — that output survives only as quoted here. The check
now keeps the last good reading per image when a registry refuses.

Evidence from elsewhere for the three: ssh-audit's arm64 build is in the
offline bundle at its pinned digest and ran as arm64 in M0's emulation smoke
test; `docker:29-cli`'s arm64 build was pulled to build the arm64 harness
image; `registry:2` is no longer used — the bundle's registry is
`ghcr.io/distribution/distribution:3.0.0`, which publishes arm64. None of
that is a registry read of the image in the list, so S1 stays undecided until
the check runs with Docker Hub answering, or with an authenticated pull.

The check itself is the deliverable here: one command, reproducible, the
criterion fixed before it ran.

**2026-10-05.** Re-run with Docker Hub answering again: 27 of 28 pass. The one
left, `positronsecurity/ssh-audit`, was refused (429) after one pass over the
list used the host's hourly allowance of 100 anonymous reads; its next read
decides S1. `registry:2` was replaced in the list by
`ghcr.io/distribution/distribution:3.0.0`, the same software the bundle was
built with, which publishes arm64. `results.json` is this run's.

**2026-10-05, later: S1 passes, 28 of 28.** With the xr7620 logged in to a Docker
Hub account, reads count against the account (200 an hour) instead of the
lab's shared address, and `positronsecurity/ssh-audit` read as publishing
`linux/amd64`, `linux/arm/v7` and `linux/arm64`. `centos:6` and `debian:jessie`
publish no arm64 build and stay lab-only, with `centos:7` and `debian:stretch`
as their arm64 stand-ins; they belong in the BRIEF's "what one GB10 does"
table, where they already are. `results.json` is this run's.

## Limits, from the M0B review (2026-10-05, F-63)

A second run of the check the same day gave the same 28 of 28 and the same
digests. What "passes" covers:

- **Tags, read on one day.** `images.yaml` holds tags, not digests, and seven
  of them are `latest`. The criterion's "at the pinned reference" describes a
  list that is not pinned yet. `results.json` records the digest each tag
  pointed at when read.
- **Not the images the build pins, in two cases.** The runner pins testssl.sh
  at `sha256:31213829…` and the harness builds from `python:3.12-slim` at
  `sha256:dddfd7e0…`; the tags S1 read now point at `sha256:51918b1e…` and
  `sha256:02108f5d…`. The pinned images do publish arm64 — the offline bundle
  holds both platforms of each — but that is the bundle's evidence.
- **A lab-only image with no stand-in passes unchecked.** Only the build-time
  copy tool is in that case; it publishes arm64 anyway.
- **Order.** The criterion's commit (`05ac3a3`, 13:18 UTC) is four minutes
  after the first run recorded above (13:14 UTC). The file may have been
  written first; git does not show it, as it does for S2.

When the M1 images are chosen, the list takes their digests and the check
reads those.

**2026-10-05, the list pinned.** `images.yaml` now carries a digest for every
image and `check.py` reads the image at that digest, not at the tag: the
repository's own pin where one exists (the Dockerfiles, the runner's
profiles, the bundle build, the S2 targets), otherwise the digest the tag
pointed at when S1 read it. Read at those digests, S1 passes, 28 of 28, and
the digest read equals the digest pinned for all 28. Two pins differ from
where their tags point today — testssl.sh and `python:3.12-slim`, as above —
and a third was found the same way: the S2 RabbitMQ target pins `rabbitmq:4`
at `sha256:1da79932…` while the tag has moved to `sha256:42b190df…`. The
build-time copy tool is marked `build_time: true`; a lab-only image with
neither a stand-in nor that mark now fails.
