# The offline bundle

Everything the slice and the harness run, in a local registry, by digest, for
`linux/amd64` and `linux/arm64`.

```sh
uv run python bundle/build.py                 # build time, with the network
uv run python bundle/load.py --expect-sums <hash> [--lab-overlay workshop/compose.lab.yaml]   # run time
```

`build.py` writes `bundle/out/` (git-ignored): the registry's data directory,
the registry's own image as one tarball per architecture, `manifest.json`,
two Compose overlays that point the slice and the harness at the bundle's
digests, and `SHA256SUMS`. It always rebuilds the harness image, so the bundle
holds the source as it stands, and records the commit in `manifest.json`; the
slice's images are kept from one build to the next unless `--rebuild` is
given, because each build of the slice makes new keys. It ends by printing the
SHA-256 of `SHA256SUMS`: carry that one value separately from the bundle.

`load.py` checks `SHA256SUMS` against that recorded hash, every listed file
against `SHA256SUMS`, and every registry blob against the SHA-256 it is named
by; loads the registry image from its tarball; starts the registry read-only
on `127.0.0.1:15000`; pulls every image from it by digest and checks the
digest is held; starts the slice with `--pull never` and no build; regenerates
the scope from what is running; then starts the harness the same way. The
runner fetches its scanners from the bundle's registry (`PQCH_REGISTRY`) and
recreates a service with the bundle's own agency overlay
(`PQCH_AGENCY_COMPOSE_FILES`), so a change applied on a bundle-started estate
keeps the bundle's image.

Why a registry: an image saved with `docker save` by digest loads back with no
name, and one saved by tag loads back under a new digest. A pinned digest has
to arrive unchanged or not at all (journal lesson 03).

## What was tested, 2026-10-05, on the xr7620 (x86_64)

The bundle was rebuilt from commit `9e45a6a`. Every bundle image and the
registry image were removed from the host's image store, and the system was
started from `bundle/out` alone:

| | |
|---|---|
| Bundle | 8 images, linux/amd64 and linux/arm64, 611 MB; harness built from `9e45a6a`; `SHA256SUMS` hashes to `a7cca8e9e7cb1832542b7457e37d5005d42e0012d02e19b7f81a6ab3d85a7236` |
| Integrity checks at load | the recorded hash matched; 216 registry blobs hash to their names |
| Load and start | 8.7 s |
| Image events the daemon reported during the load | 9: one `load` (the registry image, from its tarball) and eight `pull`s, all from `127.0.0.1:15000` by digest |
| A policy change on the bundle-started estate | `none` to `enable`: applied, verified `enabled-not-enforced`, repeated after the recreate, 65.2 s; the portal stayed on the bundle's image (change run `01M46RM79ASE4V8039GC1HXQB0`) |
| The same with the registry stopped | back to `none`: applied, verified, durable, 62.0 s (`01M46RP7WVRMW1EXNKM4D762P2`) |
| A live scan with the registry stopped | run `01M46RRF5FFA9WYNXFYM6SARKC`: every job ok; wire 22/23, host 7/10, the decoy not flagged, posture 4/4 — as before |
| The slice's egress probe | passes: no route out, no host address on the bridge |

The first bundle, tested on 2026-10-04, held a harness image built an hour
before the code it was tested with was finished, and could not have applied a
change (M0B review F-57). The table above replaces that test.

## What "egress blocked" was, and was not

**Was:** no image came from anywhere but the bundle — every pull the daemon
reported was from the local registry, and Compose ran with `--pull never`. The
slice's network is internal, with no route out and no host address.

**Was not:** the host's own route to the internet was not cut. The Docker
daemon, the registry container and the harness's UI service could have
reached the internet throughout; the test shows they did not fetch images from
it, not that they could not. Cutting the host's route is a host change and was
not made. The test that settles it is a second host with its cable out and an
empty image store (PLAN, M4 rehearsal).

## What the integrity checks cover, and what they do not

**Cover:** a bundle damaged in transit or on disk. The registry serves a blob
as it lies and does not check it, and a client does not fetch what it already
holds, so the loader hashes every blob itself before anything is served. With
one bit flipped in a layer of a copy of the registry, a client with an empty
store refused the layer; Docker on a host that already held it pulled
"successfully" without reading it.

**Do not cover, alone:** a bundle changed on purpose. `SHA256SUMS` travels
with the files it lists; edit a file and its line together and the check
passes. `--expect-sums`, with the hash kept somewhere else, is what closes
that (journal lesson 07 states the same rule for a signed ledger's key).

## Known limits

- The host's route to the internet has never been cut during a load, and the
  host's image store has never been empty of the bundle's layers. Both are
  true only on a machine that has never seen these images: the second host
  in the M4 rehearsal.
- `load.py` runs `uv run pqch scope generate` on the host. On a clean machine
  that needs `uv`, Python and the project's wheels, which the bundle does not
  carry yet (PLAN M4).
- The registry is needed to load, not to run: once the images are in the
  host's store, scans and changes run with it stopped. Pruning images
  afterwards brings the need back.
