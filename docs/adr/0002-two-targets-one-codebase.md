# ADR-0002: Two targets, one codebase

- **Status:** Superseded by ADR-0004 on 2026-10-08. The one-GB10 target was
  withdrawn; decisions 2, 4, 5, 6, 7, 9 and 11 survive in ADR-0004, the rest
  are retired. Kept for the record of why the design looked as it did.
- **Date:** 2026-10-01
- **Amended:** 2026-10-03 — the GB10 is a stated subset of the lab, not its
  equal; the runner added; memory bounds made precise (`docs/fable-review/`,
  F-08, F-11, F-15, F-16, F-20)
- **Deciders:** Ken Rollins

## Context

The workbench is developed in a lab with an x86_64 host, a model gateway
backed by more than one machine, and shared services. It must also run as a
standalone demonstration on a single arm64 Dell Pro Max GB10 with no internet
at runtime and whatever models that machine carries. The demonstration has two
jobs: to show the full path working on one box, and to show honestly where one
box stops and what more hardware changes.

## Decision

1. **The lab is the superset; one GB10 runs a stated subset.** The subset is
   the full path from Opaque to Agile, offline, on one box, and it must stand
   on its own. Anything outside it is listed in the BRIEF's "what one GB10
   does" table with the reason, the measurement, and what more hardware
   changes. A feature that works only in the lab and is not in that table is a
   defect.
2. **One inference seam.** Code asks for a tier — `fast`, `deliberate`,
   `embed`. A config file maps tiers to an OpenAI-compatible base URL, key and
   model id. Profiles: `lab` and `standalone`.
3. **Engines take turns on the standalone target.** The fast engine is the
   default. Work for the deliberate engine is queued in the ledger and drained
   in batches; a residency controller starts and stops engines and records
   each swap with its duration. The controller is not built here: the harness
   speaks a three-call contract — load, unload, status — to an existing engine
   manager. The lab's own vLLM orchestrator already offers those calls and is
   the first choice; an NVIDIA-supplied manager is used instead if spike S6
   finds one that fits better. The swap is shown, not hidden: one GB10 can do
   this work, with waits that more capable hardware removes. Which roles go to the deliberate
   engine is decided by the role bake-off (PLAN spike S3) against a threshold
   written before it runs.
4. **No shared services.** State is the ledger plus SQLite on local disk.
5. **Multi-arch, digest-pinned images for everything in the subset.** amd64
   and arm64 for every container, including scanners and every mini-agency
   service the GB10 hosts. An image with no arm64 build is lab-only and is
   listed.
6. **Containers, not virtual machines,** for all targets.
7. **Offline by construction.** Policy packs and reference documents are local
   files. UI assets are vendored. A bundle script produces everything needed
   to load, and to rebuild, the demonstration from a disk: images, a local
   registry, Python dependencies, models, repositories. Internet may be used
   at build time; never at run time.
8. **Explicit memory bounds.** Each engine is bounded by its serving flags
   (memory fraction, context length), because on unified memory a container
   limit does not reliably cap an engine's allocations. Each container is
   bounded by a cgroup limit. The budget — each engine, the workload, the
   twin, the scanners, a reserve for page cache — is in the BRIEF and sums to
   less than the machine.
9. **A runner holds the Docker socket.** It sits on the target networks, has
   no public leg, and accepts a fixed set of jobs. The service that serves the
   UI never holds the socket, on either target.
10. **Compose profiles** select the target; application code does not branch
    on it.
11. **Numbers carry their hardware.** A timing is labelled with the machine it
    was measured on. The lab's fast tier does not run on a GB10, so no gateway
    timing is presented as a standalone number.

## Alternatives considered

- **Develop in the lab, port later.** Porting late is where architecture
  assumptions surface. Checking the subset at every milestone is cheaper.
- **Require everything to run on one GB10.** It forces either cutting depth
  the lab can show, or claiming more for one box than it does. A stated
  subset keeps both the depth and the honesty.
- **Both engines resident.** On a 128 GB unified-memory machine the two engines
  leave too little for the workload and fail quietly under pressure. This is
  shown as what a second GB10 buys.
- **Single small model throughout.** Simplest; adopted for any role where the
  role bake-off (PLAN spike S3) shows it is sufficient. The seam makes this a
  config change.

## Consequences

- Every milestone's done-criteria include an arm64 and offline check of the
  subset.
- The "what one GB10 does" table is a deliverable, filled by measurement.
- The escalation queue is part of the core design, not an optimization.
- With a second GB10, queuing is switched off and both engines stay resident —
  the same code, a different profile.
