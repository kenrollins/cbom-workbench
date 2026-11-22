# ADR-0004: One deployment, in the lab; the bundle is a feature, not a target

- **Status:** Accepted
- **Date:** 2026-10-08
- **Deciders:** Ken Rollins
- **Supersedes:** ADR-0002 (two targets, one codebase)
- **Amends:** ADR-0003 (deployment shapes) — the harness-placement axis

## Context

ADR-0002 made one arm64 Dell Pro Max GB10 a second target: a stated subset of
the lab build had to run on that one box, offline, with two inference engines
taking turns in its unified memory, and the design carried that cost
everywhere — a memory budget, an escalation queue, an engine-swap controller,
a hardware table whose first column was "on one GB10".

On 2026-10-08 the requirement that something run on one GB10 alone was
withdrawn. The lab stays the venue. Nothing the lab holds is off limits: the
models served from the xr7620's GPUs, the models the lab GB10 serves through
its orchestrator, and what `ollama` on a desktop GPU host can run are all in scope for the
model roles. What the project is about has also come into focus: the
cryptography bill of materials (CBOM) and what language models, measured
role by role, add to building and using one — not an agent harness sized to a
desk-side box. The project is titled **cbom-workbench**; the import package and
the command are `pqch`.

Two things from ADR-0002 remain true and are kept: the inventory belongs on
infrastructure the organization holds, and every number carries the hardware
and the model it was measured on.

## Decision

1. **One deployment: the lab.** The harness runs on the xr7620, inference
   through the lab gateway, the mini-agency beside it. There is no second
   target to keep in step at every milestone, and no "subset" table.
2. **The bundle is a feature.** The offline bundle — images by digest in a
   local registry, dependencies, repositories, reference documents, the built
   site — stays, because it demonstrates that the whole thing moves on a disk
   and starts with no network. It is rehearsed by loading it on a second lab
   host with the network cut. It is not a separate build, and nothing in the
   application depends on which host it runs on.
3. **Every model the lab holds is in scope**, through the one inference seam.
   Which model does which role is decided by measurement against a floor
   written before the run (spike S3, lesson 21), never by assumption and never
   by a model name in code. Adding an engine is a line in the tier map.
4. **What more brings is a measured table.** Each step up — a larger model, a
   second engine resident, more GPUs — is recorded as a row in the BRIEF's
   "what more models and hardware bring" table with the measurement, the
   hardware and the model, or marked *not measured*. The journal records what
   each step changed for this workload. The table is a deliverable; the
   journal is where the reasoning lives.
5. **Multi-arch, digest-pinned images; no CDN assets; no shared services;
   state in files.** Kept, because they are what makes the bundle honest and
   the deployment portable, not because of any one machine.
6. **The runner holds the Docker socket; the UI service never does.** Kept
   from ADR-0002, decision 9.
7. **Numbers carry their hardware and their model.** Kept from ADR-0002,
   decision 11, widened: a model timing names the engine, the serving
   settings and the machine.

Retired with ADR-0002: the memory budget on one GB10; engines taking turns and
the escalation queue as a core design element; the residency controller;
compose profiles that select a target; the "what one GB10 does" table; spike
S6 and the standalone parts of milestone M4.

## Alternatives considered

- **Keep the GB10 subset as an optional profile.** Every milestone would still
  be checked against a box no longer required, and the honest table would keep
  reporting on hardware the project does not run on. Dropped; the bundle
  keeps the one property that mattered, portability.
- **Drop the bundle too.** It is already built and measured, it is the proof
  that nothing depends on the lab's shared services, and a kit without it
  cannot be stood up offline. Kept.
- **Rename the repository now.** A rename mid-build breaks the deployment's
  paths, the bundle's image names and every link in the journal. The page
  and the site carry the new name now; the repository is renamed once, at the
  public export.

## Consequences

- The BRIEF's claim loses its "stated subset on one GB10" clause and gains
  the measured role of the models as a clause with a pass test.
- Milestones M1–M3 absorb the effort the standalone target was taking: the
  Managed rung, the investigator, the full agency, the second bake-off arm on
  the models now in scope.
- Spike S3's latency half is measured in the lab, per engine, where the roles
  actually run, instead of waiting for a GB10 window.
- The site's "Hardware" page becomes "Models and hardware": what each step
  up was measured to change.
- ADR-0003's harness-placement axis has two values, `lab` and `bundle` (the
  same build loaded from the bundle on a host of the operator's choosing);
  the estate-placement axis is unchanged.
