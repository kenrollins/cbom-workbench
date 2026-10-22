# ADR-0003: Deployment shapes — where the harness runs and where the estate lives

- **Status:** Accepted
- **Date:** 2026-10-03
- **Amended:** 2026-10-08 by ADR-0004 — the harness-placement value `gb10`
  becomes `bundle`: the same build loaded from the offline bundle on a host
  the operator chooses. The demo-box uses below read as bundle uses; the
  estate axis, the scope file, the change package and the line between
  showing a change and making one are unchanged.
- **Deciders:** Ken Rollins
- **Builds on:** ADR-0002, now ADR-0004

## Context

The project has four uses, and they pull in different directions:

- A lab build on the xr7620 that carries every feature and remains the place
  to demonstrate the work after the workshop. In the lab, the GB10 serves
  inference only.
- A demo box: one GB10 that shows the full path on its own files, with nothing
  else attached. This is what the workshop builds.
- The same demo box scanning an estate that lives on a second machine, such as
  a laptop on a direct cable.
- A kit: a public repository from which someone else can stand up the same
  thing on their own GB10, as a personal open-source research project and not
  a Dell product.

Treated as four products, this is four things to build and keep working.
Treated as two independent choices, it is one codebase with two seams.

## Decision

1. **Two axes, not four products.**

   | Axis | Values |
   |---|---|
   | **Harness placement** — where the service, scanners and inference run | `lab` (xr7620, inference through the gateway) · `gb10` (everything on one box, engines taking turns) |
   | **Estate placement** — where the thing being inventoried lives | `colocated` (the mini-agency in containers beside the harness) · `remote` (the mini-agency on a second host over a private link) · `external` (a network the operator names) |

2. **The four uses are points on those axes.**

   | Use | Harness | Estate | Notes |
   |---|---|---|---|
   | Lab | `lab` | `colocated` | Every feature. The standing demonstration venue. |
   | Demo box | `gb10` | `colocated` | The workshop build, and the fallback for every other GB10 use. Must stand alone. |
   | Demo box with a second machine | `gb10` | `remote` | The estate is on the laptop; the twin stays on the GB10, so rehearsal happens off the estate. Hosts x86-only legacy images. |
   | Kit | `gb10` | `colocated` out of the box; `external` when the operator supplies a scope | Published. Ships pointed at the bundled mini-agency. |

3. **The estate seam is a scope file.** The harness never discovers what to
   scan. It reads a scope: the hosts or address ranges, the ports, how each
   host is reached for host and image evidence, and where its source and
   configuration are. For `colocated` and `remote`, the scope is generated
   from the mini-agency's compose file. For `external`, the operator writes
   it. The runner refuses any target not in the scope.

4. **Scope is authorization, and it is on the ledger.** The first event of any
   run is the scope with its hash. For an `external` estate the operator also
   records who authorized the scan. The author's own use — lab and demo — still
   scans only networks built for the purpose.

5. **The runner reaches a remote estate through one mechanism:** a Docker
   context over SSH on a private link with fixed addresses. No agent is
   installed on the estate.

6. **The demo box is the kit.** There is one GB10 build. The kit is that build
   as published: the repository, the specification, the evaluation kit, and a
   bundle script. The bundle script fetches images and model weights from
   their publishers on the operator's own connection; the repository
   redistributes neither.

7. **The kit states when it was last verified on a GB10,** with the date and
   the evaluation score from that run. After the workshop there may be no GB10
   to test on; arm64 emulation in the lab is a smoke test, not a verification,
   and the kit says so.

8. **Every published surface carries the disclaimer:** a personal research
   project, open source, not a Dell product, reference architecture or
   supported offering.

## The line between showing a change and making one

9. **The harness changes only estates it built.** On the mini-agency and its
   twin it runs the full loop: propose, rehearse, approve, apply, verify.
10. **On any other estate it hands off and then verifies.** It produces a
    *change package*: the configuration diff, the rollback, the compatibility
    matrix, and the exact test that will count as verified. Where the operator
    has supplied images and configuration, the change is rehearsed in a twin
    first and the package carries the rehearsal's verifier verdicts. Where
    they have not, the package is still produced and is labelled
    `not rehearsed`. The operator makes the change through their own process;
    the harness sees it arrive as a change event, re-scans, and issues the
    verdict.
11. **Enforced by construction.** The runner's apply job acts only on
    containers it created itself. There is no setting that extends it. The
    repository is public and open source; someone who wants more can change
    the code, and that is their decision to make and to own.
12. **Evidence for an `external` scope:** wire always; images and source where
    the operator points at them; credentialed host inspection later.

## Alternatives considered

- **A separate kit repository.** Two codebases drift. The kit is a published
  view of the one build.
- **Lab only, with the GB10 as a slide.** Leaves the workshop with nothing
  running on the box, and the claim about one machine untested.
- **GB10 only.** Leaves no way to demonstrate the work once the workshop
  machine is returned.
- **An agent on the estate for host evidence.** More capable, and one more
  thing to install on a system that belongs to someone else.

## Consequences

- The scope file and the runner's refusal of out-of-scope targets are built in
  the first slice, not added for the kit.
- `colocated` on the GB10 is the configuration every milestone checks; `remote`
  and `external` are the same code with a different scope.
- The lab build must not depend on anything the GB10 build lacks without that
  feature being listed in the BRIEF's "what one GB10 does" table.
- The published repository needs an operator's guide: prerequisites, the
  bundle step, the scope file, and what the kit does not do.
