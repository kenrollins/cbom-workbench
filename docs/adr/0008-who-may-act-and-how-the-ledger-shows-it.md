# ADR-0008: Who may act, and how the ledger shows it

- **Status:** Accepted
- **Date:** 2026-11-09
- **Deciders:** Ken Rollins
- **Builds on:** ADR-0001 (the ledger is the system of record), ADR-0003 (the runner enforces the scope)

## Context

The workbench was built for one owner. Anyone signed on through the front door could propose a
change, approve it and have the runner apply it in the same request, and the command line took a
typed name. The federal readiness review (FR-01) found that this is the first thing an authorizing
official stops on: there is no role, no separation between the person who asks for a change and the
person who approves it, and nothing on the ledger says which role an approval rested on. The review
deferred the work; an engagement with more than one person triggers it.

What exists already is the right foundation. Identity is the front door's sign-on header, believed
only on a connection from the front door, and an approval is a human event under a signed checkpoint
that the runner reads for itself before it acts. The missing pieces are a role, its source, and a
refusal.

## Decision

1. **Role comes from the identity provider, through the front door.** The front door sends the
   signed-on person's groups in a second header (`PQCH_GROUPS_HEADER`, default `X-Forwarded-Groups`),
   read only on a connection from a trusted proxy like the sign-on itself. The deployment names the
   group an approver must be in (`PQCH_APPROVER_GROUP`). The page refuses an approval by a person not
   in it and says which groups the front door listed.
2. **The approval event records what it rested on.** `approval.granted` and `approval.denied` carry
   `role: approver`, `groups` (the front door's list) and, as before, `authenticated_by` (the
   provider or the console). A reader of the ledger sees not only who approved but why they were
   allowed to.
3. **Separation of duties is a setting the runner enforces** (`PQCH_SEPARATION_OF_DUTIES=1`). Under
   it the runner refuses an apply whose approval was given by the person who asked for the change
   (the one who recorded the policy, or proposed the change as a person), and one whose approval
   carries no approver role. The page then approves in one request and applies in another, by a
   second button, and the runner reads the ledger again before the apply.
4. **The command line approves only in a labelled single-operator mode.** Under separation,
   `pqch change approve` refuses unless `--single-operator` is given, records the approval as made
   in that mode with the approver role, and does not apply; `pqch change apply` is the second step.
   One person at a console can still run the whole loop, and the ledger says so in words.
5. **Reads keep needing identity behind the front door**, as they do: the lab's pages answer only a
   signed-on viewer from a trusted proxy.

## Alternatives considered

- **Roles typed into the context file.** Rejected: a role is the identity provider's fact, not the
  owner's; typed in, it would be a supplied fact anyone with the file could change.
- **The workbench as its own identity provider.** Rejected: one more credential store, with its own
  controls to assess, for a system whose deployments sit behind an agency's front door that already
  has one (ADR-0004).
- **Separation always on.** Rejected for now: the kit on one box has one operator by design, and
  the demo's loop is one person's. The setting is on in any deployment with more than one person,
  which is the review's trigger, and the single-operator mode is labelled so the ledger does not
  pretend otherwise.
- **The approver also recorded on `change.proposed`.** Not needed: the requester is on the ledger
  as the person who recorded the policy or proposed by hand, and the refusal compares the two.

## Consequences

- An approval with no groups (the console, or a front door that sends none) is still an approval
  where no approver group is set; where one is set it is refused, and the message names the gap.
- A deployment that turns separation on after the fact finds earlier approvals have no role and
  will not apply again; they are already applied, and the runner's log says so.
- The assessment the review asked for (AC-5, AC-6, CM-5) now has a setting to point at and events
  to read; the identity provider's groups claim is the agency's to map onto `PQCH_APPROVER_GROUP`.
