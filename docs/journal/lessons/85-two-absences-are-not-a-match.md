---
id: lesson-85-two-absences-are-not-a-match
type: lesson
title: "Two absences are not a match, and \"restored\" describes what is running"
date: 2026-11-21
audience: [engineer, architect]
rung: agile
tags: [verification, agility, ledger]
one_line: "A verdict bound to no container passed its binding check because nothing equals nothing, and a failed apply wrote the old file back and said restored while the new configuration could still be serving; presence is required before comparison, and after any failed recreate the service is recreated on the restored file and the record says what listens."
claims:
  - text: "A verdict whose apply or probes name no container, or whose container lookup failed, is `inconclusive` with the reason; a binding counts as stable only when a container was seen both times."
    provenance: "by reading src/pqch/verifier/__init__.py and src/pqch/runner/__init__.py at HEAD; tests/test_runner_review.py (test_a_verdict_is_not_enforced_when_no_container_was_ever_identified, test_a_probe_whose_container_lookup_failed_is_inconclusive_even_when_ids_match), passing on xr7620, 2026-11-21; commits 2cf34f4 and 10320bb"
  - text: "When Compose fails or times out during an apply, a reset or a recreate, the runner writes the previous file back, recreates the service on it, and returns a log entry that says whether the service listens afterwards and which container holds the address; the harness records it as `apply.failed` or `reset.failed`."
    provenance: "by reading src/pqch/runner/apply.py (_put_back, apply) at HEAD; tests/test_runner_review.py (test_a_compose_failure_during_apply_leaves_the_service_up_on_the_restored_file, test_when_the_restore_cannot_be_brought_up_the_log_says_the_service_is_down, test_a_failed_apply_is_on_the_ledger_with_the_state_the_estate_was_left_in); commit 8067649"
  - text: "An estate reset passes the same approval gate as an apply (`Applier.authorize_reset`): an `approval.granted` for its request in a run of kind reset, with the approver role and a second person under separation of duties."
    provenance: "by reading src/pqch/runner/apply.py (authorize_reset) at HEAD; tests/test_runner_review.py (the reset tests); commit 8067649"
  - text: "Compose passes the runner's enforcement switches by name with no value, never as `${VAR:-}`: an unset variable stays absent from the container, where a default would set a uid allow-list to the empty string, a list that admits nobody."
    provenance: "by reading compose.yaml (the runner's environment and its comment) at HEAD; tests/test_runner_review.py::test_compose_passes_the_runners_enforcement_switches_through_and_never_as_an_empty_value; commit d085b86"
reuse: [whitepaper, runbook]
---

# Two absences are not a match, and "restored" describes what is running

## The rule

Before comparing two values for equality, require that both exist. "Unknown
equals unknown" is true in most languages and is never evidence. And a word
that describes a system's state (restored, rolled back, enforced, stable) is
written only after checking the running system, not after performing the
step that usually produces that state.

## Why

**The comparison.** A wire verdict (new-only succeeds and old-only is
refused) is worth something only if the probes spoke to the same container
the change was applied to. So the verifier binds them: the container id
recorded at apply must equal the one seen by each probe. When a lookup fails,
the id is absent. Two failed lookups give `None == None`, the binding check
passes, and a verdict reads `enforced` while bound to nothing. The same
slip makes a listener "stable" between two observations in neither of which
a container was seen. An equality test answers "are these the same"; the
question asked was "is this the one", and that needs a one.

**The word.** Applying a change is: write the new configuration file,
recreate the service, wait for it to listen. If the recreate fails or times
out, the natural handler writes the old file back and logs "restored". But a
recreate that timed out may have succeeded a moment later, and a recreate
that failed may have left the old container running: after the handler, the
file on disk is the old one and the process serving may have been started
from either. "Restored" was true of a file. The reader of the log takes it to
be true of the service. The only way to make it true of the service is to
recreate once more on the restored file and then look.

Two neighbours of the same kind:

- **A destructive act with a lighter gate.** Resetting an estate to its
  starting state rewrites every configuration the changes touched. If an
  apply needs an approval event on the ledger and a reset does not, the reset
  is the way round the approval.
- **A default that turns a check on.** `${VAR:-}` in a Compose file passes an
  unset variable into the container as the empty string. For a boolean switch
  that is harmless. For an allow-list of user ids, "set and empty" is a list,
  and it admits nobody: a deployment that never configured the check finds it
  enforced, against everyone.

All four are a statement made from the absence of information.

## When it applies

Any check that binds two observations by an identifier (container ids,
process ids, hashes, session ids, serial numbers); any recovery path that
reports its own success; any privileged operation that sits beside a gated
one; any configuration passed through a layer that distinguishes unset from
empty. It is the verifier's form of the rule that a positive verdict needs
positive evidence ([lesson 78](78-a-positive-verdict-needs-positive-evidence.md)).

## How to apply it

1. Write binding checks as presence, then equality: a missing or failed
   lookup on either side makes the result `inconclusive`, with the reason in
   words. Never let it fall through to the comparison.
2. Resolve `inconclusive` by measuring again, never by inference.
3. In a recovery path, after putting the old state back, drive the system to
   it and observe: recreate on the restored file, wait for the listener, read
   which container holds the address. Record those three facts, and if the
   service did not come up, say that it is down.

    ```python
    # src/pqch/runner/apply.py, _put_back
    entry["restored"] = True
    self._recreate(service)
    entry["listening_after_restore"] = all(self._wait_listening(a, p) for a, p in endpoints)
    ```

4. Put the failure on the ledger as its own event (`apply.failed`,
   `reset.failed`) with the state the estate was left in; a failed apply that
   leaves no event is an estate changed off the record.
5. Give every operation that changes the estate the same gate. If one needs an
   approval, a role and a second person, so do the rest.
6. Pass optional settings through by name with no value, so unset stays
   unset; and test that the rendered configuration contains no empty value
   for a list-valued switch.

## Where the claim stops

The failure paths are exercised against a stand-in for Compose that fails or
times out on command. A real Docker daemon that hangs with the container half
created has not been provoked. "Which container holds the address" is read
from the runner's own binding lookup; if that lookup fails after a restore,
the record says the state is unknown, which is the honest answer and still
needs a person.
