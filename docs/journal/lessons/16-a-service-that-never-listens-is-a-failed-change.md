---
id: lesson-16-a-service-that-never-listens-is-a-failed-change
type: lesson
title: "Count a change as applied only when the service answers, and put the old configuration back when it does not"
date: 2026-10-05
audience: [engineer]
tags: [agility, verification]
rung: agile
one_line: "The orchestrator reporting a container started is not the service coming up; a configuration the service cannot load leaves it down unless the applier restores the previous one."
claims:
  - text: "A TLS configuration with one unknown curve name passed a shape check and a diff check; Compose reported the container started; nginx exited on the file and the container restarted in a loop. The applier recorded the change as applied and left the file in place."
    provenance: "measured 2026-10-05, M0 slice portal (nginx 1.28), xr7620 (x86_64); M0B review F-56"
  - text: "With the applier restoring the previous file when the port does not answer within 30 s, the same change was refused, the file was unchanged afterwards and the service was up."
    provenance: "measured 2026-10-05, same listener"
reuse: [customer-question]
---

# Count a change as applied only when the service answers, and put the old configuration back when it does not

## The rule

An automated configuration change is applied when the service answers on the
new configuration. If it does not, the applier writes the previous
configuration back, brings the service up on it, and records a failed
attempt — not an apply.

## Why

Three checks can all pass on a file that takes a service down. A shape check
confirms the file holds only the directives the tool is allowed to write. A
diff check confirms the file is what was approved. The orchestrator confirms
it created and started a container. None of them loads the file as the
service will. A value the service's own libraries reject — a curve name, a
cipher string, a path — is found only by the service, at start, and the
service's answer is to exit.

An applier that handles only the orchestrator's errors treats that as
success. The verifier that runs next reports `inconclusive`, because its
probes cannot connect, and the record says a change was applied when what
happened is an outage with the bad file still in place.

## When it applies

Any tool that edits configuration and restarts a service: policy-driven TLS
settings, feature flags in files, generated proxy configuration. It matters
most where the change is to cryptographic settings, because the valid values
depend on the library the service was built with, which the tool writing the
file may not share.

Where the service has a configuration test command (`nginx -t`, `sshd -t`),
run it first; the rule still holds, because a file can pass the test and
fail under the service's real environment.

## How to apply it

1. Keep the previous file in memory before writing the new one.
2. Recreate the service, then wait for the listener — a TCP connect to the
   service's own address and port, with a deadline.
3. If the deadline passes: write the previous file back, recreate again, wait
   again, log `apply-failed` with whether the service came back, and return
   an error to the caller.
4. Log an apply only on the other path, and include the new container's id,
   so a later check can tell the two apart.
