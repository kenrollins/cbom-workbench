---
id: lesson-19-confirm-a-cause-by-changing-it
type: lesson
title: "Label a cause only after changing it and watching the effect go"
date: 2026-10-05
audience: [engineer]
tags: [verification, inference]
rung: all
one_line: "A reference answer of the form 'this line causes that behaviour' is earned by two observations: the behaviour with the line as written, and its absence with the line changed."
claims:
  - text: "36 configuration-to-behaviour items across nginx, OpenSSH, PostgreSQL, RabbitMQ and Kafka were each started twice — as written, and with the named line's value changed or, for a default, every line naming the directive removed — and all 36 passed both observations."
    provenance: "measured 2026-10-05, spike S3 lab on the xr7620 (x86_64); spikes/s3/build_r5.py, raw output under spikes/s3/observations/"
  - text: "Six 'cannot tell' items were each built as two configurations that yield the same shown evidence and different observed behaviour."
    provenance: "measured 2026-10-05, same lab; spikes/s3/build_r4.py"
reuse: [whitepaper, talk]
---

# Label a cause only after changing it and watching the effect go

## The rule

When a test set's reference answer names a cause — the configuration line
behind a behaviour, the commit behind a regression — do not write the answer
from reading. Run the system twice: once as it is, to see the behaviour, and
once with the named cause changed, to see the behaviour go. Keep the item
only if both hold, and keep both raw outputs with it.

## Why

A label written by reading is an expert's prediction, and it carries the
expert's model of the software. Precedence rules, defaults and silently
ignored files are exactly where that model is wrong, and they are also exactly
what such a test set exists to probe. A model under test that shares the
labeler's misconception will then be scored correct, and one that knows
better will be scored wrong.

Two observations remove the labeler's beliefs from the label. The first
shows the behaviour is real. The second is a small controlled experiment:
change one thing and see whether the effect follows. It also catches the
subtler error where the named line is *a* setting of the behaviour and not
the one in force — deleting it changes nothing, because another line or the
default supplies the same value.

"No line causes it" is a claim too, and it has its own experiment: remove
every live line that names the setting, and the behaviour must remain.

"The evidence cannot decide" is the hardest label to defend by argument and
the easiest by construction: build two systems that produce the same evidence
and behave differently, and observe both.

## When it applies

Building evaluation items, regression tests or training examples about
causes: configuration tracing, root-cause attribution, "which change fixed
it". It applies whoever writes the labels — a person, a script or a language
model — and matters most when a model writes them, because the label then
needs to stand without trusting its author.

It does not apply to labels that are definitions (a name maps to a standard
name by a registry); those need a citation, not an experiment.

## How to apply it

- Mark the cause in the fixture and state the change that should remove the
  effect; have the builder apply it mechanically.
- Choose a change of *value*, not a deletion, when the default would restore
  the same behaviour.
- Fail the item, loudly, when either observation disagrees with the label.
- Store the two raw outputs and their hashes beside the label.
