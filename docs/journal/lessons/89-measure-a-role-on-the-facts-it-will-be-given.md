---
id: lesson-89-measure-a-role-on-the-facts-it-will-be-given
type: lesson
title: "Before measuring a model on a job, read the facts the job hands it; a wrong fact comes back as a fluent, wrong sentence and is scored against the model"
date: 2026-11-22
audience: [engineer, architect]
rung: all
tags: [inference, verification, demo]
one_line: "The role that speaks one line per plan row was handed a listener's posture as its key-exchange state and a step that had already landed as its next step. The model repeated both faithfully. The first measurement would have failed the model for the input's errors; with the facts corrected, 24 of 24 lines passed the rule check and a person's read."
claims:
  - text: "A plan row for a service that accepts only the hybrid key-exchange group was described to the narration role as 'a hybrid group offered, classical still accepted', because the row took its key-exchange state from the listener's posture, where 'mixed' means a post-quantum key exchange with a classical certificate; and its step, already applied and proved, was given as its next step."
    provenance: "by reading src/pqch/planning.py and src/pqch/ui/demo.py at commit d6df803, and the facts recorded for row 1 in the first measurement of 2026-11-22"
  - text: "On the corrected facts the role's lines passed the rule check on 24 of 24 calls (eight plan rows, three calls each, 1.4 to 1.9 s a line) and the owner's read of each row's line against the row; in the first run 21 of 24 passed, the three failures being one row whose own next step names another service."
    provenance: "measured 2026-11-22 on the lab's fast tier (Gemma 4 31B on four NVIDIA L4 GPUs, vLLM, thinking off) against the plan from the mini-agency's scan of 2026-11-21; eval/role-cards.yaml, role narrate-plan-row"
reuse: [whitepaper, talk]
---

# Before measuring a model on a job, read the facts the job hands it; a wrong fact comes back as a fluent, wrong sentence and is scored against the model

## The rule

A measurement of a model on a job measures the job's input as much as the
model. Before the first scored call, print what the job will send for every
item and read it against the system's own record. A fact that is wrong, or
that is right under a label that says something else, is fixed there. Only
then is a floor applied.

## Why

A language model given labelled facts and asked for one sentence does what it
was asked: it says the facts. If a fact is wrong the sentence is wrong, in
good grammar and with no sign of doubt. A person scoring the sentence against
the truth marks it wrong and the tally says the model failed, though the
defect is two layers upstream, in the code that built the row.

The workbench's stage speaks one line for each row of the migration plan. The
row's facts were assembled from the plan's ranking. Two of them were wrong for
the same service. Its key-exchange state came from the listener's *posture*,
a word the posture rule uses for key establishment and authentication
together: `mixed` means a post-quantum key exchange with a classical
certificate. The row translated `mixed` as "a hybrid group offered, classical
still accepted", which is a statement about key exchange alone, and false for
a listener that refuses every classical group. And the row carried the
service's step in the key-exchange lane, which for a service whose change has
landed is that finished change; the row offered it as the next step. The
model said both, three calls out of three.

Neither error is the kind a rule check on the output finds. The check asked
whether the line named its own service and no other, was one line, and was
not cut short; a line can pass all of that and repeat a false fact. A third
error ran the other way: one row's next step names a second service ("Upgrade sftp-legacy to
the OpenSSH the estate already runs on bastion"), and the check that no
other service is named failed every line that repeated the row's own fact.
The check had to learn that a row may name what its own facts name.

So the same measurement held three defects that were not the model's, two
that would have let a false sentence pass and one that failed a true one. All
three were found by reading inputs beside outputs before believing the count.

## When it applies

Whenever a model is given derived facts: a summary of a record, a row of a
plan, a finding with its context, retrieved passages. It applies before a
floor is used to bind a role, and again whenever the code that assembles the
input changes, since the floor was cleared on the old input.

It applies less where the model is given the raw record itself and the
question is whether it reads it correctly; there the input is the evidence
and the model's reading is what is measured.

## How to apply it

1. Make the input printable. One function builds the facts for an item, and
   the measurement stores them beside each reply, so a reader sees what was
   asked next to what was said.
2. Label each fact with what it is, not with the field it came from. A key
   named for a rule's internal word (`posture`) invites a translation that is
   wrong half the time; a key named for the claim
   (`key_exchange_today`) can be checked by anyone.
3. Take each fact from the place that decides it. Whether a classical key
   exchange is still accepted is in the lists the posture rule keeps of what
   it saw, not in the one word it summarises them with.
4. Give a finished thing as finished. A step with a state is sent with its
   state, in words: "done and proved on the wire" is a different fact from
   the step's title alone.
5. Let the output check allow what the input contains, and nothing else of
   its kind.
6. Write the floor before the run, run it, and when a run fails read three
   failing items end to end before concluding anything about the model.
   Record on the role's card what was corrected before the measurement that
   counts.

## Scope

One role, one model, eight rows, three calls each: enough to bind a line of
colour that decides nothing, and not a study of narration. The person's read
was one reader comparing each sentence with its row. The line's facts are
still only as good as the plan's; the model is not a check on them.
