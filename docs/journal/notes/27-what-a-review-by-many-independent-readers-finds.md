---
id: note-27-what-a-review-by-many-independent-readers-finds
type: note
title: "What does a review by many independent readers, each checked by a skeptic, find in a system its tests pass?"
date: 2026-11-21
audience: [leader, architect, engineer]
tags: [verification, qa, inference, evidence]
rung: all
one_line: "Sixteen readers, one per subsystem, reported 180 findings in a system whose test suite passed; sixteen skeptics sent to refute them confirmed 178, left 2 uncertain and refuted none. What they found were not broken functions but true-looking statements made from nothing: an empty case read as success, a reader that knew one shape, a check with nothing loaded. The zero refuted is a result about the skeptics as much as about the findings."
claims:
  - text: "The review used 16 readers, one per subsystem or question, each read-only, and one skeptic per reader told to refute its findings by going to the code and the data; the readers reported 180 findings, rated by themselves 32 high, 92 medium and 56 low; the skeptics marked 178 confirmed, 2 uncertain and 0 refuted."
    provenance: "counted 2026-11-21 from the review's sixteen findings files, one per area, each finding headed by the reader's severity and the skeptic's verdict"
  - text: "One defect, the importer naming a certificate after the key it references, appears as a finding in seven of the sixteen areas, and the importer placing nothing from the other document shape in four; no count of distinct defects was made."
    provenance: "counted 2026-11-21 from the headings of the same files"
  - text: "Every finding carries the skeptic's own statement of the fix beside the reader's, and each of the sixteen skeptics' reports has a section for what the reader missed."
    provenance: "counted 2026-11-21 from the same files: 180 corrected-fix fields, 16 missed sections"
  - text: "The fixes were made by six workers in separate git worktrees with disjoint file lists, and by the lead on the importer, scoring, projection, pipeline and command line, each fix with a test; they are the commits from 504aadd on branch m1-prep."
    provenance: "git log and git worktree list in this repository, 2026-11-21"
  - text: "The readers, skeptics and fixers were instances of one model, Claude (Anthropic), model id claude-fable-5-2, run through Claude Code on xr7620 (x86_64) on 2026-11-20 and 21, in two sessions: a usage limit stopped the first part-way and the run was resumed from its journal with the finished agents' results reused."
    provenance: "the session's own record; named once here as provenance"
reuse: [whitepaper, talk, customer-question]
---

# What does a review by many independent readers, each checked by a skeptic, find in a system its tests pass?

## The answer

It finds the statements the system makes when it has nothing to go on. The
workbench's tests passed before the review and its scores against the answer
key were correct. Sixteen readers, each given one subsystem and no ability
to change anything, still reported 180 findings; sixteen second readers,
each told to refute one reader's findings at the code and the data,
confirmed 178, could not settle 2, and refuted none. Almost none of the
findings was a function that computed a wrong value from good input. They
were places where an empty list, a missing file, an unfamiliar document or a
failed lookup produced the same output as success. Tests had not found them
because tests are written from the cases the author thought of, and each of
these is a case the author did not think was a case.

Two things the numbers do not say. "Confirmed" means a second instance of
the same model, reading the same code, agreed; it is not a proof, and where
it mattered the finding was reproduced in a scratch directory and then held
by a test. And a refuting reader that refutes nothing in 180 tries has
either been given unusually sound findings or is too agreeable to be called
a skeptic. This review cannot tell which.

<figure class="sketch" markdown>
![A pipeline from left to right. A box of 16 readers, one per subsystem. An arrow to the number 180, findings, with 32 high, 92 medium, 56 low beneath it in pencil. An arrow to a box of 16 skeptics, told to refute. Three arrows leave it: 178 confirmed, 2 uncertain, and 0 refuted, ringed in red, with the note under it: the findings, or the skeptics. An arrow down from the skeptics to a box: 6 fix workers and the lead, every fix with a test.](../img/sketches/27-readers-skeptics-fixers.svg)
<figcaption>The review as a pipeline; the severities are the readers' own rating, and the count that needs explaining is the zero.</figcaption>
</figure>

## The concept

A test suite answers "does the code do what its author expected, on the
cases its author wrote down". A review answers a different question: "is
what this code says true". The two overlap less than they appear to. A test
is an example with an assertion; it can only fail on a case someone
constructed. A reader has no such limit and no such precision: a reader
notices that a branch exists for which no one decided the answer.

The usual objection to review is that it does not scale and that reviewers
anchor on each other. The method here answers both with structure, not
effort. Many readers work at once, each on one bounded part, and none sees
another's conclusions. Each reader's output is then handed to a second
reader whose instruction is the opposite of the first's: not "find what is
wrong" but "show that this finding is wrong". Only after that does anyone
change code.

## The mechanism

**Readers, by subsystem.** Sixteen areas, each a subsystem or a question
that cuts across them:

| Subsystems | Cross-cutting questions |
|---|---|
| the ledger; the CBOM projection; the wire scanners; the host and code scanners; scoring; the assessor and policy; planning; the runner and verifier; model use; the pages; the command line and pipeline; the public export and leak check | the documents against the code; another tool's CBOM format; the method of comparing two tools; the tests and the repository's own rules |

Each reader was read-only: it could run tests and write experiments in a
scratch directory, and could not touch the repository or the deployment.
Each reported what it covered, what it ran, what it found sound, what it did
not check, and then its findings, each with a location, the evidence, the
failure it leads to and a proposed fix. The "found sound" and "not checked"
sections matter as much as the findings: they are what makes a clean area a
statement and not a silence.

**A skeptic per reader.** A second instance received one reader's findings
and the instruction to refute each by going to the code and the data, not by
reasoning about the write-up. For each finding it recorded a verdict, what
it did to reach it, and the fix as it would make it. It also reported what
the reader had missed.

**Fixers, with disjoint files.** Six workers, each in its own git worktree
with a list of files no other worker held, and the lead on the parts that
crossed lists. A fix was not accepted without a test that fails without it.
Branches were merged one at a time.

**What the skeptics changed.** Confirming was not the same as agreeing. In
the confirmed findings the skeptics lowered severities, replaced fixes and
sharpened causes. Three examples, each from the findings files:

- A reader reported that retention follows an evidence reference out of
  the store, took the ledger carrying such a reference to be a corrupt one,
  and proposed among its fixes to skip runs that do not verify. The skeptic
  built such a ledger through the normal writer and verified it: the schema
  does not constrain the reference, so skipping would not have helped. Path
  containment is the fix
  ([lesson 82](../lessons/82-delete-a-shared-artefact-by-who-still-cites-it.md)).
- The ledger's reader found the writer looser than the verifier. Its skeptic
  added what the reader had not seen: a run's closing event sat after the
  last signed checkpoint, so deleting that one line left a ledger that
  verified as open and could be extended
  ([lesson 83](../lessons/83-a-writer-enforces-what-its-verifier-requires.md)).
- Seven of the sixteen readers, coming from seven directions, reported that
  the importer names a certificate after the key it references. No reader
  knew another had. That is seven findings and one defect.

## What was found

By kind, with the lesson that states each as a rule:

| Kind of defect | What it looked like | Lesson |
|---|---|---|
| A rule's empty case reads as success | a migration item with no finding attributed to it was "met"; a listener never seen to exchange a key was "classical" | [78](../lessons/78-a-positive-verdict-needs-positive-evidence.md) |
| A reader understands only its own writer's shape | an importer placed nothing from a document that keeps its facts in properties, and misread its own writer's certificates | [76](../lessons/76-read-another-tools-document-in-its-own-shape.md), [77](../lessons/48-write-cbom-facts-where-the-reader-looks.md) |
| A check with nothing loaded reports a pass | a leak check with no patterns printed the clean result; an unreachable listener was a completed scan with no findings | [80](../lessons/80-a-check-with-nothing-loaded-must-say-so.md), [79](../lessons/79-a-scan-that-did-not-connect-is-not-a-clean-scan.md) |
| A stand-in kinder than the real boundary | a fake ssh that ran an argument list where sshd hands a joined string to a shell | [84](../lessons/84-a-test-double-applies-the-boundarys-transformation.md) |
| A number that contradicts the sentence beside it | a score printed over a denominator the text said three items had left | [86](../lessons/86-excuse-a-miss-only-on-evidence.md) |
| Material where no text check reads | an image's pixels, test data, a comment | [81](../lessons/81-text-checks-do-not-read-pixels.md) |
| A writer looser than its verifier | a clock stepped back, or a lost newline, made a ledger unverifiable for good | [83](../lessons/83-a-writer-enforces-what-its-verifier-requires.md) |
| A statement made from two absences | a verdict bound to no container; "restored" said of a file | [85](../lessons/85-two-absences-are-not-a-match.md) |
| A deletion decided from one owner's list | retention removing output a younger run still cites | [82](../lessons/82-delete-a-shared-artefact-by-who-still-cites-it.md) |
| A vote counted on the wrong thing | a majority of three taken over every field of the reply | [87](../lessons/87-count-a-majority-on-the-one-decision.md) |

Most rows are one sentence in different clothes: *the absence of evidence
was reported as evidence*. That is the kind of defect a passing suite is
least able to show, because the suite's fixtures always supply the evidence.

The review also changed what the workbench says in small ways that no one
would have filed as a defect. X25519 and X448 are now given the classical
strengths their own specifications state, 128 and 224 bits, where a table
keyed on field size had given 112 and 192. And sntrup761x25519, which is
post-quantum by design and not standardised, has a family of its own and is
called neither quantum-vulnerable nor acceptable.

## What follows

For someone planning such a review:

- **Divide by subsystem, and add questions that cross them.** The
  cross-cutting readers (documents against code, another tool's format, the
  comparison method) found the defects with the widest consequences, because
  a subsystem's own reader takes its inputs as given.
- **Make readers unable to change anything.** A reader that can fix will
  fix, and the finding is then a diff nobody verified.
- **Ask every reader for what it found sound and what it did not check.**
  Otherwise an area with no findings cannot be told from an area nobody
  read.
- **Give the second reader the opposite instruction**, and require it to go
  to the code and data. Then read its corrections and its "missed" section,
  not its verdict column. Here the verdict column carried almost no
  information and the corrections carried a great deal.
- **Expect duplicates and do not count them away.** One defect reported from
  seven directions is strong evidence it is real and seven entries in the
  total. Report findings as findings.
- **Hold each fix with a test that fails without it**, and give fixers
  disjoint files so that their work merges.
- **Budget for the corrections to existing documents.** A review that finds
  a number wrong finds it wrong everywhere it was quoted.

## Scope

- **Confirmed is not proven.** A confirmation is a second reading by the
  same model. The findings that mattered were reproduced and are now held by
  tests; the rest stand on two readings.
- **Nothing was refuted.** Zero in 180 may mean the readers were careful, or
  that an instance of a model is reluctant to contradict another's
  well-argued finding. The review has no control to separate the two: no
  planted false finding was given to a skeptic to see whether it would be
  refuted. A later review should plant some.
- **The severities are the readers' own.** High, medium and low were
  assigned by sixteen readers with no common scale, and the skeptics moved
  some. The split 32, 92, 56 describes the reports, not the system.
- **No count of distinct defects exists.** 180 is findings as reported.
- **One model read its own kind of work.** The system under review was
  written with the help of the same model. Defects that model is systematically
  blind to are, by construction, the ones least likely to be here.
- **What the readers did not check is listed per area** and was not
  followed up by this review: the real signer service, contention on the
  ledger's lock, and behaviour against a live Docker daemon or a real sshd
  (stand-ins only) among them.
- This note describes one review of one system on two days. It does not
  compare the method with a human review or with another model.

## References

- The lessons numbered 76 and 78 to 87 in `docs/journal/lessons/`: one rule each,
  with the code and tests that hold it.
- `docs/adr/0007-property-names-where-cyclonedx-has-no-field.md`, amendment
  of 2026-11-21: what the CBOM writes for a consumer, decided from the
  review's reading of the writer.
- The commits from 504aadd on branch `m1-prep`: each fix with its test.
