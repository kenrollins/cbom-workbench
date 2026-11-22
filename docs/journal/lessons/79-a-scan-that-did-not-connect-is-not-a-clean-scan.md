---
id: lesson-79-a-scan-that-did-not-connect-is-not-a-clean-scan
type: lesson
title: "A scan that did not connect is not a scan that found nothing; the tool's own statement decides, not the container's exit"
date: 2026-11-21
audience: [engineer, architect]
rung: enumerated
tags: [discovery, evidence, verification]
one_line: "An unreachable listener recorded as a completed scan with zero findings is counted as reached and clean; whether a scan happened is read from what the tool wrote, because one scanner's exit code is its policy verdict and another's is a count, and a scan that fails part-way still closes its window and its run on the ledger."
claims:
  - text: "`normalize.tool_problem()` decides from the tool's output, never its exit code: testssl.sh says a scan did not happen in a `scanProblem` entry of severity FATAL, ssh-audit by writing a line of text where its JSON would be; the `scan.completed` event then carries status `unreached` (or `error`), `reached: false`, the tool's words as the reason and the runner's status beside them, and the listener becomes a gap."
    provenance: "by reading src/pqch/scout/normalize.py (tool_problem) and src/pqch/scout/__init__.py (record, scan_ok) at HEAD; tests/test_scout_wire_review.py, passing on xr7620, 2026-11-21"
  - text: "ssh-audit's exit code is its policy verdict, 2 or 3 on a listener it read in full; testssl.sh's is a count of what it found."
    provenance: "by reading the docstring and tests of normalize.tool_problem; observed in the stored outputs named below"
  - text: "A scan that fails part-way writes `window.closed` with `aborted` and the reason, then `run.failed`, is checkpointed and closed like any other run, and the LATEST pointers go back to the run they named; the command exits 3 when the run was written and some job did not complete."
    provenance: "by reading src/pqch/pipeline.py at HEAD; commit cd14763; tests/test_copy.py"
reuse: [whitepaper, customer-question]
---

# A scan that did not connect is not a scan that found nothing; the tool's own statement decides, not the container's exit

## The rule

Record three outcomes for a scan job, not two: it read the listener, it could
not reach the listener, or it broke. Decide which from what the tool itself
wrote about the attempt. An exit code is the tool's answer to its own
question, which is rarely "did I connect".

## Why

A scanner run as a container returns two things: a stream of output and an
exit status. A harness that treats "the container ran and the output parsed"
as success has no place to put the commonest failure of all, a listener that
did not answer. The tool starts, fails to connect, writes a well-formed
report of that fact, and exits. The report parses. It contains no findings.
The harness records a completed scan with zero findings, and every later
count is wrong in the favourable direction: the listener is "reached", it
has no weak algorithm, coverage rises.

The exit status cannot repair this, because the tools use it for something
else:

| Tool | What its exit status means | How it says "I did not connect" |
|---|---|---|
| ssh-audit | its policy verdict: 2 or 3 on a listener it read in full and found wanting; 1 on one it never reached | a line of text where its JSON would be |
| testssl.sh | a count of what it found | a short JSON document with a `scanProblem` entry of severity `FATAL` |

Reading "non-zero is failure" throws away every SSH listener with a weak
algorithm, which are the ones the scan exists to find. Reading "zero is
success" keeps the unreachable ones. The only reliable signal is the
sentence the tool wrote.

The same reasoning applies one level up. A scan is a window on the ledger:
opened, jobs, closed. If a job is refused or the runner fails part-way and
the command simply stops, the ledger shows an open window and an open,
unsigned run, and the pointer to "the latest scan" names a run that is not
one. A reader cannot tell an interrupted scan from one still running.

## The same rule for a tool that runs and says nothing

A scanner that connected and reports nothing has either found nothing or
cannot see: a hybrid group its TLS library lacks, a library it has no rules
for, code it cannot resolve without a build, a monitoring script whose event
handler names an event that does not exist. Zeek ran such a handler without a
word and logged nothing. Only a known positive tells the two apart, so an
empty result is a finding about the tool until the tool has been shown
something it should find:

- Score a discovery tool against a planted estate with an answer key,
  decoys included (`pqch import … --key agency/answer-key.yaml`), and record
  the tool's version and image digest with the result; coverage changes
  between releases.
- Run a new passive detection beside a client known to produce what it
  detects, and assert the detection's own log holds the expected value before
  reading its silence on other traffic:

    ```sh
    # a client that offers the hybrid group
    openssl s_client -connect TARGET:443 -groups X25519MLKEM768:X25519 </dev/null
    # Zeek in the client's network namespace, with the script under test
    docker run --network container:CLIENT --cap-add NET_RAW zeek/zeek:lts \
      zeek -C -i eth0 groups.zeek LogAscii::use_json=T
    ```

  Keep the generator and the check with the script, and rerun them when the
  monitor is upgraded: event names and codepoint tables change between versions.

## When it applies

Any harness that wraps another program and records what it found: scanners,
linters, test runners, probes. It applies whenever "no findings" is a
favourable result. It does not apply where the wrapped tool has a documented
exit status for "could not run" that is distinct from its verdict; then the
status is the tool's statement and may be read as one.

## How to apply it

1. For each tool, find how it reports that the scan did not happen, from its
   documentation and from one deliberate run against a closed port. Keep the
   sample output as a test fixture.
2. Parse that statement before parsing findings. Here:

    ```python
    # src/pqch/scout/normalize.py
    problem = tool_problem(raw, job)   # None, or {"reason": …, "reached": False, "output": False}
    ```

3. Record the outcome as a status on the scan's event, with the tool's own
   words: `unreached` with `reached: false`, or `error`. Keep the runner's
   status in a separate field; it is evidence, not the verdict.
4. Let every count use one test of a usable scan (`scan_ok`), so "reached"
   on the coverage page and "has a prior scan" in the change path cannot
   disagree.
5. Turn an unreached listener into a recorded gap, not an absence
   ([note 25](../notes/25-how-much-of-an-estates-cryptography-a-tool-can-reach.md)).
6. Close what was opened whatever happens: on any failure write the window's
   close with `aborted` and the reason, a `run.failed` event, the checkpoint
   and the run's close, and put the latest-run pointers back.

## Where the claim stops

Two tools' statements are read, the two wire scanners in use; a new scanner
needs its own. The words that mean "did not connect" are matched by pattern,
so a tool that rewords its message in a later version is recorded as `error`
until the pattern is extended, which is the safe side.

