---
id: note-13-where-models-belong
type: note
title: "Where do language models belong in this pipeline, and where not?"
date: 2026-10-20
audience: [leader, architect, engineer]
tags: [inference, verification, agility]
rung: all
one_line: "Measured on 216 labeled items across fifteen arms of every model the lab holds: a 31B model on four L4s reads call sites and classifies algorithms, and drafts change plans better and 27 times faster than the largest model; tracing a wire finding to the configuration line behind it is the one role that needs a 120B model; naming a tool's spelling and resolving a conflict between layers are better done by rules; and no model decides whether a change worked."
claims:
  - text: "On the small Nemotron engine alone no role reached its floor. With reasoning on, the same engine read call sites correctly on 28 of 30 items and classified algorithms on 30 of 30."
    provenance: "measured 2026-10-07 to 2026-10-08, spike S3, Nemotron 3.5 Lightning 30B-A3B on the lab GB10 through the lab gateway, three calls per item, majority of three; spikes/s3/results/scored/report.json"
  - text: "Nemotron 3 Super 120B-A12B traced a wire finding to its configuration line on 28 of 30 items on each of two runs nine days apart (1 and 2 harmful), against 9 for the small engine; no other arm but its successor at medium reasoning effort (26, 2 harmful) reached the floor of 24 within the 3 harmful allowed."
    provenance: "measured 2026-10-08 and 2026-10-16, spike S3 role R5, lab GB10; GPT-OSS 120B on a desktop GPU host scored 26 with 4 harmful"
  - text: "Gemma 4 31B FP8 on four L4s had 27 of 30 change plans verified on the wire with none harmful at a median of 3.5 s a plan; the 120B had 24 with one harmful at 95 s."
    provenance: "measured 2026-10-14 to 2026-10-15, spike S3 role R6, every plan applied and probed in the lab by spikes/s3/change_check.py"
  - text: "No arm of fifteen resolved 24 of 29 conflicts between layers within 2 harmful answers; the best, Nemotron 3.5 Super VL at medium effort, resolved 23 with 4 harmful. No arm normalized 28 of 30 spellings; four reached 27."
    provenance: "measured 2026-10-08 to 2026-10-16, spike S3 roles R4 and R2"
  - text: "On the live lab/reason lane after the slot changed to Nemotron 3.5 Super VL at medium-effort thinking, trace-to-cause scored 27 of 30 with 2 harmful at a median of 12.7 s a call; against the old engine's 28, three items lost and two gained, sign test p = 0.5."
    provenance: "measured 2026-10-20, spike S3 round 4, arm lab-reason-supervl, 90 calls through the lab gateway, no failures; spikes/s3/results/scored/lab-reason-supervl/"
  - text: "The same Nemotron 3.5 Super VL weights traced 9 of 30 findings with thinking off, 26 at medium effort and 21 with full thinking, where 8 of 90 calls hit the 900 s timeout."
    provenance: "measured 2026-10-16, spike S3 role R5, lab GB10 at a 0.62 memory share"
  - text: "At temperature 0 the 120B gave different replies to the same prompt on 57 of 178 items, the thinking engine on 50; 32 of 119 distinct change plans across the first three arms left the service not listening."
    provenance: "measured 2026-10-08, spike S3 round 1; spikes/s3/results/r6-plan-cache.json"
  - text: "The investigator's loop traced nine wire findings of the eight-service mini-agency, one per listener, on the live lab/reason lane: 2 to 4 steps and 1,846 to 6,433 tokens each, median 27.6 s, range 23.1 to 89.1 s; eight agreed with the answer key's cause and the ninth was right where the key was wrong; repeated with a 4,000-token reply cap the ninth returned no answer after 449 s, and with a 16,000 cap answered in 44.9 s."
    provenance: "measured 2026-10-20, investigate runs 01M5CV4QP9K8M4EE4EDTKYRV2H, 01M5D0J6AR6TNT904C40Y3JJ2S and 01M5D11HXJZ4GDAV7KJBYD1CVX; lab/reason served by the GB10 (Nemotron 3.5 Super VL 120B-A12B NVFP4, medium-effort thinking) per the gateway's response header"
  - text: "A seventh role, explaining an item's queue over retrieved passages of the policy pack, reached 3 of 14 items against a floor of 13 on Gemma 4 31B with 3 harmful calls; retrieval missed the settling passage in 11 of 14."
    provenance: "measured 2026-10-20, explain run 01M5DG1NY5M7E165RF1TCYVSRN; floor of 13 of 14 written before the first call"
  - text: "Spike S3 round 5, the live lab/reason lane (Nemotron 3.5 Super VL 120B-A12B NVFP4, medium-effort thinking) on R1 to R4 and R6: call-site reads 25 of 30, normalization 28 with none harmful (its floor), classification 30, conflict resolution 26 of 29 with 2 harmful (its floor, 10 items unstable), change plans 19 with 4 harmful."
    provenance: "measured 2026-10-21 14:48 to 18:21 UTC through the lab gateway, three calls per item; spikes/s3/README.md, Round 5"
reuse: [whitepaper, talk, customer-question]
---

# Where do language models belong in this pipeline, and where not?

## The answer

In four places, measured, and not in two others. A model reads a flagged
call site in source code, classifies an algorithm against a policy, and
drafts the change that would alter a listener's posture — a 31B model on the
lab's four L4s does all three, the first with its reasoning mode on, and
drafts the plan better and far faster than the largest model the lab holds.
A model traces a finding on the wire to the configuration line that produces
it — that is the one role that needs a 120B model. A model does not decide
whether a change worked; the verifier is a pair of probes. And two roles the
design first gave to a model go back to rules: naming a tool's spelling,
which is a table lookup, and resolving a conflict between findings, which no
arm of fifteen did within the harm allowed. These are measurements on 216
labeled items with a floor per role written before any run, across three
rounds and every model the lab holds, not opinions about what models can do.

## The concept

Rules, parsers and scanners first; a model only where interpretation is
needed. That is the project's rule, and the question it leaves open is where
interpretation is actually needed — and which model, since the lab's models
live on different machines with different costs: a 30B engine resident
beside the 120B on a desk-side box, a 31B model on four data-centre GPUs, a
second host that serves one model at a time. Spike S3 answers it the way the
rest of the project answers things: a labeled set per role, a floor per role
below which the output cannot be used as designed, a threshold written down
before anything ran, and a verifier, not a reader, scoring the role whose
output can be verified.

A **floor** matters more than a comparison. A model that beats another is
not thereby good enough; a role whose output goes into the inventory
unchecked needs near-perfect accuracy, and a role whose output is rehearsed
and verified before anything depends on it can tolerate less. Once several
arms clear a floor, the cheapest by latency is bound.

## The mechanism

Six roles, one prompt each, the same prompt for every arm, a JSON schema on
every reply so that scoring compares fields, and three calls per item with the
majority taken. Round 1 compared the two engines the lab had bound to its
tiers; rounds 2 and 3 ran every other model the lab holds, and a successor to
the 120B, on the same items against the same floors. The floors, what each
role's reply is checked against, and where each role landed:

| Role | Reply checked against | Floor (harmful allowed) | Bound to | Measured | The nearest other arms |
|---|---|---|---|---|---|
| Call-site read | A label with the quoted line and what in it decides each field | 27 (1) | Gemma 4 31B on four L4s, reasoning on | 29 of 30, 13.6 s | 120B 29 at 42 s; 30B with reasoning 28 at 84 s; 30B alone 21 |
| Normalization | RFCs, the IANA registries, OIDs | 28 (0) | rules: a name table; the live `lab/reason` as fallback since 2026-10-21 | 28 with none harmful, 9.8 s (round 5), the only arm at the floor | best before 27, four arms; a fallback reply is shown as unconfirmed |
| Classification | The memo's own table of quantum-vulnerable algorithms | 28 (0) | Gemma 4 31B on four L4s, no reasoning | 30 of 30, 1.1 s | five arms at 30; 30B alone 25 |
| Conflict resolution | What the wire showed when the configuration was started | 24 of 29 (2) | rules decide; the live `lab/reason` explains beside them since 2026-10-21 | 26 with 2 harmful, 41 s (round 5, the live lane), the first arm at the floor; 10 of 29 items unstable | 23 with 4 harmful for the same model through the bake-off's lane; Gemma 31B with reasoning 21; 30B alone 1, with 13 harmful |
| Trace to cause | The line whose change made the finding go | 24 (3) | `deliberate` on the lab GB10: Nemotron 3 Super 120B with full thinking until 2026-10-19, Nemotron 3.5 Super VL 120B at medium effort since | 28 of 30 on both the old engine's runs, 36 to 44 s; 27 of 30 on the live lane after the change, 12.7 s | Super VL at medium effort 26 (2 harmful); GPT-OSS 120B 26 but 4 harmful; Gemma 31B 22 with reasoning; 30B 9 |
| Change plan | The plan applied in a lab and probed by the verifier | 24 (2) | Gemma 4 31B on four L4s, no reasoning | 27 of 30, none harmful, 3.5 s | 120B 24 to 25 with 1 harmful at 95 s; Super VL thinking off 24 with 2 harmful; Gemma 31B with reasoning on the second host 24 with 1 at 75 s |

The binding rule: a role goes to the cheapest arm, by median latency, that
reaches the floor with no more harmful answers than the role allows; a role
no arm reaches stays a rule's job. "Harmful" is a wrong answer that would
cause damage as designed: a plan that takes the service down, a definite
layer named where the evidence cannot tell. Round 1's stricter test for
"needs the larger model" — the small engine below the floor, the large one
above it, and at least five discordant pairs at p ≤ 0.05 on an exact sign
test — is what first separated the trace role from the rest.

Three measurements the rule does not score and a design must:

- **Temperature 0 is not determinism.** The 120B gave different replies to
  the same prompt on 57 of 178 items, the thinking engine on 50. Majority of
  three makes the counts above stable; a single call is not.
- **A wrong change plan usually fails by taking the service down.** Of 119
  distinct plans run in the lab across round 1's arms, 32 left the service not
  listening and 6 landed a change that did not take. That is the argument for
  rehearsal in a twin and for an applier that restores the previous file when
  the service does not come up.
- **The reasoning setting moves a result more than a change of model.** The
  120B's successor, Nemotron 3.5 Super VL, loaded in the same slot, traced 9
  of 30 findings with thinking off, 26 at medium effort and 21 at full
  thinking with a quarter of its long calls timing out; the two 120B models
  at the same setting differed by two
  ([lesson 26](../lessons/26-name-the-reasoning-setting-beside-the-model.md)).
  The incumbent's two runs nine days apart differed by about two items per
  role, which is the spike's noise.

## Worked example

The trace-to-cause role, where the models differ most. One item: OpenSSH 10
with `KexAlgorithms` set twice in `sshd_config`, the first line listing
`curve25519-sha256,ecdh-sha2-nistp256` and a later line, after a "hardening
pass" comment, listing `diffie-hellman-group14-sha256`. The wire finding is
that the listener offers `ecdh-sha2-nistp256`. OpenSSH takes the first value
it reads, so the cause is line 4; the label was confirmed by changing that
line and watching the finding go ([lesson 19](../lessons/19-confirm-a-cause-by-changing-it.md)).
The small engine answered `default` — no line sets it — on this and on most
items; the 120B named line 4. Across the thirty items, which also
turn on include order in OpenSSH, last-value-wins in PostgreSQL and
innermost-block-wins in nginx ([lesson 20](../lessons/20-know-each-servers-precedence-rule.md)),
the 120B was right on 28 and the small engine on 9, and no model under 120B
parameters passed 22.

The change-plan role, where the number to read is the other one. The item is
an nginx server with a classical curve line in an included snippet, and the
intent `require`. A correct plan edits the snippet to `ssl_protocols
TLSv1.3;` and `ssl_ecdh_curve X25519MLKEM768;`; the verifier then finds the
hybrid-only client accepted and the classical-only client refused:
`enforced`. The plans that failed did not mostly leave the service classical;
they wrote a line nginx would not load, and the service never listened. The
31B model on the L4s wrote no such plan in 30 items; the 120B wrote one, and
Llama 3.3 70B on the second host wrote fourteen.

## What follows

- **Bind roles to tiers from the measurement, with the reasoning setting.**
  The inference seam binds each role to a tier and a reasoning flag in its
  configuration file; code never chooses a model for a role, and a role no
  arm reached is left unbound and is a rule's job. Today `fast` is the 31B
  model on the L4s and `deliberate` the 120B on the lab GB10.
- **One role needs the big machine.** The trace is answered inline at the
  120B's own latency, a median of 13 s on the engine serving today. Everything else a model does
  here runs on four L4s at a few seconds a call, and a person asking "why is
  this listener classical" gets the rule's answer at once either way.
- **Measure a successor against the floor before it takes the slot, and
  again on the live lane after it has.** A newer model of the same size in
  the same slot was not a step up for this work; at its medium reasoning
  effort it clears the one floor the slot serves, two items under the
  incumbent, and with thinking off it does not. The lab's slot changed to it
  on 2026-10-19, at medium effort, for the sake of its other callers; the one
  role this project binds there was re-measured on the live lane the next day:
  27 of 30 with 2 harmful at 12.7 s a call, one item under the old engine and
  within the noise, so the binding stands (spike S3 round 4). A slot that
  serves several callers is bound to one reasoning setting, and the setting
  is part of what was measured.
- **Conflict resolution is a rule's job, and is built as one.** The rule
  `conflict/resolve/1` settles each disagreement between a file in an image
  and what the wire shows from evidence the ledger already holds — *not-served*,
  *tool-limit*, or *cannot-tell* with what is missing named — in the
  vocabulary the spike labelled. On the eight-service estate it settled all
  three conflicts present with no model call. A deployment that binds the
  `resolve-conflict` role may have a model explain each conflict beside the
  rule's answer; the explanation is recorded as the model's, marked unused by
  any rule, and never settles one. The lab binds no model to the role.
- **The investigator's loop runs on the bound engine at about half a minute
  a finding.** The trace role, measured as one call with every file handed
  over, now runs as a loop: the model reads, greps and answers over the
  service's build files through three typed tools under a step budget of 8
  and a token budget of 60,000, with no shell. On the first run over the
  eight-service estate it traced nine findings, one per listener, in two to
  four steps and 1,800 to 6,400 tokens each, a median of 27.6 s and a range
  of 23 to 89 s on the live lane; eight agreed with the answer key's cause
  and the ninth disagreed because the key was wrong
  ([lesson 31](../lessons/31-confirm-an-answer-keys-annotations-the-same-way.md)).
  Every trace is recorded as the model's claim with the engine, the settings,
  each step and the measured time; no rule, link or verdict reads it. One
  trace repeated twice shows why a single call is not a measurement
  ([lesson 21](../lessons/21-set-a-floor-before-comparing-models.md)): with
  a 4,000-token cap per reply the engine's thinking on one step ran 232 s and
  the next reply came back empty, no answer after 449 s; with the cap at
  16,000, as the spike ran the single call, the same finding was answered in
  two steps and 44.9 s. On a lane that thinks, the reply cap bounds the
  thinking too, and a cap that fits a terse answer starves the step that
  needed to deliberate ([lesson 26](../lessons/26-name-the-reasoning-setting-beside-the-model.md)).
- **A seventh role was tried and is not bound.** Explaining, in plain words,
  why a migration item sits in its queue — over passages of the policy pack
  that an embedding retrieved — was given a floor before its first call and
  reached 3 of 14 items on Gemma 4 31B, with 3 harmful answers. The model was
  not the limit: retrieval missed the passage naming the item's queue in 11 of
  14, and where it was retrieved the model passed every call
  ([lesson 34](../lessons/34-score-retrieval-before-the-answer.md)). The page
  shows the rule's own basis instead.
- **A new engine was measured on every role, on the lane as it serves.** Round
  5 ran Nemotron 3.5 Super VL on the live `lab/reason` lane on the five roles
  round 4 left. Two roles no arm had reached now reach their floor there —
  normalization at 28 with none harmful, conflict resolution at 26 with 2 — and
  neither changes who decides: the name table and the conflict rule still do,
  and the model is the fallback and the explainer. Change plans fell to 19
  with 4 harmful, and stay on Gemma 31B. The same model and setting scored
  differently through the bake-off's lane and the live one (lesson 26).
- **Never act on a single reply.** Repeat, verify, or use a rule.

## Scope

Covered: six roles, 30 scored items each (29 for conflict resolution),
fifteen arms through the lab gateway between 2026-10-07 and 2026-10-20:
Nemotron 3.5 Lightning 30B-A3B with and without reasoning and Nemotron 3
Super 120B-A12B on the lab GB10; Gemma 4 31B FP8 with and without reasoning
on the xr7620's four L4s; on a second host through `ollama`, Gemma 4 31B q8
with and without reasoning (the thinking arm's last three roles completed on
2026-10-20 after two refused-connection losses), GPT-OSS 120B, Llama 3.3 70B
and Lightning;
Nemotron 3.5 Super VL 120B-A12B in the 120B's slot with thinking on, at
medium effort and off, beside the incumbent re-run the same day. Labels
checked by a second reader; threshold and items committed before the first
run.

Not covered: GPT-OSS 120B and Llama 70B under vLLM on the GB10, which would
evict the deliberate engine; prompts tuned beyond six development items per
role; the embed tier. The investigator's loop has run once, on nine findings
of the planted estate, and is a measurement of that engine on those files,
not a second spike: no other arm has run the loop, and nine is not thirty. A floor of 24 or 28
on 30 items is a coarse instrument, and the incumbent's two runs show the
noise is about two items; a role within two of its floor could land on the
other side on another draw.

## References

- `spikes/s3/README.md` — the design, the threshold, the labels' provenance
  and the results of all three rounds, with every file's hash.
- `spikes/s3/results/scored/report.json` — the scores per role and arm and
  the decision rule's output.
- `spec/interfaces.md` §4 — the frozen inference seam with its per-tier
  reasoning block and the roles section bound from these results.
- OMB M-26-15, Appendix A — the table the classification role is scored
  against.
