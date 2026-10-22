# Spike S3 — which model roles need the larger model

Written 2026-10-05, before any S3 item was labeled, any S3 prompt was written,
or any model was called for S3.

## Question

For each place the design calls a model, is the `fast` tier good enough, or
does the role need the `deliberate` tier — which on one GB10 means a queue, an
engine swap and a batch (BRIEF, "Models"; ADR-0002)?

The answer is per role. It decides what the residency controller queues, and
it fills one row of the BRIEF's "what one GB10 does" table.

## The roles

Six, taken from the BRIEF's architecture and its model table. Each is one
call through the inference seam with a JSON Schema on the reply, so a reply is
scored by comparing fields, never by a model reading it.

| # | Role | Used by | Input | Typed reply | BRIEF's starting assumption |
|---|---|---|---|---|---|
| R1 | Call-site read | Investigator, leaf | One candidate call site: up to 60 lines around a line a rule flagged, with the file path and language | `is_crypto_use` (bool); `family` (enum of standard names, or `none`); `role` (the six of `pqch.finding/1`); `key_bits` (int or null) | fast |
| R2 | Normalization | Scout | One tool spelling the name table does not hold, with the tool and the field it came from | `name` (a standard name from a closed list, or `unknown`); `asset_type`; `role` | fast |
| R3 | Typed classification | Assessor | One finding and the policy's algorithm table | `quantum_vulnerable` (bool); `function` (`key-establishment`, `signature`, `neither`); `family` (enum) | fast |
| R4 | Conflict resolution | Assessor | Two or three findings about one asset that disagree (wire, image file, configuration), with their evidence excerpts | `in_force` (`wire`, `host`, `config`, `cannot-tell`); `reason` (enum: `not-served`, `default-applies`, `overridden`, `other-listener`, `stale-file`, `tool-limit`) | deliberate |
| R5 | Trace to cause | Investigator, root | One wire finding, and the service's configuration files with line numbers | `file`; `line_start`, `line_end`; or `cause: default` when no line sets it | deliberate |
| R6 | Change plan | Migrator | One finding, the service's configuration, and the policy intent (`enable` or `require`) | `edits` (file, line range, replacement text); or `blocked` (enum: `supplier`, `protocol`, `none`) with no edits | deliberate |

Not in S3: the `embed` tier (it is not a fast-against-deliberate question);
the investigator's multi-step loop with its budgets (R1 and R5 test its two
single calls, not the loop; M1 builds the loop); prompt tuning beyond the
development set below.

## The items

About 30 per role: 30 scored items and 6 development items, 36 labeled in
all, 216 across the six roles. If a role's sources cannot yield 30 honest
items, it runs with what it has, never fewer than 24, and its result says so.

| Role | Where items come from | What makes a third of them hard |
|---|---|---|
| R1 | The three pinned federal repositories (`eval/pins.yaml`): 10 call sites each from `18F/identity-idp` (Ruby), `CMSgov/dpc-app` (Java) and `CMSgov/bluebutton-web-server` (Python), drawn by `git grep` for the patterns counted in the BRIEF facts table | At least 10 are not a cryptographic use: a comment, a test fixture, a string, a name that only looks like one |
| R2 | Spellings in the raw outputs under `var/raw/` and `spikes/s2/results/` — testssl.sh ids and findings, ssh-audit algorithm strings, cbomkit-theia component names, OpenSSL's own text — that `src/pqch/scout/names.py` does not map on the day the items are drawn | Spellings that name a size, not a group (`DH, 3072 bits`); vendor suffixes (`@openssh.com`); OIDs; at least 5 that are not algorithms at all and must come back `unknown` |
| R3 | Algorithm names from OMB M-26-15 Appendix A section 2, CNSA 2.0, FIPS 203, 204 and 205, and the IANA TLS and SSH registries | Hybrids, hash-based signatures, symmetric algorithms and hashes (not quantum-vulnerable in the memo's table), finite-field groups named by RFC |
| R4 | Configurations whose truth was observed on the wire: the slice, the S2 targets, and variations of them built for this — a certificate in an image that no listener serves, a server's own list naming a group it refuses, a file changed and the service not restarted, two server blocks on one listener | At least 6 where the right answer is `cannot-tell` from the evidence given |
| R5 | The same services' configuration files, with the wire finding each produces: nginx, OpenSSH, Postgres, RabbitMQ, Kafka | Included files, a value set twice, and at least 8 where no line sets the behaviour and the answer is `default` |
| R6 | The same services, each with an intent | At least 6 where the change is not possible with the image as built — RabbitMQ 4 on Erlang/OTP 27 and Kafka 4.1 offer no ML-KEM group (spike S2) — and the right reply is `blocked: supplier` |

### How the items are labeled

No model under test labels an item, suggests a label, or drafts an item, and
no label rests on a model's word: every label carries the evidence that
settles it, so a reader can check it without trusting whoever wrote it.

Amended 2026-10-05, before any item was drawn (decided by Ken Rollins): the
labels for R1, R2 and R3 are written by the build session — Claude Fable 5.1,
a model, and not one of the two being compared — and not "by hand" as first
written. What keeps that honest is the citation on every label and the second
reader's check below; a label whose citation does not settle it is a bad
label whoever wrote it. The items themselves are real lines, real tool output
and names from the registries, chosen by a seeded draw and a stated quota,
never composed.

- **R1, R2, R3** — labeled from the source: the code as written; the
  IANA registries and OID arcs; the policy documents. Each label carries the
  citation that settles it — for R1, the quoted line and what in it decides
  each field.
- **R4, R5** — labeled by construction and observation: the configuration is
  built or taken as it is, the service is started on the slice network, and
  the wire is probed with the S2 method (one group per handshake, TLS 1.3 and
  TLS 1.2 separately; lesson 10). The label is what was observed, and the item
  records the raw output's hash. For R5 the line range is confirmed by
  changing that line and seeing the wire finding change.
- **R6** — not labeled with an answer. It is scored by running the reply (see
  the metric). The 6 `blocked` items are labeled from S2's observations.

Each role's items are one JSONL file under `spikes/s3/items/`, with the label
in a separate file under `spikes/s3/labels/`. Both are committed, and the
SHA-256 of every label file is recorded in this README's results section,
before the first scored call. The prompts — one per role, the same text for
both tiers — are written against the 6 development items only, committed with
their hashes at the same time, and not changed afterwards.

A fifth of each role's labels (6 of 30, chosen by a seeded shuffle recorded
in the commit) are checked by a second reader — Ken Rollins, or a review
session that did not write them — before the run. Because a model wrote the
R1 to R3 labels, at least the R1 sample is read by Ken Rollins himself. A label found wrong then is
corrected. A label disputed after the run is changed only with the reason
recorded, and the role's score is reported both ways.

## The run

Every call goes through `pqch.inference.complete(tier, messages, schema=…,
purpose="s3-<role>")`: the same seam, the same schema validation, no retry
beyond the seam's own. `max_tokens` and the context given are the same for
both tiers. Sampling is the seam's: it sends temperature 0 on every call, so
the three calls per item measure what nondeterminism is left at that setting,
not a spread of samples. (Corrected 2026-10-05, before any call: this section
first said "the endpoint's defaults", which the seam does not use.)

The token cap is 16000 per reply (20000 for R6), the same for every arm: a
thinking engine's reasoning counts against the cap, and at 300, and still
at 6000 on a long item, that arm returned nothing (seen on the development
items, 2026-10-06). A reply cut off by the cap is recorded with its
`finish_reason` and scored as wrong. Each item is called three times per tier. An item is **correct** for a tier
when at least two of its three replies are correct. A reply that fails the
schema, times out or is refused is wrong. Items whose three replies do not
all agree are counted and reported as unstable.

Recorded per call: tier, model id, the `hardware` label, token usage, latency,
the reply, and its score. Model ids, engine, quantization and context length
go in the results.

A third arm is run and reported, and decides nothing by itself: the fast
engine with thinking on (`lab/reason-fast` in the lab). It costs no swap. See
"Outcomes". Each arm is a tier name in the configuration given to `run.py`
(`config/inference.s3.example.yaml`).

### What "correct" means, per role

| Role | A reply is correct when | A harmful error is |
|---|---|---|
| R1 | Every field equals the label (`key_bits` only where the label has one) | A real cryptographic use answered `is_crypto_use: false` |
| R2 | `name`, `asset_type` and `role` equal the label | A standard name given to a spelling labeled `unknown`, or a wrong standard name |
| R3 | All three fields equal the label | `quantum_vulnerable: false` for an algorithm the policy table lists as vulnerable |
| R4 | `in_force` equals the label, and `reason` equals it when `in_force` is not `cannot-tell` | A definite answer where the label is `cannot-tell`, or the wrong definite answer |
| R5 | `file` equals the label and the reply's line range lies within the label's, or `cause: default` where labeled | A line named where the label is `default` |
| R6 | The edits are applied to a copy of the service in a scratch container on the slice network; the service loads the configuration and listens; and the verifier's paired probes and witness return the status the intent requires — `enforced` for `require`, `enabled-not-enforced` or `enforced` for `enable`. For a `blocked` item: `blocked` equals the label and there are no edits | Edits after which the service does not start |

R6 is scored by the verifier, with no model in the loop, for the same reason
the product is: a plan is right when the wire says so.

## The metric

Per role and tier: **accuracy**, the number of the 30 scored items that are
correct. Beside it: the harmful-error count, the unstable-item count, and the
schema-failure count.

Between the tiers, per role: the **discordant pairs** — `b`, items the
deliberate tier got right and the fast tier got wrong; `c`, the reverse. The
tiers are compared on the same items, so the discordant pairs are what
separates them, and the exact one-sided sign test on `b` against `c` is the
test. With 30 items an accuracy gap of two or three items is noise; the
threshold below is written with that in mind.

## The threshold

A role's **floor** is the accuracy below which its output cannot be used as
designed. Roles whose output goes into the inventory unchecked have a high
floor; roles whose output is checked by a rule or the verifier before anything
depends on it have a lower one.

| Role | Floor (of 30) | Harmful errors allowed | Why this floor |
|---|---|---|---|
| R1 | 27 | 1 | A missed call site is an inventory gap nothing downstream catches |
| R2 | 28 | 0 | A wrong name is a wrong CBOM entry; `unknown` is always available and is safe |
| R3 | 28 | 0 | Classification sets the queue and the deadline |
| R4 | 24 | 2 | The reply is shown with its evidence and a person decides on it |
| R5 | 24 | 3 | A wrong line is found wrong when the change does not verify |
| R6 | 24 | 2 | Every plan is rehearsed and verified before approval |

A tier **clears** a role when its accuracy is at or above the floor and its
harmful errors are within the allowance. A role run with fewer than 30 items
scales its floor by the same fraction, rounded up.

**A role needs the larger model when all three hold:**

1. the fast tier does not clear the role;
2. the deliberate tier clears it;
3. the deliberate tier is better on the same items: `b − c ≥ 5`, and the
   exact one-sided sign test on the discordant pairs gives p ≤ 0.05 (with no
   reverse pairs that is `b ≥ 5`; with one, `b ≥ 7`; with two, `b ≥ 9`).

### Outcomes

Every role ends in exactly one of these, and the BRIEF's model table and "what
one GB10 does" table are edited to say which.

| Outcome | When | What the build does |
|---|---|---|
| **fast** | The fast tier clears the role — whatever the deliberate tier scored | The role runs on the fast tier. No queue |
| **fast, thinking** | The fast tier does not clear it, and the fast engine with thinking on does | The role runs on the fast engine with thinking on; no swap. Recorded as needing a per-role option in the inference seam's configuration |
| **needs the larger model** | The three conditions above | The role's items queue for the deliberate tier and are drained in batches |
| **undecided** | The fast tier does not clear it, the deliberate tier does, and condition 3 fails | 30 more items are labeled by the same method and the rule is applied once to all 60 (floors doubled; condition 3 unchanged). Still undecided: the role stays on the fast tier, flagged for a person's review, and the BRIEF says the bake-off could not separate the tiers |
| **neither** | Neither tier clears it | The role is not given to a model as designed. It goes back to rules, or to a person, or is redesigned; the BRIEF says so |

The threshold is about accuracy. It is not adjusted for speed: a role that
needs the larger model needs it however long the swap takes, and what the
swap costs is S6's measurement.

## What S3 does not decide

- **Latency and swap cost on a GB10.** S3's first run is in the lab, where the
  fast tier is served by the L4 fleet and the deliberate tier by the lab GB10
  with nothing else loaded. Those latencies are recorded with their hardware
  labels and are not standalone numbers. The latency half — tokens per second
  per tier and per role, and the cost of a swap — is run on the GB10 inside
  the S6 window, on the same items and prompts.
- **Whether accuracy holds on the GB10's serving settings.** Context length
  and memory fraction there are set in S6. If they differ from the lab's, the
  accuracy run is repeated on the GB10 for any role within three items of its
  floor.
- **Other models.** The result is about the two models bound to the tiers on
  the day of the run, named in the results.

## Pass criterion

S3 passes when every role has one of the five outcomes, reached by the rule
above from scores on items and prompts whose hashes were committed before the
first scored call; the label check by a second reader is recorded; and the
BRIEF's two tables say what was decided. A role that ends `neither` or
`undecided` does not fail S3. An unscored role does.

## Method

```sh
# drawing and labeling — done, 2026-10-05; no model
uv run python spikes/s3/draw.py r1 && uv run python spikes/s3/draw.py r2     # seeded candidates from the pinned sources
uv run python spikes/s3/make_r123.py       # R1 to R3 items and their cited labels
uv run python spikes/s3/build_r5.py        # R5: each scenario started, observed, its cause line changed, observed again
uv run python spikes/s3/build_r4.py        # R4: each conflict from an observed configuration
uv run python spikes/s3/build_r6.py        # R6: each start observed, one solution per intent verified
uv run python spikes/s3/split.py r4 r5 r6  # six development items per role, by seeded shuffle

# the second reader — not done
uv run python spikes/s3/sample.py          # six scored items per role, with label and evidence; record in labels/SECOND-READER.md

# the run — not done; refused until the hashes below match and the check is recorded
uv run python spikes/s3/run.py --config <arms.yaml> --arm fast --arm fast-thinking:<thinking-arm.yaml> --arm deliberate --set scored
uv run python spikes/s3/score.py --set scored
```

The lab (`lab.py`) starts one service at a time at `172.16.106.60` on the
slice's network and probes only that address, the slice's own and the S2
targets'. Rebuilding R4 to R6 needs the images `pqch-agency/portal:m0`,
`pqch-agency/bastion:m0`, `pqch-agency/sftp-legacy:m0`, `pqch/harness:m0` and
the S2 targets' images.

## Results

**Run 2026-10-07 to 2026-10-08 through the lab gateway**, every arm on every role, three calls per
item. Lab bindings: `fast` is Nemotron 3.5 Lightning 30B-A3B (NVFP4) on the L4 fleet; `fast,
thinking` is the same engine with reasoning on; `deliberate` is Nemotron 3 Super 120B-A12B (NVFP4)
on the lab GB10 as sole resident. Each reply records the model id the gateway returned; the
backends were checked to be serving those models throughout. The fast and deliberate arms ran
concurrently on one host, so the lab latencies below carry that contention and are, as the design
says, not standalone numbers.

### The outcome, by the rule above

| Role | Fast | Fast, thinking | Deliberate | Floor (harmful) | b / c, p | Outcome |
|---|---|---|---|---|---|---|
| R1 call-site read | 21 | 28 | 29 | 27 (1) | 8 / 0, .004 | **fast, thinking** |
| R2 normalization | 23 | 26, 1 harmful | 27 | 28 (0) | 4 / 0, .063 | **neither** |
| R3 classification | 25 | 30 | 30 | 28 (0) | 5 / 0, .031 | **fast, thinking** |
| R4 conflict resolution | 1 of 29, 13 harmful | 13 of 29 | 13 of 29, 1 harmful | 24 (2) | 12 / 0, .0002 | **neither** |
| R5 trace to cause | 9 | 10, 1 harmful | 28, 1 harmful | 24 (3) | 20 / 1, <.001 | **needs the larger model** |
| R6 change plan | 14, 2 harmful | 23, 3 harmful | 24, 1 harmful | 24 (2) | 10 / 0, .001 | **needs the larger model** |

Counts are items correct of 30 (29 for R4), where an item is correct when at least two of its
three replies are. `b` is the number of items the deliberate tier got right and the fast tier
wrong, `c` the reverse, `p` the exact one-sided sign test. The full report is
`results/scored/report.json`; the replies are under `results/scored/<arm>/`.

What each outcome means for the build:

- **R1 and R3 run on the fast engine with thinking on.** The fast tier alone clears neither; with
  reasoning it reaches 28 and 30. That costs no swap on a GB10. It does need a per-role switch the
  inference seam does not have: the seam knows the tiers `fast`, `deliberate` and `embed`, and
  this spike ran the thinking arm as a second configuration file. That switch is the one change
  `pqch.inference/1` needs before it is frozen.
- **R2 is `neither`, by one item.** The deliberate tier scored 27 against a floor of 28 with no
  harmful error allowed; the thinking arm 26 with one harmful (a standard name given to a spelling
  labeled `unknown`). The role is a table lookup, and a table is what it should be: the three
  spellings all arms missed are candidates for `scout/names.py`, not for a model. The role goes
  back to rules, with the model consulted only for a spelling the table does not hold and its
  answer shown as unconfirmed.
- **R4 is `neither`, and far from the floor.** The best arm resolves 13 of 29 conflicts. The fast
  tier's 13 harmful errors were almost all a definite layer where the label was `cannot-tell`; the
  deliberate tier gave different answers to the same item in 18 of 29 cases. Conflict resolution
  as designed — a model picks the layer in force from the findings alone — is not something either
  model does reliably. It goes back to the design: the rules that already decide `not-served` and
  `default-applies` deterministically should decide more, and the model should be asked only to
  explain, with its answer shown beside the rule's.
- **R5 needs the larger model.** 28 of 30 against 9 and 10, with 20 discordant pairs its way.
  Tracing a wire finding to the configuration line behind it, across include order and each
  server's precedence rule, is the role that separates the two models most.
- **R6 needs the larger model, and the number to read is the other one.** 24 of 30 plans
  verified on the wire, exactly the floor, with one plan that took the service down. Across all
  three arms, 32 of the 119 distinct plans run in the lab left the service not listening, 6 made
  a change that did not land, and the deliberate tier gave different plans to the same item in 24
  of 30 cases. Every plan is rehearsed and verified before approval, which is why the floor is
  24; the harmful count is what the rehearsal exists to catch.

### What else the run measured

| | Fast | Fast, thinking | Deliberate |
|---|---|---|---|
| Median latency, R1 / R5 / R6 | 1.7 s / 1.4 s / 3.8 s | 84 s / 33 s / 59 s | 42 s / 36 s / 95 s |
| 90th percentile, R4 | 1.1 s | 578 s | 214 s |
| Median completion tokens, R6 | 90 | 4822 | 812 |
| Replies cut off by the 16000-token cap | 0 | 14 (11 on R4) | 0 |
| Replies lost to the 600 s timeout | 0 | 7 (all on R4) | 0 |
| Items whose three replies differed, all roles | 19 | 50 | 57 |

Three things the rule does not score and the build must:

1. **Temperature 0 is not determinism.** The deliberate tier gave different replies to the same
   prompt in 57 of 178 items, the thinking arm in 50. An item is scored by majority of three, which
   is why the counts above are stable; a single call is not. Anything that acts on a model's reply
   without a verifier needs the repeat, or a rule that does not need the model.
2. **The thinking arm is slow and can fail to answer.** Its median on R1 was 84 s against the
   fast tier's 1.7 s, and on the long R4 items it reached the cap or the timeout 18 times in 87
   calls. "Fast, thinking" is cheaper than a swap; it is not fast.
3. **A change plan that is wrong is usually wrong by taking the service down**, not by leaving it
   classical: 32 of 119 plans across the arms. The applier's restore on a service that does not
   listen (M0B review F-56) is what makes that survivable.

### Lab latencies are not GB10 numbers

The latency half of S3 runs on the GB10 inside the S6 window, on the same items and prompts, and
sets the swap cost beside these accuracies. The first R1 to R3 roles on the thinking engine, the
R5 and R6 roles on the larger one, and the queue between them are what S6 measures.

**Addendum, 2026-10-08.** The one-GB10 target was withdrawn the day the results were scored
(ADR-0004), so the GB10 latency half described here and in "Deferred to S6" above is not run.
The lab latencies per arm in the table above are the numbers, each labelled with the engine and
the machine that served it. The second arm is now every other model the lab holds — Gemma 4
31B on the xr7620's L4s, GPT-OSS 120B and Llama 3.3 70B through the lab GB10's orchestrator,
`ollama` on a desktop GPU host — on the same items against the same floors. The design section is
left as it was committed before the run.

**Correction, 2026-10-12.** The fast and thinking arms did not run on the L4 fleet. The lab's gateway
moved `lab/flash` and `lab/reason-fast` to the GB10's Lightning NVFP4 engine (`:8013`, co-resident with
the 120B) on 2026-10-06, the day before this spike ran, and the spike's config still carried the label
`lab-l4-fleet`. The result files keep that label as written; read every `hardware: lab-l4-fleet` in them
as the lab GB10. Every latency in the tables above is therefore a GB10 number, for both engines.

### Round 2, 2026-10-14 to 2026-10-15: every other model the lab holds

The same 216 items, prompts and floors, three calls per item, seven more arms through the lab
gateway, one at a time (`workshop/inference.s3-arms/*.yaml`, git-ignored; each binds the arm's lane
to the `fast` tier). Lanes and where they served from, read from the gateway's configuration on
2026-10-14 and recorded as the arm's hardware label: Gemma 4 31B FP8 on the xr7620's four L4s
(`vllm/gemma-4-31b-l4`, and `-think` for reasoning on); on a desktop GPU host through `ollama` (2× RTX 6000):
Gemma 4 31B q8 with and without thinking, GPT-OSS 120B MXFP4, Llama 3.3 70B, Nemotron 3.5
Lightning. The GB10 vLLM lanes for GPT-OSS and Llama 70B were not run: loading either evicts the
120B that serves `deliberate`. Every R6 plan from every arm was applied and probed in the lab by
the scorer as in round 1. Items correct, of 30 (29 for R4); `h` is harmful answers:

| Role (floor, harmful allowed) | Nemotron 30B | 30B thinking | Nemotron 120B | Gemma 31B L4 | Gemma 31B L4 thinking | Gemma 31B desktop | Gemma 31B desktop thinking | GPT-OSS 120B desktop | Llama 70B desktop | Lightning desktop |
|---|---|---|---|---|---|---|---|---|---|---|
| R1 call-site read (27, 1) | 21 | 28 | 29 | 25 | **29** | 23 | **29** | 26 | 19 | 21 |
| R2 normalization (28, 0) | 23 | 26 h1 | 27 | 27 h1 | 25 h1 | 27 h1 | 25 h1 | 27 | 24 h4 | 24 |
| R3 classification (28, 0) | 25 | 30 | 30 | **30** | **30** | **30** | **30** | **30** | 29 h1 | 27 |
| R4 conflict resolution (24, 2) | 1 h13 | 13 | 13 h1 | 19 h3 | 21 | 19 h3 | 20 | 19 h2 | 9 h5 | 2 h12 |
| R5 trace to cause (24, 3) | 9 | 10 h1 | **28** h1 | 18 | 22 | 17 | 19 | **26** h4 | 11 | 9 |
| R6 change plan (24, 2) | 14 h2 | 23 h3 | **24** h1 | **27** | **24** | **25** h1 | **24** h1 | 20 h4 | 9 h14 | 7 h3 |

Median latency per call, R1 / R5 / R6, in seconds: Gemma L4 1.5 / 1.3 / 3.5; Gemma L4 thinking
13.6 / 20.9 / 45.3; Gemma desktop 2.1 / 2.1 / 4.8; GPT-OSS desktop 3.3 / 2.5 / 5.1; Llama 70B desktop
1.9 / 1.6 / 6.3; Lightning desktop 0.7 / 0.7 / 1.0; Gemma desktop thinking 14.4 / 22.6 / 75.3; against
round 1's 1.7 / 1.4 / 3.8 (30B), 84 / 33 / 59 (thinking) and 42 / 36 / 95 (120B), all on the GB10. The
desktop thinking arm's R4–R6 were lost twice to the desktop host refusing connections mid-run (2026-10-15 and
2026-10-19; `ollama` there serves one model at a time and drops callers when another model loads) and
completed on 2026-10-19/20 with the lost calls made again; 3 of its 87 R4 calls hit the 900 s
timeout. Its R6 reaches the floor — 24 with one harmful plan — at 75 s a plan where Gemma on the L4s
without thinking has 27 at 3.5 s, so the binding stands.

**What round 2 decides.** The rule for a second round, stated here before its numbers were read into
the configuration: a role is bound to the cheapest arm, by median latency, that reaches the floor with
no more harmful answers than the role allows; a role no arm reaches stays a rule's job.

- **Call-site reads:** Gemma 4 31B with thinking, on the L4s — 29 of 30 at 13.6 s, where the 30B
  with thinking was 28 at 84 s and the 120B 29 at 42 s. Bound: `fast` with reasoning, `fast` now
  being Gemma on the L4s.
- **Classification:** five arms at 30 of 30; Gemma on the L4s without thinking is the cheapest at 1.1 s.
  Bound: `fast`, no reasoning.
- **Change plans:** Gemma on the L4s, 27 of 30 with no harmful plan at 3.5 s, clears a floor the 120B
  cleared at 24 with one harmful plan at 95 s. Bound: `fast`, no reasoning. This is the round's surprise:
  the role that most looked like it needed the largest model is done better and 27× faster by a 31B
  model on four L4s.
- **Trace to cause:** only the 120B (28) and GPT-OSS 120B on the desktop GPU host (26, with 4 harmful against the
  120B's 1 and a floor allowing 3) reach it. Bound: `deliberate`, the 120B; GPT-OSS is the alternate
  if the GB10 is busy, with its harmful count noted.
- **Normalization:** no arm of ten reaches 28. A rule's job; the model fallback stays `fast`.
- **Conflict resolution:** Gemma with thinking reaches 21 of 29, eight above any round-1 arm, still
  under 24. A rule's job; the round says the floor is in sight for a mid-size model with reasoning.

So the GB10 is needed for one role of six. The lab's own four L4s, with a model that was chosen for
other work, cover the rest — and the lab's second host adds a credible alternate for the one. That
is the row the "what more models and hardware bring" table was built to hold.

### Round 3, 2026-10-16: a successor in the deliberate slot

NVIDIA released Nemotron 3.5 Super VL 120B-A12B on 2026-10-15, a successor to the Nemotron 3 Super
120B-A12B that serves `deliberate`. The lab's own bake-off for the GB10's reasoning slot (run
2026-10-16, pre-registered, lab-only) used this spike as its labelled reasoning test: the candidate
was loaded in the incumbent's slot on the lab GB10 at the same memory share (0.62), the same
131,072-token window and the same 32 concurrent sequences, Lightning resident beside it as in
production, through gateway lanes made for the test with no fallback and deleted afterwards. The
five arms' configurations are git-ignored like round 2's; their replies are committed under
`results/scored/bake-*`, each reply with the lane's model id and the hardware label. The incumbent
was re-run as one arm, so the comparison is same day, same slot, same vLLM settings — and that
re-run doubles as a measure of this spike's run-to-run noise. Items correct, of 30 (29 for R4);
`h` is harmful answers; the round-1 deliberate column is the 2026-10-07 run of the incumbent:

| Role (floor, harmful allowed) | Incumbent, round 1 | Incumbent, thinking on | Incumbent, thinking off | Super VL, full thinking | Super VL, medium effort | Super VL, thinking off |
|---|---|---|---|---|---|---|
| R1 call-site read (27, 1) | 29 | 27 | — | 27 | — | — |
| R2 normalization (28, 0) | 27 | 27 | — | 27 | — | — |
| R3 classification (28, 0) | 30 | 30 | — | 30 | — | — |
| R4 conflict resolution (24, 2) | 13 h1 | 14 h2 | 10 h5 | 6 of 10 run | **23** h4 | 9 h5 |
| R5 trace to cause (24, 3) | **28** h1 | **28** h2 | 23 | 21 h1 | **26** h2 | 9 |
| R6 change plan (24, 2) | **24** h1 | **25** h1 | **25** h3 | 4 of 9 run | 21 h1 | **24** h2 |

The candidate's full-thinking arm was stopped partway through R4 and R6 by the bake-off's own
amendment: its replies on those roles ran to a median of about 3,500 completion tokens, four times
the incumbent's, and 12 of its 29 R4 calls and 11 of its 26 R6 calls hit the 900 s timeout. The
"medium effort" arm is the same model with its chat template's `medium_effort` flag, which brings
its deliberation back to the incumbent's length (a median of 904 tokens on R4 against the
incumbent's 905). The thinking-off arms were run because that is the setting the gateway pins on
the lane prism's editor uses, and a slot serves every caller at once.

Median latency per call, R4 / R5 / R6, in seconds: incumbent thinking on 96 / 44 / 91; thinking off
5.1 / 7.3 / 10.5; Super VL medium 123 / 38 / 127; Super VL thinking off 4.2 / 3.1 / 13.6; Super VL
full thinking 782 / 96 / 762 with the timeouts counted. All on the lab GB10 at the 0.62 share.

**What round 3 decides, by the round-2 rule** (the cheapest arm, by median latency, that reaches the
floor with no more harmful answers than the role allows):

- **Trace to cause stays with the incumbent.** 28 against 26 at medium effort, p = 0.31 on the sign
  test: not a significant difference, and the candidate at medium effort is the first arm besides
  the incumbent to clear this floor within the harmful allowance (GPT-OSS 120B on the desktop GPU host scored 26
  with 4 harmful where 3 are allowed). If the lab swaps the slot, the project's one `deliberate`
  role is still served, two items lower, at about the same latency. With thinking off, neither
  model traces: 23 and 9.
- **Conflict resolution is still a rule's job, and now by harmful count alone.** 23 of 29 at medium
  effort is the best of fifteen arms and within one of the floor, but with 4 harmful answers where
  2 are allowed: a definite layer named where the label was `cannot-tell`.
- **Change plans are unchanged**: bound to Gemma 4 31B on the L4s since round 2 (27, none harmful,
  3.5 s). Nothing here reaches 27.
- **R1 to R3 are a tie** between the two 120B models, and run on the fast tier anyway.
- **Run-to-run noise is about two items per role.** The incumbent scored 29 / 27 / 30 / 13 / 28 / 24
  on 2026-10-07 and 27 / 27 / 30 / 14 / 28 / 25 on 2026-10-16 at the same settings. A difference of
  two between arms is not a difference.

The round's largest effect is not between the two models but between one model's settings: Super VL
traces 9 of 30 with thinking off, 26 at medium effort and 21 at full thinking with a quarter of its
calls timing out; it resolves 9 and 23 conflicts. That is the subject of
[lesson 26](../../docs/journal/lessons/26-name-the-reasoning-setting-beside-the-model.md).

### Round 4, 2026-10-20: the live lane after the slot changed

On 2026-10-19 the lab's gateway moved `lab/reason` — the lane `deliberate` is bound to — from Nemotron
3 Super 120B-A12B at full thinking to Nemotron 3.5 Super VL 120B-A12B NVFP4 at the lane's medium-effort
thinking (vLLM 0.32, `:8014`, 0.62 share beside Lightning), for the slot's other callers. The one role this
project binds there is trace-to-cause (R5). Round 3 had measured the same model at medium effort through
the bake-off's own lane (26 of 30); this round measures the lane as it now serves, with the arm
`lab-reason-supervl` bound to `lab/reason` and sending no template arguments of its own (a request's
`chat_template_kwargs` replace the lane's; the lane's setting is the point). R5 only, 30 items, three
calls each, scored by the same rule:

| Arm | Engine, setting | R5 of 30 | harmful | median s | median completion tokens |
|---|---|---|---|---|---|
| `deliberate`, round 1 (2026-10-07) | Nemotron 3 Super, full thinking | 28 | 1 | 35.7 | 313 |
| `bake-nemotron-120b`, round 3 | the same, re-run 2026-10-16 | 28 | 2 | 44.4 | 327 |
| `bake-nemotron-supervl-medium`, round 3 | Super VL, medium effort, bake-off lane | 26 | 2 | 38.3 | 233 |
| **`lab-reason-supervl`, round 4** | **Super VL, medium effort, the live `lab/reason`** | **27** | **2** | **12.7** | **248** |

Against the round-1 arm: 3 items the old engine had and the new one misses, 2 the other way, sign test
p = 0.5 — within the two-item run-to-run noise round 3 measured on the incumbent itself. No call failed;
the 90th-percentile latency was 35 s on a lane serving the lab's other traffic.

**What round 4 decides, by the round-2 rule.** The live lane reaches the floor of 24 with 2 harmful
answers where 3 are allowed, and it is the cheapest arm that does: 12.7 s a call against 36 to 44 s for
the old engine. Trace-to-cause stays bound to `deliberate` on `lab/reason` as it now serves. The
full-thinking lane (`lab/reason-deep`) is not asked for: round 3 measured full thinking at 21 with a
quarter of its calls timing out, and it is not on this project's key. The old engine, kept on the GB10's
disk as a swap, is not needed for this role. The `deliberate` tier's hardware label now names the new
engine and its setting (lesson 26); the three rounds before this one remain measurements of the old one.

### Round 5, 2026-10-21: the live lane on the other five roles

Round 4 re-measured only trace-to-cause after the GB10's reasoning slot changed engine. Round 5
runs the same arm, `lab-reason-supervl` — the live `lab/reason` lane, Nemotron 3.5 Super VL
120B-A12B NVFP4 at the lane's medium-effort thinking, no template arguments of its own — on R1 to
R4 and R6, the same items, labels, prompts and floors, three calls per item (2026-10-21, 14:48 to
18:21 UTC, through the gateway while the lane served the lab's other callers). Scored by the same
rule; the bound arm beside it for comparison, its replies re-scored the same day:

| Role (floor, harmful allowed) | `lab-reason-supervl`, round 5 | median s | unstable items | Bound arm, same scorer |
|---|---|---|---|---|
| R1 call-site read (27, 1) | 25 | 13.7 | 1 | Gemma 4 31B, reasoning on: 29, 13.6 s |
| R2 normalization (28, 0) | **28**, 0 harmful | 9.8 | 2 | none: a rule; best before, 27 |
| R3 classification (28, 0) | 30 | 13.8 | 0 | Gemma 4 31B, no reasoning: 30, 1.1 s |
| R4 conflict resolution (24, 2) | **26**, 2 harmful | 41.1 | 10 | none: a rule; best before, 23 with 4 harmful |
| R5 trace to cause (24, 3) | 27, 2 harmful (round 4) | 12.7 | — | this arm |
| R6 change plan (24, 2) | 19, 4 harmful | 50.1 | 24 | Gemma 4 31B, no reasoning: 27, none harmful, 3.5 s |

**What round 5 decides, by the round-2 rule.**

- **Normalization reaches its floor for the first time**, at exactly 28 with no harmful answer,
  the only one of the thirteen arms that ran it to do so. The name table still decides; the live lane is the fallback
  for a spelling the table lacks, shown as unconfirmed. A result on the floor is within the
  spike's two-item noise of falling below it.
- **Conflict resolution reaches its floor for the first time**: 26 of 29 with 2 harmful where 2
  are allowed, against the bake-off lane's 23 with 4 harmful for the same model and setting. It is
  also this arm's least stable role: 10 of 29 items drew different answers across the three calls.
  The project's rule `conflict/resolve/1` keeps deciding the conflicts it can; the role is bound so
  that a model may explain a conflict beside the rule's answer, as M1 designed, never settle it.
- **Call-site reads, classification and change plans stay where they are.** Call-site reads fall
  two under the floor; classification ties at 30 and the bound arm is twelve times faster; change
  plans fall five under with twice the harmful allowance, and 24 of 30 items were unstable.
- **The live lane differs from the bake-off's lane for the same model and setting** on the two
  roles both measured: R4 26 against 23, R5 27 against 26. Lesson 26 holds: the setting is part of
  the name, and so, here, is the lane.

### What exists, 2026-10-05

216 items, 36 per role, each with a label that carries its evidence
(`labels/README.md` says how each kind was made). R4 and R5 were labeled by
starting about a hundred configurations on the slice network and probing them; R6's 30
solvable items each had one solution applied and verified, and its 6 blocked
items record what the runtime lists.

SHA-256 of each role's files. `run.py` refuses a scored run unless every one of
these files still hashes to the value here.

| Role | Scored | Dev | Items | Labels | Prompt |
|---|---|---|---|---|---|
| R1 | 30 | 6 | `2eeb9900894d9c8faa1e30ea000445ea380b723454752f8a4d9ef2a5e9bc6cc1` | `4d796e54b7c97fbe7395909b59ba443f4f9ac120d43b3e5ca0bd798906c9f6c8` | `da630dac6436808137634033def0df648048f3372f5ca8618886d930ee0b79b2` |
| R2 | 30 | 6 | `7be3bcac2ec2ac4aba9898cca868b0d235ddd6c358329725a5b3a08f59c5c758` | `4ce0f93665a4b2404bfbd953fdf9af629fd3d9158b82c5887ab9497de07a26d7` | `f821418ff28db60f1b9fff92e1f2d119acf91eb86a609397e9ac7809ff7f1bfd` |
| R3 | 30 | 6 | `b9cf4a80658eda2b79dfe701563a23d5c9e477a8bea4e131b35a63999819d496` | `9a17b2063c566d72f45aca68307fc2025dd81c9d37c72af0daa6d055b9ff8f44` | `3698320f792664cff936033bb311664d7519208df61f0168b2e72075dccc7c96` |
| R4 | 29 | 6 | `ab430801ff164320b8fb0dbae2d2222e356c47f351ad6d5725a64b1df003e850` | `c343e8bc8589a2010b1d9ca382f705e67abb40f0f7d84c821adf6f47dd52b4fc` | `8419b280ee56a21f2b98e9b4949ceaa639c4b15dfb260f9899ee057adf6480e6` |
| R5 | 30 | 6 | `ee47bf9c6ced8310f35f8e957c0a8a53340ba5ac312cad7936b7bc7edb868947` | `3426fda56c9d5ed726b11517814d508a0d468b877c8cffc4036216d84326d399` | `999f7165f91d7f6364df12369f32e6be5f71866532a22522d82e195a15433912` |
| R6 | 30 | 6 | `c7ec4228a70849e48a88bd2b399e3b00b3497d8abc694d14ecbb054a9f9c6641` | `ee6494d18910edc68530b7700330b34d7c5689892cd936933248d306d0896fa9` | `61bfe8ad9520f5e0a1094ad56bb1c0c9981c2060335f50a9fdc401aa76b52dd8` |

### The second reader's sample

Six scored items per role, by seeded shuffle (`sample.py` prints them with
their labels and evidence). The R1 six are for Ken Rollins to read himself.

| Role | The six to check |
|---|---|
| R1 | `r1-061`, `r1-036`, `r1-097`, `r1-096`, `r1-024`, `r1-111` |
| R2 | `r2-32`, `r2-04`, `r2-17`, `r2-16`, `r2-06`, `r2-25` |
| R3 | `r3-35`, `r3-13`, `r3-15`, `r3-18`, `r3-26`, `r3-33` |
| R4 | `r4-07`, `r4-22`, `r4-23`, `r4-30`, `r4-35`, `r4-28` |
| R5 | `r5-k03`, `r5-s02`, `r5-n13`, `r5-p06`, `r5-s04`, `r5-p02` |
| R6 | `r6-e-enable`, `r6-n-enable`, `r6-m-enable`, `r6-l-enable`, `r6-j-require`, `r6-a-require` |

The check is recorded in `labels/SECOND-READER.md`: R1 by Ken Rollins, R2 to R6 by a
review session on another model that had not seen the labels. All 36 sampled labels
stood. One R4 item, `r4-22`, was taken out of scoring on the reader's point that
the fact deciding it was not shown to the model; R4 is scored on 29 items, with its
floor scaled as the threshold section says (24 of 30 becomes 24 of 29). Four
config findings in R4's other-listener items gained the server block they sit in.
The development run then showed one more defect the sample had not reached: `r4-03`
described an elliptic-curve key as ML-DSA-65, a bug in the builder's key naming;
the statement was corrected and the builder fixed.

### The development run, 2026-10-06

All three arms over the six development items per role, through the lab
gateway (`workshop/inference.s3.yaml`; fast and thinking on the L4 fleet,
deliberate on the lab GB10). It was for the prompts, and it changed one: the
R6 prompt's "blocked: protocol" rule, which the fast arm had read as "TLS 1.2
cannot carry it, so blocked", now says a TLS service is changed to TLS 1.3,
never blocked by protocol. Nothing else was changed from what it showed.
What it showed, recorded and not acted on: the thinking arm reached the
16000-token cap on 8 of 36 R4 and R5 calls and took up to 519 s on one; the
deliberate arm gave different replies to the same R4 item in 4 of 6 cases at
temperature 0. Scores on development items decide nothing and are in
`results/dev/report.json`.

### Where the build departed from the design above

- **Who labels R1 to R3** — the build session, not "by hand"; amended above
  before any item was drawn.
- **Sampling** — the seam's temperature 0, not "the endpoint's defaults";
  corrected above.
- **R1's draw** — changed once, before labeling: imports are not call sites.
  Java still yields six uses, not eight; that role's items are 22 uses and 14
  non-uses.
- **R3's sources** — the memo's Appendix A only. CNSA 2.0 could not be read
  first-hand, so LMS and XMSS are not among the items.
- **R6's services** — TLS only: nginx, Postgres, RabbitMQ, Kafka. The verifier
  has no SSH check yet, so a plan for sshd could not be scored by running it.
- **R6 on `enable`** — the verifier's refuse list is every classical group for
  both intents, as in the product; `enable` is met by `enabled-not-enforced`.

None of these touches the metric or the threshold.
