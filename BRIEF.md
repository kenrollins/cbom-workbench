# cbom-workbench — design brief

*Repository: `cbom-workbench`; import package and command `pqch`.*

**A cryptography bill of materials, built from evidence, kept on a signed
ledger, and put to work — with the role of AI in that work measured, not
assumed.** A workbench that builds a CBOM from wire, host and code evidence,
keeps it current, and uses it to carry a mixed estate up the crypto-agility
maturity ladder, from Opaque to Agile. Language models are used where
interpretation is needed and nowhere else, and which model does which role is
decided by measurement against a floor written before the run. Everything runs
on infrastructure the organization holds; what each step up in models or
hardware changes is a measured row, or is marked not measured.

Audience: federal CIO/CISO staff and the technical sellers who talk to them.
Owner-only in the lab. Not tied to the 2026-11-03 workshop (decided
2026-10-21); it is shown when it is finished.

Its first purpose is to show what a CBOM is — an entry, its fields, the
evidence behind each, the chain it sits in — and what it makes possible once
it exists, a model's work among it: a CBOM entry is the context that lets a
model trace a weakness to the line that causes it and draft the change, and
the evidence that lets a verifier prove the change landed.

---

## What this is for

An exploration, shared freely: every step an agency has to take to get from a
spreadsheet to crypto agility, the technical detail at each step, and how an
agent harness is built to carry it — with the working code, the
specification, the evaluation kit and the notes published for anyone to use.
It is not a product, and it is not trying to become one. Where a choice is
between completeness as a product and clarity as a worked example, clarity
wins.

It also makes one argument about where this work should run. A cryptographic
inventory is a map of where an organization is weakest, down to the line of
code. That is not something to send to someone else's cloud. The workbench
runs on infrastructure the organization holds — in this project, one lab:
an x86_64 server with its GPUs, a desk-side GB10 and a second GPU host, every
model they serve reachable through one seam — and the demonstration shows
what each step up in models or local hardware adds, by measurement where
there is one and plainly marked where there is not.

And it makes one argument about *when*. The inventory is required now, before
anyone has said what it must contain. That is the reason the record under it
has to be built so that it can be projected into whatever is asked for later,
and the reason to start before the asking.

---

## The clock

Federal policy fixes the dates this work runs against. Each is cited in the
facts table below; the project's reading of each is in the last column.

| Date | What | Source | What it means for a CBOM |
|---|---|---|---|
| 2026-10-22 | Each agency's PQC Migration Plan is due at OMB and ONCD (120 days from M-26-15) | OMB M-26-15 §1 | The plan has to name an inventory approach before the inventory exists |
| 2026–2027 | Phase 1: strategy, planning and discovery — inventory, assessment, governance | M-26-15 §3.D | This is the inventory year. A CBOM built now is built against no published minimum |
| 2027-01-01 | New national security system acquisitions CNSA 2.0 compliant | NSA CNSA 2.0 FAQ, through secondary summaries; the primary refused the download on 2026-10-05 and 2026-10-20 and was not read | Signature and key-establishment choices in new buys are already constrained |
| **2027-03-19** | **CISA and NIST publish the minimum elements of a CBOM** (270 days from EO 14412) | EO 14412 | Until this date "a CBOM" means CycloneDX 1.6 plus whatever each agency or vendor adds. After it, an agency's CBOM will be measured against a list it does not yet have |
| 2027–2028 | Phase 2: pilots and early migration of prioritized systems | M-26-15 §3.D | The CBOM has to say *what first* — owners, deadlines, blockers — the Managed rung |
| 2030-01-02 | TLS 1.3 supported everywhere | M-26-15 §4 | Hybrid key establishment in TLS is a TLS 1.3 mechanism; a listener that cannot do 1.3 cannot do ML-KEM |
| 2030-12-31 | Key establishment on HVAs, high-impact and highly sensitive systems is post-quantum | EO 14412; M-26-15 Phase 3 | The first queue. "Harvest now, decrypt later" makes this the urgent clock |
| 2031-12-31 | Digital signatures on the same systems are post-quantum | EO 14412; M-26-15 Phase 4 | The second queue; it waits on validated modules and certificate chains |
| 2035 | Full migration of remaining systems | M-26-15 Phase 5 | — |

Two consequences shape the design:

- **Build the record, not the document.** Because the minimum elements are
  not published, the workbench keeps every finding with its evidence on a
  ledger and treats the CBOM as a projection of that ledger (ADR-0001). When
  the minimum elements arrive, producing a CBOM that meets them is a new
  projection of the same record — a rebuild, not a re-scan. A CBOM edited
  by hand to a template cannot do that.
- **Carry more than any minimum is likely to ask.** Dependencies, data
  lifetime, the evidence hash for every entry, the listener's posture
  (enabled against enforced), and the verifier verdict for every change.
  The project's bet is that the minimum elements will ask for a subset of
  these, and the way to find out which is to have them all and project.

The demonstration shows this clock on the page, with today marked, because
it is the answer to *why now* and *why this shape*.

---

## The claim

> **A CBOM built from wire, host and code evidence — and verified by
> re-scanning — is enough to take this mixed estate, the mini-agency, from
> Opaque to Agile. Every entry carries its evidence, every applied change is
> confirmed by a non-model verifier — on the wire where the change is
> observable there — and an algorithm policy change is executed and verified in
> minutes. Measured against an answer key and against the open-source scanners
> run alone. Where a language model takes part, which model and whether it is
> needed at all was decided by measurement against a floor written before the
> run; what more models or hardware change is measured or marked not
> measured.**

Falsifiable at every clause:

- **Coverage** — scored against the answer key, by layer, with decoys and
  known misses in the key (see Targets).
- **The delta** — over two baselines: CBOMkit alone, and all the scanners run
  alone with no harness. The second is the workbench's own contribution.
- **Verified change** — the receipts show changes verified, changes applied,
  and finding classes that have no verifier. An applied change without a
  verifier verdict falsifies the clause.
- **Time-to-change** — from the policy-change event to the last verifier
  verdict for every endpoint the policy affects, rehearsal included, computed
  from ledger timestamps. The interval from approval to verdict is reported
  beside it as a second, labelled number. The limit in minutes is set once
  the full agency has been measured in M3; over the limit, or any affected
  endpoint without a verdict, and the clause fails.
- **The role of the models** — six roles, a floor per role written and
  committed before the run, every call repeated (spike S3). A role is given
  to a model only when that model reached the floor; a role no model reached
  goes to rules. A model used where the table says it was not needed, or a
  model timing without its engine and hardware, falsifies the clause.
- **What more brings** — the table under "What more models and hardware
  bring" is filled by measurement in this lab, or marked not measured. A row
  that claims without measuring falsifies the clause.
- **Each rung** — has a pass test in the table below.

Framings deliberately **rejected**:

- *"AI solves PQC."* It does not, and the audience knows it. Models are used
  only where interpretation is needed; rules, scanners and parsers do the rest.
- *"A replacement for commercial discovery platforms."* Those are fielded
  products with sensors across live estates. This is an open exploration of
  what the CBOM enables once it exists; it complements runtime discovery by
  tracing a finding to the line that must change.
- *"Faster than X."* No speed comparisons against other vendors' hardware or
  products. The numbers shown are coverage, verification and time-to-change.
  A step up in models or local hardware is described by what it enables for
  this workload, using this project's own measurements; a step that has not
  been measured is marked as not measured.
- *"A product."* Nothing here is for sale or supported. The harness does not
  change an estate it did not build: elsewhere it hands off a change package
  and verifies the result (ADR-0003).
- *"Self-improving agents."* Anything the harness learns is a reviewed playbook
  entry, credited only when a verifier confirms it helped. No weight updates.

---

## The story: five rungs, one CBOM

The spine is the crypto-agility maturity model. Each rung is a question the
agency can now answer, and each is a screen in the demo.

| Rung | What the agency has | What the CBOM answers | What is on screen | Passes when |
|---|---|---|---|---|
| **Opaque** | A stale spreadsheet | Nothing reliable | Six hand-kept rows, already out of date | — (the starting point) |
| **Enumerated** | Scanner output | Where is quantum-vulnerable cryptography? | Wire and host scans fill a flat list | Coverage by layer is scored against the key, with decoys not flagged |
| **Structured** | A CBOM with dependencies | What depends on it, and how long must the data stay secret? | The chain: server, certificate, application, mission function, data lifetime — each link with evidence | Every discovered link in every chain resolves to a ledger event with evidence; supplied links are labelled as supplied |
| **Managed** | Owners, priorities, approvals | What first? What is blocked on a supplier or a validated module? What changed since yesterday? | Two queues by deadline (key establishment 2030, signatures 2031); a change event arrives and waits for approval | Every key item has an owner, a queue, a blocker state and the rule id that put it there |
| **Agile** | Change as routine | If policy changes, how fast can we respond, and did it land? | Policy is changed, the wire is re-scanned, the time is shown | Time-to-change is under the limit and every affected endpoint has an `enforced` or `enabled-not-enforced` verdict |

### The opening 90 seconds

The opening answers the customer's question fast; the walkthrough after it is
where the depth is. Inside the opening there is no model call and no engine
swap: anything a model produced was produced earlier, is read back from the
ledger, and carries its ledger timestamp on screen. Each step is marked.

1. The spreadsheet. "This is most inventories today." *(static)*
2. One button. Targeted scans run against the mini-agency network; the list
   fills. *(live — targeted checks with a per-endpoint time budget; image and
   source scans replayed from the ledger)*
3. The list folds into a CBOM. Click one entry: the dependency chain, the
   evidence for each link, and which federal deadline it falls under.
   *(replayed — the trace was made earlier)*
4. The priority view: two queues, and the reason each item sits where it does.
   *(live — rules)*
5. A policy change is approved. Configs regenerate, the wire is re-scanned by
   a hybrid-only and a classical-only probe, and the elapsed time is on screen.
   *(live — on a native-code server, rehearsed in the twin beforehand; both
   intervals shown)*
6. The receipts panel: coverage against the answer key, the two baselines
   beside the workbench, and the ledger entry for the change just made.
   *(scores precomputed; the ledger entry live)*

### The walkthrough

After the opening, the same path at full depth and live: a full scan, an
investigator trace run from cold on the larger model with its ledger event
and its measured time, a policy change that moves from `enabled-not-enforced`
to `enforced` through the compatibility matrix, a change event arriving in
Watch mode, and the table of which roles need which model and what each step
up in models or hardware was measured to change. The waits are part of the
demonstration, labelled with the engine and the machine that produced them.

The moment that lands: *the inventory is not a report, it is the thing the
change was made from and verified against.*

---

## Architecture

**Agents propose. Verifiers dispose. The ledger remembers.**

```
 policy packs (M-26-15 · CNSA 2.0)          human approval
          │                                      │
 SCOUT ──► INVESTIGATOR ──► ASSESSOR ──► MIGRATOR ──► VERIFIER (no model)
 wire +     traces a          rules first;   proposes;     re-scan · cert parse
 host       finding to        model only     rehearses     · compatibility matrix
 scanners   code/config       on conflict    in the twin
          └──────────────┬───────────────────────┘
                 CBOM LEDGER  — CycloneDX CBOM + append-only, hash-chained,
                                signed JSONL event log (the system of record)
```

- **Scout** — deterministic. testssl.sh and ssh-audit on the wire;
  cbomkit-theia on images and directories; the CBOMkit source scanners for
  candidate call sites in Java, Python and Go; an Opengrep rule pack (Semgrep
  rule format), kept as data, for languages CBOMkit does not read (Ruby
  first). Passive capture
  with Zeek is the one route to client-side posture — what a service offers
  when it connects out: Zeek runs as a sidecar sharing the network namespace of
  a designated client container, and a traffic generator gives it something to
  observe. Output is normalized findings.
- **Runner** — the only container with the Docker socket. It sits on the
  target networks, has no public leg, and accepts a fixed set of jobs: named
  scan profiles, and the apply of an approved change id. The service that
  serves the UI never holds the socket.
- **Investigator** — the one place a model reasons at length. It works the way
  a recursive language model does: it writes code over the repository and
  configs, and calls a small model on the specific call sites that need
  reading. It turns "this endpoint negotiates classical key exchange" into
  "because of this line".
- **Assessor** — rules first: quantum-vulnerable or not, key establishment or
  signature, data lifetime, high-value asset, deadline. A model is consulted
  only when evidence conflicts.
- **Migrator** — proposes a change, applies it in a twin of the network built
  from the same configs, and only then asks for approval to apply it. It
  applies only to an estate the harness built. For any other estate it emits
  a change package — the diff, the rollback, the compatibility matrix, the
  rehearsal evidence or the label `not rehearsed`, and the test that will
  count as verified — and the operator makes the change.
- **Verifier** — no model. A change counts when the re-scan says so, and the
  re-scan is a pair of probes: a hybrid-only client must succeed, and a
  classical-only client must be refused. Both hold: `enforced`. Only the first:
  `enabled-not-enforced`, which is a real state and not a pass. A second
  witness of a different kind (`openssl s_client -groups`) confirms the first.
  A verdict is bound to the address, container, image digest and certificate
  fingerprint it was taken from, and is repeated after the service is
  recreated. See ADR-0001.
- **Ledger** — every finding, decision, approval, model swap and verifier
  verdict is an event. The CBOM is a projection of the ledger. See ADR-0001.
- **The page and the site** — the page is the demonstration, the site is the
  reference. The page carries one orienting line and, per section, a short
  "why" that opens in place and links to the note that goes deep; the site
  holds the notes, lessons, sources and provenance. The site is served from
  the same host as the page, and the bundle carries it, so every link works
  with the cable out. Nothing a viewer needs to follow the demonstration is
  only on the site, and nothing a reader needs to understand an idea is only
  in the page.

Two modes share all of this:

- **Build** — first inventory of an estate.
- **Watch** — the CBOM as a source of change events. Only what changed is
  re-examined; high-impact actions wait for a person.

### Models

Tiers, never model names in code.

| Tier | Lab binding (gateway) | Runs on, in the lab | Role |
|---|---|---|---|
| fast | `vllm/gemma-4-31b-l4` (Gemma 4 31B FP8), reasoning via `-think` — since 2026-10-15; `lab/flash` (Nemotron 3.5 Lightning 30B-A3B) before | the xr7620's four L4s | the fallback for a spelling the name table does not hold, shown as unconfirmed (S3: normalization and classification need thinking on) |
| fast, thinking | the same engine with reasoning on (`vllm/gemma-4-31b-l4-think`) | the xr7620's four L4s | call-site reads (S3 round 2: 29 of 30 at 13.6 s); bound per role in the seam's `roles` section |
| deliberate | `lab/reason` — since 2026-10-19 Nemotron 3.5 Super VL 120B-A12B NVFP4 at the lane's medium-effort thinking (vLLM 0.32, `:8014`); Nemotron 3 Super 120B-A12B at full thinking before, the engine rounds 1 to 3 measured | the lab GB10 at a 0.62 share, Lightning resident beside it | tracing a finding to its configuration line (S3: 28 of 30 on the old engine; 26 of 30 for the new one at medium effort in the bake-off's lanes; 27 of 30 with 2 harmful on the live lane, 2026-10-20, S3 round 4, at 12.7 s a call: it stays). Change plans moved to `fast` in round 2; conflict resolution is a rule's job |
| embed | `lab/embed` | `ollama`, beside the gateway | narrowing candidates before a read |

Which roles need the larger model was decided by spike S3 against a floor
written before the spike ran: the trace to a configuration line is the one
role that needs it; change plans, call-site reads (with thinking on) and
classification run on Gemma 4 31B on the L4s since round 2; normalization and
conflict resolution go back to rules (`spikes/s3/README.md`, note 13). The
GB10's reasoning slot changed engine on 2026-10-19; round 4 re-measured the
trace on the live lane, and round 5 (started 2026-10-21) measures the other
five roles there, since a role may be better served by the new engine than by
Gemma. Every timing is labelled with the
engine, its serving settings and the machine; a model timing without them is
not a number.

**Every model the lab holds is in scope** (ADR-0004). Beyond the three bound
above: Gemma 4 31B on the xr7620's L4s; GPT-OSS 120B and Llama 3.3 70B,
which the lab GB10's orchestrator can load in turn with the 120B; and what
`ollama` on a desktop GPU host serves (gpt-oss:120b and a 70B at a 65536-token context).
Each is a candidate arm for the S3 roles, bound to a tier in config and
scored against the same floors; the result goes in the table below. Rounds 2
and 3 ran them (2026-10-14 to 2026-10-20); round 5 adds the GB10's new
reasoning engine on its live lane.

---

## One deployment, one bundle

The workbench runs in the lab: the xr7620, inference through the gateway, the
mini-agency beside it on internal-only bridges. There is no second target
(ADR-0004 supersedes ADR-0002). The offline bundle is a feature: images by
digest in a local registry, dependencies, repositories, reference documents
and the built site, loaded on a host with the network cut, so that the whole
thing demonstrably moves on a disk and depends on none of the lab's shared
services. It is rehearsed on a second lab host, not built as a separate
target.

### Three uses, two axes

The harness runs from one of two places, and the estate it inventories lives
in one of three. See ADR-0003 as amended.

| Use | Harness | Estate | What it is for |
|---|---|---|---|
| Lab | the xr7620, inference through the gateway | mini-agency beside it | Every feature; the standing demonstration venue |
| Bundle | the same build, loaded from the bundle on a host the operator chooses | the bundled mini-agency, or the mini-agency on a second host over a private link | Shows that it all moves on a disk; the rehearsal for the kit |
| Kit | the bundle as published | the bundled mini-agency, or a network the operator names in a scope file | For anyone to run; scans only what its operator lists |

The harness never discovers what to scan. It reads a scope file, records it on
the ledger as the first event of a run, and the runner refuses any target
outside it.

### What more models and hardware bring

This table is a deliverable. It is filled by measurement in this lab — the
models the xr7620, the lab GB10 and a desktop GPU host serve, through the one seam — and
the journal records what each step changed for this workload. "More" means
more local capacity: a larger model, a second engine resident, more GPUs.
Anything beyond what the lab holds is described as not measured. Rows known
today:

| Capability | Measured | What a step up changes | Provenance |
|---|---|---|---|
| Call-site reads, typed classification | the 30B-A3B engine reaches the floor only with reasoning on: 28 and 30 of 30; without it 21 and 25 | reasoning costs latency: a median of 84 s against 1.7 s per read on the same engine. The larger model reached 29 and 30 of 30 at a median of 42 s per read. Round 2: Gemma 4 31B on four L4s reaches 29 with reasoning at 13.6 s and 30 on classification without it at 1.1 s — the same floors, no GB10 | spike S3, 2026-10-08 (both engines on the lab GB10; the result files' `lab-l4-fleet` label is stale, corrected 2026-10-12) and round 2, 2026-10-15 |
| Trace to a configuration line | the 120B-A12B reaches the floor on both its runs: 28 of 30 with 1 harmful (2026-10-08) and 28 with 2 (2026-10-16); the small engine does not | Its successor, Nemotron 3.5 Super VL 120B-A12B in the same slot at medium reasoning effort, reaches it at 26 with 2 harmful in the bake-off's lane (p = .31 against the incumbent) and at 27 with 2 harmful on the live `lab/reason` after the slot changed (2026-10-20, 12.7 s a call, p = .5): the role stays bound there, at a third of the old engine's latency. GPT-OSS 120B on a desktop GPU host's two RTX 6000 scores 26 but with 4 harmful where 3 are allowed. No mid-size model reaches it, with or without reasoning (Gemma 31B: 18, 22 thinking). With thinking off neither 120B traces: 23 and 9 | spike S3 rounds 1 to 3 |
| Explaining an item's queue over the policy pack | Gemma 4 31B on four L4s, thinking off, over the three passages `lab/embed` retrieved: 3 of 14 items against a floor of 13, 3 harmful calls of 42, 3.2 s a call. Not bound | Not the model's limit: retrieval missed the item's queue passage in 11 of 14, and the model passed 9 of 9 calls where it was there. A larger model would not change that; a better query or a filtered index might, measured on fresh items (lesson 34) | explain run `01M5DG1NY5M7E165RF1TCYVSRN`, 2026-10-20; floor in PLAN.md M2 |
| The GB10's new reasoning engine on every role, on its live lane | Nemotron 3.5 Super VL at medium effort through `lab/reason`, spike S3 round 5: call-site reads 25 (floor 27), normalization 28 with none harmful (floor 28), classification 30, conflict resolution 26 of 29 with 2 harmful (floor 24, 2), change plans 19 with 4 harmful (floor 24, 2); trace 27 (round 4) | The first arm to reach the normalization and conflict floors. Neither changes who decides: the name table and the conflict rule still do, and the lane is the fallback and the explainer. Gemma 31B on four L4s stays the better arm for call-site reads, classification and change plans, at a third to a fifteenth of the latency | spike S3 round 5, 2026-10-21, `spikes/s3/README.md` |
| Change plan | the 120B: 24 of 30, 1 harmful, 95 s a plan | Gemma 4 31B on four L4s: 27 of 30, no harmful plan, 3.5 s — better and 27× faster than the largest model. Bound to `fast` | spike S3 round 2, 2026-10-15; every plan applied and probed in the lab |
| Conflict resolution between layers | no arm of fifteen reaches the floor of 24 with 2 harmful allowed: Nemotron 3.5 Super VL at medium effort 23 of 29 but with 4 harmful; Gemma 31B with reasoning 21; the Nemotron 3 engines 13 and 14 | a rule's job still; the count is within one of the floor for a 120B at medium effort, and what keeps it out is a definite layer named where the evidence cannot tell | spike S3 rounds 1 to 3 |
| Normalizing a tool's spelling of a name | no arm of fifteen reaches the floor of 28; the best are 27 (both 120B Nemotrons, Gemma 31B, GPT-OSS 120B) | a name table does this exactly; a model is the fallback, shown as unconfirmed | spike S3 rounds 1 and 2 |
| Fast-tier decode speed | 113.8 tok/s on the L4 fleet | 56.8 tok/s for the same model on one GB10 | lab orchestrator `models.yaml`, bake-off 2026-08-11 and note of 2026-08-12 |
| Both engines resident | yes, on the lab GB10 itself: Lightning 30B-A3B at NVFP4 (memory fraction 0.22) beside the 120B-A12B reasoning engine (Nemotron 3 Super at 0.66 from 2026-10-06; Nemotron 3.5 Super VL at 0.62 since 2026-10-19), no swap | on a box that cannot hold both they take turns: about 60 s a warm swap, about 10 min cold | GB10 orchestrator status, read 2026-10-12; lab orchestrator notes |
| Other models the lab holds on the S3 roles | measured: seven arms (Gemma 4 31B on the L4s with and without reasoning; on a desktop GPU host's `ollama`: Gemma 4 31B q8, GPT-OSS 120B, Llama 3.3 70B, Nemotron 3.5 Lightning). Llama 70B and Lightning on a desktop GPU host add nothing over the bound arms; Llama 70B wrote 14 harmful change plans of 30 | the GB10 is needed for one role of six; the lab's four L4s with a 31B model cover five; the second host offers an alternate for the sixth. GPT-OSS 120B and Llama 70B under vLLM on the GB10 not measured (they would evict the deliberate engine) | spike S3 round 2, 2026-10-14/15; a desktop GPU host's thinking arm R4–R6 completed 2026-10-20 after two refused-connection losses: 20 of 29, 19 of 30 and 24 of 30 with one harmful plan at 75 s a plan; nothing rebinds |
| A successor model in the deliberate slot | measured: Nemotron 3.5 Super VL 120B-A12B (released 2026-10-15) loaded in the incumbent's slot on the lab GB10 at the same share and window, five arms: thinking on, at medium effort, and off, beside the incumbent re-run the same day. On the one role bound to the slot it trails the incumbent 26 to 28 (not significant); R1–R3 tie; with thinking off it falls to 9; at full thinking a quarter of its long calls hit the 900 s timeout | a newer model of the same size is not a step up for this work; its reasoning setting is the lever: the same weights move from 9 to 26 on trace-to-cause and 9 to 23 on conflict resolution between thinking off and medium effort (lesson 26). The incumbent's two runs nine days apart differ by two items per role, which is the spike's noise | the lab's GB10 bake-off, 2026-10-16 (pre-registered, lab-only); replies under `spikes/s3/results/scored/bake-*`; spike S3 round 3 |
| Size of estate scanned and rehearsed in a twin at once | not measured | — | M3 |
| Many estates, many investigators at once | not measured; one queue today | the case for a GPU server or an AI factory, to be extrapolated from measured load once the models and the harness are settled | not measured |

Consequences that are already decisions:

- **No shared services.** No Supabase, neo4j or RAGFlow. State is files and
  SQLite so the whole thing moves on a disk.
- **One inference seam.** A base URL, a key, and a tier-to-model map in config.
  Nothing else knows where a model lives.
- **Every image is multi-arch and pinned by digest.** A bundle script saves
  the images, repositories, Python dependencies, models and reference
  documents for an offline load, and carries a local registry so digest
  references resolve with no network.
- **Numbers are scored on the build being shown.** A rebuild is scored by the
  evaluation kit at the time it is shown; lab numbers are labelled as lab
  numbers.
- **No assets from a CDN.** Fonts, scripts and styles are vendored.
- **Model-agnostic.** A model is a line in the tier map; the kit may not
  carry the lab's models, and says which it was scored with.

---

## Targets

**The mini-agency** — about twelve containers in a deliberately mixed posture:
legacy bases with old OpenSSL and OpenSSH defaults; typical web, identity,
database, messaging and Java services with RSA or ECDSA certificates; an
internal certificate authority; and endpoints already negotiating hybrid
ML-KEM. Configs live in the repository, which is what lets a wire finding be
traced to a line. Every weakness is planted, so the answer key is exact.

**The answer key** is written to make the score honest, not high. Each item
has a class and names the verifier that could confirm its fix:

| Class | Meaning | In the score |
|---|---|---|
| `present` | Planted and within reach of the evidence | counted |
| `decoy` | Looks like a finding and is not: a certificate in an image that is never served, a weak cipher in a commented line, crypto in a test fixture | flagging it is a false positive |
| `out-of-reach` | Real, and outside what the workbench can see: client-side posture without capture, a mutual-TLS-only listener, a UDP protocol, a statically linked binary, at-rest encryption | counted in the denominator, reported as a known miss |
| `supplied` | Typed in, not discovered: mission function, data lifetime, high-value status, blocker states without a dated source | excluded from coverage, labelled in the UI |

Mixed entries are keyed as mixed: a hybrid ML-KEM endpoint with a classical
certificate; a current OpenSSH with a post-quantum key exchange and classical
host keys. The key for each milestone is committed, and its hash recorded on
the ledger, before the scout for that milestone is written. A **held-out
variant** of the agency — ports moved, configs renamed, plants changed — is
scored once, at the dress rehearsal, and never tuned against.

**Real federal source code**, pinned to commits and analyzed read-only:
`CMSgov/dpc-app` (Java, with Ruby and Go beside it),
`CMSgov/bluebutton-web-server` (Python) and `18F/identity-idp` (login.gov,
Ruby). The Ruby repository is the
case where CBOMkit is blind, and is labelled so: its candidates come from the
rule pack, not from a model reading unaided. Findings are presented as what an
inventory reveals, never as vulnerability disclosures.

**Baselines** — two, always shown beside the workbench, by layer:

1. **CBOMkit alone** on the same targets. It is the first stage of the
   workbench.
2. **The scanners alone** — the raw union of CBOMkit, cbomkit-theia,
   testssl.sh, ssh-audit and the rule pack, with no harness. The workbench's
   own contribution is the delta over this one.

---

## Measured and known facts

Each carries its provenance. Add to this list; do not put a number in the UI or
a note that is not on it.

| Fact | Provenance |
|---|---|
| The lab GB10 shows 121 GB total and 8 GB available with its normal residents loaded | measured, `free -g` on the GB10, 2026-10-01 |
| Nemotron 3 Super NVFP4 weights are 62 GB; Lightning NVFP4 weights are 25 GB. Nemotron 3.5 Super VL NVFP4, which took the slot on 2026-10-19, is 75.1 GB on disk against the incumbent's 80.4 GB and fits the same 0.62 share | lab orchestrator `models.yaml`; the lab's GB10 bake-off report, 2026-10-16 (on-disk sizes, a different measure from the loaded-weights row) |
| A warm model restart on the GB10 takes about 60 s; a cold start about 10 min | lab orchestrator notes; re-measure at class settings |
| CBOMkit scans Java, Python and Go source and container images, outputs CycloneDX 1.6, and does not do network scanning, reachability, prioritization or remediation | PQCA architecture write-up, 2026 |
| OMB M-26-15 is dated 2026-06-24 and requires each agency's PQC Migration Plan within 120 days — 2026-10-22. It does not apply to national security systems | OMB M-26-15, sections 1 and 3.B, read 2026-10-03; date computed |
| M-26-15 scope for prioritized migration: high-impact systems, High Value Assets, systems with highly sensitive data, and systems an agency determines are particularly vulnerable. Key establishment for these in Phase 3 (2028–2030); digital signatures in Phase 4 (2031); remaining systems by 2035. Agencies are to mitigate "as much quantum risk as feasible by December 31, 2030" | OMB M-26-15, sections 3.A, 3.C.2 and 3.D |
| M-26-15 names the three evidence layers and the CBOM: software composition analysis, static and dynamic testing "to find cryptographic functions in code, and network scanners to detect protocols and cipher suites", populating "a central Cryptographic Bill of Materials" | OMB M-26-15, Appendix A, section 6 |
| M-26-15 on enforcement: "To avoid downgrade attacks, ensure that devices can be configured to use only acceptable algorithms." It also requires TLS 1.3 support no later than 2030-01-02, and calls a hybrid architecture "an intricate and resource-intensive stopgap" to be evaluated for its tradeoffs | OMB M-26-15, Appendix A, sections 3, 4 and 5 |
| Executive Order 14412 (2026-06-22): "transition all HVAs and high impact systems to use PQC for key establishment by December 31, 2030" and "for digital signatures by December 31, 2031". National security systems are excluded. CISA and NIST are to publish the minimum elements of a cryptographic bill of materials within 270 days — 2027-03-19 | Executive Order 14412, White House page fetched 2026-10-03, quoted through a summarizing tool — check the quotations against the page before publishing; the 270-day date computed |
| CNSA 2.0: new national security system acquisitions compliant by 2027-01-01 | secondary summaries of the NSA CNSA 2.0 FAQ, which agree; NSA's site refused the primary on 2026-10-05 and 2026-10-20 (HTTP 403), so it was not read first-hand; `policy/packs/cnsa-2.0.yaml` carries it `verified: false` |
| M-26-15 phases: 1 strategy, planning and discovery 2026–2027; 2 pilots and early migration 2027–2028; 3 prioritized migration of key establishment 2028–2030; 4 signature migration 2031; 5 full migration 2035. TLS 1.3 support no later than 2030-01-02 | OMB M-26-15 §3.D and §4, read first-hand 2026-10-03 |
| Models the lab holds beyond the three bound tiers: Gemma 4 31B served from the xr7620's L4s outside the gateway's lanes; GPT-OSS 120B (MXFP4) and Llama 3.3 70B (NVFP4) as swap candidates in the lab GB10's orchestrator; `ollama` on a desktop GPU host serving gpt-oss:120b at MXFP4 and a 70B at a 65536-token context | owner's statement 2026-10-07 (Gemma); lab orchestrator `models.yaml`, read 2026-10-08, for the GB10 entries and its comments on a desktop GPU host |
| The xr7620 Docker default address pools are exhausted; new bridges need an explicit subnet | platform backlog item 42 |
| The lab's fast tier runs on the L4 fleet at 113.8 tok/s; the same model on the GB10 measured 56.8 tok/s | lab orchestrator `models.yaml`, notes of 2026-08-11 and 2026-08-12 |
| On the lab GB10 the 120B is the sole resident, at a memory fraction of 0.85 and a 131072-token context | lab orchestrator `models.yaml`, commit `a53ae6d` |
| On unified memory, page cache from weight reads counts against what CUDA can allocate: 6.7 GiB CUDA-free while Linux showed 118 GB available | lab orchestrator `orchestrator.py`, measured 2026-08-09 |
| The two engines' weights alone total 87 GB (62 + 25), before any KV cache or workload | computed from the weights row above |
| `centos:6` and `debian:jessie` publish no arm64 image; `ubuntu:14.04`, `ubuntu:16.04`, `centos:7` and `debian:stretch` do, as do the testssl.sh, ssh-audit, Zeek, cbomkit and cbomkit-theia images | `docker buildx imagetools inspect`, 2026-10-03 |
| CBOMkit's source scanners read Java, Python and Go; not Ruby | sonar-cryptography README, "Supported languages", read 2026-10-03 |
| `18F/identity-idp` is Ruby; `CMSgov/bluebutton-web-server` is Python; `CMSgov/dpc-app` holds 594 Java, 601 Ruby and 13 Go files | GitHub languages API and `git ls-files`, 2026-10-03, dpc-app at `5f65ca2` |
| `identity-idp` references `OpenSSL::PKey` in 9 files, JWT, JWE or JWK in 10, and digests or HMAC in 27, under `app/`, `lib/` and `config/`. `dpc-app` references BouncyCastle in 16 files. `beneficiary-fhir-data` has two JCA call sites and was not chosen | `git grep` counts of files, 2026-10-03, at `62cf387`, `5f65ca2` and `79dcbb8`; counts of matches, not of confirmed findings |
| Targeted scan time per endpoint on the M0 slice, all of a run's jobs running at once. TLS, testssl.sh 3.2.4 with `-S -f`: portal (classical, TLS 1.2 and 1.3) 39.8–46.0 s; api (hybrid, TLS 1.3 only) 26.8–34.4 s. SSH, ssh-audit 3.9.0: sftp-legacy 1.9–2.3 s; bastion 2.9–3.3 s. Image, cbomkit-theia 1.1.2 with its default plugins: 71–96 s per image, almost all of it the secrets plugin. With images replayed, a run's wall time is the slowest TLS scan. The time is the scanner's own: lifting the target's CPU limit from 0.5 to 2 did not shorten a TLS scan | measured 2026-10-03 on the xr7620 (x86_64); runner job durations from the `scan.completed` events of six native M0 runs (wire) and one (images); the arm64 run under emulation excluded |
| With testssl.sh's `-E` added to the TLS profile, so that RSA key transport is seen: portal 59.9 s, api 38.5 s, against 42.8 s and 29.2 s for the same listeners an hour earlier without it. With images replayed, a run's wall time is the slower of the two, 60.1 s | measured 2026-10-05 on the xr7620 (x86_64), scan runs `01M46T91V6KZ6ZAX3HEXBPAP6J` (with) and `01M46RRF5FFA9WYNXFYM6SARKC` (without), one run each |
| With no key-exchange, protocol or cipher line configured: nginx 1.28 on OpenSSL 3.5 accepts X25519MLKEM768 beside seven classical groups, TLS 1.2, and RSA key transport; PostgreSQL 18 on the same OpenSSL accepts X25519 and P-256 only, with RSA key transport and 2048-bit DHE; OpenSSH 10.0 offers mlkem768x25519-sha256 first. RabbitMQ 4 on Erlang/OTP 27 and Kafka 4.1 on OpenJDK 21 list no ML-KEM group | measured 2026-10-05 on the xr7620 (x86_64), spike S3's lab, one group per handshake; `spikes/s3/observations/r6-e-before.txt`, `r6-n-before.txt`, `r6-p-runtime.txt`, `r6-r-runtime.txt`; ssh-audit 3.9.0 |
| Spike S3's fast and thinking arms were served from the lab GB10 (the gateway's `lab/flash` and `lab/reason-fast` lanes → Lightning NVFP4 at `:8013`, co-resident with the 120B), not the L4 fleet: the gateway moved the lane on 2026-10-06 and the spike's config label was not updated. Every S3 latency is therefore a GB10 number | gateway `conf/config.yaml` and dmz commit of 2026-10-06, read 2026-10-12; S3 result files carry the stale label |
| Spike S3 round 2 (2026-10-14/15): seven more arms on the same 216 items and floors. Gemma 4 31B FP8 on the xr7620's four L4s: call-site reads 29 of 30 with reasoning (13.6 s median), classification 30 of 30 (1.1 s), change plans 27 of 30 with no harmful plan (3.5 s); conflict resolution 21 of 29 with reasoning, the best of ten arms, under the floor of 24. GPT-OSS 120B on a desktop GPU host: trace to cause 26 of 30 with 4 harmful. No arm reaches the normalization floor. Llama 3.3 70B on a desktop GPU host: 9 of 30 change plans, 14 harmful | `spikes/s3/results/scored/<arm>/`, `report.json`; lanes and hosts from the gateway's configuration read 2026-10-14 |
| Spike S3, 216 labeled items, three calls per item: on the fast tier alone no role reaches its floor; with thinking on, call-site reads 28 of 30 and classification 30 of 30; the larger model traces a wire finding to its configuration line in 28 of 30 against 9, and has 24 of 30 change plans verified on the wire against 14; conflict resolution between layers reaches 13 of 29 for either model. At temperature 0 the larger model gave different replies to the same item in 57 of 178; 32 of 119 distinct change plans across the arms took the service down | measured 2026-10-07 to 2026-10-08 through the lab gateway, fast on the L4 fleet, deliberate on the lab GB10 as sole resident; `spikes/s3/results/scored/report.json` |
| The thinking arm's median latency was 84 s on call-site reads against 1.7 s for the same engine without reasoning, and it reached the 16000-token cap or the 600 s timeout on 18 of 87 conflict-resolution calls | measured 2026-10-08, same run; lab numbers with two arms sharing one host, not GB10 numbers |
| The lab GB10's reasoning slot changed model on 2026-10-19: `lab/reason` now serves Nemotron 3.5 Super VL 120B-A12B NVFP4 at medium-effort thinking (vLLM 0.32, `:8014`, 0.62 share beside Lightning); Nemotron 3 Super 120B-A12B at full thinking, which spike S3 rounds 1 to 3 measured as `deliberate`, stays on disk as a swap. The one role bound to the slot, trace-to-cause, was re-measured on the live lane on 2026-10-20: 27 of 30, 2 harmful, 12.7 s median, p = .5 against the old engine's 28 (S3 round 4); it stays bound | gateway reply header `x-litellm-model-api-base` read 2026-10-20; the lab's GB10 bake-off report; `workshop/inference.lab.yaml` dated lines |
| The eight-service estate (nine listeners; 40 keyed wire items, 20 keyed image items, 7 decoys across layers), scored: scanners alone wire 38 of 40 with no false positive, image 14 of 20 with both image decoys flagged, no posture; workbench wire 38 of 40, image 20 of 20 with no decoy flagged, posture 9 of 9. The two wire misses are keyed out of reach (a client's offered groups; the partners' client certificates). CBOMkit alone: wire 0, image 14 of 20 | measured 2026-10-19 on the xr7620 (x86_64), run `01M5AS1BSKH8SQN8XN6NCFE1E5`, `eval/score.py` against `agency/answer-key.yaml` sha256 `f07f8b59…`, harness `63475e9` (CBOMs rebuilt at `a3a6de1`) |
| Scanning the eight-service estate, every job at once: 25 runner jobs, 206 s wall. cbomkit-theia 75–136 s per image (798 s summed); the harness's own file reader 1.0–7.6 s per image (27 s summed), 123 findings against theia's 70; the records database through PostgreSQL's TLS upgrade 94 s; plain TLS listeners 37–65 s; SSH 2–3 s | measured 2026-10-19, same run, `scan.completed` events |
| The four M0 slice images build for `linux/arm64`, start, and answer their scans under qemu-user on the xr7620; the slice scores the same against the M0 key as the amd64 build. A smoke test of the images, not a GB10 verification; the scanners ran amd64 | measured 2026-10-03, run `01M40YB9QE8JCJAGAHMWHVZPR3`, qemu-user-static 1:8.2.2+ds-0ubuntu1.18 |
| `docker save` then `docker load` (Docker 29.1.5, containerd image store) restores an image saved by repository and tag under that tag, and an image saved by digest reference (`repo@sha256:…`) only as an untagged image ID: the digest reference no longer resolves, and a runner pinned by digest cannot start the scanner. The bundle needs the local registry it is designed with | measured 2026-10-03 on the xr7620; run `01M40YH61ZS2Z7CAKNR8A7TRKA` records the failed scans |
| ML-DSA-65 ledger checkpoints: OpenSSL 3.5.7 signs in 0.88 ms and verifies in 0.16 ms (`openssl speed`); a checkpoint through the signer's command-line path takes 5–11 ms, median 7 ms, process start included, and 44 ms median round trip with the signer re-verifying a 73-event chain. Signatures made by the OpenSSL command line verify with the `cryptography` library and the reverse. The same image built for arm64 passes the checkpoint tests under qemu-user; timings under emulation are not GB10 numbers and are not given | measured 2026-10-03 on the xr7620 (x86_64), harness image (Debian 13, OpenSSL 3.5.7), run `01M416HVH3A1ZE2MFBNFDY1RR5` and 20 further checkpoints over it |
| Time-to-change on the M0 slice's portal, from ledger timestamps, approval given by script about 0.6 s after the proposal, with the check refusing every classical group (M0A review, F-44): `none` to `enable` — `enabled-not-enforced`, durable — policy to last verdict 63.4 s, approval to last verdict 62.9 s; `enable` to `require` — `enforced`, durable — 63.4 s and 62.9 s; `require` back to `none` — 56.5 s and 55.9 s. Each includes two verdicts (after the apply, and after the service is recreated). Per verdict, the testssl.sh witness takes 21–31 s and each OpenSSL probe about 1 s; an apply or recreate takes about 1.5 s; a checkpoint 7–12 ms. A person approving adds their own wait to the first interval only. The timestamps are the harness's own clock | measured 2026-10-03 on the xr7620 (x86_64), change runs `01M422W8CYQXJ8R5Y4B86HNYX2`, `01M422Y6WP5TNB65NPFFEWNAK4`, `01M423058Q1SSYWQ54JMEG5RGR` |
| cbomkit-theia 1.1.2's 70–96 s per image is its secrets plugin reading a file's contents once for every symlink that points to it: one 800 KB file takes 1.1 s alone, 18.4 s with 50 symlinks, 69.8 s with 200; a bare `alpine:3.22` (304 symlinks to an 809 KB BusyBox) takes 93.7 s; 4 MB of plain files takes 1.6 s. The other plugins take about 1 s each | measured 2026-10-04 on the xr7620 (x86_64), each plugin run alone, synthetic and real images; spike S2 |
| cbomkit-theia's own CBOMs, scored with no normalizer, cover host 7 of 10 and flag the decoy — item for item the projected CBOMkit-alone baseline — when theia's own reference from a certificate to its key is followed; 5 of 10 by component name alone, because theia names a certificate by its subject | measured 2026-10-04, M0 slice, `eval/score_raw_theia.py` |
| Every runner profile — testssl.sh, ssh-audit, cbomkit-theia, the verifier's OpenSSL probes and testssl.sh witness — ran as `linux/arm64` under qemu-user, through an arm64 runner that also applied and recreated the portal with the arm64 Docker CLI; the slice scored as on x86_64 and the change verified `enforced`, durable. Emulated times (TLS 79–108 s, image 633–837 s, time-to-change 127 s) are not GB10 numbers | measured 2026-10-04 on the xr7620, runs `01M43GE2HJY9B6WW4839KRFYWN` and change `01M43HW0BE7JVD5TC4BT8SCFX0` |
| Of the 28 images planned for the mini-agency, the harness, the scanners and the bundle, 26 publish `linux/arm64` at the tag read; `centos:6` and `debian:jessie` do not and stay lab-only, with `centos:7` and `debian:stretch` standing in. The reading is of tags on that day, not of the digests the build pins | `docker buildx imagetools inspect`, 2026-10-05, read twice with the same digests; spike S1, `spikes/s1/results.json`; M0B review F-63 |
| Time-to-change on the slice's portal with a signature on each side of the policy event and of the approval, approval by script about 0.5 s after the proposal: `enable` to `none`, verified and durable, 55.6 s on the ledger's clock and no more than 55.6 s on the signer's. On an estate started from the offline bundle: `none` to `enable` 65.2 s, and back to `none` with the bundle's registry stopped 62.0 s. Starting the slice and the harness from the bundle, with the images already in the host's store: 8.7 s | measured 2026-10-05 on the xr7620 (x86_64), harness at `9e45a6a`; change runs `01M46RCKJZA12PD1REM722YF4F`, `01M46RM79ASE4V8039GC1HXQB0`, `01M46RP7WVRMW1EXNKM4D762P2`; `bundle/load.py` |
| Postgres 18 with `ssl_groups=X25519MLKEM768:X25519` still completes a TLS 1.2 handshake with RSA key transport (`AES256-GCM-SHA384`): key establishment with no group, which a list of accepted groups does not show. The slice's nginx listeners refuse it | measured 2026-10-05 on the xr7620, OpenSSL 3.5 `s_client -tls1_2 -cipher kRSA` against the S2 Postgres target and the slice; M0B review F-62 |
| In TLS 1.3 the server's certificate is encrypted, so passive capture records the key exchange and version of a 1.3 session and no certificate | RFC 8446 §4.4.2 |
| The Structured rung on the eight-service estate: 9 of 9 listeners with a complete dependency chain; 17 service links asserted by `link/service/1` on the runner's binding records; 24 owner-supplied facts for 8 services recorded as supplied links and labelled in the CBOM; the key's 5 supplied items carried and labelled, coverage unchanged at wire 38 of 40, image 20 of 20, posture 9 of 9; 188 of 220 CBOM entries with no verifier (every host entry and the six SSH host-key algorithms), 25 with the paired probes, 7 with the certificate parse; 3 conflicts settled by rule (2 not-served, 1 tool-limit), no model call. The whole scan, images replayed, 92 s wall | measured 2026-10-20 on the xr7620 (x86_64), runs `01M5CTXE9PH6Y2BKPHZPZ9KFK6` (chains, verifiers) and `01M5D07C5R46RQZR1EWECAM7CE` (conflicts, after the rule learned to leave CA files alone), harness `e742741` and after; `score.json`, the rules' events |
| The investigator's loop on the live `lab/reason` lane (Nemotron 3.5 Super VL 120B-A12B NVFP4, medium-effort thinking, GB10 `:8014` per the gateway's header): 9 wire findings traced, one per listener, in 2 to 4 steps and 1,846 to 6,433 tokens each; median 27.6 s, range 23.1 to 89.1 s per trace; 8 agreed with the key's cause, and the ninth said `default` where the key named a commented-out line and the key was wrong. The ninth repeated twice on the same lane: with a 4,000-token reply cap per step the second step thought for 232 s and the third returned no content at all (449 s, no answer); with the cap at 16,000, as spike S3 ran the single call, it answered `default` in 2 steps and 44.9 s | measured 2026-10-20, investigate runs `01M5CV4QP9K8M4EE4EDTKYRV2H` over scan `01M5CTXE9PH6Y2BKPHZPZ9KFK6`, then `01M5D0J6AR6TNT904C40Y3JJ2S` and `01M5D11HXJZ4GDAV7KJBYD1CVX` over `01M5D0DT0FFHY09VQP6QFJVFFG`; `agency/answer-key.yaml` item `records-kex-dh-2048` corrected; lesson 31 |
| The Managed rung on the eight-service estate under OMB M-26-15 (pack read first-hand, every quote checked against the memo's text): 7 of 8 services prioritized (3 by high impact, HVA and data lifetime; 4 by lifetime alone); 14 items open and 2 met — 6 in key establishment by 2030-12-31, 6 in signatures in 2031, 2 by 2035; 2 TLS listeners without TLS 1.3 against 2030-01-02; 7 items blocked on their supplier (OpenSSH 6.6, Java 8, RabbitMQ 4 on Erlang/OTP 27, and OpenSSH 10's host keys); no item in a validated module — 7 with one available for the library and not in use, 7 with none. Score unchanged: wire 38 of 40, image 20 of 20, posture 9 of 9, supplied 5 of 5 | measured 2026-10-20 on the xr7620 (x86_64), scan run `01M5DFXYNNG08S8ADTDF48WYFE`; capability snapshot `policy/snapshots/capabilities-2026-10-20.json` (each image's runtime, no network); CMVP snapshot `policy/snapshots/cmvp-2026-10-20.json` |
| Active CMVP certificates matching OpenSSL, Java, Erlang or OpenSSH on 2026-10-20: 92; listing ML-KEM among approved algorithms: 1 (certificate 5523, a vendor's build of the OpenSSL FIPS provider); listing ML-DSA: 2. The OpenSSL project's own validated provider (4985) lists neither; no Java, Erlang or OpenSSH module lists either | NIST CMVP search and certificate pages, read 2026-10-20 by `tools/cmvp_snapshot.py`; every page's hash in the snapshot |
| Watch mode on the unchanged estate: a scan with images replayed, the comparison with the previous scan of the same scope, no change recorded and nothing sent to a model, in 100 s of wall time | measured 2026-10-20, run `01M5DG85J78FF3FVG3GDH26SWZ`, xr7620 (x86_64) |
| The first model-drafted change: the records database (PostgreSQL 18), intent require. Gemma 4 31B on four L4s drafted the policy file from the listener's 7 CBOM entries, the investigator's trace and the service's 4 files: 3 of 3 replies usable, about 5 s each (4.8–5.4 s, 3,789–3,831 tokens); the draft sets the hybrid group and a TLS 1.3 minimum. Rehearsed on a copy on the twin network: enforced on all four probes, 33 s. A hand-made copy with the hybrid group alone refused every classical-only TLS 1.3 client and accepted DHE-RSA and RSA key transport over TLS 1.2 | measured 2026-10-21 on the xr7620 (x86_64), change run `01M5FGP0R99EF496M74YYJYNBD`; lesson 36 |
| The first SSH change: the jump host (OpenSSH 10), intent require, rendered by rule into `KexAlgorithms mlkem768x25519-sha256`. Rehearsed on a copy: an ML-KEM-only client agreed a key exchange, a client offering every other key exchange (the NTRU Prime hybrid included) was refused, ssh-audit found only the hybrid offered — enforced, about 3 s | measured 2026-10-21 on the xr7620 (x86_64), change run `01M5FHSAWHMY78JV1EJX1YQA87` |
| The receipts' 49 verdicts on the deployment, each re-derived from its own raw output: 27 enforced, 14 enabled-not-enforced, 1 not landed, 1 inconclusive; 6 re-derive to another status than they claim, and those are the M0B review's deliberate forgeries | computed 2026-10-21 over every change run under the deployment's `var/runs`; lesson 37 |
| The thin code layer: 18F/identity-idp at its pin, a twelve-pattern Ruby rule pack (data), 85 candidate lines; the call-site-read role (Gemma 4 31B FP8 on four L4s, reasoning on, 3 calls each, majority) judged 79 uses and 6 not (a documentation comment, five `rescue` clauses), unanimous on 75; the two candidates that are S3 labelled sites matched their labels; median 16.3 s a call, p90 30.6 s, 255 calls | measured 2026-10-21, scan-code run `01M5FJH69143N17Q6PCF782P8R` |
| Opengrep is LGPL-2.1 and ships a single Linux aarch64 binary. The public `scanoss/open-crypto-rules` set covers C, Go, JavaScript and Rust, not Ruby, and is GPL-3.0 | GitHub releases (v1.30.0) and repository contents at `c5f32b7`, 2026-10-03 |

### Still to verify before relying on it

Which scanners correctly report ML-DSA certificates, STARTTLS and
client-certificate listeners across the full agency (spike S2 covers the
planned cells); the bundle loaded on a second host with the network cut and
an empty image store; the other models the lab holds, on the S3 roles.

---

## Alternatives rejected

| Alternative | Why not |
|---|---|
| Text-diffusion model as the engine | Optimizes read speed, which is not the bottleneck here; weaker quality on terse technical text; immature serving path |
| World-model or other visual demo | Not this project's strength, and it competes on spectacle rather than on evidence |
| Port of an existing harness | The point is a new build with a new problem shape |
| Shared Postgres for state | Breaks the bundle: the record must move on a disk; a ledger file and SQLite are enough and are portable |
| VMs for legacy targets | The twin doubles the estate; containers cost megabytes, VMs cost gigabytes |
| One GB10 as a second target (ADR-0002) | Carried a memory budget, an escalation queue and an engine-swap controller for a box the project no longer has to fit. Withdrawn 2026-10-08; the bundle keeps the one property that mattered, portability (ADR-0004) |
| The UI service holding the Docker socket | The one container with a public address would control the daemon; a runner with no public leg holds it instead |
| CBOMkit alone as the only baseline | It does no network scanning, so the wire-layer delta would measure testssl.sh, not the workbench |
| A model that grades its own fixes | Unverifiable; the wire re-scan is ground truth |
| Scanning any network not built for the purpose | Out of bounds for the author's own use: the mini-agency, and the lab's own DMZ with care, are the only live targets. The kit scans only what its operator lists in a scope file, with the authorization recorded on the ledger |
| Separate builds for the lab, the bundle and the kit | Three things to keep working. One build with two seams — harness placement and estate placement — covers all three |

---

## Claims discipline

This will be shown to people who check.

- Every number on screen is measured live or scored against the answer key,
  on the build being shown, and labelled with the hardware it ran on.
- Anything on screen that is not live says so and carries its ledger
  timestamp.
- Both baselines are always shown next to the workbench's result.
- The receipts list what the verifier cannot see, and which findings have no
  verifier.
- What each step up in models or hardware changes is shown with the
  measurement, the engine and the machine; what has not been measured says
  so. Nothing is oversold, in either direction.
- Coverage is stated by layer: wire, host, code. Firmware and silicon are
  ingested as supplier attestations, and the UI says so.
- The workbench never denies or changes anything without an approval event.
- The owner's lab is shown only to its owner. The public site and the
  exported repository carry no finding, address, name or capture from it.
- This is a personal exploration, not a Dell product or reference architecture.
