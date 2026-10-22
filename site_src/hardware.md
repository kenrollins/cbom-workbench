---
title: Models and hardware
---

# Models and hardware

## What more models and hardware bring

This table is a deliverable, and this page carries the same rows as the
project brief. It is filled by measurement in one lab — the models an x86_64
server's L4 GPUs, a desk-side GB10 and a second GPU host serve, through one
inference seam — and marked *not measured* where the lab has not measured it. "More" means more local capacity: a larger model, a
second engine resident, more GPUs.

| Capability | Measured | What a step up changes | Provenance |
|---|---|---|---|
| Call-site reads, typed classification | the 30B-A3B engine reaches the floor only with reasoning on: 28 and 30 of 30; without it 21 and 25 | reasoning costs latency: a median of 84 s against 1.7 s per read on the same engine. The larger model reached 29 and 30 of 30 at a median of 42 s per read. Round 2: Gemma 4 31B on four L4s reaches 29 with reasoning at 13.6 s and 30 on classification without it at 1.1 s — the same floors, no GB10 | spike S3, 2026-10-08 (both engines on the lab GB10; the result files' `lab-l4-fleet` label is stale, corrected 2026-10-12) and round 2, 2026-10-15 |
| Trace to a configuration line | the 120B-A12B reaches the floor on both its runs: 28 of 30 with 1 harmful (2026-10-08) and 28 with 2 (2026-10-16); the small engine does not | Its successor, Nemotron 3.5 Super VL 120B-A12B in the same slot at medium reasoning effort, reaches it at 26 with 2 harmful (p = .31 against the incumbent): a swap of the slot keeps this role served, two items lower, at about the same latency. GPT-OSS 120B on a desktop GPU host's two RTX 6000 scores 26 but with 4 harmful where 3 are allowed. No mid-size model reaches it, with or without reasoning (Gemma 31B: 18, 22 thinking). With thinking off neither 120B traces: 23 and 9 | spike S3 rounds 1 to 3 |
| Change plan | the 120B: 24 of 30, 1 harmful, 95 s a plan | Gemma 4 31B on four L4s: 27 of 30, no harmful plan, 3.5 s — better and 27× faster than the largest model. Bound to `fast` | spike S3 round 2, 2026-10-15; every plan applied and probed in the lab |
| Conflict resolution between layers | no arm of fifteen reaches the floor of 24 with 2 harmful allowed: Nemotron 3.5 Super VL at medium effort 23 of 29 but with 4 harmful; Gemma 31B with reasoning 21; the Nemotron 3 engines 13 and 14 | a rule's job still; the count is within one of the floor for a 120B at medium effort, and what keeps it out is a definite layer named where the evidence cannot tell | spike S3 rounds 1 to 3 |
| Normalizing a tool's spelling of a name | no arm of fifteen reaches the floor of 28; the best are 27 (both 120B Nemotrons, Gemma 31B, GPT-OSS 120B) | a name table does this exactly; a model is the fallback, shown as unconfirmed | spike S3 rounds 1 and 2 |
| Fast-tier decode speed | 113.8 tok/s on the L4 fleet | 56.8 tok/s for the same model on one GB10 | lab orchestrator `models.yaml`, bake-off 2026-08-11 and note of 2026-08-12 |
| Both engines resident | yes, on the lab GB10 itself: Lightning 30B-A3B at NVFP4 (memory fraction 0.22) beside the 120B-A12B reasoning engine (Nemotron 3 Super at 0.66 from 2026-10-06; Nemotron 3.5 Super VL at 0.62 since 2026-10-19), no swap | on a box that cannot hold both they take turns: about 60 s a warm swap, about 10 min cold | GB10 orchestrator status, read 2026-10-12; lab orchestrator notes |
| Other models the lab holds on the S3 roles | measured: seven arms (Gemma 4 31B on the L4s with and without reasoning; on a desktop GPU host's `ollama`: Gemma 4 31B q8, GPT-OSS 120B, Llama 3.3 70B, Nemotron 3.5 Lightning). Llama 70B and Lightning on a desktop GPU host add nothing over the bound arms; Llama 70B wrote 14 harmful change plans of 30 | the GB10 is needed for one role of six; the lab's four L4s with a 31B model cover five; the second host offers an alternate for the sixth. GPT-OSS 120B and Llama 70B under vLLM on the GB10 not measured (they would evict the deliberate engine) | spike S3 round 2, 2026-10-14/15; a desktop GPU host's thinking arm R4–R6 completed 2026-10-20 after two refused-connection losses: 20 of 29, 19 of 30 and 24 of 30 with one harmful plan at 75 s a plan; nothing rebinds |
| A successor model in the deliberate slot | measured: Nemotron 3.5 Super VL 120B-A12B (released 2026-10-15) loaded in the incumbent's slot on the lab GB10 at the same share and window, five arms: thinking on, at medium effort, and off, beside the incumbent re-run the same day. On the one role bound to the slot it trails the incumbent 26 to 28 (not significant); R1–R3 tie; with thinking off it falls to 9; at full thinking a quarter of its long calls hit the 900 s timeout | a newer model of the same size is not a step up for this work; its reasoning setting is the lever: the same weights move from 9 to 26 on trace-to-cause and 9 to 23 on conflict resolution between thinking off and medium effort (lesson 26). The incumbent's two runs nine days apart differ by two items per role, which is the spike's noise | the lab's GB10 bake-off, 2026-10-16 (pre-registered, lab-only); replies under `spikes/s3/results/scored/bake-*`; spike S3 round 3 |
| Size of estate scanned and rehearsed in a twin at once | not measured | — | M3 |
| Many estates, many investigators at once | not measured; one queue today | the case for a GPU server or an AI factory, to be extrapolated from measured load once the models and the harness are settled | not measured |

Every model timing names the engine, its serving settings and the machine; a
timing without them is not a number here.

## Measured so far

All on the lab's x86_64 server (a Dell XR7620) unless the row says otherwise,
the dates and runs named in the repository's facts table.

| What | Measurement |
|---|---|
| Targeted TLS scan of one listener, every cipher suite enumerated | 60 s (TLS 1.2 and 1.3), 38 s (TLS 1.3 only) |
| Targeted SSH scan | 2 to 3 s |
| Image scan with cbomkit-theia | 71 to 96 s per image, almost all of it the secrets plugin reading one file once per symlink ([lesson 09](lessons/09-time-a-scanner-on-the-bare-base-image.md)) |
| ML-DSA-65 checkpoint through the signer | 5 to 11 ms including process start; 0.88 ms to sign, 0.16 ms to verify in `openssl speed` |
| Time-to-change on one listener, two verdicts included | 55.6 to 65.2 s, of which the enumerating witness is 21 to 31 s per verdict |
| Loading the slice and the harness from the offline bundle | 8.7 s, 611 MB, eight images for amd64 and arm64 |
| arm64, under qemu-user emulation | every slice image, scanner and probe ran and scored as on x86_64; Zeek's packet capture does not run under emulation; emulated times are not reported as anything but emulated |

## The offline bundle

A local registry carrying every image by digest for both architectures, the
registry's own image as a tarball, and a checksum file whose own hash is
carried separately. `docker save` and `docker load` do not preserve digest
references, which is why the registry is there
([lesson 03](lessons/03-digest-references-need-a-registry.md)); the loader
hashes every blob against its name before serving anything
([lesson 15](lessons/15-check-a-bundles-blobs-and-anchor-its-checksums.md)).
Still to be shown: a load on a second host with the cable out and an empty
image store.
