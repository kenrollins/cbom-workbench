---
id: lesson-49-measure-an-engine-on-the-box-before-binding-a-role-to-it
type: lesson
title: "Before binding a role to an inference engine on a new machine, check four things the engine decides for itself: that it has a profile for the GPU, the context window it will serve, the share of memory it will take, and the model id it answers to"
date: 2026-11-04
audience: [engineer, architect]
rung: all
tags: [inference, discovery]
one_line: "An engine container chooses its GPU profile, its context window, its memory share and its served model id on its own; on a desk-side box with unified memory each of the four can silently make a role unservable, and only a call through the seam with the role's real request shows it."
claims:
  - text: "Of five NVIDIA NIM containers tried on a DGX Spark (GB10, 128 GB unified memory, driver 580.173.02), two served: the Llama 3.1 8B Instruct and Nemotron Nano 9B v2 builds tagged for DGX Spark. The Nemotron 3 Super 120B-A12B NIM 1.0.0 found 0 compatible profiles; the llama-3.2-nv-embedqa-1b-v2 retrieval NIM matched only its ONNX fp16 profile, whose first embedding request failed inside ONNX Runtime; the TensorRT profiles it lists name compute capabilities 8.6, 8.9, 9.0, 10.0 and 12.0 and were all marked incompatible."
    provenance: "measured 2026-11-04 on the lab GB10 (aarch64, Ubuntu 24.04, Docker 29.2.1, NVIDIA Container Toolkit 1.19.1, CDI); container logs and `list-model-profiles` output"
  - text: "The Llama 3.1 8B DGX Spark NIM served a context window of 8,192 tokens by default; every spike S3 call, which asks for up to 16,000 completion tokens, was refused with HTTP 400 before any inference ran. NIM_MAX_MODEL_LEN=40960 on the Nemotron Nano NIM made the same calls succeed."
    provenance: "measured 2026-11-04; spikes/s3/results/dev/gb10-nim-llama8b/r3.jsonl (18 of 18 calls 400, 34 to 54 ms); dev/gb10-nim-nano9b/r3.jsonl (18 of 18 answered, median 1,862 ms)"
  - text: "A NIM takes 0.7 of the GPU's memory by default and refuses to start when less is free: the Nemotron Nano 9B NIM asked for 85.14 of 121.63 GiB while the 8B NIM held 57 GiB (8.49 GiB of weights and 48.37 GiB of KV cache). NIM_MAX_GPU_MEMORY_UTILIZATION_STARTUP=0.2 let it start beside a second engine."
    provenance: "measured 2026-11-04; the Nano NIM's engine-core error and the 8B NIM's startup log"
  - text: "The Nemotron Nano 9B NIM answers to the model id nvidia/nemotron-nano-9b-v2, not to its image name nvidia-nemotron-nano-9b-v2-dgx-spark; a tier map carrying the image name drew HTTP 404 on 90 of 90 calls."
    provenance: "measured 2026-11-04; /v1/models of the container; spikes/s3/results/scored/gb10-nim-nano9b/r3.jsonl before the correction"
  - text: "Nemotron 3.5 Super VL 120B-A12B NVFP4 served from vLLM's pinned nightly image at a 0.55 memory share loaded 88 safetensor shards in about 10 minutes on the same box, and the open source embedding engine (ollama, mxbai-embed-large) embedded on the GPU at first request."
    provenance: "measured 2026-11-04; container logs; kit/engines.sh"
  - text: "With a JSON schema on the reply, the Nemotron Nano 9B NIM produced no thinking whichever switch asked for it (the template flag or a /think system message): a reply took 32 to 35 completion tokens either way, and the scored arms with and without the flag matched item for item. Without the schema the same request produced 280 to 338 tokens of thinking, placed in the content because the NIM runs no reasoning parser."
    provenance: "measured 2026-11-04; spikes/s3/results/scored/gb10-nim-nano9b and gb10-nim-nano9b-think (R1 16 and 16, R2 23 and 23, R3 27 and 26 of 30); two direct requests to /v1/chat/completions"
  - text: "The same family under vLLM with a reasoning parser (Nemotron 3.5 Lightning 30B-A3B NVFP4, --reasoning-parser nemotron_v3, 0.20 share) thinks under the schema: four classification calls with thinking on each produced about 2,270 completion tokens and a correct typed reply, at a median of 117 s a call while a 120B engine shared the GPU."
    provenance: "measured 2026-11-04; spikes/s3/results/dev/gb10-lightning-vllm/r3.jsonl (4 calls before the session's 600 s limit)"
reuse: [runbook, talk, customer-question]
---

# Before binding a role to an inference engine on a new machine, check four things the engine decides for itself

## The rule

Before a role is bound to an engine on a machine it has not run on, call the engine through the inference
seam with the role's own request and read what comes back. Four things the engine chooses without asking,
and a fifth about how it answers, decide whether the role can run at all: whether the container holds a profile for that GPU; the context
window it serves; the share of the machine's memory it takes at start; and the model id it answers to. Only
the role's real request exercises all four. A health check or a one-line chat shows none of them.

## Why

A packaged engine (a NIM, a vLLM image, an ollama container) ships for many machines and chooses at start
what to do on this one. Each choice is sound for a dedicated data-centre GPU and wrong, or merely different,
on a desk-side box whose 128 GB is one pool shared by the CPU, every engine and every container.

| What the engine decides | Default behaviour | What it did on the DGX Spark, 2026-11-04 |
|---|---|---|
| **GPU profile** | The container carries built engines per GPU family and picks one that matches; none matching is a start failure | The Nemotron 3 Super 120B NIM found no profile and exited. The retrieval NIM matched only an ONNX fp16 profile (every TensorRT profile, compute capability 8.6 to 12.0, marked incompatible) and that profile failed on its first request inside ONNX Runtime. The two images tagged `-dgx-spark` (Llama 3.1 8B, Nemotron Nano 9B v2) matched and served |
| **Context window** | The profile's own maximum sequence length, not the model's | The 8B NIM served 8,192 tokens; the harness's roles ask for up to 16,000 completion tokens (a reasoning model thinks in the budget), so every call was refused with 400 in under 60 ms. `NIM_MAX_MODEL_LEN=40960` removes the limit |
| **Memory share** | 0.7 of the GPU at start (vLLM-based NIMs), refused if less is free | The Nano NIM wanted 85.14 GiB with 55 free and exited. On unified memory the share counts against every other tenant: `NIM_MAX_GPU_MEMORY_UTILIZATION_STARTUP=0.2` for the small engine, 0.55 for the 120B under vLLM, and the harness, the estate and the page in what is left |
| **Thinking under structured output** | A reasoning model thinks before the typed reply only when a reasoning parser separates the two; a NIM without one, asked for a JSON schema, is held to the schema from the first token | The Nano NIM's "thinking" arm matched its plain arm item for item (32 to 35 completion tokens a reply); the same request without the schema thought for 280 to 338 tokens, in the content. The roles that need thinking (call-site read, classification: spike S3) cannot get it from this container; under vLLM with `--reasoning-parser` the same model family can |
| **Model id** | The id baked into the profile, visible at `/v1/models` | `nvidia/nemotron-nano-9b-v2`, while the image is `nvidia-nemotron-nano-9b-v2-dgx-spark`; a tier map with the image's name drew 404 on every call |

None of these is a defect of the engine. Each is a choice an engine makes for a machine it cannot see
whole, and the seam is the only place the four meet the role's request.

## When it applies

Whenever an engine moves to a machine or an image it was not measured on: a new box, a new container
tag, a profile change, a second engine placed beside it. It applies with any OpenAI-compatible engine; the
variable names above are NVIDIA NIM's, vLLM takes `--max-model-len` and `--gpu-memory-utilization`,
ollama takes neither and sizes itself.

It does not replace the measurement that binds the role (spike S3's floors): a call that comes back is
necessary, not sufficient. And it says nothing about which engine is faster or better; it says only
whether the role's request can be served at all.

## How to apply it

1. `list-model-profiles` (a NIM) or the engine's start log: is there a profile for this GPU, and which
   backend is it?
2. `GET /v1/models`: the served `id` and `max_model_len`. Put that id, not the image name, in the tier
   map; make the window larger than the role's prompt plus its completion budget.
3. Set the memory share before the engine starts, from the budget of everything that will be resident,
   and check `free -g` and the engine's "available KV cache" line after it loads.
4. Run the role's own request through the seam (`spikes/s3/run.py --set dev` on six items) and read the
   recorded error field, not the HTTP status alone.
5. For a role that needs reasoning, compare completion tokens with and without the thinking switch under
   the role's schema; equal counts mean the switch did nothing, and the arm must not be labelled "thinking".

The kit's `kit/engines.sh` carries these settings per tier in `kit/engines.env`, so the next box starts
from what this one measured.
