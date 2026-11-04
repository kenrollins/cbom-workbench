---
id: note-18-what-the-workbench-is-built-from-and-what-an-enterprise-would-use
type: note
title: "What is the workbench built from, why each part, and what would an enterprise run in its place?"
date: 2026-11-04
audience: [leader, architect, engineer]
rung: all
tags: [cbom, discovery, verification, inference, policy]
one_line: "Every part of the workbench is a standard or an open source tool chosen because it can be checked; each has an enterprise equivalent that changes the scale, the support and the audit story, not the method."
claims:
  - text: "The workbench's discovery runs testssl.sh, ssh-audit and cbomkit-theia as containers pinned by digest, Zeek for passive capture, and OpenSSL 3.5 for the verifier's probes; its CBOM is CycloneDX 1.6; its ledger is append-only JSONL with ML-DSA-65-signed checkpoints; its inference seam speaks the OpenAI chat and embeddings API to any engine; its service is FastAPI, server-rendered, with vendored assets."
    provenance: "cited: this repository (src/pqch/runner/profiles.yaml, src/pqch/cbom, src/pqch/ledger, src/pqch/inference, Dockerfile)"
  - text: "On one DGX Spark the whole of it ran beside three engines: Nemotron 3.5 Lightning 30B-A3B under vLLM (fast tier; a Nemotron Nano 9B v2 NIM served the slot first and reached no role's floor), Nemotron 3.5 Super VL 120B-A12B under vLLM (deliberate tier) and ollama with mxbai-embed-large (embed tier), loaded from the offline bundle in 8 s and scanning the mini-agency in under five minutes."
    provenance: "measured 2026-11-04 on the lab GB10 (aarch64); bundle/load.py output; run 01M6J326QNTAFJW3CQNVR2JFPJ"
reuse: [whitepaper, talk, customer-question]
---

# What is the workbench built from, why each part, and what would an enterprise run in its place?

## The answer

The workbench is assembled from standards and open source tools, one per job, each chosen because its
output can be checked by something other than itself: a scanner's finding by a second scanner and a
probe, a model's answer by a rule or a re-scan, a ledger entry by a hash chain and a signature. Every part
has an enterprise equivalent. Swapping one in changes scale, support and who signs the audit, not the
method: the same CBOM, the same ledger, the same paired proof on the wire.

## The concept

A cryptography bill of materials (CBOM) is an inventory of the algorithms, keys, certificates and
protocols an estate uses, with where each was found. Building one takes discovery (reading the wire, the
host and the code), a record (where findings go and how they are kept honest), a document (the CBOM a
consumer reads), judgement (which findings matter, by policy), change (what to do and in what order) and
proof (that a change worked). The workbench has one component per step. The table below names each, the
reason it was chosen, and what an enterprise would run instead.

## The parts

| Step | The workbench runs | Why this one | Enterprise equivalent |
|---|---|---|---|
| Wire discovery | testssl.sh and ssh-audit, as containers pinned by digest, one job per listener | Both read what a server offers and negotiates, not what a file says; both are reproducible by anyone from the same digest | A commercial PQC discovery platform's network sensor; a vulnerability scanner's TLS module. Same evidence, licensed, with fleet management |
| Image and host discovery | cbomkit-theia (IBM's CBOM generator for images) and the workbench's own file reader for keys, certificates and keystores | theia emits CycloneDX directly, so its CBOM can be scored beside the workbench's; the file reader covers what theia does not (keystores, retired keys) | Endpoint agents from the same platforms; software composition analysis with crypto rules |
| Passive capture | Zeek on a mirror port, with a script that logs each TLS handshake's offered and selected groups | Shows what clients offer, which no server scan can; open, scriptable, standard logs | Network detection and response platforms; a vendor sensor appliance on the same mirror |
| Code discovery | A rule pack per language, then a model judging each flagged call site | Rules find candidates cheaply; a model reads context a rule cannot; the model's verdict is measured against a labelled set | Static analysis with crypto rule sets; the same model role on a hosted engine |
| The record | An append-only JSONL ledger per run, hash-chained, with checkpoints signed by ML-DSA-65 (FIPS 204) through OpenSSL 3.5 | Files, not a service: it moves on a disk and is verified by anyone with the public key; the post-quantum signature is the project's own medicine | An immutable audit store (write-once object storage, a transparency log), an HSM-backed signer, a SIEM for the events |
| The document | CycloneDX 1.6 CBOM, a projection rebuilt from the ledger | The one standard consumers read; a projection means the CBOM is never edited, only rebuilt | The same standard; the consumer is the enterprise's asset platform or GRC system |
| Judgement | Policy packs as data (OMB M-26-15, CNSA 2.0) checked against the memo's text; the quantum-vulnerability rule; a model only for interpretation | A rule that can be read beside its source is auditable; a model's role is bound only by measurement (spike S3) | A GRC platform's policy engine; the discovery platform's own baseline policies |
| Change | Renderers per service for what a setting can move, change packages for what it cannot; a model drafts, a rehearsal on a copy and a client matrix check | Nothing applies without an approval event; a draft is a proposal until the verifier says otherwise | Configuration management (Ansible, a PKI platform's automation), change tickets, the same rehearsal in a staging environment |
| Proof | Paired probes: new-only succeeds and old-only is refused; a certificate parse; a compatibility run | "Enabled" is not "enforced"; only a refusal proves a removal | Continuous control monitoring; the same probes, scheduled |
| Inference | One seam speaking the OpenAI chat and embeddings API; tiers `fast`, `deliberate`, `embed` bound to engines in a config file; engines are vLLM, NIM or ollama containers | Never a model name in code; a role moves to an engine only by measurement against a floor written first; on the GB10 the two vLLM engines earned the roles and the NIM tried did not (lesson 49) | NVIDIA NIM under NVIDIA AI Enterprise, a hosted API behind a gateway, or the same containers under Kubernetes; the seam is unchanged |
| Service and page | FastAPI, server-rendered, vendored assets, port 8080, one container without the Docker socket | Readable by a person and by a model; no CDN, so the bundle works with the cable out | The same behind the enterprise's single sign-on; or the pages become a plugin of the asset platform |
| Packaging | Docker Compose; multi-arch images by digest; an offline bundle with its own read-only registry; state in files | Moves on a disk; starts on x86_64 or aarch64; every image arrives unchanged or not at all | Kubernetes with a private registry (Harbor, Artifactory), GitOps for the config |
| The test estate | The mini-agency: eight services on an internal bridge with planted weaknesses and an answer key with decoys | The method is scored, not trusted: wire, host and posture counts against a key nobody tuned to | A cyber range; a staging copy of a real estate with a written answer key |

## The mechanism, on one box

On 2026-11-04 the whole table ran on one DGX Spark (GB10, aarch64, 128 GB unified memory): the bundle
loaded in 8 s, the mini-agency came up, a live scan finished in under five minutes with the same wire
score as the lab's x86_64 run (35 of 40, no false positives), and three engines sat beside it: Nemotron 3.5
Lightning 30B-A3B under vLLM for the fast tier (a Nemotron Nano 9B v2 NIM held the slot first and reached no
role's floor), Nemotron 3.5 Super VL 120B-A12B under vLLM for the deliberate tier and ollama's
mxbai-embed-large for the embed tier. Which engine serves which role is decided by the spike's
floors on that box, not by the table above; lesson 49 records what an engine decides for itself before
any role can reach it.

## What follows

An agency choosing between this method and a commercial platform is not choosing a different method.
The discovery evidence, the CBOM standard and the paired proof are the same; what the platform adds is
scale (thousands of hosts, scheduled), support, and a vendor's name on the audit. What the workbench adds
is that every step can be checked by a reader with the repository: the rule beside its source, the
model's score beside its floor, the ledger beside its signature. The two are complementary: the
workbench's CBOM can be uploaded to a platform and judged there (lesson 48), and a platform's CBOM can be
imported here and scored against the answer key.

## Scope

This note names the parts as they stand in the repository on 2026-11-04 and what ran on one machine that
day. It does not compare the commercial platforms with each other, and it names no measurement of one.
Enterprise equivalents are categories with examples, not recommendations.

## References

- This repository: `src/pqch/runner/profiles.yaml` (the scanners by digest), `src/pqch/ledger` (the hash chain and the signed checkpoints), `src/pqch/cbom` (the CycloneDX 1.6 projection), `src/pqch/inference` (the seam), `kit/` (one box).
- CycloneDX 1.6 specification, cryptographic assets: the document format.
- FIPS 204 (ML-DSA): the checkpoint signature.
- Lesson 48: writing CBOM facts where a consumer reads them. Lesson 49: what an engine decides for itself.
