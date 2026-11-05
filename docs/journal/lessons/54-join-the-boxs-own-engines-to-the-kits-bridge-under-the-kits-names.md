---
id: lesson-54-join-the-boxs-own-engines-to-the-kits-bridge-under-the-kits-names
type: lesson
title: "When a box already serves the engines on its loopback, join their containers to the kit's bridge under the kit's names instead of starting them again"
date: 2026-11-04
audience: [engineer]
rung: all
tags: [inference]
one_line: "A harness that reaches its engines by container name on a bridge cannot see a port bound to the host's loopback; `docker network connect --alias` puts the box's own engine containers on the bridge under the names the tier map expects, with the box's tested launch recipe left untouched."
claims:
  - text: "On the demo GB10, whose workshop stack serves Nemotron 3.5 Lightning under vLLM and the Llama Nemotron embed NIM on 127.0.0.1:8000 and :8001, the two containers joined the kit's bridge pqch-kit-inference as pqch-engine-fast and pqch-engine-embed with two connect commands; both names resolved from a container on the bridge and the harness, started from the bundle, reached them without a change to the kit's compose overlay."
    provenance: "measured 2026-11-04 on the demo GB10 (Dell Pro Max GB10, aarch64, Docker 29.6.2); kit/compose.kit.yaml and kit/inference.yaml at commit dc252fb with the base URLs on port 8000"
reuse: [runbook]
---

# When a box already serves the engines on its loopback, join their containers to the kit's bridge under the kit's names instead of starting them again

## The rule

If the machine the kit lands on already runs the inference engines in containers of its own, published
on the host's loopback, do not start the kit's engine containers beside them. Attach the box's containers
to the kit's bridge with `docker network connect --alias <kit name> <bridge> <container>`, point the tier
map at the container's own listening port, and leave the box's launch recipe as it is.

## Why

The kit's UI service runs on a bridge with an explicit subnet and reaches each engine by a name the tier
map gives (`pqch-engine-fast`, `pqch-engine-embed`). A port published on `127.0.0.1` is the host's
loopback, which a container on a bridge cannot reach; `host-gateway` reaches the host's bridge address,
not its loopback. Starting the kit's own engine containers would work but would double the GPU
residency and discard a recipe the box's operators have tuned and tested for that hardware (on the demo
GB10, Lightning under vLLM 0.27.1 with DSpark speculative decoding, flags the kit's launcher does not
carry). A Docker container can belong to several networks; an alias on the second network is a name
only that network resolves. The engine is then one process, reachable by the box's tools on the
loopback and by the kit on the bridge.

Two consequences follow. The tier map names the port the container listens on, not the host's published
port (8000 inside, where the host sees 8001). And the attachment lives on the container: whatever
recreates the container, such as the box's own `up` and `down`, drops it, so the two connect commands
are part of any restart.

## When it applies

A machine with its own container stack for inference that is tested on that hardware: a workshop
image, a shared lab box, a vendor's demonstration unit. It does not apply to a bare host, where
`kit/engines.sh` starts the engines on the bridge directly, nor to engines that run outside Docker,
which need a relay on the bridge or a bind to the bridge's address.

## How to apply it

```sh
docker network create --subnet 172.16.108.0/24 pqch-kit-inference
docker network connect --alias pqch-engine-fast  pqch-kit-inference <llm container>
docker network connect --alias pqch-engine-embed pqch-kit-inference <embed container>
docker run --rm --network pqch-kit-inference <any local image> getent hosts pqch-engine-fast pqch-engine-embed
```

In `kit/inference.yaml`, each tier's `base_url` uses the container's listening port and its served model
id; the roles stay unmeasured on that engine until spike S3's dev set has run against it
([lesson 49](49-measure-an-engine-on-the-box-before-binding-a-role-to-it.md)).
