---
id: lesson-02-give-an-internal-bridge-no-host-address
type: lesson
title: "Give an isolated Docker network no host address, and test for it"
date: 2026-10-04
audience: [engineer]
tags: [discovery, verification]
rung: all
one_line: "An `internal` Docker bridge has no route out, but the host still sits on it as the gateway; set the gateway mode to isolated, and probe for the host as well as for a route."
claims:
  - text: "From a container on an internal Docker bridge, a connect to the bridge's gateway address on port 22 reached the host's SSH daemon."
    provenance: "measured 2026-10-03, Docker 29.1.5, xr7620 (x86_64); M0 review F-29"
  - text: "With com.docker.network.bridge.gateway_mode_ipv4 set to isolated, the host holds no address on the bridge and the same connect fails with \"Host is unreachable\"; containers on the bridge still reach each other."
    provenance: "measured 2026-10-03, same host"
reuse: [talk, customer-question]
---

# Give an isolated Docker network no host address, and test for it

## The rule

A Docker network meant to hold deliberately weak or untrusted containers is
created `internal` *and* with its IPv4 gateway mode set to `isolated`, and its
isolation test checks that the host holds no address on it.

## Why

`internal: true` removes the route from the bridge to other networks. It does
not remove the host from the bridge. Docker still assigns the bridge's gateway
address to the host's side of it, so every service the host binds to all
interfaces — SSH, a database, another project's published port — is reachable
from every container on that network at the gateway address. Nothing is
routed, so a test that looks for a default route, or tries an outside address,
passes.

Measured on Docker 29.1.5: a container on an internal bridge reached the
host's SSH daemon at the gateway address. An egress probe that checked the
routing table and two off-subnet addresses had passed.

For a test estate built to contain old software, or for scanner containers
aimed at such an estate, that is the opposite of isolation: the weakest
containers have a path to the host.

## When it applies

Any bridge network whose purpose is containment: vulnerable-by-design
targets, malware or fuzzing sandboxes, rehearsal copies of an estate. It needs
Docker 28 or later. It does not apply to a network whose containers must
reach the host on purpose.

## How to apply it

```yaml
# compose.yaml
networks:
  target_net:
    internal: true
    driver_opts:
      com.docker.network.bridge.gateway_mode_ipv4: isolated
    ipam:
      config:
        - subnet: 172.16.106.0/24
```

Check from the host that it holds no address in the subnet, and from a
container that the failure is explicit:

```sh
ip -o -4 addr show | grep -F '172.16.106.' && echo "host is on the bridge"
docker exec CONTAINER wget -q -T 6 -O /dev/null http://172.16.106.1:22/
#   want: "Host is unreachable" — not a timeout, and not a missing tool
```

Write the isolation test so that only an explicit "unreachable" passes. A
timeout, or a container image without a tool that can attempt a connection,
is not evidence. Then point the test at an address that *is* reachable and
confirm it fails.
