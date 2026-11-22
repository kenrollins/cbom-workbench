---
id: lesson-06-bind-a-scan-to-what-it-reached
type: lesson
title: "Record which container a scan reached, and join evidence only when it is the one you think it is"
date: 2026-10-04
audience: [architect, engineer]
tags: [cbom, discovery, verification]
rung: structured
one_line: "An address is not an identity: before linking what was seen on the wire to what was found in an image, check that the container at that address runs that image, at the start and the end of the scan."
claims:
  - text: "With a service restarted from another image and the scope file unchanged, the workbench linked nothing, marked both served certificates as not in use, and scored 5 of 10 on the host layer against 7 of 10 for the scanners alone."
    provenance: "measured 2026-10-03, M0 slice, xr7620 (x86_64), run 01M413N38MT1MAAAXKR30YHW2N; M0 review F-31"
  - text: "With each wire scan bound to the container and image it reached, the same situation reports the listener as unbound, joins nothing to it, and scores as the scanners alone do."
    provenance: "measured 2026-10-03, same estate, run 01M422NHBC20T535DTRYM5343E"
  - text: "A verification pointed at a different container than the one a change was applied to returns inconclusive, naming both containers."
    provenance: "measured 2026-10-03, change run 01M4189RVMMBREE31W3RY39WGJ"
reuse: [whitepaper, customer-question]
---

# Record which container a scan reached, and join evidence only when it is the one you think it is

## The rule

Every network scan records the container that held the target address while
it ran and the digest of the image that container runs. Evidence from the
network and evidence from an image are joined only when those agree with what
the inventory believes; when they do not, each is reported on its own and the
disagreement is stated.

## Why

A cryptographic inventory joins layers: *this* certificate, seen in a TLS
handshake at an address, is *that* file in an image. The join is where the
value is — it is the first link in tracing a finding to the thing that must
change. It rests on an assumption: that the service at the address is running
the image that was scanned.

That assumption comes from configuration — a compose file, a deployment
manifest, a scope document — and configuration goes stale the moment anything
is rebuilt, restarted from a different tag, or loaded from a bundle.

When it is stale, the result is not an error. It is a confident wrong answer.
Measured: with one service running a different build than the scope named,
the image scan read the old image, found certificates that matched nothing on
the wire, and the "is it in use?" rule concluded that the *served*
certificates were unused. The inventory was worse than the raw scanner output
it was built from, with no warning.

The same assumption sits under verification. "The change landed" is a
statement about a specific container. A probe that reaches a different one —
another replica, a stale instance, the wrong service at a reused address —
measures something else.

## When it applies

Whenever results from different vantage points are merged about "the same"
service: wire and image, wire and source, scan and re-scan, change and
verification. It applies to estates the tool can inspect through the
container runtime.

Where it cannot — a network someone else operates — the container identity
is unavailable. The binding is then the address and the served certificate's
fingerprint, and the inventory must say that the join is weaker.

## How to apply it

For each scan, look up the container on the target network by address before
and after, and keep both:

```json
"binding": {"address": "172.16.106.10", "container_id": "…",
            "image": "agency/portal:m0", "image_digest": "sha256:…", "stable": true}
```

Then, as a rule whose result is itself recorded:

- image digest equals the one the scope names, and `stable` is true: *bound*
  — join freely;
- anything else: *unbound* — report the wire findings, link nothing, judge
  nothing in that image as unused, and show the reason next to the listener.

A negative conclusion needs more than a positive one. "This certificate is
not served" is asserted only when every listener of the image was scanned,
each is bound, and every certificate they served was found in the image.

For a verification, compare each probe's container with the one the change
was applied to, and return "inconclusive" on a mismatch.

Check on each platform how the runtime reports a container's image: the
comparison here relies on the container's image id being the repository
digest, which holds with Docker's containerd image store and has not been
checked on the classic store.
