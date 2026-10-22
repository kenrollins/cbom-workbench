---
id: lesson-24-a-hardware-label-is-a-claim
type: lesson
title: "A hardware label in a config is a claim; record what served the call"
date: 2026-10-12
audience: [engineer, architect]
rung: all
tags: [inference, provenance, measurement]
one_line: "When model calls go through a gateway that can move a lane between machines, the hardware label in the caller's config is a claim that goes stale silently; record the upstream the gateway names on each reply beside the label, and check the label against it before publishing a timing."
reuse: [runbook, whitepaper]
---

# A hardware label in a config is a claim; record what served the call

## The rule

Every timing taken through a gateway carries two facts: the hardware label
the caller's configuration asserts, and the upstream the gateway actually
routed to. Record both on every call. Before a timing is published with a
machine's name on it, the label is checked against the upstream; where they
disagree, the upstream wins and the label is corrected.

## Why

A gateway exists so that callers do not know where a model lives — and so
that the operator can move it. The caller's configuration names a machine
because a number without one is worthless; but nothing updates that name
when the operator rebinds the lane. In this project a bake-off's fast arm was
labelled as running on a four-GPU fleet; the lane had been moved to a
desk-side box the day before the bake-off ran. Every latency in the result
was a number from the wrong machine until the live reply's headers were read,
four days later. The accuracies were unaffected; the hardware column of a
table that exists to say what hardware brings was wrong.

Most gateways name the upstream on each reply. LiteLLM sends
`x-litellm-model-api-base`; others send their own. A caller that records it
has provenance per call, not per configuration file.

## When it applies

Any measurement of latency, throughput or cost taken through an inference
gateway, a load balancer or a model router — anything that can choose or
change the backend without the caller's configuration changing.

## How to apply it

- The inference seam records the upstream named in the reply's header as
  `served_by` on every completion and on the ledger actor of every event a
  model contributed to, beside the config's `hardware` label.
- A result file for a measurement carries both; a report reads `served_by`
  and treats `hardware` as the claim it is.
- A deployment's configuration says what each label means on what date, and
  a lane move in the gateway is a dated line in that file.
- Where the gateway sends no such header, the measurement names the gateway
  as the hardware and says the machine behind it is not recorded.
