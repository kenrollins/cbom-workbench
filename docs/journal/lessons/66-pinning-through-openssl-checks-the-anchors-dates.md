---
id: lesson-66-pinning-through-openssl-checks-the-anchors-dates
type: lesson
title: "Pinning a self-signed certificate by making it the only trust anchor still checks its dates; an expired management-controller certificate fails the pin"
date: 2026-11-06
audience: [engineer]
rung: all
tags: [verification, discovery]
one_line: "Loading the certificate a server served as the context's only trust anchor (with partial-chain verification for a leaf a CA issued) is a sound pin in Python's ssl module and anything built on OpenSSL, but OpenSSL still checks the anchor's validity dates, so a long-expired self-signed controller certificate is refused; renew it before turning the pin on, or the read stops before it starts."
claims:
  - text: "In Python 3.12's ssl module over OpenSSL, a client context whose only trust anchor is a self-signed certificate that expired the day before refuses the handshake with that server; the same certificate within its dates is accepted."
    provenance: "measured 2026-11-06 on x86_64, tests/test_redfish_trust.py, a local TLS server with generated P-256 certificates"
  - text: "ssl.VERIFY_X509_PARTIAL_CHAIN lets a certificate that is not self-signed act as a trust anchor."
    provenance: "cited: Python documentation, ssl.VERIFY_X509_PARTIAL_CHAIN (OpenSSL X509_V_FLAG_PARTIAL_CHAIN)"
reuse: [runbook]
---

# Pinning through OpenSSL checks the anchor's dates

## The rule

Before pinning a management controller's certificate (or holding a session to the certificate just observed), check that
the certificate is within its validity dates. If it is not, issue the controller a new certificate
first. Otherwise the pinned read fails before any credential is sent.

## Why

A management controller (iDRAC, iLO, a BMC) usually serves a self-signed certificate. No CA
vouches for it, so the usual choices are no verification or a pin: the fingerprint seen once,
required ever after.

With Python's `ssl` module and anything else on OpenSSL, the simplest sound pin is a context that
trusts only the served certificate:

- load the served certificate as the context's only trust anchor
- turn hostname checking off (controllers are reached by address)
- for a leaf a CA issued, add partial-chain verification so the leaf alone can anchor

OpenSSL then checks the chain it builds, and that check includes the anchor's validity dates. A
baseboard management controller (BMC, the service processor that manages a server out of band;
Dell's is the iDRAC) ships with a self-signed certificate issued at first boot with a fixed lifetime,
and in our experience it is rarely renewed, so an expired anchor is the common case rather than the
exception (the lab's one controller; not a survey). The failure is correct: an expired certificate is not trustworthy by its own terms.
But it surprises an operator who expected the pin to compare fingerprints only.

## Where the measurement stops

Measured with a self-signed P-256 certificate carrying the CA bit (`BasicConstraints: CA`), as the
test generates it. Not measured: a CA-issued leaf used as the anchor through partial-chain
verification, and a self-signed certificate without the CA bit, which is what a controller usually
serves; both go through the same OpenSSL date check by its documentation, and the test asserts the
refusal names expiry.

## When it applies

Any pin, trust on first use, or hold-to-observed-certificate built by loading the served certificate into an OpenSSL trust store. It
does not apply to a pin that compares a fingerprint after an unverified handshake. That pin accepts an
expired certificate, and the credentials are sent before the comparison unless the code is careful.

## How to apply it

Read the controller's certificate dates from an observing handshake first. The workbench's reader
records them with no credential sent. Renew the certificate if it has expired, then turn the pin on
in the controller's secrets file:

```sh
# PQCH_CONTROLLER_SECRETS/<host>.env
REDFISH_TRUST=observed       # the session held to the certificate this read observed; or: pin, with
                             # REDFISH_PIN_SHA256=<the fingerprint an earlier read recorded>
```

The read records its mode and fingerprints in the controller's `platform.observed` event. When the
session does not verify, it records why and stops before the login.
