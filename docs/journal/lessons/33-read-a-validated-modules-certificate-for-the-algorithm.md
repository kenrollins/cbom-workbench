---
id: lesson-33-read-a-validated-modules-certificate-for-the-algorithm
type: lesson
title: "Read a validated module's certificate for the algorithm you need, and check that the module is active, before calling a system validated"
date: 2026-10-20
audience: [engineer, architect]
rung: managed
tags: [policy, verification]
one_line: "A FIPS 140 validation covers the algorithms its certificate lists, in the module it names, when that module is the one in use; the library's name and version say none of that, and a FIPS provider shipped in an image is not one in use."
claims:
  - text: "Of 92 active CMVP certificates matching OpenSSL, Java, Erlang or OpenSSH, one lists ML-KEM among its approved algorithms and two list ML-DSA; the OpenSSL project's own validated provider, certificate 4985, lists neither, while Chainguard's validated provider for OpenSSL, certificate 5523, lists both."
    provenance: "NIST CMVP search and certificate pages read 2026-10-20 by tools/cmvp_snapshot.py; policy/snapshots/cmvp-2026-10-20.json"
  - text: "The RabbitMQ image ships an OpenSSL FIPS provider (fips.so, 3.5.9) with its activation line commented out; the running library uses the default provider only."
    provenance: "measured 2026-10-20, pqch-agency/queue:m1 run with --network none: openssl list -providers, /opt/openssl/etc/ssl/fipsmodule.cnf; eval/capabilities/2026-10-20/queue.txt"
reuse: [runbook, customer-question]
---

# Read a validated module's certificate for the algorithm you need, and check that the module is active, before calling a system validated

## The rule

To say a system uses a validated module for an algorithm, three things must
hold and each must be checked: a FIPS 140 certificate exists whose list of
approved algorithms includes that algorithm; the module the system loads is
that certified module; and it is active, not merely present. Read the first
from the certificate page, not from the library's name or release notes. Read
the other two from the running image.

## Why

A validation certifies a module, not a library family. Many vendors validate
their own builds of the same open-source provider, at different times and
with different algorithm lists, and a newer release of the library may add an
algorithm its validated build does not yet cover. On 2026-10-20 the OpenSSL
project's own validated provider listed neither ML-KEM nor ML-DSA, while one
vendor's validated build of the same provider listed both. "We use OpenSSL,
which has a validated module" says nothing about post-quantum algorithms.

Presence is not use either. An image can carry a FIPS provider, built and
installed, with the configuration that activates it commented out; every
handshake then runs on the default provider, which is not the validated one.

## When it applies

Any claim that a system meets a validated-module requirement, and any
blocker that says a post-quantum change waits for one. It applies per
algorithm: a module validated for ECDH and RSA is not thereby validated for
ML-KEM. It does not settle whether a given build matches the certified
version; that is in the certificate's Security Policy, which a full check
reads too.

## How to apply it

1. Take a dated snapshot of the active certificates for the libraries the
   estate runs, with each certificate page's list of approved algorithms and
   the page's hash (`tools/cmvp_snapshot.py`).
2. In each image, list the loaded providers and read the configuration that
   activates them (`openssl list -providers`; the `.include` of
   `fipsmodule.cnf` and its `activate` line).
3. Record one of three states per item and algorithm: `in-use` (the certified
   module is loaded and active), `available-not-in-use` (a certificate covers
   the algorithm for this library; the system does not use it), or
   `none-validated` (no active certificate in the snapshot covers it).
