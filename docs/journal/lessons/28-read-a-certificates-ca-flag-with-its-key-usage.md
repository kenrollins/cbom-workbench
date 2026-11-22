---
id: lesson-28-read-a-certificates-ca-flag-with-its-key-usage
type: lesson
title: "Read a certificate's CA flag together with its key usage; a self-signed server certificate is usually marked CA:TRUE"
date: 2026-10-19
audience: [engineer, architect]
rung: structured
tags: [discovery, signatures, verification]
one_line: "openssl req -x509 writes basicConstraints CA:TRUE into every self-signed certificate it makes, server certificates included, so an inventory rule that treats CA:TRUE as 'a certificate authority' misfiles them; a certificate authority's certificate is one with CA:TRUE and keyUsage keyCertSign, and the in-use rules for leaf certificates must not be applied to it."
claims:
  - text: "Of six certificate files in the mini-agency's images with basicConstraints CA:TRUE, three are server or retired certificates made with openssl req -x509 and three are certificate authorities; only the three authorities carry keyUsage keyCertSign."
    provenance: "measured 2026-10-19, pqch image-files over the agency images (pq-gateway.crt, portal-2019.crt, queue-2020.crt against ca.crt in records-db and queue and partner-ca.crt in api), xr7620"
  - text: "A rule marking every certificate file no listener serves as not in use marked the internal CA's certificate and the partner CA's certificate not in use; three keyed items were lost to it on the first M1 scan."
    provenance: "measured 2026-10-19, run 01M5AR5EABKD821CHJZAY2937F scored by eval/score.py against agency/answer-key.yaml"
reuse: [runbook, whitepaper]
---

# Read a certificate's CA flag together with its key usage; a self-signed server certificate is usually marked CA:TRUE

## The rule

Call a certificate a certificate authority's only when it has
`basicConstraints` CA:TRUE **and** `keyUsage` with `keyCertSign`. Record
the bare CA:TRUE flag separately. Apply the rules that judge a leaf
certificate — "no listener serves it, so it is not in use" — only to
certificates that are not authorities by that reading; an authority's
certificate is in use through what it issued or what names it, never by
being served.

## Why

`openssl req -x509` makes a self-signed certificate, and since OpenSSL 1.1.1
it adds `basicConstraints = critical, CA:TRUE` to it by default. That is
how most self-signed server certificates in the world are made, so most of
them claim to be certificate authorities. A reader that takes the flag at
its word puts a web server's certificate, a database's and a long-retired
one in the same class as the organisation's internal CA.

The distinction matters because the two classes are judged by different
evidence. A leaf certificate is in use when a listener serves it; one that
no listener serves, in an image whose listeners were all scanned, can be
marked not in use — that is what keeps a retired certificate left in an
image out of the inventory
([lesson 05](05-penalize-what-an-inventory-invents.md)). An authority's
certificate is never served as a leaf: the records database's `ca.crt` is
what it verifies client certificates against, the partner CA's certificate
is what the API's partner listener requires a client to chain to. The same
rule marks both not in use and is wrong both times, and on the first scan of
the M1 estate it cost the workbench three keyed items its baselines kept.

RFC 5280 section 4.2.1.3 is the ground: when a certificate carries the
`keyUsage` extension and is used to verify signatures on certificates,
`keyCertSign` must be set. A CA that issues anything carries it; `openssl
req -x509` does not add it unless asked. The exception is an authority
without any `keyUsage` extension, which the standard permits; such a
certificate reads as a leaf here, and the inventory errs toward "unknown"
rather than toward inventing an authority.

## When it applies

Any inventory of certificate files on hosts or in images, and any rule
that judges a certificate by whether it is served. It applies with
particular force to internal PKI, where self-signed authorities and
self-signed servers come from the same command.

## How to apply it

- The harness's own reader records both fields on every certificate
  finding: `is_ca` (CA:TRUE with keyCertSign) and `basic_constraints_ca`
  (the bare flag). The parser is `pqch.scout.keys.parse_certificate_pem`;
  the reader is `pqch image-files`.
- The in-use rule skips every finding read from a file whose certificate
  has `is_ca`; its basis says why. An authority's in-use status is a
  question for the issuer links (M1, dependency chains) and the
  configuration that names it, which the reader records as
  `referenced_by`.
- When writing an answer key, key the authority's certificate file as
  `present` with `kind: certificate-authority`, and expect a scanner that
  reports it as "self-signed, CA" to have read only half of it.
