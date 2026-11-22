---
id: lesson-51-probe-a-refusal-before-scanning-what-it-refuses
type: lesson
title: "Where a protocol upgrade can be refused, ask for it once and record the answer before scanning what it would carry: a scanner that cannot represent a refusal records a timeout"
date: 2026-11-04
audience: [engineer]
rung: enumerated
tags: [discovery, verification]
one_line: "A TLS scanner pointed at a PostgreSQL listener that refuses TLS waits out its budget and records a timeout, which reads as a failed scan; one SSLRequest answered N in a millisecond is the finding: the database speaks in the clear."
claims:
  - text: "PostgreSQL answers a client's SSLRequest with one byte, S when TLS follows and N when it does not, after which the connection continues in the clear."
    provenance: "cited: PostgreSQL documentation, Frontend/Backend Protocol, SSL Session Encryption"
reuse: [runbook]
---

# Where a protocol upgrade can be refused, ask for it once and record the answer before scanning what it would carry

## The rule

When a protocol reaches TLS through an upgrade the server may refuse (PostgreSQL's SSLRequest,
STARTTLS in SMTP, IMAP or LDAP), send the request once, record the answer as a finding, and run the
TLS scan only if the answer is yes. A refusal is a result, and the plainest one: the connection
continues in the clear, credentials included.

## Why

A TLS scanner is built to describe TLS. Given a server that declines the upgrade, testssl.sh waits for
a handshake that never comes, and the runner's budget ends it: the record says `timeout`, with no
findings. A timeout and a refusal look alike in a list of jobs, and only one of them is a fact about
the server. PostgreSQL's answer to SSLRequest is a single byte, `S` (TLS follows) or `N` (it does not);
reading that byte takes a millisecond and states the fact.

## When it applies

Any listener whose TLS is negotiated inside another protocol. It does not apply to a listener that
starts with a TLS handshake; there a refusal is a failed handshake the scanner already reports.

## How to apply it

The runner's `postgres-tls-offer` profile sends the SSLRequest and records the byte; a system scan
runs it first for every PostgreSQL listener and scans TLS only where the answer is `S`. The finding is
a protocol entry with `tls_offered: false`, and a plan puts "turn on TLS" ahead of any key-exchange
step on that listener.
