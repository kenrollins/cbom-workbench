---
id: lesson-10-a-group-is-accepted-when-it-is-negotiated
type: lesson
title: "Count a key-exchange group as accepted only when it is the one negotiated — and sweep TLS 1.2 groups as TLS 1.2"
date: 2026-10-04
audience: [engineer]
tags: [discovery, verification, key-establishment]
rung: enumerated
one_line: "A handshake can succeed on a group the client did not offer, and fail after the server has accepted the one it did; judge each probe by the group the server chose."
claims:
  - text: "Offered only brainpoolP256r1 over TLS 1.2, a Postgres 18 server completed the handshake with finite-field DHE at 2048 bits."
    provenance: "measured 2026-10-04, spike S2 target s2-postgres (OpenSSL 3.5.7), xr7620"
  - text: "Offered only brainpoolP256r1 over TLS 1.2, a RabbitMQ 4 server (Erlang/OTP 27) chose that curve; OpenSSL 3.5.7 then aborted with \"wrong curve\" because the server's ECDSA P-256 certificate curve had not been offered."
    provenance: "measured 2026-10-04, spike S2 target s2-rabbitmq; client error and server log"
  - text: "OpenSSL 3.5.7 reports a TLS 1.3 finite-field group as \"Temp Key: DH, 3072 bits\", not by its name."
    provenance: "measured 2026-10-04, against Kafka 4.1 (spike S2 target s2-kafka)"
  - text: "With these corrections, testssl.sh 3.2.4 and a one-group-at-a-time OpenSSL sweep agree on every TLS target in spike S2."
    provenance: "measured 2026-10-04, spike S2 results/amd64.json"
reuse: [talk, customer-question]
---

# Count a key-exchange group as accepted only when it is the one negotiated — and sweep TLS 1.2 groups as TLS 1.2

## The rule

When probing which key-exchange groups a TLS server accepts, offer one group
at a time and count it as accepted only when the server's key share is in that
group — not when the handshake succeeds, and not only when it completes.
Groups that exist only in TLS 1.2 are probed with TLS 1.2.

## Why

"Did the handshake work?" answers a different question from "does the server
accept this group?", in both directions:

- **Success on another group.** Offered only `brainpoolP256r1` in TLS 1.2, a
  Postgres server whose groups exclude it completed the handshake anyway — with
  finite-field Diffie-Hellman (DHE) at 2048 bits, because the client also
  offered DHE cipher suites and the server chooses DHE parameters itself.
  Counting that success as "Brainpool accepted" is wrong.
- **Failure after acceptance.** Offered the same curve, a RabbitMQ server did
  accept it and sent its key share; the OpenSSL client then aborted with
  "wrong curve", because in TLS 1.2 the offered curves also limit the
  certificate's curve, and the server's ECDSA certificate was on P-256.
  Counting that failure as "Brainpool refused" is also wrong.

Two version traps sit beside these. Brainpool curves have TLS 1.2 codepoints
that cannot be used in TLS 1.3; offered beside TLS 1.3 they are silently
ignored, so a sweep that does not force TLS 1.2 never sees them. And OpenSSL
3.5.7 prints a TLS 1.3 finite-field group as `Temp Key: DH, 3072 bits`, so a
sweep that matches on the group's name misses it.

Each of these made one tool look wrong in this project's scanner comparison,
and in each case the fault was the comparison's probe. Once the probe judged
by negotiated group and swept TLS 1.2 names as TLS 1.2, testssl.sh and the
OpenSSL sweep agreed on every target: a hybrid web server, Postgres, RabbitMQ,
Kafka, and a client-certificate listener.

## When it applies

Any active TLS probe that reports which groups a server accepts: inventory
scanners, verification probes, compliance checks. It matters most for
"refused" results, which a verifier uses to say a classical exchange is gone.

## How to apply it

```sh
# one group, its negotiated name compared with the one offered
openssl s_client -connect HOST:PORT -groups X25519 </dev/null 2>&1 \
  | grep -E 'Negotiated TLS1.3 group|Temp Key'
# TLS 1.2-only curves, forced to TLS 1.2
openssl s_client -connect HOST:PORT -tls1_2 -groups brainpoolP256r1 </dev/null 2>&1 | grep 'Temp Key'
# finite-field groups: compare the size, since OpenSSL prints "DH, <bits> bits"
openssl s_client -connect HOST:PORT -tls1_3 -groups ffdhe3072 </dev/null 2>&1 | grep 'Temp Key'
```

A key share in the offered group means accepted, whatever happens after it.
A completed handshake in another group means not that group. Compare
finite-field groups by size: tools name the same group by RFC 3526, RFC 7919
or bit count.
