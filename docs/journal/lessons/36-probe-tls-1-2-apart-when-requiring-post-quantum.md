---
id: lesson-36-probe-tls-1-2-apart-when-requiring-post-quantum
type: lesson
title: "When verifying that a listener requires post-quantum key establishment, probe TLS 1.2 on its own; a classical-only TLS 1.3 client is refused, not downgraded"
date: 2026-10-21
audience: [engineer, architect]
rung: agile
tags: [verification, key-establishment]
one_line: "A server that shares no group with a TLS 1.3 client refuses it rather than falling back to TLS 1.2, so a negative probe offering every classical group says nothing about TLS 1.2; a listener restricted to the hybrid group can pass it while still accepting finite-field Diffie-Hellman and RSA key transport over TLS 1.2."
claims:
  - text: "A copy of a PostgreSQL 18 listener with ssl_groups set to X25519MLKEM768 alone refused an OpenSSL 3.5 client offering X25519, P-256 and P-384, and completed a TLS 1.2 handshake with DHE-RSA-AES256-GCM-SHA384 and another with RSA key transport (AES256-GCM-SHA384)."
    provenance: "measured 2026-10-21 by hand on the twin network, the records database's image (sha256 8bb6e791…), openssl s_client -starttls postgres from the harness image"
  - text: "With ssl_min_protocol_version also set to TLSv1.3, the TLS 1.2 handshake was refused and the four-probe check returned enforced."
    provenance: "the rehearsal of change 01M5FGPG3KKTXXA1CRJPMXZ2B9, run 01M5FGP0R99EF496M74YYJYNBD, 2026-10-21"
reuse: [runbook, customer-question]
---

# When verifying that a listener requires post-quantum key establishment, probe TLS 1.2 on its own; a classical-only TLS 1.3 client is refused, not downgraded

## The rule

A check that a listener *requires* hybrid post-quantum key establishment
includes a TLS 1.2 handshake that must be refused, separate from the probe that
offers every classical group. An accepted TLS 1.2 handshake means classical key
establishment is still possible, whatever the other probes said.

## Why

The negative probe of a paired check offers every classical group and allows
any protocol version, on the idea that a server which would accept classical
key exchange will do so. Against a TLS 1.3 server that is not what happens.
The client offers TLS 1.3 and TLS 1.2; the server picks TLS 1.3, finds no group
it shares with the client, and ends the handshake. It does not go back and
offer TLS 1.2. So the probe is refused, and the check reads that as
"classical refused".

TLS 1.2 is still there for a client that asks for it. In TLS 1.2 the key
exchange is chosen by the cipher suite: ECDHE uses a group, but DHE uses the
server's finite-field parameters, and RSA key transport uses no group at all.
Restricting the groups leaves both open. And TLS 1.2 cannot carry the hybrid
group, so any TLS 1.2 handshake that completes is classical key establishment.

This is the change most easily written for "require the hybrid group": set
the groups, and stop. It is the plan that looks right, and on PostgreSQL it
leaves RSA key transport in place, the weakest key establishment the listener
had.

## When it applies

Any verification of *require* on a TLS listener whose software supports TLS
1.2: nginx, PostgreSQL, Java, Erlang and most others. It does not apply to
*enable*, where classical key establishment is still allowed. A listener that
is TLS 1.3 only passes it by construction.

## How to apply it

Add a fourth probe for *require*: `openssl s_client -tls1_2` with the
client's default suites (and `-starttls postgres`, or the protocol's own
upgrade, where there is one). It must be refused; an accepted handshake caps
the verdict at `enabled-not-enforced` and names TLS 1.2 among what the listener
also accepts. On the server the matching change is a minimum protocol of TLS
1.3, beside the groups.
