---
id: lesson-18-observe-a-services-defaults-before-planning-its-change
type: lesson
title: "Observe what a service accepts with nothing configured before planning its migration"
date: 2026-10-05
audience: [architect, engineer]
tags: [key-establishment, discovery, agility]
rung: enumerated
one_line: "The same TLS library gives different key-exchange defaults under different servers; with no line set, one already offers the hybrid group and another does not, and both accept RSA key transport."
claims:
  - text: "nginx 1.28 on OpenSSL 3.5 with no ssl_ecdh_curve, ssl_protocols or ssl_ciphers line accepts X25519MLKEM768, X25519, X448, P-256, P-384, P-521, ffdhe2048 and ffdhe3072 over TLS 1.3, TLS 1.2, and RSA key transport."
    provenance: "measured 2026-10-05, spike S3 lab on the xr7620 (x86_64), one group per handshake; spikes/s3/observations/r6-e-before.txt"
  - text: "PostgreSQL 18 on OpenSSL 3.5 with no ssl_groups line accepts X25519 and P-256 only, no hybrid group, and also RSA key transport and finite-field DHE at 2048 bits over TLS 1.2."
    provenance: "measured 2026-10-05, same lab; spikes/s3/observations/r6-n-before.txt"
  - text: "OpenSSH 10.0 with no KexAlgorithms line offers mlkem768x25519-sha256 and sntrup761x25519-sha512 first. RabbitMQ 4 on Erlang/OTP 27 and Kafka 4.1 on OpenJDK 21 list no ML-KEM group at all."
    provenance: "measured 2026-10-05, same lab; ssh-audit 3.9.0; ssl:groups() and the JVM's own listing, spikes/s3/observations/r6-p-runtime.txt and r6-r-runtime.txt"
reuse: [whitepaper, talk, customer-question]
---

# Observe what a service accepts with nothing configured before planning its migration

## The rule

Before writing a change to a service's key establishment, start it with no
key-exchange, protocol or cipher line and probe it. Plan from what it accepts
then, not from the library it links.

## Why

Hybrid key exchange — a classical exchange and a post-quantum
key-encapsulation mechanism (KEM) run together, such as X25519MLKEM768 —
arrives in a TLS library as a group the library *can* negotiate. Whether a
server offers it is the server's decision, and servers decide differently.

Two servers on the same OpenSSL 3.5 show it. nginx passes no group list unless
told to, so it inherits the library's default list, which includes the hybrid
group: an unconfigured nginx is already "enabled". PostgreSQL sets its own
default list, X25519 and P-256, so an unconfigured Postgres is not. A plan
that says "add the hybrid group" is a no-op for the first and the whole change
for the second.

The defaults also include what a migration has to remove. Both servers,
unconfigured, accept RSA key transport over TLS 1.2 — the client encrypts the
session secret to the server's RSA key, with no group involved — and Postgres
accepts finite-field Diffie-Hellman as well. None of that appears in a
configuration file, because nothing set it.

And some runtimes cannot offer the hybrid group whatever is configured. That
is a supplier dependency, and it is found by asking the runtime what it
lists, not by reading its configuration reference.

## When it applies

Planning any change to cryptographic settings on software you did not
configure from scratch: inherited estates, container images from a vendor,
anything whose configuration is short. It applies again after every library
upgrade, because the defaults move with the library.

## How to apply it

1. Start the service with its key-exchange, protocol and cipher lines removed.
2. Probe one group per handshake, with TLS 1.3 and TLS 1.2 forced separately,
   and probe RSA key transport and finite-field DHE on their own
   ([lesson 10](10-a-group-is-accepted-when-it-is-negotiated.md)):

```sh
openssl s_client -connect host:443 -tls1_3 -groups X25519MLKEM768 </dev/null
openssl s_client -connect host:443 -tls1_2 -cipher kRSA </dev/null
openssl s_client -connect host:443 -tls1_2 -cipher kDHE </dev/null
```

3. Sort the result three ways: already offered by default; offered only when
   configured; not offered by this runtime at all. The third list goes to the
   supplier, not to the change queue.
4. To require the hybrid group, set the group list to it alone *and* restrict
   the protocol to TLS 1.3: TLS 1.2 cannot carry it, and leaving TLS 1.2 on
   leaves RSA key transport and DHE on with it.
