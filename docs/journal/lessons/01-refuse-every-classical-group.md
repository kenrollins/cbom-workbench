---
id: lesson-01-refuse-every-classical-group
type: lesson
title: "When verifying that a post-quantum key exchange is required, offer every classical group, not the ones the server was configured with"
date: 2026-10-04
audience: [architect, engineer]
tags: [verification, key-establishment, agility]
rung: agile
one_line: "A refuse-probe built from the server's old configuration proves only that the old configuration is gone; build it from the whole class being retired, and let an enumerating scan overrule it."
claims:
  - text: "A listener offering X25519MLKEM768 and secp384r1 was reported enforced by a probe pair that refused X25519 and P-256; a P-384-only client connected."
    provenance: "measured 2026-10-03, M0 slice portal (nginx 1.28, OpenSSL 3.5), xr7620 (x86_64); M0A review F-44"
  - text: "OpenSSL 3.5.7 accepts thirteen classical TLS groups on one s_client -groups list: X25519, X448, P-256, P-384, P-521, ffdhe2048 to ffdhe8192, and three Brainpool TLS 1.3 curves."
    provenance: "measured 2026-10-03, openssl list -tls-groups and s_client in the harness image"
reuse: [whitepaper, talk, customer-question]
---

# When verifying that a post-quantum key exchange is required, offer every classical group, not the ones the server was configured with

## The rule

To show that a listener *requires* hybrid post-quantum key establishment, the
client that must be refused offers every classical group a client could
offer, and any group an enumerating scan finds accepted outside the allowed
list rules out "enforced".

## Why

In TLS 1.3 a server picks a key-exchange group from the intersection of its
list and the client's. A *hybrid* group, such as X25519MLKEM768, pairs a
classical exchange with the post-quantum KEM (key-encapsulation mechanism)
ML-KEM-768. "Enforced" means no classical-only client can complete a
handshake.

A probe can only show that the groups *it offered* were refused. If the list
of groups to refuse is taken from the server's previous configuration — the
natural place to look — the probe answers "is the old configuration gone?",
not "is every classical exchange refused?". A server configured with the
hybrid group and any classical group not on that list passes.

Measured: with `ssl_ecdh_curve X25519MLKEM768:secp384r1`, a pair of probes
that refused X25519 and P-256 reported enforced. A client offering only P-384
connected. The second-witness scan had listed `secp384r1` as accepted, and
that list was not consulted.

Two independent mechanisms are needed because each has a blind side. A single
handshake with a long offer list shows that *one* of the offered groups was
accepted, or none. An enumerating scan tries groups one at a time, but only
the groups that scanner knows.

## When it applies

Whenever a check must establish the absence of a class of algorithm on a
listener: TLS key-exchange groups, SSH key-exchange methods, cipher suites,
signature algorithms. It applies equally in reverse: confirming a rollback to
classical means refusing every post-quantum and hybrid group.

It does not apply when the intent is only to *enable* the new algorithm
alongside the old; then the classical probe is expected to succeed, and the
result is the distinct state "enabled, not enforced".

## How to apply it

Keep the refuse list as data, by kind, separate from what any server is
configured with:

```yaml
# policy/crypto-policy.yaml
key_establishment:
  hybrid: [X25519MLKEM768]
  classical: [X25519, secp256r1]          # what the estate is configured with
  every_classical: [X25519, X448, secp256r1, secp384r1, secp521r1,
                    ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, ffdhe8192,
                    brainpoolP256r1tls13, brainpoolP384r1tls13, brainpoolP512r1tls13]
```

The negative probe, one handshake, any protocol version:

```sh
openssl s_client -connect HOST:443 -servername NAME \
  -groups X25519:X448:P-256:P-384:P-521:ffdhe2048:ffdhe3072:ffdhe4096:ffdhe6144:ffdhe8192:brainpoolP256r1tls13:brainpoolP384r1tls13:brainpoolP512r1tls13 </dev/null
```

Enforced requires a handshake failure here, a success for the hybrid-only
probe, and an enumerating scan (testssl.sh `-f`) whose accepted groups are all
on the allowed list. Regenerate the list from `openssl list -tls-groups` when
the probe's OpenSSL changes.
