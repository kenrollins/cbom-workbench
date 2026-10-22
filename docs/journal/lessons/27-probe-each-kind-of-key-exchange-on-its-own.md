---
id: lesson-27-probe-each-kind-of-key-exchange-on-its-own
type: lesson
title: "Before keying a TLS listener, probe each kind of key exchange on its own: named groups, finite-field DHE, RSA key transport"
date: 2026-10-19
audience: [engineer]
rung: enumerated
tags: [discovery, key-establishment, verification]
one_line: "A TLS 1.2 listener can establish keys three ways — a named group, an ephemeral finite-field group it supplies itself, or encryption to its RSA key — and a probe that offers one kind says nothing about the other two; key a listener only after a probe per kind, or a full cipher-suite enumeration."
claims:
  - text: "PostgreSQL 18 configured with ssl_groups X25519MLKEM768:X25519 and no ssl_dh_params_file completed TLS 1.2 handshakes on a 2048-bit finite-field group (RFC 3526 group 14) and on RSA key transport, neither of which its list of groups names."
    provenance: "measured 2026-10-19, mini-agency records-db, testssl.sh 3.2.4 -E -f through --starttls postgres and OpenSSL 3.5 s_client -tls1_2 -cipher kRSA, xr7620"
  - text: "Probes offering only named groups (-groups X25519MLKEM768, -groups X25519, -groups secp256r1) and only RSA key transport (-cipher kRSA) found the hybrid group, X25519 and key transport and did not find the DHE group; the answer key written from them lacked one of the listener's five key-establishment items."
    provenance: "the same day, same listener; agency/answer-key.yaml, item records-kex-dh-2048, added after a testssl.sh run"
reuse: [runbook, whitepaper]
---

# Before keying a TLS listener, probe each kind of key exchange on its own: named groups, finite-field DHE, RSA key transport

## The rule

Write a listener's key-establishment entries only after three separate
probes, or one full enumeration of its cipher suites: a handshake that
offers named groups only, one that offers finite-field ephemeral
Diffie-Hellman suites only (`-cipher kDHE`), and one that offers RSA
key-transport suites only (`-cipher kRSA`). A listener that answers "no"
to one kind has not answered for the others.

## Why

TLS 1.2 establishes a session key in three different ways, and a server's
configuration names at most one of them explicitly:

| Kind | What the server contributes | Where it is configured | What a group list shows |
|---|---|---|---|
| Named group (ECDHE, or TLS 1.3 FFDHE and KEM groups) | a key share in a group both sides name | `ssl_groups`, `ssl_ecdh_curve`, `jdk.tls.namedGroups` | the group |
| Ephemeral finite-field DHE (TLS 1.2) | parameters the server supplies itself, built in or from a file | `ssl_dh_params_file`, `ssl_dhparam`, or nothing | nothing: the group has no name on the wire |
| RSA key transport | its RSA certificate's key; the client encrypts the secret to it | the cipher list, by its default | nothing: no group is involved |

A probe offering only named groups exercises the first row. PostgreSQL 18
with `ssl_groups = 'X25519MLKEM768:X25519'` refused `secp256r1`, which reads
as a listener that does exactly what its configuration says; the same
listener completed a handshake on a 2048-bit finite-field group it supplied
itself (RFC 3526 group 14, PostgreSQL's built-in default when no parameters
file is set) and another on RSA key transport. Both are key establishment a
quantum computer breaks, and both were invisible to the probes that wrote
the first version of the listener's answer key. The missing item was found
by testssl.sh's cipher-suite enumeration, which reports the DHE suites and
the size of the group behind them.

The failure is quiet: a probe that offers only `-groups X25519` and succeeds
proves X25519 is accepted and proves nothing else, and the person reading
"X25519MLKEM768 and X25519 accepted, secp256r1 refused" believes the list is
complete.

## When it applies

Any TLS 1.2 listener, and any TLS 1.3 listener that also accepts 1.2.
Servers whose cipher list is a default — PostgreSQL, Java, Erlang, older
nginx builds — are the ones most likely to carry a DHE or key-transport path
their group configuration never mentions. A TLS 1.3-only listener has no
RSA key transport and no server-supplied DHE; a named-group probe is
complete there.

## How to apply it

- Hand probes, OpenSSL 3.5, each on its own:

  ```sh
  openssl s_client -connect HOST:PORT -groups X25519MLKEM768 </dev/null   # named groups, one at a time
  openssl s_client -connect HOST:PORT -tls1_2 -cipher kDHE  </dev/null   # finite-field DHE only
  openssl s_client -connect HOST:PORT -tls1_2 -cipher kRSA  </dev/null   # RSA key transport only
  ```

  Read the negotiated cipher and `Server Temp Key` lines; a `DH, 2048 bits`
  temp key is a server-supplied group, and `Cipher is AES256-GCM-SHA384` with
  no temp key is key transport.
- In the harness the wire profile runs testssl.sh with `-f` (groups) and
  `-E` (every suite per protocol), and the normalizer reads `DH_groups` and
  the `TLS_RSA_WITH_*` suites beside the group lists
  ([lesson 10](10-a-group-is-accepted-when-it-is-negotiated.md) for what
  counts as accepted).
- An answer key's listener is complete when it has an entry, present or
  decoy, for each of the three kinds; a decoy is right where the listener
  looks as if it would and refuses (M0B review F-62).
