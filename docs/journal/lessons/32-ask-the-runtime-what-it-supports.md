---
id: lesson-32-ask-the-runtime-what-it-supports
type: lesson
title: "Ask the protocol stack's runtime what it will negotiate before calling a migration blocked, or not blocked, by its supplier"
date: 2026-10-20
audience: [engineer, architect]
rung: managed
tags: [policy, discovery, agility]
one_line: "Whether software can offer a post-quantum algorithm is a property of the protocol stack that negotiates it, not of the cryptographic library underneath; ask that runtime for its own list, with no network, and keep the raw answer."
claims:
  - text: "RabbitMQ 4 on Erlang/OTP 27 links OpenSSL 3.5.9, which implements ML-KEM; Erlang's own TLS stack lists thirteen groups, none of them ML-KEM or a hybrid, and ML-DSA is absent from its TLS 1.3 signature algorithms."
    provenance: "measured 2026-10-20, pqch-agency/queue:m1 run with --network none: erl -eval ssl:groups(), ssl:signature_algs(default, 'tlsv1.3'), crypto:info_lib(); eval/capabilities/2026-10-20/queue.txt"
  - text: "OpenSSH 10.0 offers mlkem768x25519-sha256 key exchange and lists no post-quantum host-key algorithm; OpenSSH 6.6 lists neither; the Java 8 runtime's TLS provider names neither ML-KEM nor ML-DSA and has no KEM API."
    provenance: "measured 2026-10-20, the same tool; eval/capabilities/2026-10-20/{bastion,sftp-legacy,legacy-app}.txt"
reuse: [runbook, customer-question]
---

# Ask the protocol stack's runtime what it will negotiate before calling a migration blocked, or not blocked, by its supplier

## The rule

Before recording that a system's change is blocked on its supplier — or that
it is not — run the system's image with no network and ask the component that
negotiates the protocol for its own list of algorithms: the TLS stack's
supported groups and signature algorithms, the SSH daemon's key exchange and
host-key algorithms. Keep the raw output and its hash. Do not infer the
answer from the version of the cryptographic library the image contains.

## Why

A protocol stack offers only what it implements on top of the library. The
library may implement ML-KEM while the TLS layer above it does not list the
group, because the group, its code point and its key-share handling are the
TLS layer's to add. Erlang/OTP's TLS is its own implementation: OTP 27 with
OpenSSL 3.5.9 underneath has ML-KEM in the library and none in the
negotiation. The reverse also happens: OpenSSH implements its ML-KEM hybrid
itself, so its key exchange is post-quantum on a library that would not say
so, while its host keys are not post-quantum at all. A package list gives the
wrong answer both ways.

Asking the runtime with no network is cheap and leaves nothing running: the
image's entry point is replaced, nothing listens, nothing is reached. The
answer is the software's own, not the tool's or the reader's.

## When it applies

Any assessment that says a change cannot be made by configuration: a supplier
blocker, a "needs an upgrade" ticket, a replacement priority under OMB M-26-15
§3.C.3. It does not replace a wire check of what a running listener accepts,
which depends on configuration too; it answers what the software could accept
if configured. Where an image ships no tool that can list its algorithms, say
so, and use the same build observed on the wire, or record the state as
unknown.

## How to apply it

```sh
# tools/probe_capabilities.py runs these and keeps the output
docker run --rm --network none --entrypoint sh IMAGE -c 'openssl list -kem-algorithms'   # OpenSSL 3.x
docker run --rm --network none --entrypoint sh IMAGE -c 'ssh -Q kex; ssh -Q key'           # OpenSSH client
docker run --rm --network none --entrypoint sh IMAGE -c \
  "erl -noshell -eval 'io:format(\"~p~n\", [ssl:groups()]), halt().'"                      # Erlang/OTP TLS
```

Record the date, the image ID and the raw output's SHA-256 with the result;
the result is a snapshot of that image, and a rebuilt image is measured again.
