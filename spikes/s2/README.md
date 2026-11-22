# Spike S2 — scanner truth matrix, x86_64 and arm64

Written 2026-10-04, before any S2 target was built or any S2 scan was run.

## Question

For each scanner the workbench uses, on each architecture: which of the
capabilities below does it actually have, measured against targets whose
truth is known because they were built for this?

## The matrix

Columns, the tools, at their pinned versions:

| Tool | Kind |
|---|---|
| testssl.sh 3.2.4 | active, TLS |
| openssl s_client 3.5 (the verifier's probe, in the harness image) | active, TLS |
| ssh-audit 3.9.0 | active, SSH |
| cbomkit-theia 1.1.2 | files in an image |
| Zeek (lts) | passive, beside a client |
| Opengrep | source rules |

Rows, the capabilities, each with its target and what "correct" means:

| # | Capability | Target (all on 172.16.106.0/24) | Correct when the tool reports |
|---|---|---|---|
| C1 | Hybrid ML-KEM told from classical, TLS | slice `api` (hybrid) and `portal` (classical) | X25519MLKEM768 for api, and not for portal |
| C2 | Hybrid told from classical, SSH | slice `bastion` (OpenSSH 10) and `sftp-legacy` (6.6) | mlkem768x25519-sha256 for bastion, not for sftp-legacy |
| C3 | ML-DSA leaf certificate | `s2-mldsa`: TLS 1.3 server, ML-DSA-65 self-signed leaf | ML-DSA-65 as the certificate's key or signature algorithm, on the wire or in the image file |
| C4 | TLS through Postgres's in-protocol upgrade (STARTTLS-like `SSLRequest`) | `s2-postgres`: postgres 18, OpenSSL 3.5, `ssl_groups X25519MLKEM768:X25519` | both groups, and the certificate |
| C5 | TLS on RabbitMQ (AMQPS, TLS from the first byte; AMQP 0-9-1 has no STARTTLS) | `s2-rabbitmq`: rabbitmq 4, port 5671 | the groups and the certificate |
| C6 | TLS on Kafka (TLS from the first byte) | `s2-kafka`: apache/kafka 4.1, SSL listener 9093 | the groups and the certificate |
| C7 | A listener that requires a client certificate | `s2-mtls`: nginx, `ssl_verify_client on` | the groups and the server certificate, without a client certificate |
| C8 | A client's offered groups, seen passively | Zeek sidecar sharing `s2-client`'s network namespace, while it connects to `api` offering X25519MLKEM768:X25519 | X25519MLKEM768 among the client's offered groups |
| C9 | A Ruby cryptographic call site | `spikes/s2/ruby/sample.rb`, one rule in `spikes/s2/ruby/rules.yaml` | the line that calls `OpenSSL::PKey::RSA.new` |

Each cell is one of: **correct**; **wrong** (reports something false, which is
worse than nothing); **blind** (runs and reports nothing for the thing asked);
**fails** (does not complete); **n/a** (the tool is not built for it).

## Predictions, written before running

| | testssl.sh | s_client | ssh-audit | theia | Zeek | Opengrep |
|---|---|---|---|---|---|---|
| C1 | correct (seen in M0) | correct (seen in M0A) | n/a | n/a | correct | n/a |
| C2 | n/a | n/a | correct (seen in M0) | n/a | not run | n/a |
| C3 | wrong or fails: its bundled OpenSSL 1.0.2 predates ML-DSA | correct | n/a | wrong or blind: Go's x509 parser predates ML-DSA | n/a in TLS 1.3 (certificate encrypted) | n/a |
| C4 | correct, with `--starttls postgres` | correct, with `-starttls postgres` | n/a | n/a | not run | n/a |
| C5 | correct | correct | n/a | n/a | not run | n/a |
| C6 | correct | correct | n/a | n/a | not run | n/a |
| C7 | correct for groups and server certificate | correct | n/a | n/a | not run | n/a |
| C8 | n/a | n/a | n/a | n/a | correct, codepoint 4588 may print as a number | n/a |
| C9 | n/a | n/a | n/a | n/a | n/a | correct |

"Not run" means the spike does not set up that combination; it is not a claim
about the tool.

## Pass criterion

S2 passes when every cell that is not n/a or not run has an observed outcome
on **both** x86_64 and arm64 (arm64 under qemu-user on the xr7620), each with
its raw output saved and hashed in `results/`. It is a measurement: a tool
being blind or wrong does not fail S2; an unfilled cell does. A cell whose
outcome differs between the architectures is reported as a finding.

S2 also answers, in `results.md`: for each capability, which tool the workbench
relies on, and which capabilities have no tool — those go to the answer key as
out-of-reach and to the receipts as having no verifier.

Separately: why cbomkit-theia takes 70 to 95 s per image of a few megabytes.

## Method

```sh
docker compose -f spikes/s2/compose.yaml up -d --build     # the S2 targets, on the slice network
uv run python spikes/s2/run.py amd64                        # every applicable cell, x86_64
docker buildx build --platform linux/arm64 -t pqch/harness:m0b-arm64 --load .   # the arm64 harness image run.py uses for OpenSSL and Opengrep
uv run python spikes/s2/run.py arm64                        # the same, tools as linux/arm64 under qemu
docker compose -f spikes/s2/compose.yaml down
```

The S2 targets are not in the slice's scope or its answer key, so the runner
will not scan them; `run.py` starts the tools directly on the slice network,
as an operator would. Only addresses in `172.16.106.0/24` are touched.
