# Spike S2 — what it found

Run 2026-10-04 on the xr7620: every tool on x86_64, then every tool as
`linux/arm64` under qemu-user. The matrix, each cell's evidence and the raw
outputs with their hashes are in `results/matrix.md`, `results/amd64.json`,
`results/arm64.json` and `results/<arch>/`.

## Against the pass criterion

S2 does **not** pass yet. Every applicable cell has an observed outcome on
x86_64, and every cell but two has the same outcome on arm64. The two are
Zeek's (C1 passive, C8): under qemu-user Zeek cannot open its capture interface
(`pcap_create`: not open), because the emulator does not provide the
packet-socket calls packet capture needs. That is a property of the emulation,
not an observation of Zeek on arm64. Those two cells close only on a real
arm64 host — the GB10, spike S6.

## Against the predictions

One prediction was wrong. testssl.sh 3.2.4 was predicted to fail on an ML-DSA
leaf certificate, because its bundled OpenSSL 1.0.2 predates ML-DSA; it read
the certificate as ML-DSA-65 on both architectures. Every other outcome was as
predicted, including cbomkit-theia's blindness to the ML-DSA certificate file:
it logs "x.509 certificate has unknown algorithm" and leaves the file out of
its CBOM.

## Corrections made to the measurement, not to the tools

Three times testssl.sh appeared wrong and the fault was this spike's own
reference sweep. Each is a rule for anyone probing TLS groups (journal lesson
10):

1. TLS 1.2-only curves (Brainpool's legacy codepoints) are ignored when offered
   beside TLS 1.3; they must be probed with TLS 1.2.
2. A group is accepted only when it is the one negotiated: offered one group,
   Postgres completed the handshake on finite-field DHE instead, and RabbitMQ
   accepted a Brainpool curve before the OpenSSL client aborted on the
   certificate's curve.
3. OpenSSL 3.5 prints a TLS 1.3 finite-field group as "DH, 3072 bits", not by
   name; tools name the same groups by RFC 3526, RFC 7919 or size, so they are
   compared by size.

After those, testssl.sh and the one-group-at-a-time OpenSSL sweep agree on
every TLS target, on both architectures.

The verifier's probe parser had the second fault too, in its safe direction:
a group the server accepted, followed by a client abort, became `inconclusive`
rather than `accepted`. It now judges by the group the server chose
(`spec/CHANGES.md`, 2026-10-04).

## What the workbench relies on, by capability

| # | Capability | Rely on | Second witness | Gap |
|---|---|---|---|---|
| C1 | Hybrid told from classical, TLS | testssl.sh | OpenSSL `s_client` sweep; Zeek (x86_64) | — |
| C2 | Hybrid told from classical, SSH | ssh-audit | none run in S2 | no second witness of a different kind for SSH yet |
| C3 | ML-DSA leaf certificate, on the wire | testssl.sh | OpenSSL `s_client` | — |
| C3 | ML-DSA certificate in an image file | none | — | **cbomkit-theia 1.1.2 drops the file.** The harness can parse it itself (the `cryptography` library reads ML-DSA); until it does, an ML-DSA certificate in an image is out of reach for the host layer |
| C4 | TLS through Postgres's upgrade | testssl.sh `--starttls postgres` | `s_client -starttls postgres` | the runner's TLS profile has no STARTTLS option yet (M1) |
| C5 | AMQPS (RabbitMQ) | testssl.sh | `s_client` | — |
| C6 | Kafka over TLS | testssl.sh | `s_client` | — |
| C7 | Client-certificate-required listener | testssl.sh | `s_client` | groups and server certificate are visible without a client certificate; what the application does after the handshake is not |
| C8 | A client's offered groups | Zeek sidecar, x86_64 | none | arm64 unobserved (emulation); the M1 traffic generator and sidecar are built on this method |
| C9 | Ruby call site | Opengrep 1.30.0 with the project's rule | none | one rule, one sample; the rule pack is M1's |

Erlang/OTP 27 (RabbitMQ 4) offers no ML-KEM group; Java in Kafka 4.1 offers
none either. A hybrid requirement on those brokers is not configurable with
these images — a fact for the M1 answer key and the migration story, not a
scanner gap.

## Why cbomkit-theia takes 70 to 96 s per image

Its secrets plugin reads a file's contents once for every symlink pointing to
it. Alpine's BusyBox has 304 symlinks; a bare `alpine:3.22` costs it 93.7 s.
Measured with synthetic images: one 800 KB file, 1.1 s; with 50 symlinks,
18.4 s; with 200, 69.8 s. The other plugins take about a second. Journal
lesson 09 has the method.

## Reruns and limits, from the M0B review (2026-10-05, F-62)

Rerun independently on the xr7620, with testssl.sh run directly and with a
sweep written for the review — one group per handshake, TLS 1.3 and TLS 1.2
forced separately — instead of `run.py`: C3 (testssl.sh on x86_64 and as arm64
under qemu, `s_client`, theia), C4, C5 and C7 (both tools), and C2 as arm64.
Every group list and certificate matched the committed results. The
reference sweep was right.

What the matrix's "correct" does and does not mean:

| Cell | It means | It does not mean |
|---|---|---|
| `s_client`, C4 to C7 | The sweep returned groups and a certificate, and testssl.sh agrees with it | A match against a truth set by the target: the brokers' group lists are their runtimes' defaults |
| Zeek, C1 | Zeek names the hybrid group when a client negotiates it with `api` | "Told from classical": the client never connects to `portal` |
| testssl.sh, C7 | Groups and server certificate are right without a client certificate | That it reads the requirement: it reports `clientAuth: optional` for a listener that answers 400 without one |

Two facts for the M1 answer key:

- **Postgres 18 accepts RSA key transport.** With `ssl_groups` set to
  X25519MLKEM768 and X25519, a TLS 1.2 client offering only RSA key exchange
  connects (`AES256-GCM-SHA384`). That is key establishment with no group; a
  list of accepted groups cannot show it. The TLS profile needs a cipher-suite
  check beside `-f`, and the key needs the item.
- **A server's own list is not what it accepts.** RabbitMQ's
  `ssl:groups(default)` names `brainpoolP256r1tls13`, `brainpoolP384r1tls13`
  and `brainpoolP512r1tls13`; offered any of them over TLS 1.3 it answers
  `illegal_parameter`. Both wire tools report them as not accepted, and are
  right.

The arm64 column cannot be rerun as written: `run.py arm64` needs the image
`pqch/harness:m0b-arm64`, which is no longer on the host, and its build
command is not recorded. Two arm64 cells were rerun with the scanner images'
own arm64 builds.

**Closed the same day** (branch `m1-prep`):

- Zeek's C1 is now judged on both sides. The client connects to `api` and to
  `portal` with the same offer; Zeek's `ssl.log` shows X25519MLKEM768
  negotiated with `api` and x25519 with `portal` (x86_64, 57 client hellos
  logged, each offering 4588 first). The cell stays "correct" and now means
  what its row says.
- The arm64 column can be rerun: the image is built with
  `docker buildx build --platform linux/arm64 -t pqch/harness:m0b-arm64 --load .`
  (69 s on the xr7620 with dependency layers cached), and `run.py arm64
  --only C9` reproduced its cell.
- RSA key transport is in the scan profile and the answer key: the runner's
  TLS profile adds testssl.sh's `-E`, the normalizer reports each
  `TLS_RSA_WITH_*` suite as a key-establishment finding named RSA with
  `mode: key-transport`, and the slice's key plants it on the portal as a wire
  decoy. A scan of the slice reports none and flags no decoy; the saved
  Postgres output yields the finding (`tests/fixtures/testssl-postgres-rsa-kx.json`).
  The runner still cannot reach Postgres itself — its TLS profile has no
  STARTTLS option (M1).
