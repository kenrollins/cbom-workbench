---
id: note-15-what-the-open-source-scanners-cover
type: note
title: "What do the open-source scanners cover, and what is built on top?"
date: 2026-10-19
audience: [architect, engineer]
tags: [cbom, discovery]
rung: enumerated
one_line: "Three free scanners together find everything within reach on the wire and about two thirds of what sits in images; what they cannot do is read every key format, say which findings are the same key, which are in use, or what a listener's posture is — and that is what the harness adds."
claims:
  - text: "testssl.sh 3.2.4 and ssh-audit 3.9.0 together find 22 of 23 keyed wire items on the four-service slice, including the hybrid groups X25519MLKEM768 (TLS) and mlkem768x25519-sha256 (SSH)."
    provenance: "measured 2026-10-03, M0 slice, xr7620 (x86_64), eval/score.py"
  - text: "cbomkit-theia 1.1.2 finds 7 of 10 keyed image items: it names a DSA private key only as \"private-key\" and does not report either Ed25519 SSH host key."
    provenance: "measured 2026-10-03, same run"
  - text: "cbomkit-theia reports an unserved RSA-1024 certificate in an image exactly as it reports the served one."
    provenance: "measured 2026-10-03, same run; the key's host decoy"
  - text: "Scan times with all jobs running at once: TLS listener 27 to 46 s; SSH listener 2 to 3 s; image 71 to 96 s, almost all in cbomkit-theia's secrets plugin."
    provenance: "measured 2026-10-03, xr7620 (x86_64), runner job durations over six runs (wire) and one (images)"
  - text: "The Ubuntu 14.04 and Alpine 3.22 base images carry 148 and 121 certificate-authority certificates in their trust stores."
    provenance: "measured 2026-10-04, counted in the pinned base images"
  - text: "On purpose-built targets, testssl.sh 3.2.4 reported the key-exchange groups and certificate of Postgres 18 through its TLS upgrade, RabbitMQ 4, Kafka 4.1 and a client-certificate-required listener, and read an ML-DSA-65 leaf certificate; an OpenSSL 3.5 one-group-at-a-time sweep agreed on every target, on x86_64 and on arm64 under emulation."
    provenance: "measured 2026-10-04, spike S2, xr7620; spikes/s2/results/matrix.md"
  - text: "cbomkit-theia 1.1.2 leaves an ML-DSA-65 certificate file out of its CBOM, logging \"x.509 certificate has unknown algorithm\"."
    provenance: "measured 2026-10-04, spike S2 target s2-mldsa"
  - text: "cbomkit-theia's own CBOMs, scored with no normalizer, cover the same 7 of 10 image items and flag the same decoy as the projected baseline when theia's reference from a certificate to its key is followed; 5 of 10 by component name alone."
    provenance: "measured 2026-10-04, eval/score_raw_theia.py on the M0 slice"
  - text: "Neither RabbitMQ 4 (Erlang/OTP 27) nor Kafka 4.1 accepted any ML-KEM group."
    provenance: "measured 2026-10-04, spike S2 sweeps"
  - text: "Postgres 18 configured with ssl_groups X25519MLKEM768:X25519 completes a TLS 1.2 handshake using RSA key transport (AES256-GCM-SHA384); neither testssl.sh's forward-secrecy check nor a sweep of groups reports it."
    provenance: "measured 2026-10-05, spike S2 Postgres target, OpenSSL 3.5 s_client -tls1_2 -cipher kRSA, xr7620; M0B review F-62"
  - text: "Adding every-cipher-suite enumeration to the TLS scan raised it from 42.8 s to 59.9 s on a TLS 1.2 and 1.3 listener and from 29.2 s to 38.5 s on a TLS 1.3-only one."
    provenance: "measured 2026-10-05, M0 slice, xr7620 (x86_64), one run each, runs 01M46RRF5FFA9WYNXFYM6SARKC and 01M46T91V6KZ6ZAX3HEXBPAP6J"
  - text: "RabbitMQ 4 lists three Brainpool TLS 1.3 groups among its defaults and refuses each on the wire with an illegal_parameter alert."
    provenance: "measured 2026-10-05, ssl:groups(default) on the S2 RabbitMQ target against a one-group TLS 1.3 handshake"
  - text: "On the eight-service estate the scanners alone find 38 of 40 keyed wire items (the two misses are out of reach) and 14 of 20 image items, flagging both image decoys; the workbench with its own file reader and rules finds 20 of 20 and flags neither."
    provenance: "measured 2026-10-19, run 01M5AS1BSKH8SQN8XN6NCFE1E5, xr7620 (x86_64), eval/score.py"
  - text: "The harness's own reader takes 1.0 to 7.6 s per image where cbomkit-theia takes 75 to 136 s; it read 123 findings from eight images against theia's 70, most of them Alpine's package-signing keys that theia does not report."
    provenance: "measured 2026-10-19, same run, runner job durations and finding counts by tool"
  - text: "testssl.sh through PostgreSQL's SSLRequest upgrade took 94 s on the records database against 37 to 65 s for the plain TLS listeners in the same run."
    provenance: "measured 2026-10-19, same run"
  - text: "CBOMkit does not scan networks."
    provenance: "cited: PQCA, CBOMkit architecture write-up, 2026"
  - text: "sslyze 6.2.0 (nassl) lists no post-quantum group: against a listener that requires X25519MLKEM768 it reports no TLS at all and discards the scan, and against the portal it reported secp256r1 rejected where an OpenSSL 3.5 handshake offering only P-256 completed over both TLS 1.3 and 1.2."
    provenance: "measured 2026-10-21 on the mini-agency network, xr7620 (x86_64), image nablac0d3/sslyze@sha256:0224706d…; OpenSSL 3.5 s_client from the harness image"
  - text: "Run offline at the pinned commits, cdxgen 11.11.0's CBOM mode found no cryptographic asset in CMSgov/bluebutton-web-server (Python; it listed 120 libraries after failing to resolve a dependency) or CMSgov/dpc-app (Java; its CBOM mode needs a Maven build)."
    provenance: "measured 2026-10-21, ghcr.io/cyclonedx/cdxgen@sha256:bbe0ecfd…, --network none, repositories read-only at the commits in eval/pins.yaml"
  - text: "The sonar-cryptography plugin 1.6.1 in SonarQube 25.9 community, with no network, detected no cryptographic asset in bluebutton-web-server, whose code uses hashlib, PyJWT and secrets rather than pyca/cryptography, the one Python library it covers; nor in dpc-app's Java analysed without compiled classes, though 16 of its files import JCA or BouncyCastle."
    provenance: "measured 2026-10-21, plugin jar sha256 de2f21ea…, sonar-scanner-cli 11.4 on an internal network; dpc-app was not built, since the repositories in eval/pins.yaml are never run"
  - text: "cbomkit-theia's own per-image CBOMs, imported through the workbench's generic CycloneDX importer with no theia-specific code, score 14 of 20 keyed image items and flag both image decoys — the same as its native reader."
    provenance: "measured 2026-10-21, import run 01M5GBGJ558Z8HN69M6F5BRP05 on the deployment, scored against agency/answer-key.yaml"
reuse: [whitepaper, customer-question]
---

# What do the open-source scanners cover, and what is built on top?

## The answer

Run together, three open-source tools produce most of a first cryptographic
inventory for network listeners and container images: testssl.sh for TLS,
ssh-audit for SSH, and cbomkit-theia for certificates and keys inside images.
On the four-service slice they find 22 of 23 items on the wire and 7 of 10 in
images; on the eight-service estate, 38 of 40 and 14 of 20, the two wire
misses being keyed out of reach. A harness built on top of them finds the
same wire items. What it adds is in the images and in the structure: its own
reader of key material finds what theia cannot read — an ML-DSA certificate
and its key, a PKCS#12 keystore, DSA and Ed25519 host keys — and its rules
say which wire finding and which file are the same key, which certificate in
an image is not served by anything (while leaving a certificate authority's
alone), and what each listener's posture is. On the estate that is 20 of 20
image items against 14, two decoys avoided against two flagged, and nine
postures stated against none.

## The concept: three layers, three kinds of tool

A cryptography bill of materials (CBOM) is an inventory of cryptographic
assets: algorithms, keys, certificates, protocols, each with where it was
found. Evidence for it comes from three layers:

| Layer | What is observed | Tool here |
|---|---|---|
| Wire | What a listener negotiates when a client connects | testssl.sh (TLS), ssh-audit (SSH) |
| Host | Files in an image or on a disk: certificates, keys, configuration | cbomkit-theia |
| Code | Calls to cryptographic libraries in source | CBOMkit's source scanners (Java, Python, Go) — not yet run in this project |

No single tool spans the layers. CBOMkit, the open-source CBOM toolset, does
not scan networks, so against a wire-only estate it scores zero by
construction. That makes "better than CBOMkit" an empty comparison for
anything that includes a network scanner. The comparison that means something
is against all the scanners run together with no harness.

## The mechanism: how the comparison is made fair

An answer key lists what a perfect inventory holds. Each item has a class:
*present* (planted, findable), *decoy* (looks like a finding, is not),
*out-of-reach* (real, but no scan can see it) or *supplied* (can only be typed
in). Out-of-reach items stay in the denominator and are reported as known
misses. A reported decoy is a false positive. So is a claim, on a keyed
listener, of a key-establishment or signature algorithm the key does not hold.

Three inventories are scored from one scan:

- **CBOMkit alone** — cbomkit-theia's findings only.
- **Scanners alone** — every tool's findings, unioned, with names normalized
  and duplicates folded, and nothing else.
- **Workbench** — the same findings plus the output of three rules.

Both baselines pass through the same normalizer as the workbench, so they are
scored on what the tools said in one vocabulary. That is generous to the
baselines: name normalization and de-duplication are credited to them.

## Worked example

The estate: two TLS listeners (one classical, one offering a hybrid group) and
two SSH listeners (OpenSSH 6.6 and OpenSSH 10.0), with their four images.
Measured 2026-10-03 on an x86_64 lab server.

| Layer | CBOMkit alone | Scanners alone | Workbench |
|---|---|---|---|
| Wire, of 23 | 0 | 22 | 22 |
| Host, of 10 | 7 | 7 | 7 |
| Host decoy flagged | yes | yes | no |
| Listener posture, of 4 | not stated | not stated | 4 |

**What the scanners got right.** Both wire tools report post-quantum hybrids
by name: testssl.sh lists X25519MLKEM768 under its KEM line, and ssh-audit
lists `mlkem768x25519-sha256` and `sntrup761x25519-sha512`. Every classical
key-exchange group and every host-key type on all four listeners was found.

**What they missed, and why.**

| Miss | Layer | Reason |
|---|---|---|
| What the legacy SFTP server offers when it connects *out* | Wire | No listener shows it; only traffic capture beside the client would. Keyed as out-of-reach |
| DSA host key file | Host | cbomkit-theia reports it as "private-key" with no algorithm. The workbench does not guess one |
| Two Ed25519 host key files | Host | cbomkit-theia 1.1.2 reported neither; both are in OpenSSH's own key format |

**The decoy.** One image holds a second certificate, RSA-1024 with SHA-1,
that no listener serves. cbomkit-theia reports it identically to the served
certificate, as it should: it reads files. The workbench compares the public
key of each certificate served on the wire with each certificate found in the
image, links the ones that match, and marks the unmatched one, and everything
read from that file, as not in use. It makes that judgement only when every
listener of that image was scanned and each served certificate was found in
the image; otherwise it says nothing.

**What the rules add.**

| Rule | Adds |
|---|---|
| Link by public key | "The certificate at 172.16.106.10:443 is the file `/etc/nginx/tls/portal.crt` in this image" — the first link of a dependency chain, with the hash as evidence |
| In use or not | Separates what an image *contains* from what a service *uses* |
| Posture | Per listener: classical, mixed (post-quantum key exchange, classical authentication) or post-quantum |

**Cost.** A targeted TLS scan takes 27 to 46 s per listener; SSH takes 2 to 3
s. An image scan takes 71 to 96 s for images of a few megabytes, nearly all of
it in cbomkit-theia's secrets plugin, which reads a file once for every symlink
that points to it — Alpine's BusyBox has 304
([lesson 09](../lessons/09-time-a-scanner-on-the-bare-base-image.md)). Image
contents change only when an image does, so those results are replayed from
the ledger with their original timestamps, and a routine re-scan takes as long
as its slowest TLS listener.

**The baseline is the tool's own document.** Scored with no normalizer at all,
cbomkit-theia's own CBOM files give the same 7 of 10 and the same flagged decoy
as the projected baseline — once a reader follows theia's own reference from a
certificate to its key. Read by component name alone they give 5 of 10,
because theia names a certificate by its subject, not its algorithm.

## Beyond the slice: what each scanner can see

A second set of targets was built to ask the questions the slice does not:
a TLS 1.3 server with an ML-DSA-65 certificate, Postgres 18 over its in-protocol
TLS upgrade, RabbitMQ 4 and Kafka 4.1 over TLS, a listener that demands a
client certificate, a client watched passively by Zeek, and one Ruby call
site. Each tool ran on x86_64 and again as arm64 under emulation.

| Capability | testssl.sh | OpenSSL sweep | ssh-audit | cbomkit-theia | Zeek | Opengrep |
|---|---|---|---|---|---|---|
| Hybrid told from classical, TLS | yes | yes | — | — | yes (x86_64) | — |
| Hybrid told from classical, SSH | — | — | yes | — | — | — |
| ML-DSA-65 certificate | yes, on the wire | yes, on the wire | — | **no**: drops the file | — | — |
| Postgres over its TLS upgrade | yes | yes | — | — | — | — |
| RabbitMQ, Kafka over TLS | yes | yes | — | — | — | — |
| Client-certificate listener | yes | yes | — | — | — | — |
| A client's offered groups | — | — | — | — | yes (x86_64) | — |
| A Ruby call site | — | — | — | — | — | yes, one rule |

The open-source wire tools are further along than expected: testssl.sh reads
an ML-DSA certificate even though its own bundled OpenSSL predates ML-DSA. The
weak point is the file layer. Neither broker offered any post-quantum group,
so on those images a hybrid requirement cannot be configured at all — a
migration fact, not a scanner gap.

Two limits of this table. A list of accepted groups is not the whole of key
establishment: in TLS 1.2 a server may also accept RSA key transport, where
the client encrypts the session secret to the server's RSA key and no group
is involved. The Postgres target, configured with the hybrid group and
X25519, still accepts it. A scan that reports groups reports that server as
"hybrid and X25519"; anyone recording its traffic needs only the server's RSA
key, later. An inventory of key establishment on a TLS 1.2 listener needs the
cipher suites as well as the groups. The harness's TLS scan therefore asks
testssl.sh for every cipher suite as well (`-E`), which costs 9 to 17 s more
per listener on the slice, and reports each `TLS_RSA_WITH_*` suite as key
establishment by RSA. On the slice's portal — an RSA certificate, TLS 1.2
allowed, only ECDHE suites configured — it correctly reports none; that
listener is the answer key's wire decoy for exactly this inference. And a "yes" in the table means the two
wire tools agree with each other and with what the target was configured to
offer; for the two brokers, whose group lists are their runtimes' defaults,
it means the tools agree. A server's own account is not a third witness:
RabbitMQ lists three Brainpool TLS 1.3 groups it then refuses on the wire.

Three times testssl.sh looked wrong and the reference was wrong instead
([lesson 10](../lessons/10-a-group-is-accepted-when-it-is-negotiated.md)): a
comparison of scanners is only as good as its reference probe.

## Other open-source tools, tried and not adopted

Three more free tools were tried on the same terms — pinned image, run on the
workbench's networks or offline, judged against what they should find:

| Tool | What it should find | What it did | Decision |
|---|---|---|---|
| sslyze 6.2.0 | the groups each TLS listener accepts | lists no post-quantum group; reports a hybrid-only listener as no TLS at all; reported secp256r1 rejected where a direct P-256 handshake completed | not adopted for key establishment; testssl.sh stays, and the second witness stays OpenSSL 3.5 probes |
| cdxgen 11.11.0, CBOM mode | crypto call sites in Java and Python | none, offline, in either pinned repository | not adopted: needs a build and the network |
| sonar-cryptography 1.6.1 (CBOMkit) in SonarQube | crypto call sites in Java, Python, Go | none: Python coverage is pyca/cryptography only, which the Python repository does not use; Java needs compiled classes | not adopted while third-party repositories are never built; the right tool for a team scanning its own built code |

The pattern is the one a reader should test for in any tool: silence is not a
finding until the tool has been shown something it should report. All three
were silent where the planted or labelled material says otherwise.

## Any tool's CBOM, scored

Federal agencies inventory with commercial discovery tools. Rather than pick
among them, the workbench imports any tool's CycloneDX CBOM as evidence
(`pqch import`): each entry is placed on a scoped listener, a file in a named
image or a call site in a pinned repository, named the way the workbench names
its own, and scored against the answer key. Entries the importer cannot place —
the CycloneDX project's own CBOM examples have no locations — are kept in the
import's record by name and not counted. cbomkit-theia's own CBOMs, imported
this way, score exactly what its native reader scores.

## What follows

- **Start with the free scanners.** For listeners and images they give most of
  an Enumerated-rung inventory with no harness at all.
- **Expect noise at the host layer.** This estate's images had their system
  trust stores removed so the key could be exact. The base images they are
  built from carry 148 (Ubuntu 14.04) and 121 (Alpine 3.22)
  certificate-authority certificates, and a file scanner reports every one.
  Telling "contains" from "uses" is the first real problem there.
- **Check each scanner against a known target before trusting an absence.** A
  tool that does not parse one key format reports nothing, which reads the
  same as "none present".
- **State the delta honestly.** At this rung a harness earns its place by
  structure and by what it enables next — tracing, prioritizing, verifying a
  change — not by finding more.

## What the harness adds at M1: its own reader of files

cbomkit-theia stays the candidate generator and the baseline for the image
layer. Beside it the runner runs the harness's own reader (`pqch
image-files`) from its own image, with no network, over the same archive:
it walks the image's layers, honouring whiteouts, reads PEM and DER
certificates (ML-DSA included), private and public keys (OpenSSH included),
Diffie-Hellman parameters and PKCS#12 keystores — trying no password, the
empty one and the Java default, and recording which opened the store — and
writes on every certificate whether it is a certificate authority's
(basicConstraints CA with keyUsage keyCertSign,
[lesson 28](../lessons/28-read-a-certificates-ca-flag-with-its-key-usage.md))
and on every file which configuration files name it. It is in neither
baseline, so the scanners-alone column is still exactly the tools. On the
eight images it took 1 to 8 s each where theia took 75 to 136 s, and it is
what closes the image layer from 14 of 20 to 20 of 20.

## Scope

Covered: eight services and nine listeners (TLS 1.2 and 1.3, TLS behind
PostgreSQL's upgrade, SSH), wire and image layers, pinned tool versions
(testssl.sh 3.2.4, ssh-audit 3.9.0, cbomkit-theia 1.1.2) and the harness's
own reader, on x86_64. The four-service numbers are from 2026-10-03.

Also covered, outside the slice and its answer key: Postgres, RabbitMQ and
Kafka over TLS, a client-certificate listener, an ML-DSA-65 certificate, a
client's offered groups, one Ruby rule — each tool on x86_64 and on arm64
under qemu-user emulation (spike S2).

Not covered: symmetric ciphers and MACs in a suite (the scan reads suites
only for RSA key transport); CBOMkit's source scanners on real code (the
key's five code-layer decoys are untested, the code layer is not scanned);
Java keystores in JKS format (reported as unopened); UDP protocols; Zeek on
arm64 (packet capture does not run under emulation); the M1 images under
arm64. Arm64 results are from emulation, not a native arm64 host.

## References

- `agency/answer-key.yaml` — the items, classes and matching rules.
- `eval/README.md` — how the two baselines are constructed; `eval/score_raw_theia.py`.
- `spikes/s2/README.md`, `results.md`, `results/matrix.md` — the targets, the
  predictions written before the run, and every cell's evidence.
- `docs/fable-review/M0-review.md` F-32 to F-36 — what was found wrong with
  the first scorer and key, and what was changed.
- PQCA, *CBOMkit architecture* — what CBOMkit covers.
- OWASP CycloneDX, *Authoritative Guide to CBOM* — asset types.
- Related: [what the CBOM workbench is](00-what-the-cbom-workbench-is.md);
  [lesson 05, penalize what an inventory invents](../lessons/05-penalize-what-an-inventory-invents.md);
  [lesson 08, identify a key by its public-key hash](../lessons/08-identify-a-key-by-its-public-key-hash.md).
