---
id: note-05-what-can-be-seen-on-the-wire-host-and-code
type: note
title: "What can be seen on the wire, on a host and in code — and what cannot?"
date: 2026-10-21
audience: [architect, engineer]
tags: [discovery, wire, capture, enumerated]
rung: enumerated
one_line: "A targeted wire scan shows what one listener accepts; passive capture shows what every client offers and every server chooses across an estate, but not a TLS 1.3 certificate; host and code evidence show what is installed and written, not what runs. Each layer answers a different question, and a cryptographic inventory needs all three."
claims:
  - text: "In TLS 1.3 the server's certificate is sent encrypted, so passive capture sees the negotiated key-exchange group and version but never the certificate."
    provenance: "cited: RFC 8446 §4.4.2 (Certificate is in the encrypted handshake)"
  - text: "In 18F/identity-idp at commit 62cf387, a twelve-pattern Ruby rule pack matched 85 candidate lines under app/, lib/ and config/; the call-site-read role (Gemma 4 31B FP8 on four L4s, reasoning on, three calls each) judged 79 live cryptographic uses and 6 not — a documentation comment and five exception handlers — agreeing within its three calls on 75; both candidates that are spike S3 labelled sites matched their labels; median 16.3 s a call."
    provenance: "measured 2026-10-21 on the xr7620, scan-code run 01M5FJH69143N17Q6PCF782P8R; policy/code-rules/ruby.yaml"
reuse: [whitepaper, talk, customer-question]
---

# What can be seen on the wire, on a host and in code — and what cannot?

## The answer

Three kinds of evidence feed a cryptographic inventory, and each answers a
question the others cannot. A **targeted wire scan** asks one listener what it
accepts — every group, every suite, every version, its certificate — and gets
a complete answer for that listener and nothing about its clients. **Passive
capture** of a network's traffic shows what every client *offers* and what
every server *chooses* in real handshakes, across the whole estate at once,
including clients and servers nobody listed; it cannot see what a server
would accept but was never asked for, and in TLS 1.3 it cannot see the
server's certificate at all. **Host and code evidence** — files in images,
call sites in source — shows what is installed and written, which is where a
wire finding gets traced to a line that must change, but not whether any of it
runs or is reachable. The inventory OMB M-26-15 asks for names all three
(Appendix A §6). A scan of the listeners alone misses the clients that can
never do post-quantum key exchange, and a capture alone misses every
certificate behind a TLS 1.3 listener.

## The concept

A TLS handshake begins with the client listing what it supports — key-exchange
groups in order of preference, signature algorithms, protocol versions — and
the server choosing one of each. A hybrid post-quantum group such as
X25519MLKEM768 combines a classical exchange with ML-KEM, so the session is
protected if either holds. Whether a session is post-quantum is therefore
decided twice: the client has to offer a hybrid group, and the server has to
choose it. An inventory that sees only one side cannot say which side is the
obstacle.

Passive capture is the only way to see the client side without touching the
client: a switch mirror copies every frame crossing a trunk to a port where a
sensor (Zeek here) parses the handshakes and records what each side said.
Nothing is sent. The sensor's port has no address.

## The mechanism: what each layer yields

| Evidence | Sees | Does not see |
|---|---|---|
| Targeted wire scan of a listener (testssl.sh, ssh-audit, paired probes) | Everything the listener accepts: every group, suite and version, the certificate chain and its key, whether the old algorithm is still accepted after a change | Any client; which of the accepted options are ever used; listeners not in the scope |
| Passive capture at a mirror (Zeek) | For every real handshake: the client's offered groups, versions and signature algorithms, the server's chosen group and version, the server name; SSH key exchange and host-key algorithms as negotiated; every client and server that spoke, listed or not | What a server would accept but was not offered; TLS 1.3 certificates; anything that did not cross the mirrored trunk; frames the mirror dropped |
| Host evidence (cbomkit-theia on images and hosts) | Keys, certificates and libraries present in files, with their parameters | Whether a file is served or loaded; what a running process negotiates |
| Code evidence (CBOMkit source scanners, rule packs) | Call sites: which algorithm a program asks a library for, and where | Runtime configuration that overrides the code; what the deployed binary does |

**What a code rule finds, and what it cannot decide.** A rule pack matches
lines that name a cryptographic library: `OpenSSL::PKey::RSA`, `Digest::SHA256`,
`JWT.decode`. A match is a candidate, not a use. In `18F/identity-idp` at its
pinned commit, a Ruby pack of twelve patterns matched 85 lines under `app/`,
`lib/` and `config/`. A model reading each line in its context
(the `call-site-read` role: Gemma 4 31B with reasoning on, three calls each)
judged 79 to be live cryptographic uses and 6 not: a documentation comment,
and five exception handlers (`rescue OpenSSL::Cipher::CipherError`) that name
a library class and call nothing. Its three calls agreed on 75 of the 85 and
split two to one on the other 10. On the two candidates that are among spike
S3's labelled call sites, its judgement matched the label. The judgement is
the CBOM's `pqch:in-use` for each code entry, labelled as the model's.

Two details of the capture layer matter in practice:

- **The VLAN tag on a connection is the originator's.** A mirror of a trunk
  carries each frame with the tag of the segment it was on when it reached
  the trunk, and the sensor records the tag of the first packet, which the
  client sent. A listener's own VLAN is not in the capture; it is inferred
  from the tags the clients on its subnet carried, and labelled as inferred.
- **Capture loss must be measured, and offload turned off.** A trunk is
  usually faster than the mirror port; the sensor counts gaps in TCP streams
  as loss. With generic receive offload on, the network card merges segments
  before the sensor sees them, and those merges are counted as loss too, so the
  figure can read many times what the host actually dropped. Every count from
  a capture is reported beside its loss figure.

## One inventory from two layers

The capture and the targeted scan are not two reports to read side by side.
Each observation becomes a CBOM entry named by its fingerprint — what the
asset is and where it is, not which tool saw it — so the same key exchange on
the same listener is one entry whether Zeek saw it chosen or testssl.sh found
it accepted. Merged, that entry carries both tools and both ledger events, and
a listener's entries together give the readings a planner needs without
anyone lining up two reports: a hybrid group accepted and never chosen, a
server that accepts none while its clients keep offering one.

## Scope

Covered: TLS and SSH handshakes as Zeek's `ssl`, `ssh` and `x509` logs and a
handshake-level script record them; the three evidence layers as this project
uses them.

Code: one repository, one language, twelve patterns; the candidates are only
as complete as the pack, and no CBOMkit source scanner has run yet. The
model's judgements were not checked line by line beyond the six rejections and
the two labelled sites.

Not covered: traffic that never crossed the trunk (two devices on one VLAN
talking directly); QUIC and DTLS; encrypted client hello, which would hide the
server name; what a mirror by VLAN rather than by trunk would add; client
certificates; the signature algorithms clients offer, which the sensor records
but this note does not analyze.

## References

- OMB M-26-15, Appendix A §6 — the central CBOM and its three evidence sources.
- RFC 8446, *The Transport Layer Security (TLS) Protocol Version 1.3*, §4.4.2
  — the Certificate message is encrypted.
- Zeek documentation: `base/protocols/ssl`, `policy/protocols/conn/vlan-logging`,
  `policy/misc/capture-loss`.
- `capture/README.md` and `src/pqch/scout/zeek/posture.zeek` in the
  repository — the capture as built; `spec/interfaces.md` — the `client`
  subject and the scope's capture points.
- Related: [what "verified" means](08-what-verified-means.md);
  [what the open-source scanners cover](15-what-the-open-source-scanners-cover.md).
