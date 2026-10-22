---
id: lesson-29-a-plain-tls-scan-of-an-upgrade-port-is-silent
type: lesson
title: "Give a listener that carries TLS behind a protocol upgrade its own scan profile; a plain TLS scan of its port is silent, not negative"
date: 2026-10-19
audience: [engineer, architect]
rung: enumerated
tags: [discovery, key-establishment]
one_line: "PostgreSQL, SMTP, IMAP, LDAP and others start TLS only after an in-protocol request, so a scanner that opens the port and speaks TLS gets nothing back and reports nothing; the listener's protocol must be named in the scope and bound to a profile that speaks the upgrade, and a scope protocol no profile claims must be visible as unscanned, never as clean."
claims:
  - text: "The mini-agency's records database, scanned by the profile bound to plain TLS listeners, produced no finding and no error; through the profile that speaks the SSLRequest upgrade the same listener yielded the hybrid group, X25519, a 2048-bit DHE group, RSA key transport and its certificate in 91 s."
    provenance: "measured 2026-10-19, testssl.sh 3.2.4 with and without --starttls postgres against 172.16.106.30:5432, xr7620"
reuse: [runbook, whitepaper]
---

# Give a listener that carries TLS behind a protocol upgrade its own scan profile; a plain TLS scan of its port is silent, not negative

## The rule

Name the protocol of every listener in the scope — `tls` only for TLS
from the first byte, otherwise the protocol whose upgrade carries it
(`postgres`, `smtp`, `imap`, `ldap`). Bind each such protocol to a scan
profile that speaks the upgrade, and let the plain TLS profile refuse those
listeners. A listener whose protocol no profile claims is shown as not
scanned; it is never shown as having no cryptography.

## Why

Several protocols begin in the clear and switch to TLS when the client asks:
PostgreSQL's `SSLRequest`, SMTP's and IMAP's `STARTTLS`, LDAP's
`StartTLS` extended operation. A scanner that opens the port and sends a
TLS ClientHello is speaking the wrong language. The server answers in its
own protocol or closes the connection, the scanner finds no TLS, and —
because "no TLS" is a legitimate result for a port — it reports nothing
wrong. Nothing distinguishes this from a listener with no cryptography.
The records database in this project, which accepts RSA key transport and
a server-supplied DHE group as well as the hybrid group its configuration
names, is exactly the listener an inventory most needs to see, and the
plain profile saw none of it.

The fix is not a smarter scanner but an honest scope. The scope says what
each listener is; the runner binds a profile per protocol and refuses a
mismatch, so the silent case cannot occur by accident; and the scan plan
skips a protocol no profile claims and says so, so the gap is on the page
rather than in a column of zeros.

## When it applies

Databases (PostgreSQL, MySQL's own upgrade), mail (SMTP, IMAP, POP3),
directories (LDAP), XMPP, FTP with AUTH TLS, and any service whose TLS is
"optional" in its protocol. It does not apply to listeners that are TLS
from the first byte on a dedicated port (HTTPS, AMQPS, LDAPS, SMTPS), which
the plain profile scans.

## How to apply it

- In the estate's compose file, the `x-pqch.endpoints` entry names the
  protocol: `{port: 5432, protocol: postgres}`. The scope generator carries
  it; the runner's profile `tls-starttls-postgres` claims it and
  `tls-targeted` refuses it.
- testssl.sh speaks the upgrades with `--starttls postgres|smtp|imap|ldap`;
  OpenSSL's `s_client -starttls` does the same for hand probes. Every
  handshake repeats the upgrade, so budget about twice the time of a plain
  scan.
- A wire finding carries the listener's protocol as the scope names it,
  so the rules and the answer key meet it at the same subject.
- Check for the silent case the way lesson 11 checks a monitor: scan a
  listener you know carries TLS behind an upgrade, and confirm the plain
  profile is refused rather than returning an empty result.
