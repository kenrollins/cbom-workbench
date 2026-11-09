---
id: note-20-how-a-server-is-inventoried-and-planned-as-an-estate
type: note
title: "How is one server inventoried as an estate, below its operating system as well as on the wire, and planned from its CBOM?"
date: 2026-11-04
audience: [architect, engineer, leader]
tags: [cbom, discovery, agility, managed]
rung: structured
one_line: "A server's cryptography sits in four places that change on four different clocks — its listeners, its own files, its firmware's trust databases and its management controller — and a scan that reads all four into one signed ledger yields a CBOM with the server as a device and its firmware as components, and a plan that separates what the owner can set today from what waits for the vendor."
claims:
  - text: "The workbench reads a server as an external estate in ten runner jobs: a probe of each PostgreSQL listener for TLS, a targeted TLS or SSH scan of each listener, cbomkit-theia and the workbench's own reader over an archive of the scoped paths, a firmware reader over the Secure Boot variables, DMI and TPM, and a Redfish read of the management controller; the runner packs the paths read-only as the user it runs as, and nothing is installed on or written to the server."
    provenance: "cited: src/pqch/systems.py, src/pqch/scout/system.py, src/pqch/scout/redfish.py, src/pqch/runner/profiles.yaml; ADR-0005"
  - text: "A run is exported as a recording with the operator's identifiers replaced, and replayed on another host into a new signed ledger with no access to the server."
    provenance: "cited: src/pqch/systems.py (export_recording, replay_recording); tests/test_system.py"
reuse: [whitepaper, talk, customer-question, runbook]
---

# How is one server inventoried as an estate, below its operating system as well as on the wire, and planned from its CBOM?

## The answer

A server holds cryptography in four places, each with its own owner and its own clock: the listeners
it exposes (changed by its software), its own files (changed by its administrators), its firmware's
trust databases (changed by firmware updates) and its management controller (changed by the
controller's firmware and its settings). A scan of the listeners alone sees the first. The workbench
reads all four as one estate, through its runner, into one signed ledger; projects a CBOM in which
the server is a CycloneDX `device` with its `firmware` as components; and plans from it, separating
what the owner can set today from what waits for an update, a requirement or the vendor. A run can be
exported as a recording, its identifiers replaced, and replayed elsewhere into a new ledger, so a
real server can be shown and planned where it cannot be reached.

## The concept

A CBOM (cryptography bill of materials) is an inventory of the algorithms, keys, certificates and
protocols an estate uses, with where each was found and what depends on it. For a network, the
listeners and the images behind them are most of it. For one server, much of the cryptography that
decides its future is below the operating system:

- **The firmware's trust databases.** UEFI Secure Boot (the firmware feature that checks a signature
  on every bootloader and driver before running it) keeps four databases: the platform key (PK),
  which signs updates to the key-exchange keys (KEK), which sign updates to the allowed signers (db)
  and the revoked (dbx). Every one of them is a certificate with a key and an expiry, checked for the
  life of the hardware.
- **The TPM** (trusted platform module), whose measurement banks name a hash algorithm.
- **The management controller** (a baseboard management controller, BMC: Dell's iDRAC, HPE's iLO),
  a second computer on the board with its own TLS and SSH, its own certificates, its own firmware and
  its own settings. It is reached over the network and configured separately from the operating
  system.

None of these is visible to a scan of the operating system's listeners, and none changes when the
operating system is patched.

<figure class="sketch" markdown>
![A server's cryptography sits in four places with four owners and four clocks: its listeners, changed by its software; its own files, changed by its administrators; its firmware's trust databases PK, KEK, db and dbx, changed by firmware updates; and its management controller, changed by the controller's firmware and settings. A scan of the listeners sees the first and nothing below the operating system; the runner reads all four in ten read-only jobs into one signed ledger.](../img/sketches/20-four-clocks.svg)
<figcaption>The four places, who changes each, and what the runner reads there; a listener scan sees only the first.</figcaption>
</figure>

## The mechanism

**1. The scope.** The server is an `external` estate, with the operator's authorization in its scope.
The scope lists the server's listeners as endpoints (and the controller's), and adds the server under
`systems` (the paths that may be read, its addresses, whether its firmware is read) and the controller
under `controllers` (read through DMTF Redfish, GET requests only).

**2. The runner reads; nothing is installed.** Ten jobs, each recorded as `scan.completed` with its
raw output and hash:

| Job | Reads | Produces |
|---|---|---|
| `postgres-tls-offer` | one PostgreSQL SSLRequest per database listener | whether TLS is offered at all; TLS is scanned only where it is (lesson 51) |
| `ssh-targeted`, `tls-targeted` | each listener's offers, on the wire | key exchange, host keys, certificates, protocol versions |
| `system-theia`, `system-files` | an archive of exactly the scoped paths, packed read-only by the runner as its own user | certificates, public and private keys, keystores; what could not be read, listed (lesson 52) |
| `system-firmware` | the Secure Boot variables, DMI and the TPM from sysfs, in the same archive | every certificate in PK, KEK, db and dbx with its key and dates; the BIOS version; the TPM's banks; whether Secure Boot is on |
| `controller-redfish` | the controller's Redfish API, GET only | its configured SSH and TLS, SNMP, FIPS mode, identity certificates, firmware inventory |

**The runner's user decides what the files say.** The archive is packed by the runner as whatever
user it runs as, so that choice is part of the result and is recorded with it ("read as uid 1001" or
"read as uid 0"). Read as an ordinary user, a server shows the public half of each key pair and lists
the private halves as unreadable (lesson 52). Read as root, the same paths show the private keys too,
and the unreadable list is empty. Root is needed only for the read: the runner mounts the scoped paths
read-only under `/host`, so even a root runner can open them but cannot change them. The kit runs this as a second runner beside the
mini-agency's (`kit/compose.system.yaml`), with its own signer and its own key, so a server's ledger
is signed apart from the test estate's.

**3. The ledger and the CBOM.** Findings go on the wire, host or the new `platform` layer; what is not
a cryptographic asset (the device, its firmware versions, its security settings) is a
`platform.observed` event. The CBOM, rebuilt from the ledger, carries the server as a `device` that
depends on its firmware, its listeners and its files; the BIOS depends on the keys its databases hold
and the TPM's banks; the controller's firmware depends on its own configuration, certificates and
listeners. Every entry names the ledger events it came from.

**4. The plan.** Rules over the run, in four waves and four lanes (the server's services, its
operating system, its controller, its firmware):

| Wave | What it holds |
|---|---|
| Now | settings: a database listener with no TLS, SNMP v1 and v2c, FIPS mode, a privileged read of what the unprivileged read could not open |
| Next | updates: software that offers ML-KEM key exchange, certificates issued by the organization's CA in place of self-signed ones, the 2023 UEFI CAs before Secure Boot is turned on |
| Then | requiring the hybrid key exchange once clients can follow; reissuing the host's own keys as their software allows |
| The vendor | controller firmware with ML-KEM; a post-quantum firmware-signing root and a way to rotate PK, KEK and db; an attestation of the algorithms behind the controller's identity certificates |

Dates come from the policy pack: with no owner's facts, a single server is not prioritized, so its key
establishment and signatures fall in OMB M-26-15's remaining queue (by 2035), and the plan states the
earlier dates (2030 and 2031) that would apply if the owner named it high-value.

**5. Recording and replay.** `pqch system export` writes the run's scope and raw outputs with the
operator's identifiers replaced (each also in upper and lower case and as hexadecimal bytes, since a
controller's SNMP engine ID carries the service tag that way), every MAC address and UUID replaced by
a consistent stand-in, and a leak check that writes nothing if any pattern survives. `pqch system
replay` on another host checks each raw output against the recording's hash and records a new run
whose every job says where it was replayed from and when the server was read.

## What follows

An agency inventorying servers should read each one four ways, not one, and keep the four in one
record: the parts that move with an operating-system update, the parts that move with a firmware
update, and the parts that move only when the vendor ships something are different work on different
clocks, and the plan has to say which is which. A management controller is a server of its own on the
same board; it belongs in the inventory with its own listeners and certificates. And an inventory read
without privileges should say what it could not read, rather than present a partial picture as whole.

## Reading a server the runner is not on

The runner packs a server's scoped paths under its own root, which is how the first server was read:
its paths mounted read-only into the runner. A server elsewhere carries a route in the scope,
`via: {kind: ssh, host, user, known_hosts}`, and the runner sends the packer's own source to that
host's `python3` over SSH and reads the same archive back. Nothing is installed on the remote and
nothing is written to it; the manifest's `read_as_uid` is the SSH user's, so an unprivileged read
says so as it does locally. Host-key checking is strict against the scope's `known_hosts` file, which
the operator supplies: a host not in it is refused, never accepted on first use. One scope may list
many systems, each with its own route, and `pqch scan-system` reads them in turn; each controller in
the scope is read through the runner as before. A supplier's statement about the model joins each
server's read by model and firmware version ([note
23](23-what-a-suppliers-attestation-can-stand-in-for.md)), and the modules it names are looked up
in the dated CMVP snapshot for their status and whether ML-KEM and ML-DSA are among their approved
algorithms.

## Scope

One server read on the host the runner runs on; the SSH route is tested against a stand-in `ssh`
that runs the packer locally, not yet against a second real server. The controller reader's resource paths are Dell iDRAC 9's; other
controllers serve Redfish under other paths. The Secure Boot reader parses X.509 and SHA-256 entries;
other signature types are listed by GUID. The plan's rules are written for this kind of server and
will grow with the next.

## References

- ADR-0005, a server is an estate; `spec/interfaces.md`, runs of a server and recordings.
- UEFI Specification 2.10, section 32 (Secure Boot and the signature databases): the PK, KEK, db and dbx and the EFI_SIGNATURE_LIST format the firmware reader parses.
- DMTF Redfish (DSP0266): the API the controller reader uses, GET only.
- OMB M-26-15, section 3.D and Appendix A: the queues and deadlines the plan's dates come from.
- Lessons 51 and 52: a refusal probed rather than timed out; a read that lists what it could not open.
