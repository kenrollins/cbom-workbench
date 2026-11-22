# ADR-0005: A server is an estate — its listeners, its files, its firmware and its controller, recorded and replayable

- **Status:** Accepted
- **Date:** 2026-11-04
- **Deciders:** Ken Rollins
- **Builds on:** ADR-0001 (the ledger is the system of record), ADR-0003 (external estates and the scope)

## Context

The workbench's estates so far are networks: the mini-agency, built with its weaknesses planted and
an answer key, and the lab, a real network seen through a mirror port and targeted scans. Both see a
server as the listeners it exposes. A server's cryptography is not all there. Its own key files sit
on its disk; its firmware holds the keys that decide what it will boot; and a management controller
beside it (a BMC: Dell's iDRAC, HPE's iLO) runs its own TLS and SSH, holds its own identity
certificates, and is configured separately from the operating system. None of that is reached by a
wire scan of the server, and none of it changes when the operating system is patched.

Two further needs come with a real server. Its evidence is the owner's and identifies the hardware
(service tag, serials, MAC addresses), so it cannot be published as it is. And it has to be shown
where the server is not: on a demonstration machine with no route to it.

## Decision

1. **A server is an `external` estate**, with the operator's authorization in its scope like any
   other, and two additions to `pqch.scope/1`: `systems` (the paths that may be read, the addresses
   that are the server's, whether its firmware is read) and `controllers` (its management controller,
   read through DMTF Redfish with GET requests only).
2. **The runner does every read.** It packs exactly the scoped paths, read-only and as the user it
   runs as, into an archive handed to readers with no network, the way an image's archive is handed
   to the image readers. cbomkit-theia reads the archive as a directory; the workbench's own readers
   read key material, and the firmware's identity, TPM and Secure Boot databases. The controller is a
   runner job too. No scanner is installed on the server and nothing is written to it.
3. **A new layer, `platform`**, for what sits below the operating system: the Secure Boot databases'
   certificates, the TPM's banks, the controller's configuration and certificates. Facts that are not
   cryptographic assets (the device, its firmware and their versions, its security settings) are a
   `platform.observed` event, and the CBOM projects them as CycloneDX `device` and `firmware`
   components with dependencies: the device on its firmware, listeners and files; the BIOS on the
   keys it enforces; the controller's firmware on its own configuration, certificates and listeners.
4. **A run is exported as a recording and replayed as a new run.** The export applies the operator's
   map of identifiers (with their case and hexadecimal spellings) and, optionally, replaces every MAC
   address and UUID with a consistent stand-in; it stops if any of the operator's leak patterns
   survives. Replay checks every raw output against the recording's hash and records it again with
   `replayed_from` naming the recording and the original read's time. The new ledger is signed where
   it is replayed; the evidence and its times are the recording's, and every page that shows the run
   says it was replayed and when the server was read.
5. **A server's plan is its own planner**, returning the same structure as the others: lanes per part
   of the server (its services, its operating system, its controller, its firmware), waves from what
   the owner can set today through what waits for the vendor, and the traps a plan from a device list
   falls into.

## Alternatives considered

- **An agent on the server.** Reads everything, including private keys, but is software installed on
  the target, which the project does not do (CLAUDE.md, "Scanners"). The runner's archive covers the
  same ground for what the reading user can open, and says what it could not.
- **Read the controller through IPMI.** Available in-band without credentials, but reports little
  beyond the controller's firmware version; Redfish is the standard interface and carries the
  configuration and certificates.
- **Publish the recording with the repository.** It is the owner's real evidence; recordings live in
  the deployment, never in the repository, like captures and the lab's ledgers.
- **Merge the server's findings into the lab's run.** A chain is bound to one scope (ADR-0001 and the
  ledger's design); a combined view is a projection over several chains.

## Consequences

- A server's CBOM names its firmware, its controller and the keys its boot chain trusts, and its plan
  can say which steps are settings, which are updates and which wait for the vendor.
- A read as an unprivileged user misses private keys the user cannot open; the inventory lists them
  as unreadable, and a privileged read-only pass is a step in the plan.
- Recordings make a real server demonstrable anywhere, at the price of an identifier map the operator
  maintains and a leak check that must know the server's identifiers.
- Reading a remote server's files needs a transport the runner does not have yet (an SSH session
  packing the same paths); the first server read is the host the runner runs on. The controller is
  already read remotely.
