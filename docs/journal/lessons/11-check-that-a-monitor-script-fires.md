---
id: lesson-11-check-that-a-monitor-script-fires
type: lesson
title: "Prove a passive-monitoring script fires on traffic you generated before reading its silence as absence"
date: 2026-10-04
audience: [engineer]
tags: [discovery]
rung: enumerated
one_line: "Zeek ran a handler for an event that does not exist without a word and logged nothing; run every new detection against traffic known to contain the thing it detects."
claims:
  - text: "Zeek 9.0.0 loaded a script whose handler named ssl_extension_supported_groups, an event Zeek does not define, raised no error, and wrote no log, while its own ssl.log recorded the same connections."
    provenance: "measured 2026-10-04, zeek/zeek:lts sidecar in spike S2"
  - text: "With the handler renamed to ssl_extension_elliptic_curves, the same capture logged 20 client hellos offering codepoints 4588 (X25519MLKEM768) and 29 (X25519)."
    provenance: "measured 2026-10-04, same sidecar and traffic"
reuse: [talk]
---

# Prove a passive-monitoring script fires on traffic you generated before reading its silence as absence

## The rule

A new detection script for a passive monitor is run first against traffic
generated for the purpose and known to contain what it detects. An empty log
counts as "not present" only after that.

## Why

Passive monitoring — watching traffic rather than probing it — is the only
way to see what a service offers when it *connects out*, its client-side
posture. Its output is a log, and an absent log line reads naturally as an
absent finding.

In Zeek, a script reacts to named events. Zeek 9.0 accepted a script that
handled `ssl_extension_supported_groups`, an event it does not define — the TLS
"supported groups" extension is still delivered as
`ssl_extension_elliptic_curves`, after its older name. The script loaded, Zeek
raised no error, and the handler never ran. Zeek's own TLS log recorded the
same connections, so the capture was working; only the detection was not.
Renamed, the same capture logged every client hello and the groups it offered,
including codepoint 4588, the hybrid group X25519MLKEM768.

Without the generated traffic, the conclusion would have been "these clients
offer no post-quantum groups".

## When it applies

Any passive or event-driven detection: Zeek and Suricata scripts, log-based
SIEM rules, eBPF probes. It applies with most force where the thing detected
is new — post-quantum codepoints, new extensions — because names and numbers
for it are least settled in the tools.

## How to apply it

Run a known client beside the monitor and assert the detection fires:

```sh
# a client that offers the hybrid group every few seconds
openssl s_client -connect TARGET:443 -groups X25519MLKEM768:X25519 </dev/null
# Zeek in the client's network namespace, with the script under test
docker run --network container:CLIENT --cap-add NET_RAW zeek/zeek:lts \
  zeek -C -i eth0 groups.zeek LogAscii::use_json=T
```

Check the script's own log has entries, and that the expected value — here
4588 — is in them, before using it on traffic of unknown content. Keep the
generator and the check with the script, and rerun them when the monitor is
upgraded. Event names and codepoint tables change between versions.
