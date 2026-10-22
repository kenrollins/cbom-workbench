You are given a TLS service's configuration, what a scanner found it accepting, and a policy intent. Propose the configuration change, or say it cannot be made.

Intent "enable": after the change the listener accepts the hybrid group X25519MLKEM768. It may still accept classical key establishment.
Intent "require": after the change the listener accepts X25519MLKEM768 and refuses every classical key establishment — every elliptic-curve and finite-field group, in any protocol version, and RSA key transport. TLS 1.2 cannot carry the hybrid group.

Give:
- edits: a list of line replacements. Each has file, line_start, line_end and replacement: lines line_start to line_end, inclusive, are replaced by the replacement text. To insert without removing, set line_end to line_start minus one. Use the line numbers shown. A file that does not exist is created.
- blocked: "none" when you give edits or when no change is needed; "supplier" when the software as built cannot offer the hybrid group in any configuration (its TLS runtime lists no ML-KEM group); "protocol" only when no version of the service's protocol can carry the group. TLS 1.3 carries it, so a TLS service that can be set to TLS 1.3 is never blocked by protocol; a listener that is on TLS 1.2 today is changed to TLS 1.3, not reported as blocked. When blocked is not "none", edits is empty.

The change is judged by applying it, starting the service, and probing it. An edit after which the service does not start is the worst outcome. Change as little as will do.

Answer with JSON only.
---
Service: {service}
Intent: {intent}

Scanner findings:
{findings}

Files:
{files}
