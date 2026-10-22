# Passive capture

Zeek on a switch mirror port, for the `external` estate (ADR-0003): what every
client and server on the mirrored VLANs offers and negotiates, from handshakes
alone. `compose.yaml` runs it; `src/pqch/scout/zeek/posture.zeek` is what it
logs — one line per TLS handshake with the client's offered groups, key
shares, signature algorithms and versions and the server's chosen group, next
to Zeek's own `ssl`, `ssh`, `x509` and `conn` logs, rotated hourly.

The interface and the log directory are deployment settings, kept with the
deployment and never here. Captures contain addresses, server names and
certificates of a real estate; they stay in the deployment's state directory
and never enter the repository, the site or the export.
