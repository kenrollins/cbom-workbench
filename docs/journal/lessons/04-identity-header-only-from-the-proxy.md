---
id: lesson-04-identity-header-only-from-the-proxy
type: lesson
title: "Believe an identity header only on a connection from the proxy that sets it"
date: 2026-10-04
audience: [architect, engineer]
tags: [verification]
rung: managed
one_line: "A forward-auth proxy strips and sets the user header, but an upstream that listens where anything else can reach it will accept the same header typed by hand."
claims:
  - text: "Two HTTP requests sent straight to the upstream from another container on the same VLAN, carrying a hand-written sign-on header, proposed and approved a change; it was applied and recorded as a single-sign-on approval."
    provenance: "measured 2026-10-03, lab VLAN 13, xr7620; M0A review F-45"
  - text: "With the header honoured only from the proxy's address, the same requests from another peer return 403; an approval made through the front door records the signed-on user."
    provenance: "measured 2026-10-03 and 2026-10-04, same deployment; change 01M43EN2B4ZVTSKAPG0WZTNZXT"
reuse: [talk, customer-question]
---

# Believe an identity header only on a connection from the proxy that sets it

## The rule

An application behind a forward-auth proxy accepts the proxy's identity
header only when the connection comes from the proxy's own address, and
treats it as absent from anywhere else. With no proxy address configured, it
accepts none.

## Why

In forward auth, a reverse proxy asks an identity provider whether a request
is signed on, and if so copies the provider's headers — the user name, the
groups — onto the request it forwards. A careful proxy also deletes those
headers from the incoming request first, so a client cannot supply its own.

All of that protects the path *through the proxy*. The application itself
still listens on an address, and anything else that can reach that address
bypasses the proxy and can send any header it likes. On a shared network
segment that is every neighbour.

Measured: an application that took the approver's name from
the sign-on header the proxy sets on any request. From a neighbouring container, two
plain HTTP requests with a made-up name proposed a configuration change and
approved it. The change was applied to a running service, and the audit log
recorded an approval "authenticated by single sign-on". Every downstream
control — a signed checkpoint, a runner that checks for an approval before
acting — accepted it, because the approval event was well formed.

## When it applies

Any service that makes an authorization decision from a header set by a
proxy: forward auth (Authelia, oauth2-proxy and the like), a service mesh
sidecar, a cloud load balancer's identity headers. It matters most where the
decision is consequential — approving a change, not rendering a filtered page.

It is a floor, not a full answer. Whoever can originate connections from the
proxy's address — the proxy host itself, or an attacker able to take over
that address on the segment — can still forge the header. A decision that
must survive that needs a credential the application verifies itself: a
signed token from the identity provider, or a signature by the approver's own
key.

## How to apply it

```python
# the peer address, not a forwarded-for header
TRUSTED = {a for a in os.environ.get("TRUSTED_PROXIES", "").split(",") if a}

def identity(request):
    if request.client.host not in TRUSTED:
        return None
    return request.headers.get(IDENTITY_HEADER) or None
```

Default to an empty list, so a deployment that forgets to configure it cannot
approve anything rather than trusting everyone. Refuse a state-changing
request whose `Origin` is another site. Record in the audit event *how* the
identity was established, in words a reader can check. Then test it from a
peer that is not the proxy: the request must fail, and the page must offer no
action.

Better still, do not give the application an address neighbours can reach.
Where the platform requires one, the peer check is the control.
