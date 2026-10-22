"""Rules that turn findings into structure. No model; every result is an event.

Four rules, each with an id recorded on the event it produces:

- `binding/scope/1` — per listener: the container the runner found at the
  address during the scan runs the image the scope names for that listener, and
  was the same container at the start and end of the scan. A listener that is
  not bound is still reported, but its evidence is never joined to an image's:
  no link, and no in-use judgement for that image.

- `link/public-key/1` — a certificate or host key seen on the wire and a file in
  an image hold the same public key: `link.asserted`, wire to file, discovered.
- `in-use/served/1`, `in-use/not-served/1` — whether a certificate or key found
  in an image is served by a listener. A certificate is marked not in use only
  when every TLS listener its image serves was scanned, each certificate those
  listeners served was found in the image, and none of them is this one. If a
  listener serves a certificate the image does not hold, the scope's claim that
  this image serves that listener is in doubt and nothing is judged. The
  judgement covers everything read from the same file. A key with no public
  half to compare is left unjudged. Client use is not examined.
- `posture/kex-auth/1` — per listener: `classical` (no post-quantum key
  establishment offered), `mixed` (post-quantum key establishment, classical
  authentication) or `pq` (both post-quantum).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from pqch.run import Run
from pqch.scout import TLS_PROTOCOLS


def load_policy(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text())


def _actor(rule_id: str) -> dict:
    return {"kind": "rule", "id": rule_id}


def _ep_key(subject: dict) -> tuple[str, int]:
    return subject["host"], subject["port"]


def _image_ref(finding: dict) -> str:
    """The digest reference of the image a host finding was read from."""
    return f"{finding['subject'].get('image', '')}@{finding['source'].get('subject_digest', '')}"


def structure(run: Run, policy: dict) -> dict:
    events = list(run.ledger.events())
    scope = events[0]["payload"]["scope"]
    findings = [(ev["id"], ev["payload"]) for ev in events if ev["type"] == "finding.observed"]
    wire = [(i, f) for i, f in findings if f["layer"] == "wire"]
    host = [(i, f) for i, f in findings if f["layer"] == "host"]
    ok_scans = {(ev["payload"]["target"].get("host"), ev["payload"]["target"].get("port"))
                for ev in events if ev["type"] == "scan.completed" and ev["payload"]["status"] == "ok"}
    counts = {"links": 0, "in_use": 0, "not_in_use": 0, "postures": 0, "unbound": 0}

    # Binding: is the listener served by the image the scope says it is?
    scan_ev = {}
    for ev in events:
        if ev["type"] == "scan.completed" and ev["payload"]["status"] == "ok" and "host" in ev["payload"]["target"]:
            t = ev["payload"]["target"]
            scan_ev[(t["host"], t["port"])] = ev
    bound: set[tuple[str, int]] = set()
    for ep in scope["endpoints"]:
        key = (ep["host"], ep["port"])
        ev = scan_ev.get(key)
        if ev is None or not ep.get("image"):
            continue
        b = ev["payload"].get("binding") or {}
        want = ep["image"].split("@", 1)[1]
        if not b.get("image_digest"):
            ok, reason = False, "no container was found at the address"
        elif b["image_digest"] != want:
            ok, reason = False, (f"the container at the address runs {b.get('image')} "
                                 f"({b['image_digest'][:19]}…), not the scope's {ep['image']}")
        elif not b.get("stable", False):
            ok, reason = False, "the container at the address changed during the scan"
        else:
            ok, reason = True, f"{b['container_name']} runs the scope's image"
        run.ledger.append("assessment.made", _actor("binding/scope/1"), {
            "subject": {"kind": "endpoint", "host": ep["host"], "port": ep["port"], "protocol": ep["protocol"]},
            "rule_id": "binding/scope/1",
            "classification": {"bound": ok, "container_id": b.get("container_id"),
                               "running_image_digest": b.get("image_digest"), "scope_image": ep["image"]},
            "basis": reason,
        }, inputs=[ev["id"]])
        if ok:
            bound.add(key)
        else:
            counts["unbound"] += 1

    # Links: the same public key on the wire and in an image.
    linked: dict[str, list[dict]] = {}
    wire_linked: set[str] = set()
    for wid, w in wire:
        if _ep_key(w["subject"]) not in bound:
            continue
        wp = w["asset"]["parameters"]
        for hid, h in host:
            hp = h["asset"]["parameters"]
            basis = None
            if w["asset"]["type"] == "certificate" and h["asset"]["type"] == "certificate" \
                    and wp.get("spki_sha256") and wp.get("spki_sha256") == hp.get("spki_sha256"):
                basis = f"SubjectPublicKeyInfo SHA-256 {wp['spki_sha256']}"
            elif w["asset"]["role"] == "signature" and wp.get("ssh_fingerprint_sha256") \
                    and wp.get("ssh_fingerprint_sha256") == hp.get("ssh_fingerprint_sha256"):
                basis = f"OpenSSH host key fingerprint SHA256:{wp['ssh_fingerprint_sha256']}"
            if basis:
                run.ledger.append("link.asserted", _actor("link/public-key/1"), {
                    "from": wid, "to": hid, "kind": "served-from", "status": "discovered",
                    "rule_id": "link/public-key/1", "basis": basis,
                }, inputs=[wid, hid])
                linked.setdefault(hid, []).append(w)
                wire_linked.add(wid)
                counts["links"] += 1

    # In use, for certificates and keys found in images.
    tls_eps_by_image: dict[str, list[dict]] = {}
    for ep in scope["endpoints"]:
        if ep.get("image") and ep["protocol"] in TLS_PROTOCOLS:
            tls_eps_by_image.setdefault(ep["image"], []).append(ep)
    # A certificate authority's certificate (basicConstraints CA with keyUsage keyCertSign, as
    # the harness's own reader records it) is never the one a listener serves; the rule below is
    # about leaf certificates and says nothing about a CA's file. Which of the files a CA's
    # certificate shares a path with it is: every finding read from that file is left alone.
    ca_files = {json.dumps(h["subject"], sort_keys=True) for _, h in host
                if h["asset"]["type"] == "certificate" and h["asset"]["parameters"].get("is_ca")}
    for hid, h in host:
        if h["asset"]["type"] not in ("certificate", "related-crypto-material"):
            continue
        if json.dumps(h["subject"], sort_keys=True) in ca_files:
            continue
        if hid in linked:
            where = ", ".join(sorted({f"{w['subject']['host']}:{w['subject']['port']}" for w in linked[hid]}))
            run.ledger.append("assessment.made", _actor("in-use/served/1"), {
                "finding": hid, "rule_id": "in-use/served/1",
                "classification": {"in_use": True}, "basis": f"served by {where}",
            }, inputs=[hid])
            counts["in_use"] += 1
            continue
        eps = tls_eps_by_image.get(_image_ref(h), [])
        served = [wid for wid, w in wire if w["asset"]["type"] == "certificate"
                  and _ep_key(w["subject"]) in {(ep["host"], ep["port"]) for ep in eps}]
        if h["asset"]["type"] == "certificate" and h["asset"]["parameters"].get("spki_sha256") and eps \
                and all((ep["host"], ep["port"]) in ok_scans for ep in eps) \
                and all((ep["host"], ep["port"]) in bound for ep in eps) \
                and served and all(wid in wire_linked for wid in served):
            listed = ", ".join(f"{ep['host']}:{ep['port']}" for ep in eps)
            for fid in [i for i, o in host if o["subject"] == h["subject"] and i not in linked]:
                run.ledger.append("assessment.made", _actor("in-use/not-served/1"), {
                    "finding": fid, "rule_id": "in-use/not-served/1",
                    "classification": {"in_use": False},
                    "basis": f"no TLS listener of this image serves it ({listed} scanned); client use not examined",
                }, inputs=[fid] if fid == hid else [fid, hid])
                counts["not_in_use"] += 1

    # Posture, per listener with a successful scan.
    pq_kex = set(policy.get("key_establishment", []))
    pq_sig = set(policy.get("signature", []))
    by_ep: dict[tuple[str, int], list[tuple[str, dict]]] = {}
    for wid, w in wire:
        if w["subject"]["kind"] == "endpoint":
            by_ep.setdefault(_ep_key(w["subject"]), []).append((wid, w))
    for ep in scope["endpoints"]:
        key = (ep["host"], ep["port"])
        if key not in ok_scans or key not in by_ep:
            continue
        items = by_ep[key]
        kex = sorted({w["asset"]["name"] for _, w in items if w["asset"]["role"] == "key-establishment"})
        auth = sorted({w["asset"]["name"] for _, w in items if w["asset"]["role"] == "signature"})
        kex_pq = [k for k in kex if k in pq_kex]
        if not kex_pq:
            posture = "classical"
        elif auth and all(a in pq_sig or a.startswith(tuple(pq_sig)) for a in auth):
            posture = "pq"
        else:
            posture = "mixed"
        subject = {"kind": "endpoint", "host": ep["host"], "port": ep["port"], "protocol": ep["protocol"]}
        run.ledger.append("assessment.made", _actor("posture/kex-auth/1"), {
            "subject": subject, "rule_id": "posture/kex-auth/1",
            "classification": {"posture": posture, "kex_pq": kex_pq,
                               "kex_classical": [k for k in kex if k not in pq_kex], "auth": auth},
        }, inputs=[i for i, _ in items])
        counts["postures"] += 1
    return counts
