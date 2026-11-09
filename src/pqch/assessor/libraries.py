"""`link/library/1`: the library that provides each cryptographic asset, from the image's SBOM (M9).

An SBOM says which libraries an image carries; the wire says what its listeners do. The two meet
here: for a service whose image's SBOM lists a cryptography-providing library, every asset its
listeners negotiate or serve is linked to that library as the thing that provides it (CycloneDX
1.6's `provides` relation), and the library is marked in use. A library the SBOM lists that provides
nothing observed stays a capability: present, in use unknown. With more than one such library in an
image the rule links the one the capability snapshot names for the service's software when it can,
else all of them as candidates, and says so; it never guesses from a name alone which one served
the handshake.
"""

from __future__ import annotations

from pqch.run import Run

RULE = "link/library/1"


def _norm(s: str | None) -> str:
    return (s or "").lower().replace("lib", "", 1) if (s or "").lower().startswith("lib") else (s or "").lower()


def link(run: Run, capabilities: dict | None = None) -> dict:
    events = list(run.ledger.events())
    sboms = {e["payload"]["image"]: {**e["payload"], "_event": e["id"]} for e in events if e["type"] == "sbom.observed"}
    if not sboms:
        return {"library_links": 0, "libraries": 0, "libraries_in_use": 0}
    svc_of_image: dict[str, tuple[str, str]] = {}
    for e in events:
        p = e["payload"]
        if e["type"] == "link.asserted" and not isinstance(p.get("from"), str) and p["from"].get("kind") == "image" \
                and p.get("to", {}).get("kind") == "service":
            svc_of_image[p["from"]["image"].split("@")[0]] = (p["to"]["name"], e["id"])
    scope = events[0]["payload"]["scope"]
    svc_listeners: dict[str, list[tuple[str, int]]] = {}
    for ep in scope.get("endpoints", []):
        if ep.get("service"):
            svc_listeners.setdefault(ep["service"], []).append((ep["host"], ep["port"]))
    wire = [(e["id"], e["payload"]) for e in events if e["type"] == "finding.observed" and e["payload"]["layer"] == "wire"]
    counts = {"library_links": 0, "libraries": 0, "libraries_in_use": 0}
    for image, sb in sboms.items():
        libs = sb.get("crypto_libraries") or []
        counts["libraries"] += len(libs)
        svc = svc_of_image.get(image)
        if not svc or not libs:
            continue
        name, link_ev = svc
        named = ((capabilities or {}).get("services") or {}).get(name, {}).get("library") or []
        chosen = [lb for lb in libs if any(_norm(lb["name"]) and _norm(lb["name"]) in _norm(n) for n in named)] or libs
        basis_how = ("the capability snapshot names it as the service's TLS library" if chosen is not libs
                     else "the only cryptography-providing library in the image" if len(libs) == 1
                     else f"one of {len(libs)} cryptography-providing libraries in the image; which one served the handshake is not observed")
        listeners = set(svc_listeners.get(name, []))
        assets = [(fid, f) for fid, f in wire if (f["subject"].get("host"), f["subject"].get("port")) in listeners]
        for lb in chosen:
            for fid, f in assets:
                run.ledger.append("link.asserted", {"kind": "rule", "id": RULE}, {
                    "from": {"kind": "library", "image": image, "purl": lb.get("purl"), "name": lb["name"], "version": lb.get("version")},
                    "to": fid, "kind": "provides", "rule_id": RULE, "candidates": len(chosen),
                    "basis": f"{lb['name']} {lb.get('version') or ''} in {image}'s SBOM provides what {name}'s listener "
                             f"{f['subject'].get('host')}:{f['subject'].get('port')} negotiates or serves: {basis_how}",
                }, inputs=[sb["_event"], link_ev, fid])
                counts["library_links"] += 1
            if assets:
                counts["libraries_in_use"] += 1
    return counts
