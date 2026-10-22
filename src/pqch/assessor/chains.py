"""The dependency chain: listener, certificate, service, mission function, data lifetime.

Each link is a `link.asserted` event. Two rules assert the discovered links from
the evidence a scan left on the ledger; the supplied links are read from the
owner's context file and recorded with a human actor and `status: supplied`, so
nothing downstream can mistake a typed-in fact for a discovered one.

- `link/public-key/1` (in `pqch.assessor`): a certificate or host key on the wire
  and the file in an image that holds the same public key.
- `link/service/1`: a listener and the compose service that serves it. Asserted
  only when the scope names the service and the runner found a container at the
  address running the scope's image for the whole scan (`binding/scope/1`); an
  unbound listener gets no service link, and the chain says so. The same
  evidence links the image to the service.
- supplied: mission function, data lifetime and high-value status per service,
  from `agency/context.yaml`, each carrying the file's path and hash as evidence.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from pqch.common import sha256_hex
from pqch.run import Run

CONTEXT_SCHEMA = "pqch.context/1"
SUPPLIED_KINDS = {"mission_function": "mission-function", "data_lifetime_years": "data-lifetime",
                  "high_value_asset": "high-value-asset", "fips199_impact": "fips199-impact",
                  "owner": "owner", "national_security_system": "national-security-system"}


def load_context(path: str | Path) -> tuple[dict, str]:
    data = Path(path).read_bytes()
    ctx = yaml.safe_load(data)
    if ctx.get("schema") != CONTEXT_SCHEMA:
        raise ValueError(f"{path}: expected schema {CONTEXT_SCHEMA}, found {ctx.get('schema')!r}")
    for name, facts in (ctx.get("services") or {}).items():
        unknown = set(facts) - set(SUPPLIED_KINDS)
        if unknown:
            raise ValueError(f"{path}: service {name!r} carries an unknown fact {sorted(unknown)[0]!r}")
        if "data_lifetime_years" in facts and not isinstance(facts["data_lifetime_years"], int):
            raise ValueError(f"{path}: service {name!r}: data_lifetime_years is a whole number of years")
        if facts.get("fips199_impact", "low") not in ("low", "moderate", "high"):
            raise ValueError(f"{path}: service {name!r}: fips199_impact is low, moderate or high")
    return ctx, sha256_hex(data)


def link_services(run: Run) -> dict:
    """`link/service/1`: listener -> service and image -> service, from the binding each scan recorded."""
    events = list(run.ledger.events())
    scope = events[0]["payload"]["scope"]
    bindings = {(e["payload"]["subject"]["host"], e["payload"]["subject"]["port"]): e
                for e in events if e["type"] == "assessment.made"
                and e["payload"].get("rule_id") == "binding/scope/1"}
    counts = {"service_links": 0, "image_links": 0, "unnamed": 0, "unbound": 0}
    image_inputs: dict[tuple[str, str], list[str]] = {}
    for ep in scope["endpoints"]:
        service = ep.get("service")
        if not service:
            counts["unnamed"] += 1
            continue
        b = bindings.get((ep["host"], ep["port"]))
        if b is None or not b["payload"]["classification"]["bound"]:
            counts["unbound"] += 1
            continue
        c = b["payload"]["classification"]
        run.ledger.append("link.asserted", {"kind": "rule", "id": "link/service/1"}, {
            "from": {"kind": "endpoint", "host": ep["host"], "port": ep["port"], "protocol": ep["protocol"]},
            "to": {"kind": "service", "name": service},
            "kind": "served-by", "status": "discovered", "rule_id": "link/service/1",
            "basis": (f"the scope names service {service} for this listener, and the runner found container "
                      f"{c.get('container_id', '')[:12]} at the address running the scope's image "
                      f"{ep['image'].split('@')[0]} for the whole scan"),
        }, inputs=[b["id"]])
        counts["service_links"] += 1
        if ep.get("image"):
            image_inputs.setdefault((ep["image"], service), []).append(b["id"])
    for (image, service), inputs in sorted(image_inputs.items()):
        run.ledger.append("link.asserted", {"kind": "rule", "id": "link/service/1"}, {
            "from": {"kind": "image", "image": image},
            "to": {"kind": "service", "name": service},
            "kind": "runs", "status": "discovered", "rule_id": "link/service/1",
            "basis": f"the container the runner found serving {service}'s listener runs this image",
        }, inputs=sorted(set(inputs)))
        counts["image_links"] += 1
    return counts


def supply(run: Run, context_path: str | Path, *, author: str) -> dict:
    """Record the owner's facts for every service the scope names, each as a supplied link."""
    ctx, digest = load_context(context_path)
    events = list(run.ledger.events())
    scope = events[0]["payload"]["scope"]
    named = sorted({ep["service"] for ep in scope["endpoints"] if ep.get("service")})
    counts = {"supplied": 0, "services_without_context": []}
    for service in named:
        facts = (ctx.get("services") or {}).get(service)
        if not facts:
            counts["services_without_context"].append(service)
            continue
        for key, kind in SUPPLIED_KINDS.items():
            if key not in facts:
                continue
            value = facts[key]
            run.ledger.append("link.asserted", {"kind": "human", "id": author}, {
                "from": {"kind": "service", "name": service},
                "to": {"kind": "fact", "name": kind, "value": value},
                "kind": kind, "status": "supplied",
                "basis": f"typed in by {ctx.get('supplied_by', 'the owner')}; no scan can discover it",
                "source": {"path": str(context_path), "sha256": digest},
            }, evidence=[{"ref": str(context_path), "sha256": digest}])
            counts["supplied"] += 1
    return counts
