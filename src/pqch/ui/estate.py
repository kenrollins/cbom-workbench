"""The test agency at a glance: what the mini-agency is, its services and what was planted in each.

Read from the estate's own files — what each service is for (about.yaml), the owner's facts
(context.yaml), the listeners (compose.yaml) and the answer key — never from a scan: this is the
estate as built, the state a reset returns it to.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import yaml

CLASSES = ("present", "decoy", "supplied", "out-of-reach")


def _service_of(item: dict, by_host: dict[str, str], names: set[str]) -> str | None:
    s = item.get("subject") or {}
    if s.get("service"):
        return s["service"]
    if s.get("host"):
        return by_host.get(s["host"])
    if item.get("image"):
        return item["image"].split("/")[-1]
    path = item.get("path") or ""
    parts = path.split("/")
    return parts[1] if len(parts) > 2 and parts[0] == "agency" and parts[1] in names else None


def build(agency: Path, key_path: Path) -> dict:
    about = yaml.safe_load((agency / "about.yaml").read_text())
    context = yaml.safe_load((agency / "context.yaml").read_text())["services"]
    compose = yaml.safe_load((agency / "compose.yaml").read_text())
    key = yaml.safe_load(key_path.read_text())
    network = next(iter(compose["networks"].values()))
    by_host: dict[str, str] = {}
    listeners: dict[str, list[dict]] = {}
    for name, svc in compose["services"].items():
        addr = next(iter(svc["networks"].values()))["ipv4_address"]
        by_host[addr] = name
        listeners[name] = [{"address": addr, **e} for e in svc.get("x-pqch", {}).get("endpoints", [])]
    posture = {(p["host"], p["port"]): p["posture"] for p in key["posture"]}
    for ls in listeners.values():
        for e in ls:
            e["posture"] = posture.get((e["address"], e["port"]), "")
    counts: dict[str, Counter] = {n: Counter() for n in about["services"]}
    for item in key["items"]:
        svc = _service_of(item, by_host, set(about["services"]))
        if svc in counts:
            counts[svc][item["class"]] += 1
    services = [{"name": n, **a, "context": context.get(n, {}), "listeners": listeners.get(n, []),
                 "address": listeners[n][0]["address"] if listeners.get(n) else "",
                 "managed": "policy" in compose["services"][n].get("x-pqch", {}),
                 "counts": {c: counts[n][c] for c in CLASSES},
                 "issued_by_ca": n in about["ca"]["issues"]}
                for n, a in about["services"].items()]
    groups = [{**g, "services": [s for s in services if s["group"] == g["id"]]} for g in about["groups"]]
    totals = Counter(i["class"] for i in key["items"])
    return {"summary": about["summary"], "groups": groups, "services": services, "ca": about["ca"],
            "network": {"name": network.get("name", ""), "internal": network.get("internal", False),
                        "subnet": ".".join(next(iter(by_host)).split(".")[:3]) + ".0/24"},
            "listeners": sum(len(v) for v in listeners.values()),
            "totals": {c: totals[c] for c in CLASSES}, "keyed": len(key["items"]),
            "postures": Counter(p["posture"] for p in key["posture"])}
