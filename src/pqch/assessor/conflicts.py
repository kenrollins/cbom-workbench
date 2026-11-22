"""`conflict/resolve/1`: when two findings about one asset disagree, which layer is in force.

Spike S3 (role R4) measured this as a model's task and no arm reached the floor;
it is a rule's job. A conflict is two or three findings about one asset — a file
in an image, what a listener serves, what a second tool read from the same
file — that cannot all describe what is in force. The rule names the layer in
force and the reason, in the vocabulary the spike labelled with:

- `not-served`: the file exists and no listener of its image serves it. In force:
  the wire. Decided from `in-use/not-served/1`, whose preconditions (every
  listener of the image scanned, bound to the scope's image, and every served
  certificate found in the image) are what make the wire's silence evidence.
- `tool-limit`: one tool reports a certificate in a file and another reports
  nothing for the same file. In force: the host finding that carries the parse,
  because the other tool's silence is a known blind spot, not an observation.
- `cannot-tell`: the evidence does not decide it — a listener that did not run
  the scope's image during the scan, a listener whose served certificate is in no
  file of the image, a scan that failed. The rule says what is missing.

Reasons the spike labelled that need configuration evidence — `default-applies`,
`overridden`, `other-listener`, `stale-file` — are not decided here: the harness
reads no configuration layer yet, so no such conflict can arise on its ledger.
A model may explain a conflict beside the rule's answer (`explain.py`), never
settle one.
"""

from __future__ import annotations

import json

from pqch.run import Run
from pqch.scout import TLS_PROTOCOLS

RULE = "conflict/resolve/1"
HARNESS_READER = "pqch-image-files"


def _subject_key(f: dict) -> str:
    return json.dumps(f["subject"], sort_keys=True)


def resolve(run: Run) -> dict:
    events = list(run.ledger.events())
    scope = events[0]["payload"]["scope"]
    findings = {e["id"]: e["payload"] for e in events if e["type"] == "finding.observed"}
    host = {i: f for i, f in findings.items() if f["layer"] == "host"}
    wire = {i: f for i, f in findings.items() if f["layer"] == "wire"}
    in_use = {e["payload"]["finding"]: e for e in events
              if e["type"] == "assessment.made" and "in_use" in e["payload"].get("classification", {})}
    bindings = {(e["payload"]["subject"]["host"], e["payload"]["subject"]["port"]): e for e in events
                if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "binding/scope/1"}
    ok_scans = {(e["payload"]["target"].get("host"), e["payload"]["target"].get("port")): e for e in events
                if e["type"] == "scan.completed" and e["payload"]["status"] == "ok"
                and "host" in e["payload"]["target"]}
    links_to = {e["payload"]["to"] for e in events if e["type"] == "link.asserted"
                and e["payload"].get("rule_id") == "link/public-key/1"}
    eps_by_image: dict[str, list[dict]] = {}
    for ep in scope["endpoints"]:
        if ep.get("image") and ep["protocol"] in TLS_PROTOCOLS:
            eps_by_image.setdefault(ep["image"], []).append(ep)
    counts = {"conflicts": 0, "wire": 0, "host": 0, "cannot_tell": 0}

    def record(fid: str, in_force: str, reason: str | None, basis: str, inputs: list[str], others: list[str]):
        run.ledger.append("assessment.made", {"kind": "rule", "id": RULE}, {
            "finding": fid, "rule_id": RULE, "disagrees_with": others,
            "classification": {"in_force": in_force, "reason": reason},
            "basis": basis,
        }, inputs=sorted({fid, *inputs}))
        counts["conflicts"] += 1
        counts[{"wire": "wire", "host": "host", "cannot-tell": "cannot_tell"}[in_force]] += 1

    # A certificate authority's certificate is never the one a listener serves, so a file any tool
    # read as a CA (basicConstraints CA with keyCertSign, as the harness's reader records it) is no
    # conflict for any finding read from it, whichever tool made that finding.
    ca_files = {_subject_key(h) for h in host.values()
                if h["asset"]["type"] == "certificate" and h["asset"]["parameters"].get("is_ca")}
    # One judgement per file: every finding read from the same file shares its fate.
    seen_files: set[str] = set()
    for hid, h in sorted(host.items()):
        if h["asset"]["type"] != "certificate" or _subject_key(h) in ca_files:
            continue
        if hid in links_to:
            continue    # served: wire and host agree
        image_ref = f"{h['subject'].get('image', '')}@{h['source'].get('subject_digest', '')}"
        eps = eps_by_image.get(image_ref, [])
        if not eps:
            continue    # nothing on the wire to disagree with
        key = _subject_key(h)
        if key in seen_files:
            continue
        seen_files.add(key)
        served = [wid for wid, w in wire.items() if w["asset"]["type"] == "certificate"
                  and (w["subject"]["host"], w["subject"]["port"]) in {(ep["host"], ep["port"]) for ep in eps}]
        listed = ", ".join(f"{ep['host']}:{ep['port']}" for ep in eps)
        judged = in_use.get(hid)
        if judged and judged["payload"]["classification"]["in_use"] is False:
            record(hid, "wire", "not-served",
                   f"the file holds a certificate no listener of its image serves ({listed} scanned, bound, "
                   f"each served certificate found in the image); what the wire serves is in force",
                   [judged["id"], *served], served)
            continue
        missing = []
        for ep in eps:
            k = (ep["host"], ep["port"])
            if k not in ok_scans:
                missing.append(f"no successful scan of {ep['host']}:{ep['port']}")
            elif not (bindings.get(k) and bindings[k]["payload"]["classification"]["bound"]):
                missing.append(f"{ep['host']}:{ep['port']} did not run the scope's image during the scan")
        unmatched = [wid for wid in served if wid not in {e["payload"]["from"] for e in events
                     if e["type"] == "link.asserted" and e["payload"].get("rule_id") == "link/public-key/1"}]
        if unmatched:
            missing.append("a certificate served by this image's listener is in no file of the image, so the "
                           "scope's claim that this image serves it is in doubt")
        if not served and not missing:
            missing.append("the scan recorded no certificate on this image's listeners")
        if not missing:
            continue    # nothing on the wire disagrees with the file, and nothing is missing: no conflict
        record(hid, "cannot-tell", None, "the evidence does not decide it: " + "; ".join(missing),
               [e["id"] for k, e in bindings.items() if k in {(ep["host"], ep["port"]) for ep in eps}] + served,
               served)

    # Two host tools over one file: the harness's reader parsed a certificate, the other tool
    # reported nothing for the path. The parse is in force; the silence is the tool's limit.
    paths_by_tool: dict[str, dict[str, list[str]]] = {}
    for hid, h in host.items():
        paths_by_tool.setdefault(h["source"]["tool"], {}).setdefault(
            f"{h['subject'].get('image', '')}:{h['subject']['path']}", []).append(hid)
    others = [t for t in paths_by_tool if t != HARNESS_READER]
    for path, ids in sorted(paths_by_tool.get(HARNESS_READER, {}).items()):
        certs = [i for i in ids if host[i]["asset"]["type"] == "certificate"]
        if not certs:
            continue
        silent = [t for t in others if path not in paths_by_tool[t]]
        if not silent or not others:
            continue
        for hid in certs:
            record(hid, "host", "tool-limit",
                   f"{HARNESS_READER} read a {host[hid]['asset']['name']} certificate from this file; "
                   f"{', '.join(sorted(silent))} reported nothing for it. The parse is in force; the "
                   f"silence is the other tool's blind spot, not an observation",
                   [], [])
    return counts
