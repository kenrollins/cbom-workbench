"""Change packages for what no configuration change can do.

A migration item blocked on its supplier (`blocker/supplier/1`) has no line to render, draft or
rehearse: the software lists no post-quantum algorithm for the function. Its package says so with the
evidence — the runtime's own list, by path and hash — and says what would unblock it: a version of the
same software elsewhere in this estate that does list one, or nothing in the estate. It names the CBOM
entries the item covers, the memo's clause on replacement, and the verifier check that will count once
the software is replaced. Nothing in it is applied, so it has no rollback and is labelled
`not rehearsed`.

Every field is read from the scan run's ledger and the capability snapshot the blocker rule cited; a
rule writes it (`package/supplier/1`), not a model.
"""

from __future__ import annotations

import json
from pathlib import Path

from pqch import schemas
from pqch import scope as scope_mod
from pqch.common import ulid
from pqch.policy import load_pack
from pqch.run import Run

RULE = "package/supplier/1"
ACTOR = {"kind": "rule", "id": RULE}
VERIFY = {
    "key-establishment": "once replaced, the verifier's wire-kex check on each listener: a client offering only the "
                         "hybrid group is accepted and one offering every classical group is refused",
    "signature": "once replaced, a parse of the certificate or host key each listener presents, showing a post-quantum "
                 "signature algorithm",
}


def _family(software: str) -> str:
    """The product, without its version: "OpenSSH 6.6 (Ubuntu 14.04)" -> "OpenSSH"."""
    return software.split(" ")[0]


def unblock(service: str, function: str, snapshot: dict) -> list[dict]:
    """Other services in the snapshot running the same product that do list a post-quantum algorithm
    for the function: the upgrade path the estate already holds."""
    mine = snapshot["services"][service]
    key = "kex" if function == "key-establishment" else "sig"
    out = []
    for name, s in snapshot["services"].items():
        if name != service and _family(s["software"]) == _family(mine["software"]) and (s.get("pq") or {}).get(key):
            out.append({"service": name, "software": s["software"], "lists": s["pq"][key]})
    return out


def entries(events: list[dict], service: str, function: str) -> list[dict]:
    """The CBOM entries the item covers: what the service's listeners negotiate or present for the
    function, and the files those are served from."""
    bound = {}
    for e in events:
        p = e["payload"]
        if e["type"] == "link.asserted" and p.get("kind") == "served-by" and (p.get("to") or {}).get("name") == service:
            fr = p.get("from") or {}
            if fr.get("kind") == "endpoint":
                bound[(fr["host"], fr["port"])] = e["id"]
    finds = {e["id"]: e for e in events if e["type"] == "finding.observed"}
    served = {}
    for e in events:
        p = e["payload"]
        if e["type"] == "link.asserted" and p.get("kind") == "served-from" and p.get("from") in finds and p.get("to") in finds:
            served.setdefault(p["from"], []).append(p["to"])
    out = []
    for fid, e in finds.items():
        f = e["payload"]
        s = f["subject"]
        if f["layer"] != "wire" or (s.get("host"), s.get("port")) not in bound or f["asset"]["role"] != function:
            continue
        files = [finds[x]["payload"] for x in served.get(fid, [])]
        out.append({"fingerprint": f["fingerprint"], "event": fid, "name": f["asset"]["name"], "type": f["asset"]["type"],
                    "listener": f"{s['host']}:{s['port']}", "protocol": s.get("protocol"),
                    "files": [{"fingerprint": x["fingerprint"], "path": x["subject"].get("path"), "image": x["subject"].get("image")}
                              for x in files]})
    return sorted(out, key=lambda x: (x["listener"], x["type"], x["name"]))


def build(var: Path, scan_run: Run, *, pack_path: str | Path, snapshots_dir: str | Path = "policy/snapshots",
          signer=None) -> tuple[Run | None, list[dict]]:
    events = list(scan_run.ledger.events())
    blocked = [e for e in events if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "blocker/supplier/1"
               and e["payload"]["classification"]["state"] == "blocked"]
    if not blocked:
        return None, []
    pack = load_pack(pack_path)
    queue = {(e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]): e for e in events
             if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "queue/m-26-15/1"}
    prio = {e["payload"]["subject"]["name"]: e for e in events
            if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "priority/m-26-15/1"}
    owner = {e["payload"]["from"]["name"]: {"value": e["payload"]["to"]["value"], "event": e["id"]} for e in events
             if e["type"] == "link.asserted" and e["payload"].get("status") == "supplied" and e["payload"].get("kind") == "owner"}
    snaps = sorted(Path(snapshots_dir).glob("capabilities-*.json"))
    snapshot = json.loads(snaps[-1].read_text())
    scope = events[0]["payload"]["scope"]
    schemas.validate(scope)
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="package-supplier",
                    kind="package", runner_id="pqch-packager")
    out = []
    for b in blocked:
        sj = b["payload"]["subject"]
        svc, fn = sj["service"], sj["function"]
        q = queue.get((svc, fn))
        cap = snapshot["services"][svc]
        ups = unblock(svc, fn, snapshot)
        pkg = {
            "package_id": ulid(), "kind": "supplier-blocked",
            "item": {"run": scan_run.id, "service": svc, "function": fn,
                     "queue": q and q["payload"]["classification"].get("queue"),
                     "deadline": q and q["payload"]["classification"].get("deadline"), "queue_event": q and q["id"],
                     "prioritized": bool(prio.get(svc) and prio[svc]["payload"]["classification"]["prioritized"]),
                     "owner": owner.get(svc)},
            "why": {"blocker_event": b["id"], "basis": b["payload"]["basis"], "software": cap["software"],
                    "library": cap["library"], "lists": (cap.get("pq") or {}).get("kex" if fn == "key-establishment" else "sig") or [],
                    "snapshot": {"path": str(snaps[-1]), "taken_at": snapshot["taken_at"], "method": snapshot["method"]},
                    "evidence": b["payload"].get("evidence") or b.get("evidence") or []},
            "unblock": ups,
            "replace": {"pack": pack["id"], "section": pack["replace"]["section"],
                        "quote": " ".join(pack["replace"]["quote"].split())},
            "entries": entries(events, svc, fn),
            "verify": VERIFY[fn],
            "rollback": None, "rehearsal": "not rehearsed: there is no configuration to rehearse",
        }
        # The blocker and queue events are in the scan run, named in the payload by run and event id;
        # `inputs` holds only events of this ledger.
        run.ledger.append("package.issued", ACTOR, pkg,
                          evidence=[{"ref": x["ref"], "sha256": x["sha256"]} for x in pkg["why"]["evidence"]])
        out.append(pkg)
    run.close(signer)
    return run, out
