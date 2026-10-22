"""Passive capture to findings: Zeek's handshake logs from a mirror port, read into one capture run.

What a mirror shows is what every client offered and what every server chose, for every handshake
that crossed it. Nothing here sends a packet. The unit of evidence is one rotated Zeek log file:
each becomes a `scan.completed` event with the file's path and hash, and the findings aggregated
over the batch name every file they were read from in `inputs`.

Findings (layer `wire`, tool `zeek`, profile `capture`):
- a server listener × key-exchange group it chose (`algorithm`, `key-establishment`), with how
  often, over how many handshakes, and how many of those clients had offered a hybrid group;
- a server listener × protocol version negotiated (`protocol`);
- a client × key-exchange group it offered (`algorithm`, `key-establishment`, subject `client`);
- a client × protocol version it offered (`protocol`);
- an SSH server × negotiated key exchange and host-key algorithm, from Zeek's `ssh` log.

Rules then state, from these, each listener's observed posture and each client's capability.
"""

from __future__ import annotations

import ipaddress
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

from pqch.common import sha256_hex, ulid
from pqch.run import Run
from pqch.scout import names

ZEEK_IMAGE_DIGEST = "sha256:70733f4e540ba1608e37e00c6a93d009f79734262c9ec2ba09d90aa9abc16de5"  # zeek/zeek:lts, spike S1
TOOL = {"tool": "zeek", "version": "lts", "image_digest": ZEEK_IMAGE_DIGEST, "profile": "capture"}
HYBRID = {4587, 4588, 4589, 25497, 25498}
SCHEMA = "pqch.finding/1"


def _rows(path: Path):
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.startswith("{"):
                yield json.loads(line)


def rotated_logs(capture_dir: Path, prefix: str) -> list[Path]:
    """Completed (rotated) log files of one kind, oldest first. The live file is never read."""
    return sorted(p for p in capture_dir.glob(f"{prefix}.*.log") if p.name != f"{prefix}.log")


def _ts(x: float) -> str:
    from datetime import UTC, datetime

    return datetime.fromtimestamp(x, UTC).strftime("%Y-%m-%dT%H:%M:%S.") + f"{int((x % 1) * 1000):03d}Z"


def _private(a: str) -> bool:
    try:
        return ipaddress.ip_address(a).is_private
    except ValueError:
        return False


class Batch:
    """One ingest: the rotated files not yet read by an earlier capture run."""

    def __init__(self, capture_dir: str | Path, *, already: set[str] = frozenset()):
        self.dir = Path(capture_dir)
        self.posture = [p for p in rotated_logs(self.dir, "posture") if p.name not in already]
        self.ssh = [p for p in rotated_logs(self.dir, "ssh") if p.name not in already]
        self.vlan_files = rotated_logs(self.dir, "conn")
        self.loss_files = rotated_logs(self.dir, "capture_loss")

    def empty(self) -> bool:
        return not self.posture and not self.ssh


def ingest(var: str | Path, scope: dict, capture_dir: str | Path, *, hardware: str = "unlabelled",
           sensor_id: str = "pqch-capture") -> tuple[Run, dict]:
    """Read every rotated log not yet ingested into a new capture run. Returns the run and a summary."""
    var = Path(var)
    already = ingested_files(var)
    batch = Batch(capture_dir, already=already)
    if batch.empty():
        raise ValueError("nothing new to ingest: no rotated log since the last capture run")
    run = Run.start_capture(var, scope, sensor_id=sensor_id)
    actor = {"kind": "scanner", "id": "zeek"}

    # VLAN of each connection, from the conn log (the tag the mirror preserved).
    vlan_of: dict[str, int] = {}
    for p in batch.vlan_files:
        for r in _rows(p):
            if "vlan" in r:
                vlan_of[r["uid"]] = r["vlan"]

    # One scan.completed per file, with the file's hash: the evidence a finding points back to.
    scan_ids: dict[str, str] = {}
    first_ts, last_ts, loss = {}, {}, {}
    for p in batch.posture + batch.ssh:
        rows = list(_rows(p))
        ts = [r["ts"] for r in rows] or [p.stat().st_mtime]
        ev = run.ledger.append("scan.completed", {"kind": "runner", "id": sensor_id}, {
            "profile": "capture", "target": {"interface": scope["captures"][0]["interface"], "file": p.name},
            "tool": TOOL["tool"], "version": TOOL["version"], "image_digest": ZEEK_IMAGE_DIGEST,
            "started_at": _ts(min(ts)), "ended_at": _ts(max(ts)), "duration_ms": int((max(ts) - min(ts)) * 1000),
            "hardware": hardware, "status": "ok", "exit_code": 0,
            "raw": str(p), "raw_sha256": sha256_hex(p.read_bytes()), "records": len(rows),
            # This file's hour in one line, so a series over time can be read from the ledger alone.
            "tally": _tally(rows, vlan_of) if p.name.startswith("posture.") else None,
        })
        scan_ids[p.name] = ev["id"]
        first_ts[p.name], last_ts[p.name] = min(ts), max(ts)

    # Capture loss over the batch's span, so every count carries what the mirror did not deliver.
    span = (min(first_ts.values()), max(last_ts.values())) if first_ts else (0, 0)
    pct = [r["percent_lost"] for p in batch.loss_files for r in _rows(p) if span[0] <= r["ts"] <= span[1]]
    # In basis points (hundredths of a percent): hashed objects carry no floats.
    loss = {"intervals": len(pct), "median_bp": round(statistics.median(pct) * 100) if pct else None,
            "max_bp": round(max(pct) * 100) if pct else None}

    findings: list[dict] = []
    # ---- TLS: servers and clients, aggregated over the batch
    srv: dict = defaultdict(lambda: {"chosen": Counter(), "ver": Counter(), "n": 0, "pq_off": 0, "sni": Counter(),
                                     "files": set(), "vlans": Counter(), "sample": None})
    cli: dict = defaultdict(lambda: {"off": Counter(), "first": Counter(), "ver": Counter(), "n": 0,
                                     "chosen_for": Counter(), "files": set(), "vlans": Counter(), "sample": None})
    edges: dict = defaultdict(lambda: {"n": 0, "hybrid": 0, "refused": 0, "sni": Counter()})
    for p in batch.posture:
        for r in _rows(p):
            offered = [g for g in r.get("offered_groups", []) if not names.is_grease(g)]
            chosen = r.get("server_key_share") or r.get("server_ecdh_curve")
            vlan = vlan_of.get(r["uid"])
            if chosen is not None:
                e = edges[(r["client"], r["server"], r["server_port"])]
                e["n"] += 1
                e["hybrid"] += chosen in HYBRID
                e["refused"] += (chosen not in HYBRID) and bool(set(offered) & HYBRID)
                if r.get("sni"):
                    e["sni"][r["sni"]] += 1
            s = srv[(r["server"], r["server_port"])]
            s["n"] += 1
            s["files"].add(p.name)
            if chosen is not None:
                s["chosen"][chosen] += 1
            if r.get("version"):
                s["ver"][r["version"]] += 1
            if set(offered) & HYBRID:
                s["pq_off"] += 1
            if r.get("sni"):
                s["sni"][r["sni"]] += 1
            if vlan is not None:
                s["vlans"][vlan] += 1
            s["sample"] = s["sample"] or r
            c = cli[r["client"]]
            c["n"] += 1
            c["files"].add(p.name)
            for g in offered:
                c["off"][g] += 1
            if offered:
                c["first"][offered[0]] += 1
            for v in r.get("client_versions", []):
                if not names.is_grease(v):
                    c["ver"][v] += 1
            if chosen is not None:
                c["chosen_for"][chosen] += 1
            if vlan is not None:
                c["vlans"][vlan] += 1
            c["sample"] = c["sample"] or r

    def add(subject: dict, type_: str, role: str, name: str, params: dict, excerpt: str, files: set[str],
            observed_at: str) -> None:
        f = {"schema": SCHEMA, "id": ulid(), "observed_at": observed_at, "layer": "wire",
             "source": dict(TOOL), "subject": subject,
             "asset": {"type": type_, "role": role, "name": name, "parameters": params},
             "evidence": {"raw": str(Path(capture_dir) / sorted(files)[0]),
                          "sha256": sha256_hex((Path(capture_dir) / sorted(files)[0]).read_bytes()),
                          "excerpt": excerpt[:400]}}
        from pqch.scout.normalize import fingerprint

        f["fingerprint"] = fingerprint("wire", subject, f["asset"])
        findings.append((f, sorted(scan_ids[x] for x in files)))

    for (host, port), s in sorted(srv.items()):
        subject = {"kind": "endpoint", "host": host, "port": port, "protocol": "tls"}
        if s["sni"]:
            subject["sni"] = s["sni"].most_common(1)[0][0]
        # The tag on a connection is the originator's VLAN, so it is recorded on clients, never on a
        # listener; a listener's VLAN is inferred later from the tagged clients on its subnet.
        at = _ts(max(last_ts[x] for x in s["files"]))
        inside = _private(host)
        for gid, n in s["chosen"].most_common():
            add(subject, "algorithm", "key-establishment", names.tls_group(gid),
                {"iana_id": gid, "chosen": n, "handshakes": s["n"], "clients_offered_hybrid": s["pq_off"],
                 "inside": inside, "hybrid": gid in HYBRID,
                 "client_vlans": {str(k): v for k, v in s["vlans"].most_common(6)}},
                f"chose {names.tls_group(gid)} on {n} of {s['n']} handshakes; {s['pq_off']} clients offered a hybrid group",
                s["files"], at)
        for ver, n in s["ver"].most_common():
            add(subject, "protocol", "other", ver, {"negotiated": n, "handshakes": s["n"], "inside": inside},
                f"negotiated {ver} on {n} of {s['n']} handshakes", s["files"], at)
    for host, c in sorted(cli.items()):
        subject = {"kind": "client", "host": host, "protocol": "tls"}
        if c["vlans"]:
            subject["vlan"] = c["vlans"].most_common(1)[0][0]
        at = _ts(max(last_ts[x] for x in c["files"]))
        for gid, n in c["off"].most_common():
            add(subject, "algorithm", "key-establishment", names.tls_group(gid),
                {"iana_id": gid, "offered": n, "handshakes": c["n"], "first_choice": c["first"][gid],
                 "chosen_by_servers": c["chosen_for"][gid], "inside": _private(host), "hybrid": gid in HYBRID},
                f"offered {names.tls_group(gid)} on {n} of {c['n']} handshakes, first on {c['first'][gid]}",
                c["files"], at)
        for vid, n in c["ver"].most_common():
            add(subject, "protocol", "other", names.TLS_VERSION_IDS.get(vid, f"version-{vid}"),
                {"offered": n, "handshakes": c["n"], "inside": _private(host)},
                f"offered {names.TLS_VERSION_IDS.get(vid, vid)} on {n} of {c['n']} handshakes", c["files"], at)

    # ---- SSH: the negotiated key exchange and host key per server, from Zeek's own log
    ssh: dict = defaultdict(lambda: {"kex": Counter(), "hk": Counter(), "n": 0, "clients": Counter(), "files": set(),
                                     "server": Counter(), "vlans": Counter()})
    for p in batch.ssh:
        for r in _rows(p):
            s = ssh[(r["id.resp_h"], r["id.resp_p"])]
            s["n"] += 1
            s["files"].add(p.name)
            if r.get("kex_alg"):
                s["kex"][r["kex_alg"]] += 1
            if r.get("host_key_alg"):
                s["hk"][r["host_key_alg"]] += 1
            if r.get("client"):
                s["clients"][r["client"]] += 1
            if r.get("server"):
                s["server"][r["server"]] += 1
            v = vlan_of.get(r["uid"])
            if v is not None:
                s["vlans"][v] += 1
    for (host, port), s in sorted(ssh.items()):
        subject = {"kind": "endpoint", "host": host, "port": port, "protocol": "ssh"}
        at = _ts(max(last_ts[x] for x in s["files"]))
        for alg, n in s["kex"].most_common():
            add(subject, "algorithm", "key-establishment", names.SSH_KEX.get(alg, alg),
                {"ssh_names": [alg], "negotiated": n, "sessions": s["n"], "inside": _private(host),
                 "server_software": [k for k, _ in s["server"].most_common(2)],
                 "client_software": [k for k, _ in s["clients"].most_common(3)]},
                f"kex {alg} negotiated on {n} of {s['n']} sessions", s["files"], at)
        for alg, n in s["hk"].most_common():
            add(subject, "algorithm", "signature", names.SSH_HOSTKEY.get(alg, alg),
                {"ssh_names": [alg], "negotiated": n, "sessions": s["n"], "inside": _private(host)},
                f"host key {alg} on {n} of {s['n']} sessions", s["files"], at)

    ids: dict[str, list[str]] = defaultdict(list)   # subject key -> finding event ids
    for f, inputs in findings:
        ev = run.ledger.append("finding.observed", actor, f, inputs=inputs)
        ids[_subject_key(f["subject"])].append(ev["id"])

    # ---- rules: observed posture per listener, capability per client. No model.
    rule_events = 0
    for (host, port), s in sorted(srv.items()):
        key = f"endpoint:{host}:{port}"
        chosen_hybrid = sum(n for g, n in s["chosen"].items() if g in HYBRID)
        chosen_total = sum(s["chosen"].values())
        posture = ("pq" if chosen_total and chosen_hybrid == chosen_total else
                   "mixed" if chosen_hybrid else "classical")
        refused = s["pq_off"] - chosen_hybrid if s["pq_off"] > chosen_hybrid else 0
        run.ledger.append("assessment.made", {"kind": "rule", "id": "posture/observed/1"}, {
            "subject": {"kind": "endpoint", "host": host, "port": port, "protocol": "tls"},
            "rule_id": "posture/observed/1",
            "classification": {"posture": posture, "basis": "observed",
                               "hybrid_offered": s["pq_off"], "hybrid_chosen": chosen_hybrid,
                               "hybrid_refused": refused, "handshakes": s["n"], "inside": _private(host)},
        }, inputs=ids[key])
        rule_events += 1
    for host, c in sorted(cli.items()):
        key = f"client:{host}"
        offers_hybrid = any(g in HYBRID for g in c["off"])
        offers_13 = 0x0304 in c["ver"]
        cap = "hybrid" if offers_hybrid else ("classical-1.3" if offers_13 else "legacy")
        run.ledger.append("assessment.made", {"kind": "rule", "id": "capability/observed/1"}, {
            "subject": {"kind": "client", "host": host, "protocol": "tls"},
            "rule_id": "capability/observed/1",
            "classification": {"capability": cap, "offers_hybrid": offers_hybrid, "offers_tls13": offers_13,
                               "handshakes": c["n"], "inside": _private(host)},
        }, inputs=ids[key])
        rule_events += 1

    summary = {"run": run.id, "files": len(scan_ids), "findings": len(findings), "rules": rule_events,
               "servers": len(srv), "clients": len(cli), "ssh_servers": len(ssh), "span": [_ts(span[0]), _ts(span[1])],
               "capture_loss": loss}
    run.ledger.append("scan.completed", {"kind": "runner", "id": sensor_id}, {
        "profile": "capture-summary", "target": {"interface": scope["captures"][0]["interface"]},
        "tool": TOOL["tool"], "version": TOOL["version"], "image_digest": ZEEK_IMAGE_DIGEST,
        "started_at": _ts(span[0]), "ended_at": _ts(span[1]), "duration_ms": int((span[1] - span[0]) * 1000),
        "hardware": hardware, "status": "ok", "exit_code": 0, "raw": str(Path(capture_dir)),
        "raw_sha256": sha256_hex(json.dumps(sorted(scan_ids), separators=(",", ":")).encode()),
        "findings": len(findings), "capture_loss": loss, "files": sorted(scan_ids),
        # Every client-to-server pair with a key exchange seen: the edges of the estate's picture.
        "edges": [{"client": c, "server": sv, "port": pt, "n": e["n"], "hybrid": e["hybrid"], "refused": e["refused"],
                   "sni": e["sni"].most_common(1)[0][0] if e["sni"] else None, "inside": _private(sv)}
                  for (c, sv, pt), e in sorted(edges.items())]})
    run.close()
    return run, summary


def _tally(rows: list[dict], vlan_of: dict[str, int]) -> dict:
    """Handshakes in one file: how many negotiated a hybrid group, inside the estate and out, by VLAN."""
    t = {"handshakes": 0, "hybrid": 0, "inside": {"handshakes": 0, "hybrid": 0, "hybrid_offered": 0},
         "outside": {"handshakes": 0, "hybrid": 0, "hybrid_offered": 0}, "by_vlan": {}}
    for r in rows:
        chosen = r.get("server_key_share") or r.get("server_ecdh_curve")
        if chosen is None:
            continue   # a resumption: no key exchange to count
        hyb = chosen in HYBRID
        offered = bool(set(r.get("offered_groups", [])) & HYBRID)
        side = t["inside"] if _private(r["server"]) else t["outside"]
        t["handshakes"] += 1
        t["hybrid"] += hyb
        side["handshakes"] += 1
        side["hybrid"] += hyb
        side["hybrid_offered"] += offered
        v = vlan_of.get(r["uid"])
        if v is not None:
            b = t["by_vlan"].setdefault(str(v), {"handshakes": 0, "hybrid": 0, "hybrid_offered": 0})
            b["handshakes"] += 1
            b["hybrid"] += hyb
            b["hybrid_offered"] += offered
    return t


def _subject_key(s: dict) -> str:
    return f"{s['kind']}:{s['host']}" + (f":{s['port']}" if "port" in s else "")


def ingested_files(var: Path) -> set[str]:
    """The rotated files every earlier capture run under `var` has read."""
    done: set[str] = set()
    for d in (var / "runs").glob("*"):
        led = d / "ledger.jsonl"
        if not led.exists():
            continue
        with led.open(encoding="utf-8") as f:
            first = f.readline()
        if '"kind":"capture"' not in first:
            continue
        with led.open(encoding="utf-8") as f:
            for line in f:
                if '"profile":"capture"' in line and '"file":' in line:
                    done.add(json.loads(line)["payload"]["target"]["file"])
    return done


def prune(var: Path, capture_dir: Path) -> list[str]:
    """Delete the rotated connection logs of hours already ingested. The connection log is read only
    for VLAN tags at ingest time and is most of the capture's bulk; the handshake logs the ledger
    points at by hash (posture, ssh, x509), and the loss log, are kept. Returns what was removed."""
    done = ingested_files(var)
    stamps = {n[len("posture."):-len(".log")] for n in done if n.startswith("posture.")}
    removed = []
    for p in rotated_logs(capture_dir, "conn"):
        if p.name[len("conn."):-len(".log")] in stamps:
            p.unlink()
            removed.append(p.name)
    return removed
