"""The demo stage: one page that tells the story in beats, every number read live from this box.

Eight minutes on stage (2 executive, 2 practical, 4 technical) is one page, not eight: the estate and
the mission outcome, the scan running, what comes first, the CBOM as a graph, the stack from the
hardware up, one change proved on the wire, and the signed record. Nothing here is computed anew:
each beat draws the same run store, CBOM projection, plan and ledgers the other pages show, as one
JSON document the page animates. A model speaks only in the narration, one line per plan row, on the
`fast` tier with reasoning off, and every call is timed and labelled with the engine that served it.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from pqch import varmode
from pqch.run import Run


def _props(c: dict) -> dict:
    return {p["name"]: p["value"] for p in c.get("properties", []) if "name" in p}


def _pq(name: str | None, family: str | None) -> bool:
    s = f"{name or ''} {family or ''}".lower()
    return any(k in s for k in ("mlkem", "ml-kem", "mldsa", "ml-dsa", "kyber", "dilithium", "sntrup", "slh-dsa"))


def cbom_graph(bom: dict) -> dict:
    """The CBOM's components as nodes, its dependencies as links; a service, a listener, an image or a
    cryptographic asset, each marked quantum-vulnerable, post-quantum or neither as the rules said."""
    comps = bom.get("components") or []
    byref = {c["bom-ref"]: c for c in comps if c.get("bom-ref")}
    nodes = []
    for c in comps:
        p, cp = _props(c), c.get("cryptoProperties") or {}
        kind = p.get("pqch:kind") or cp.get("assetType") or c.get("type")
        nodes.append({"id": c["bom-ref"], "name": c.get("name"), "kind": kind, "layer": p.get("pqch:layer"),
                      "qv": p.get("pqch:quantum-vulnerable") == "true", "pq": _pq(c.get("name"), p.get("pqch:family")),
                      "role": p.get("pqch:role"), "mission": p.get("pqch:mission-function"),
                      "primitive": (cp.get("algorithmProperties") or {}).get("primitive"),
                      "verifier": p.get("pqch:verifiable-by")})
    links = [{"source": d["ref"], "target": t} for d in bom.get("dependencies") or []
             for t in d.get("dependsOn") or [] if d.get("ref") in byref and t in byref]
    return {"nodes": nodes, "links": links,
            "counts": {"components": len(nodes), "quantum_vulnerable": sum(n["qv"] for n in nodes),
                       "post_quantum": sum(n["pq"] for n in nodes), "links": len(links),
                       "services": sum(n["kind"] == "service" for n in nodes),
                       "listeners": sum(n["kind"] == "listener" for n in nodes)}}


def estate_map(graph: dict) -> dict:
    """Just the services and their listeners, for the map the demo opens on."""
    keep = {n["id"] for n in graph["nodes"] if n["kind"] in ("service", "listener")}
    nodes = [n for n in graph["nodes"] if n["id"] in keep]
    links = [l for l in graph["links"] if l["source"] in keep and l["target"] in keep]
    for n in nodes:
        if n["kind"] == "listener":
            n["protocol"] = (n["name"] or "").split(" ")[0].lower()
    return {"nodes": nodes, "links": links}


def _score(run: Run) -> dict | None:
    p = Path(run.var) / "runs" / run.id / "score.json"
    if not p.exists():
        return None
    s = json.loads(p.read_text())
    out = {"key_sha256": (s.get("key") or {}).get("sha256"), "columns": {}}
    for col, c in (s.get("columns") or {}).items():
        L = c.get("layers") or {}
        out["columns"][col] = {"label": c.get("label"),
                               "wire": {"covered": L.get("wire", {}).get("covered"), "of": L.get("wire", {}).get("denominator"),
                                        "false_positives": L.get("wire", {}).get("false_positives")},
                               "host": {"covered": L.get("host", {}).get("covered"), "of": L.get("host", {}).get("denominator"),
                                        "false_positives": L.get("host", {}).get("false_positives")},
                               "posture": c.get("posture"), "components": c.get("components")}
    return out


def _ledger(run: Run, last: int = 80) -> dict:
    """The run's chain, trimmed for the screen, and its signed verification."""
    from pqch.ledger.checkpoints import verify_signed
    events = list(run.ledger.events())
    pub = Path(run.var) / "runs" / run.id / "ledger.pub"
    try:
        v = _plain(verify_signed(events, pub.read_bytes() if pub.exists() else None, known=None))
    except Exception as e:  # the page says so rather than failing
        v = {"ok": False, "error": str(e)[:200]}
    chain = [{"seq": e.get("seq"), "type": e.get("type"), "ts": e.get("ts"), "hash": (e.get("hash") or "")[:12],
              "prev": (e.get("prev") or "")[:12], "actor": (e.get("actor") or {}).get("kind")} for e in events[-last:]]
    return {"run": run.id, "events": len(events), "chain": chain, "verify": v}


def _changes(run: Run) -> list[dict]:
    """Each change in a change run as the sequence the page animates: proposed, approved, applied,
    probed, recreated, probed again; timestamps are the ledger's own."""
    by: dict[str, dict] = {}
    for e in run.ledger.events():
        p, t = e.get("payload") or {}, e.get("type")
        cid = p.get("change_id")
        if not cid:
            continue
        c = by.setdefault(cid, {"change_id": cid, "steps": []})
        if t == "change.proposed":
            tg, dr = p.get("target") or {}, p.get("drafted") or None
            c.update({"service": tg.get("service") or tg.get("name"), "address": f"{tg.get('address') or tg.get('host')}:{tg.get('port')}" if (tg.get("address") or tg.get("host")) else None,
                      "intent": p.get("intent"), "diff": (p.get("diff") or "")[:600], "rule": p.get("rule_id"),
                      "drafted": {"role": dr.get("role"), "findings": len((dr.get("context") or {}).get("findings") or []),
                                  "scan_run": (dr.get("context") or {}).get("scan_run")} if dr else None})
            c["steps"].append({"what": "proposed", "at": e.get("ts")})
        elif t == "approval.granted":
            c["steps"].append({"what": "approved", "at": e.get("ts"), "by": p.get("by"), "how": p.get("authenticated_by")})
        elif t == "change.applied":
            c["steps"].append({"what": "applied", "at": e.get("ts"), "ms": p.get("duration_ms"), "containers": p.get("containers")})
        elif t == "verdict.issued":
            c["steps"].append({"what": "verdict", "at": e.get("ts"), "status": p.get("status"), "meets_intent": p.get("meets_intent"),
                               "durable": p.get("durable"), "also_accepts": p.get("also_accepts"),
                               "probes": [{"name": q.get("name"), "tool": f"{q.get('tool')} {q.get('tool_version') or ''}".strip(),
                                           "result": q.get("result"), "negotiated": q.get("negotiated"),
                                           "ms": _ms(q.get("started_at"), q.get("ended_at"))} for q in p.get("probes") or []]})
        elif t == "service.recreated":
            c["steps"].append({"what": "recreated", "at": e.get("ts"), "ms": p.get("duration_ms")})
        elif t == "rehearsal.completed":
            c["steps"].append({"what": "rehearsed", "at": e.get("ts"), "verdict": p.get("verdict"), "twin": p.get("twin")})
    out = []
    for c in by.values():
        c["landed"] = any(s["what"] == "verdict" and s.get("durable") for s in c["steps"])
        c["open"] = not any(s["what"] == "approved" for s in c["steps"])
        c["before"] = _before(run.var, ((c.get("drafted") or {}).get("scan_run")), c.get("address"))
        out.append(c)
    return out


def _before(var: Path, scan_run: str | None, address: str | None) -> dict | None:
    """What the listener did before the change, from the scan the draft was written from: its posture and the
    key-establishment algorithms it accepted, with which were quantum-vulnerable. Findings, not probes."""
    if not scan_run or not address or not str(scan_run).isalnum():
        return None
    path = Path(var) / "runs" / scan_run / "workbench.cdx.json"
    if not path.is_file():
        return None
    try:
        bom = json.loads(path.read_text())
    except Exception:
        return None
    ref = f"listener:{address}"
    comps = {c.get("bom-ref"): c for c in bom.get("components", [])}
    if ref not in comps:
        return None
    props = {q["name"]: q["value"] for q in comps[ref].get("properties", [])}
    deps = next((d.get("dependsOn", []) for d in bom.get("dependencies", []) if d.get("ref") == ref), [])
    kex, protos = [], []
    for d in deps:
        x = comps.get(d) or {}
        cp = x.get("cryptoProperties") or {}
        xp = {q["name"]: q["value"] for q in x.get("properties", [])}
        if cp.get("assetType") == "algorithm" and xp.get("pqch:role") == "key-establishment":
            kex.append({"name": x.get("name"), "qv": xp.get("pqch:quantum-vulnerable") == "true"})
        elif cp.get("assetType") == "protocol" and x.get("name", "").startswith("TLS"):
            protos.append(x.get("name"))
    return {"run": scan_run, "posture": props.get("pqch:posture"), "kex": kex, "protocols": sorted(set(protos))}


def policy_facts(var: Path, scan: Run, events: list[dict]) -> dict:
    """What the architecture beat says about judgement, as counts: the packs the rules read and whether
    their quotes were checked against the source, the entries' compatibility under them, the gaps the
    scan recorded and how many were filled, and how many supplier statements this deployment holds.
    Counts only, never a name or an address: the public copy carries this document whole. A part that
    cannot be read is left null and the reason kept, so the page shows words instead of a wrong number."""
    out: dict = {"packs": [], "compatibility": None, "gaps": None, "attestations": None, "register_rows": None, "unread": []}

    def part(name, fn):
        try:
            out[name] = fn()
        except Exception as e:  # a run from before a rule, a missing pack directory: the box says so in words
            out["unread"].append(f"{name}: {type(e).__name__}")

    def packs():
        import yaml
        rows = []
        for f in sorted(Path("policy/packs").glob("*.yaml")):
            d = yaml.safe_load(f.read_text()) or {}
            rows.append({"id": f.stem, "title": d.get("title") or f.stem, "verified": bool(d.get("verified"))})
        return rows

    def compatibility():
        from pqch import planning
        return planning._compatibility_counts(events)

    def gaps():
        from pqch.assessor import gaps as g
        q = g.queue(var, events)
        return q and {"open": len(q["open"]), "filled": len(q["filled"]), "recorded": q["recorded"],
                      "classes": [{"class": c["class"], "reached": c["reached"], "gaps": c["gaps"]} for c in q["classes"]]}

    def attestations():
        from pqch import attest
        return len(attest.recorded(var))

    def register_rows():
        from pqch import planning
        plan = planning.build(var, scan)
        return len(planning.register(plan, events).get("rows") or []) if plan else None

    for name, fn in (("packs", packs), ("compatibility", compatibility), ("gaps", gaps), ("attestations", attestations), ("register_rows", register_rows)):
        part(name, fn)
    return out


def _plain(v):
    """A verification result as plain JSON: its own to_dict, else its dataclass fields, else as is."""
    import dataclasses
    if hasattr(v, "to_dict"):
        return v.to_dict()
    if dataclasses.is_dataclass(v):
        return dataclasses.asdict(v)
    return v if isinstance(v, (dict, list, str, int, float, bool, type(None))) else {k: _plain(x) for k, x in vars(v).items()}


def _host_detail(var: Path, run_id: str | None) -> dict:
    """What a system scan read: the files job as a uid, the firmware's settings, and each job's count."""
    d: dict = {"jobs": [], "files": None, "firmware": None}
    if not run_id:
        return d
    try:
        r = Run(var, run_id)
        for e in r.ledger.events():
            p, t = e.get("payload") or {}, e.get("type")
            if t == "scan.completed":
                d["jobs"].append({"profile": p.get("profile"), "status": p.get("status"), "ms": p.get("duration_ms"), "findings": p.get("findings"), "replayed": p.get("replayed")})
            elif t == "platform.observed" and p.get("source") == "files":
                d["files"] = {"read": p.get("files_read"), "as_uid": p.get("read_as_uid"), "unreadable": len(p.get("unreadable") or []), "trust_store": p.get("trust_store_certificates")}
            elif t == "platform.observed" and p.get("source") == "firmware":
                s, dev = p.get("settings") or {}, p.get("device") or {}
                d["firmware"] = {"secure_boot": s.get("secure_boot"), "tpm": s.get("tpm"), "model": dev.get("model"), "vendor": dev.get("vendor"),
                                 "bios": next((f"{f.get('name')} {f.get('version')}" for f in p.get("firmware") or []), None),
                                 "enforces": [x for f in p.get("firmware") or [] for x in f.get("enforces") or []]}
            elif t == "platform.observed" and p.get("source") == "controller":
                c = p.get("controller") or {}
                d["controller"] = {"model": c.get("model"), "firmware": c.get("firmware_version")}
    except Exception as e:
        d["error"] = str(e)[:120]
    return d


def _ms(a: str | None, b: str | None) -> int | None:
    from datetime import datetime
    try:
        f = lambda s: datetime.fromisoformat(s.replace("Z", "+00:00"))
        return int((f(b) - f(a)).total_seconds() * 1000)
    except Exception:
        return None


def _engine(cfg_path: str | None) -> dict:
    """The tiers this box serves the roles with, and what the engine says it is serving, live."""
    out = {"tiers": {}, "roles": {}, "live": None}
    if not cfg_path or not Path(cfg_path).exists():
        return out
    try:
        from pqch.inference import load_config
        cfg = load_config(cfg_path)
    except Exception as e:
        out["error"] = str(e)[:200]
        return out
    for name, t in (cfg.get("tiers") or {}).items():
        out["tiers"][name] = {"model": t.get("model"), "hardware": t.get("hardware"), "base_url": t.get("base_url"),
                              "reasoning_model": (t.get("reasoning") or {}).get("model")}
    out["roles"] = cfg.get("roles") or {}
    fast = (cfg.get("tiers") or {}).get("fast") or {}
    if fast.get("base_url"):
        try:
            import requests
            t0 = time.perf_counter()
            r = requests.get(fast["base_url"].rstrip("/") + "/models", timeout=3,
                             headers={"Authorization": "Bearer " + os.environ.get(fast.get("api_key_env") or "", "local")})
            out["live"] = {"models": [m.get("id") for m in (r.json().get("data") or [])], "ms": int((time.perf_counter() - t0) * 1000),
                           "status": r.status_code}
        except Exception as e:
            out["live"] = {"error": str(e)[:120]}
    return out


def _scanners() -> list[dict]:
    """The tools the runner starts as containers, by name, version and digest, from its profiles."""
    try:
        import yaml
        p = yaml.safe_load((Path(__file__).resolve().parents[1] / "runner" / "profiles.yaml").read_text())
        profs = p.get("profiles", p) if isinstance(p, dict) else {}
        seen, out = set(), []
        for name, v in profs.items():
            if not isinstance(v, dict):
                continue
            key = (v.get("tool"), v.get("version"))
            if key in seen:
                continue
            seen.add(key)
            img = v.get("image") or ""
            out.append({"tool": v.get("tool"), "version": v.get("version"), "layer": v.get("layer"), "profile": name,
                        "image": "the harness itself" if img == "self" else img.split("@")[0], "digest": img.split("@")[1][:19] if "@" in img else None,
                        "network": v.get("network")})
        return out
    except Exception:
        return []


def payload(var: Path, sheet: list[dict], *, snapshots_dir: Path, hardware: str, inference_config: str | None,
            this_host: str | None, static: bool = False) -> dict:
    """Everything the stage draws, in one document. Static: the public copy's document, with the test agency
    only, the hardware its ledger recorded, and what the stage would have fetched carried inside it."""
    from pqch import planning, systems
    from pqch.cbom import project

    t0 = time.perf_counter()
    out: dict = {"hardware": hardware, "this_host": this_host, "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    scan = Run.latest(var, "scan")
    if scan and scan.ledger.exists():
        events = list(scan.ledger.events())
        bom = project(events)
        graph = cbom_graph(bom)
        out["scan"] = {"run": scan.id, "events": len(events), "started": events[0].get("ts") if events else None,
                       "scope_hash": (events[0].get("payload") or {}).get("scope_hash") if events else None,
                       "jobs": [{"profile": (e.get("payload") or {}).get("profile"), "target": (e.get("payload") or {}).get("target"),
                                 "status": (e.get("payload") or {}).get("status"), "ms": (e.get("payload") or {}).get("duration_ms"),
                                 "findings": (e.get("payload") or {}).get("findings")}
                                for e in events if e.get("type") == "scan.completed"]}
        out["score"] = _score(scan)
        out["cbom"] = graph
        out["estate"] = estate_map(graph)
        out["estate"]["sheet"] = sheet
        try:
            plan = planning.build(var, scan, snapshots_dir=snapshots_dir)
            out["plan"] = {"run": plan.get("run"), "ranking": plan.get("ranking"), "waves": plan.get("waves"),
                           "first_open": plan.get("first_open"), "done": plan.get("done"), "waiting": plan.get("waiting"),
                           "order": [{k: s.get(k) for k in ("id", "service", "title", "wave", "due", "state", "status", "kind", "why", "n", "done", "depends_on")}
                                     for s in plan.get("order") or []]}
        except Exception as e:
            out["plan"] = {"error": str(e)[:200]}
        out["record"] = _ledger(scan)
        out["policy"] = policy_facts(var, scan, events)
    change = Run.latest(var, "change")
    if change and change.ledger.exists():
        out["change"] = {"run": change.id, "changes": _changes(change), "record": _ledger(change, last=40)}
    if static:
        # the copy replays a change that was carried through: the latest change run in which one landed
        # (as the overview's story of one change chooses), not a run left waiting for an approval
        from pqch.ui.view import change_runs
        for cr in reversed(change_runs(var)):
            chs = _changes(cr)
            if any(c.get("landed") for c in chs):
                out["change"] = {"run": cr.id, "changes": chs, "record": _ledger(cr, last=40)}
                break
        out["this_host"] = None
        out["hosts"] = []          # the test agency only: no server, the lab's or any other, goes into a copy
        out["static"] = static_block(var, scan) if scan else {}
        out["hardware"] = out["static"].get("hardware") or "unlabelled"
        out["engine"] = out["static"].pop("engine", None) or {"tiers": {}, "roles": {}, "live": None}
        out["scanners"] = _scanners()
        out["built_ms"] = int((time.perf_counter() - t0) * 1000)
        return out
    try:
        out["hosts"] = []
        for h in systems.hosts(var):
            row = {k: h.get(k) for k in ("name", "run", "addresses", "this_machine", "recorded", "findings", "parts", "scanned_at")}
            row.update(_host_detail(var, h.get("run")))
            out["hosts"].append(row)
    except Exception as e:
        out["hosts"] = {"error": str(e)[:200]}
    out["engine"] = _engine(inference_config)
    out["scanners"] = _scanners()
    out["built_ms"] = int((time.perf_counter() - t0) * 1000)
    return out


CRITERIA_WORDS = {"high-impact": "a high-impact system", "high-value-asset": "a High Value Asset",
                  "sensitive-in-2030": "data still sensitive in 2030"}
KEX_WORDS = {"pq": "already post-quantum only", "mixed": "a hybrid group offered, classical still accepted", "classical": "classical only"}


def narration_facts(row: dict) -> dict:
    """A plan row as facts a model cannot misread: each label says what its value is. The stage and the
    recorder send short keys (`blocked`, `secret_until`, `kex`); a model given those said a service that is
    already post-quantum "will implement" it, and turned the year its data stays secret into a deadline for
    the thing its supplier blocks."""
    kex = str(row.get("kex") or "")
    blocked = row.get("blocked") if row.get("blocked") not in (None, "", "nothing") else None
    done = kex == "pq" and not blocked and not row.get("title")
    facts = {"rank": row.get("rank"), "service": row.get("service"), "mission": row.get("mission"),
             "ranked_by_the_memo_for": ", ".join(CRITERIA_WORDS.get(c.strip(), c.strip()) for c in str(row.get("why") or "").split(",") if c.strip())
                                       or "nothing: the memo does not prioritize it",
             "its_data_must_stay_secret_until_year": row.get("secret_until"),
             "key_exchange_today": "/".join(KEX_WORDS.get(k, k) for k in kex.split("/")) if kex else None,
             "waits_on_its_supplier_for": blocked or "nothing",
             "next_step": row.get("title") or ("none: every migration item is already met" if done else "none listed in this row"),
             "step_due": row.get("due")}
    return {k: v for k, v in facts.items() if v is not None}


def narrate(kind: str, row: dict, *, purpose: str = "demo-narration") -> dict:
    """One spoken line for a plan row, from the fast tier with reasoning off, timed and labelled.
    The line is colour, not a decision: the row's order and facts come from the rules."""
    from pqch.inference import complete
    facts = narration_facts(row)
    messages = [
        {"role": "system", "content": "/no_think\nYou narrate one row of a post-quantum migration plan for a federal agency, "
                                      "on stage, in one plain sentence of at most 30 words. Say the service, what it is for and "
                                      "its rank, then its next step and why it is ranked there. If next_step says none, say what "
                                      "its key exchange is today instead. Use only the facts given, each as its label says. "
                                      "No advice, no hedging, no preamble, no quotation marks."},
        {"role": "user", "content": f"Row ({kind}): {json.dumps(facts)}"},
    ]
    t0 = time.perf_counter()
    try:
        c = complete("fast", messages, max_tokens=120, purpose=purpose, reasoning=False)
        text = (c.text or "").strip().split("\n")[0][:240]
        return {"text": text, "ms": c.latency_ms, "model": c.model, "tier": c.tier, "hardware": c.hardware,
                "tokens": (c.usage or {}).get("completion_tokens"), "finish": c.finish_reason}
    except Exception as e:
        return {"error": str(e)[:200], "ms": int((time.perf_counter() - t0) * 1000)}


# ───────── the stage as a static copy: recorded once, nothing called ─────────
# The public demo has no app behind it: no scan to start, no model to ask, no host but the test agency. The
# copy carries what the stage would have fetched (every CBOM entry, the Ask answers recorded by `pqch ask
# record`, a narration line per plan row recorded by `pqch demo record`) and names the hardware the runs'
# own ledgers recorded, not the box the stage was designed on.

def ledger_hardware(run: Run) -> str | None:
    """The hardware a run's scan jobs recorded, the most common label on its scan.completed events."""
    from collections import Counter
    c = Counter((e.get("payload") or {}).get("hardware") for e in run.ledger.events() if e.get("type") == "scan.completed")
    c.pop(None, None)
    return c.most_common(1)[0][0] if c else None


def narration_row(r: dict, k: int) -> dict:
    """The facts the stage sends for plan row k (0-based), as demo.js's narrateNext builds them."""
    return {"rank": k + 1, "service": r.get("service"), "mission": r.get("mission"), "why": ", ".join(r.get("criteria") or []),
            "secret_until": r.get("sensitive_through"), "kex": "/".join(r.get("kex_now") or []),
            "blocked": ", ".join(r.get("blocked") or []) or "nothing", "title": (r.get("step") or {}).get("title")}


def recording_path(var: Path, run_id: str) -> Path:
    return Path(var) / "demo" / f"{run_id}.json"


def _engine_labels(cfg_path: str | None) -> dict:
    """The tier map's models and hardware labels, without addresses: what a recording may say about its engines."""
    e = _engine_static(cfg_path)
    for t in e["tiers"].values():
        t.pop("base_url", None)
    return e


def _engine_static(cfg_path: str | None) -> dict:
    out = {"tiers": {}, "roles": {}, "live": None}
    if not cfg_path or not Path(cfg_path).exists():
        return out
    from pqch.inference import load_config
    cfg = load_config(cfg_path)
    for name, t in (cfg.get("tiers") or {}).items():
        out["tiers"][name] = {"model": t.get("model"), "hardware": t.get("hardware"), "base_url": t.get("base_url"),
                              "reasoning_model": (t.get("reasoning") or {}).get("model")}
    out["roles"] = cfg.get("roles") or {}
    return out


def record(var: Path, scan: Run, *, snapshots_dir: Path, inference_config: str | None) -> dict:
    """Narrate every row of the scan's plan once, through the same call the stage makes, and keep the lines."""
    from pqch import planning
    plan = planning.build(var, scan, snapshots_dir=snapshots_dir)
    lines = [narrate("plan", narration_row(r, k)) for k, r in enumerate(plan.get("ranking") or [])]
    rec = {"run": scan.id, "recorded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
           "narration": lines, "engine": _engine_labels(inference_config)}
    p = recording_path(var, scan.id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rec, indent=1))
    varmode.private(p)
    return rec


def static_block(var: Path, scan: Run) -> dict:
    """What the static stage reads instead of calling the app: the entries, the recorded narration and Ask."""
    from pqch import ask as askmod
    out: dict = {"hardware": ledger_hardware(scan), "entries": {}, "narration": [], "ask": {}, "recorded_at": None}
    path = scan.dir / "workbench.cdx.json"
    if path.is_file():
        doc = json.loads(path.read_text())
        bom = {"format": doc.get("bomFormat"), "spec": doc.get("specVersion"), "serial": doc.get("serialNumber"),
               "components": len(doc.get("components", []))}
        deps = {d.get("ref"): d.get("dependsOn", []) for d in doc.get("dependencies", [])}
        for c in doc.get("components", []):
            if c.get("bom-ref"):
                out["entries"][c["bom-ref"]] = {"component": c, "depends_on": deps.get(c["bom-ref"], []), "run": scan.id, "bom": bom}
    try:
        rec = json.loads(recording_path(var, scan.id).read_text())
        if rec.get("run") == scan.id:
            out["narration"], out["recorded_at"], out["engine"] = rec.get("narration") or [], rec.get("recorded_at"), rec.get("engine")
    except (OSError, json.JSONDecodeError):
        pass
    a = askmod.load_recording(var, scan.id)
    if a:
        qs = [q for q in askmod.EXAMPLES if q in a["answers"] and "unavailable" not in a["answers"][q]]
        out["ask"] = {q: f"ask/{i}/" for i, q in enumerate([q for q in askmod.EXAMPLES if q in a["answers"]], 1) if q in qs}
        out["ask_recorded_at"] = a.get("recorded_at")
    return out
