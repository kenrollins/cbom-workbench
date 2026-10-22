"""What the page shows, assembled from one run's ledger and the files rebuilt from it."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from pqch.ledger import verify
from pqch.run import Run

LAYER_ORDER = {"key-establishment": 0, "signature": 1}


def _endpoint(subject: dict) -> str:
    return f"{subject['host']}:{subject['port']}"


def signed_view(run: Run, events: list[dict], signer=None) -> dict:
    """Checkpoints, verified against the signer's key and the signer's own record when it is reachable."""
    from pqch.ledger.checkpoints import verify_signed

    pub, known, source = None, None, "ledger.pub beside the ledger; no outside record"
    signer_key = None
    if signer is not None:
        try:
            signer_key = signer.key()
            pub = signer_key["public_key_pem"].encode()
            known = signer.record(run.id)
            source = "the signer's key and its own record of what it signed"
        except Exception as e:  # signer down: say so, and fall back to the file
            source = f"ledger.pub beside the ledger; signer unreachable ({type(e).__name__})"
    beside = run.dir / "ledger.pub"
    if pub is None and beside.exists():
        pub = beside.read_bytes()
    res = verify_signed(events, pub, known=known)
    mismatch = bool(signer_key and beside.exists()
                    and beside.read_text().strip() != signer_key["public_key_pem"].strip())
    return {"ok": res.ok, "error": res.error, "checkpoints": res.checkpoints,
            "signed_through": res.signed_through, "unsigned_after": res.unsigned_after,
            "key_id": res.key_id, "source": source, "pub_mismatch": mismatch,
            "last": next((e["payload"] for e in reversed(events) if e["type"] == "checkpoint.signed"), None)}


def run_view(run: Run, signer=None) -> dict:
    events = list(run.ledger.events())
    if not events:
        return {}
    check = verify(events)
    if not check.ok:
        # Nothing is rendered from a ledger that does not verify.
        return {"run": run.id, "broken": True, "files": [],
                "ledger": {"events": len(events), "head": check.head, "ok": False, "error": check.error,
                           "at_seq": check.at_seq}}
    started = events[0]
    scope = started["payload"]["scope"]
    by_id = {e["id"]: e for e in events}

    findings = {e["id"]: e for e in events if e["type"] == "finding.observed"}
    scans = [e for e in events if e["type"] == "scan.completed"]
    scan_of = {}
    for fid, fe in findings.items():
        if fe["inputs"]:
            scan_of[fid] = by_id.get(fe["inputs"][0])

    links_from: dict[str, list[dict]] = {}
    for e in events:
        if e["type"] == "link.asserted" and isinstance(e["payload"]["from"], str):
            links_from.setdefault(e["payload"]["from"], []).append(e)
    in_use: dict[str, dict] = {}
    postures: dict[str, dict] = {}
    bindings: dict[str, dict] = {}
    conflicts: dict[str, dict] = {}
    vclasses: dict[tuple[str, str, str], dict] = {}
    model_events = []
    for e in events:
        if e["type"] != "assessment.made":
            continue
        if e["actor"]["kind"] == "model":
            model_events.append(e)
            continue
        c = e["payload"].get("classification", {})
        rule = e["payload"].get("rule_id")
        if rule == "conflict/resolve/1":
            conflicts[e["payload"]["finding"]] = e
            continue
        if rule == "verifier/class/1":
            sj = e["payload"]["subject"]
            vclasses[(sj["layer"], sj["type"], sj["role"])] = e
            continue
        if rule == "explain/failed":
            continue
        if "in_use" in c:
            in_use[e["payload"]["finding"]] = e
        if "posture" in c:
            postures[_endpoint(e["payload"]["subject"])] = e
        if "bound" in c:
            bindings[_endpoint(e["payload"]["subject"])] = e
    # The chain's upper links: listener -> service and image -> service (rule link/service/1), and the
    # owner's supplied facts per service, each a link.asserted with a human actor and status supplied.
    svc_links: dict[str, dict] = {}
    img_links: dict[str, dict] = {}
    supplied: dict[str, dict[str, dict]] = {}
    for e in events:
        if e["type"] != "link.asserted" or isinstance(e["payload"]["from"], str):
            continue
        p = e["payload"]
        if p.get("status") == "supplied":
            supplied.setdefault(p["from"]["name"], {})[p["kind"]] = {
                "value": p["to"]["value"], "event": e["id"], "by": e["actor"]["id"], "basis": p["basis"],
                "source": p.get("source")}
        elif p["from"]["kind"] == "endpoint":
            svc_links[_endpoint(p["from"])] = e
        elif p["from"]["kind"] == "image":
            img_links[p["from"]["image"]] = e
    explanations: dict[str, dict] = {}
    for e in model_events:
        if e["payload"].get("purpose") == "explain-conflict":
            explanations[e["payload"]["finding"]] = e
    traces = traces_by_fingerprint(run.var)
    # What each service's configuration files hashed to in this scan (watch mode's manifest): a
    # trace made over other files is of an earlier configuration and is not shown as current.
    manifests = {e["payload"]["service"]: {f["path"]: f["sha256"] for f in e["payload"]["files"]}
                 for e in events if e["type"] == "config.observed"}

    def facts_links(service: str | None) -> list[dict]:
        out = []
        for kind, step in (("mission-function", "mission function"), ("data-lifetime", "data lifetime"),
                           ("high-value-asset", "high-value asset")):
            f = (supplied.get(service) or {}).get(kind) if service else None
            if f is None:
                out.append({"step": step, "label": "not supplied", "status": "missing",
                            "why": "no service to attach it to" if not service else
                            "the owner's context file carries no such fact for this service"})
                continue
            v = f["value"]
            label = f"{v} years" if kind == "data-lifetime" else ("yes" if v is True else "no" if v is False else str(v))
            out.append({"step": step, "label": label, "status": "supplied", "event": f["event"], "by": f["by"],
                        "basis": f["basis"], "source": f.get("source")})
        return out

    def conflict_of(fid: str) -> dict | None:
        e = conflicts.get(fid)
        if e is None:
            return None
        x = explanations.get(fid)
        return {**e["payload"]["classification"], "basis": e["payload"]["basis"], "event": e["id"],
                "disagrees_with": e["payload"].get("disagrees_with", []),
                "explanation": x and {"actor": x["actor"], "event": x["id"], **{k: x["payload"][k] for k in
                                      ("classification", "explanation", "agrees_with_rule", "latency_ms")}}}

    def finding_row(fid: str) -> dict:
        fe = findings[fid]
        f = fe["payload"]
        scan = scan_of.get(fid)
        replayed = scan and scan["payload"].get("replayed_from")
        return {
            "event": fe["id"], "seq": fe["seq"], "ts": fe["ts"], "observed_at": f["observed_at"],
            "layer": f["layer"], "type": f["asset"]["type"], "role": f["asset"]["role"],
            "name": f["asset"]["name"], "parameters": f["asset"].get("parameters", {}),
            "subject": f["subject"], "tool": f"{f['source']['tool']} {f['source']['version']}",
            "excerpt": f["evidence"]["excerpt"], "raw": f["evidence"]["raw"],
            "raw_sha256": f["evidence"]["sha256"], "scanner_digest": f["source"]["image_digest"],
            "replayed": replayed,
            "in_use": in_use.get(fid, {}).get("payload"),
            "links": [{"event": le["id"], "basis": le["payload"]["basis"], "rule": le["payload"]["rule_id"],
                       "to": finding_row_short(le["payload"]["to"])} for le in links_from.get(fid, [])],
            "verifiable_by": (vclasses.get((f["layer"], f["asset"]["type"], f["asset"]["role"])) or {}).get(
                "payload", {}).get("classification", {}).get("verifiable_by"),
            "verifier_event": (vclasses.get((f["layer"], f["asset"]["type"], f["asset"]["role"])) or {}).get("id"),
            "conflict": conflict_of(fid),
            "trace": _trace_row(traces.get(f["fingerprint"]), run.id, manifests),
        }

    def finding_row_short(fid: str) -> dict:
        f = findings[fid]["payload"]
        return {"event": fid, "image": f["subject"].get("image", ""), "path": f["subject"].get("path", ""),
                "name": f["asset"]["name"], "type": f["asset"]["type"]}

    listeners = []
    for ep in scope["endpoints"]:
        key = _endpoint(ep)
        rows = [finding_row(fid) for fid, fe in findings.items()
                if fe["payload"]["layer"] == "wire" and _endpoint(fe["payload"]["subject"]) == key]
        rows.sort(key=lambda r: (LAYER_ORDER.get(r["role"], 2), r["type"] != "certificate", r["name"]))
        scan = next((s for s in scans if s["payload"]["target"].get("host") == ep["host"]
                     and s["payload"]["target"].get("port") == ep["port"]), None)
        p = postures.get(key)
        svc = svc_links.get(key)
        chain = []
        if scan and scan["payload"]["status"] == "ok":
            chain.append({"step": "listener", "label": f"{ep['protocol'].upper()} {key}", "status": "discovered",
                          "event": scan["id"], "basis": f"scanned by {scan['payload']['tool']} {scan['payload']['version']}"})
        else:
            chain.append({"step": "listener", "label": f"{ep['protocol'].upper()} {key}", "status": "missing",
                          "why": "no successful scan of this listener in the run"})
        cert = next((r for r in rows if r["type"] == "certificate"), None) \
            or next((r for r in rows if r["role"] == "signature"), None)
        if cert:
            ln = cert["links"][0] if cert["links"] else None
            chain.append({"step": "certificate" if cert["type"] == "certificate" else "host key",
                          "label": f"{cert['name']} {cert['type']}", "status": "discovered", "event": cert["event"],
                          "basis": (f"served; its key is the file {ln['to']['path']} in {ln['to']['image'].split('@')[0]} "
                                    f"(rule {ln['rule']}, event {ln['event']})") if ln else
                          "served; no file in the scope's image holds the same public key", "link": ln})
        else:
            chain.append({"step": "certificate", "label": "none recorded", "status": "missing",
                          "why": "the scan recorded no certificate or host key on this listener"})
        if svc:
            chain.append({"step": "service", "label": svc["payload"]["to"]["name"], "status": "discovered",
                          "event": svc["id"], "basis": svc["payload"]["basis"]})
        else:
            chain.append({"step": "service", "label": ep.get("service") or "unknown", "status": "missing",
                          "why": "the scope does not name a service for this listener" if not ep.get("service") else
                          "the listener did not run the scope's image during the scan, so nothing joins it to a service"})
        chain += facts_links(ep.get("service"))
        listeners.append({
            "address": key, "protocol": ep["protocol"], "sni": ep.get("sni"),
            "image": ep.get("image", ""), "posture": p and p["payload"]["classification"],
            "posture_event": p and p["id"], "rows": rows,
            "binding": bindings.get(key) and {**bindings[key]["payload"], "event": bindings[key]["id"]},
            "scan": scan and {"status": scan["payload"]["status"], "ms": scan["payload"]["duration_ms"],
                              "tool": scan["payload"]["tool"], "event": scan["id"]},
            "service": svc and {"name": svc["payload"]["to"]["name"], "event": svc["id"], "basis": svc["payload"]["basis"]},
            "service_named": ep.get("service"),
            "chain": chain, "chain_complete": all(c["status"] != "missing" for c in chain),
        })

    images = {}
    image_refs: dict[str, str] = {}
    for fid, fe in findings.items():
        f = fe["payload"]
        if f["layer"] != "host":
            continue
        images.setdefault(f["subject"]["image"], []).append(finding_row(fid))
        image_refs[f["subject"]["image"]] = f"{f['subject']['image']}@{f['source'].get('subject_digest', '')}"
    for rows in images.values():
        rows.sort(key=lambda r: (r["subject"]["path"], r["type"], r["name"]))
    image_chains = {}
    for image in images:
        le = img_links.get(image_refs.get(image, ""))
        named = next((ep.get("service") for ep in scope["endpoints"] if ep.get("image") == image_refs.get(image)), None)
        chain = [{"step": "image", "label": image, "status": "discovered", "basis": "scanned image in the scope"}]
        if le:
            chain.append({"step": "service", "label": le["payload"]["to"]["name"], "status": "discovered",
                          "event": le["id"], "basis": le["payload"]["basis"]})
        else:
            chain.append({"step": "service", "label": named or "unknown", "status": "missing",
                          "why": "no listener of this image was found running it during the scan" if named else
                          "the scope names no service for this image"})
        chain += facts_links(named)
        image_chains[image] = {"chain": chain, "service": le and le["payload"]["to"]["name"],
                               "complete": all(c["status"] != "missing" for c in chain)}
    chain_summary = {
        "listeners": len(listeners), "complete": sum(1 for ln in listeners if ln["chain_complete"]),
        "service_links": len(svc_links) + len(img_links),
        "supplied": sum(len(v) for v in supplied.values()), "services_supplied": len(supplied),
    }
    shown_traces = [r["trace"] for ln in listeners for r in ln["rows"] if r.get("trace")]
    trace_summary = {
        "traces": len(shown_traces), "answered": sum(1 for t in shown_traces if t["outcome"] == "answered"),
        "keyed": sum(1 for t in shown_traces if t["key_check"]),
        "agree": sum(1 for t in shown_traces if t["key_check"] and t["key_check"]["agrees"]),
        "replayed": sum(1 for t in shown_traces if t["replayed"]),
        "latency_ms": sorted(t["latency_ms"] for t in shown_traces),
        "engines": sorted({f"{t['settings']['model']} on {t['settings']['hardware']}" + (", reasoning on" if t["settings"]["reasoning"] else "")
                           for t in shown_traces}),
    }
    conflict_rows = []
    for fid in conflicts:
        f = findings[fid]["payload"]
        conflict_rows.append({"finding": fid, "subject": f["subject"], "name": f["asset"]["name"], "type": f["asset"]["type"],
                              **conflict_of(fid)})
    verifier_rows = sorted(({"layer": k[0], "type": k[1], "role": k[2], "event": e["id"],
                             **e["payload"]["classification"], "basis": e["payload"]["basis"]}
                            for k, e in vclasses.items()), key=lambda r: (r["layer"], r["type"], r["role"]))

    score = None
    sp = run.dir / "score.json"
    if sp.exists():
        score = json.loads(sp.read_text())

    key_ev = next((e for e in events if e["type"] == "key.committed"), None)
    return {
        "run": run.id,
        "started": started["ts"],
        "closed": events[-1]["ts"] if events[-1]["type"] == "run.closed" else None,
        # Where this run's scans ran, from the run itself — not from whatever machine is serving the page.
        "hardware": "; ".join(sorted({s["payload"]["hardware"] for s in scans if s["payload"].get("hardware")}))
                    or ((score or {}).get("labels") or {}).get("hardware"),
        "scope_hash": started["payload"]["scope_hash"],
        "scope": scope,
        "key": key_ev and key_ev["payload"],
        "ledger": {"events": len(events), "head": check.head, "ok": check.ok, "error": check.error,
                   "at_seq": check.at_seq},
        "signed": signed_view(run, events, signer),
        "scans": [{"profile": s["payload"]["profile"], "target": s["payload"]["target"],
                   "status": s["payload"]["status"], "ms": s["payload"]["duration_ms"],
                   "findings": s["payload"].get("findings", 0), "tool": s["payload"]["tool"],
                   "version": s["payload"]["version"], "event": s["id"], "ts": s["ts"],
                   "started_at": s["payload"]["started_at"],
                   "replayed": s["payload"].get("replayed_from")} for s in scans],
        "listeners": listeners,
        "unbound": [ln["address"] for ln in listeners
                    if ln["binding"] and not ln["binding"]["classification"]["bound"]],
        "images": dict(sorted(images.items())),
        "image_chains": image_chains,
        "chains": chain_summary,
        "conflicts": sorted(conflict_rows, key=lambda r: (r["in_force"], str(r["reason"]), r["subject"].get("path", ""))),
        "verifiers": verifier_rows,
        "traces": trace_summary,
        "managed": queues_view(run.var, events),
        "supplied": supplied,
        "score": score,
        "models": [{"actor": e["actor"], "payload": e["payload"], "ts": e["ts"], "event": e["id"]}
                   for e in model_events],
        "files": [p.name for p in sorted(Path(run.dir).glob("*")) if p.is_file()],
    }


def estate_graph(view: dict, sheet: list[dict]) -> dict:
    """The estate as a graph a reader can zoom through: systems the sheet names, the services that
    have evidence, their listeners and images, the assets on each, and the events behind each asset.
    Every node and edge is read from this run's events; a sheet row with no evidence stays a ghost."""
    nodes, edges = [], []

    def node(nid, kind, label, **extra):
        nodes.append({"id": nid, "kind": kind, "label": label, **extra})
        return nid

    def edge(a, b, kind):
        edges.append({"from": a, "to": b, "kind": kind})

    repo = lambda image: image.split("@")[0].split("/")[-1].split(":")[0]  # noqa: E731
    services: dict[str, str] = {}
    facts = view.get("supplied") or {}
    for ln in view.get("listeners", []):
        svc = (ln.get("service") or {}).get("name") or ln.get("service_named") or (repo(ln["image"]) if ln.get("image") else ln["address"])
        if svc not in services:
            services[svc] = node(f"svc:{svc}", "service", svc, posture=None, evidence=True,
                                 linked=bool(ln.get("service")), facts={k: v["value"] for k, v in facts.get(svc, {}).items()})
        posture = ln.get("posture") or {}
        lid = node(f"ln:{ln['address']}", "listener", (ln.get("sni") or ln["address"]) + " · " + ln["protocol"],
                   address=ln["address"], posture=posture.get("posture"), bound=(ln.get("binding") or {}).get("classification", {}).get("bound", True),
                   scan=ln.get("scan"))
        edge(services[svc], lid, "listens")
        svc_node = next(n for n in nodes if n["id"] == services[svc])
        svc_node["posture"] = posture.get("posture") or svc_node["posture"]
        for r in ln["rows"]:
            aid = node(f"asset:{r['event']}", "asset", r["name"], asset_type=r["type"], role=r["role"], posture=None,
                       pq=r["name"] in (posture.get("kex_pq") or []), parameters=r.get("parameters", {}),
                       tool=r["tool"], raw=r["raw"], raw_sha256=r["raw_sha256"], event=r["event"], observed_at=r["observed_at"])
            edge(lid, aid, "negotiates" if r["role"] == "key-establishment" else "serves")
            for link in r.get("links", []):
                fid = f"file:{link['to']['image'].split('@')[0]}:{link['to']['path']}"
                if not any(n["id"] == fid for n in nodes):
                    node(fid, "file", link["to"]["path"], image=link["to"]["image"].split("@")[0], asset_type=link["to"]["type"], name=link["to"]["name"])
                edge(aid, fid, "served from")
    for image, rows in view.get("images", {}).items():
        svc = (view.get("image_chains", {}).get(image) or {}).get("service") or repo(image)
        if svc not in services:
            services[svc] = node(f"svc:{svc}", "service", svc, posture=None, evidence=True, linked=False,
                                 facts={k: v["value"] for k, v in facts.get(svc, {}).items()})
        iid = node(f"img:{image.split('@')[0]}", "image", image.split("@")[0].split("/")[-1], image=image.split("@")[0])
        edge(services[svc], iid, "runs")
        for r in rows:
            fid = f"file:{image.split('@')[0]}:{r['subject']['path']}"
            if not any(n["id"] == fid for n in nodes):
                node(fid, "file", r["subject"]["path"], image=image.split("@")[0], asset_type=r["type"], name=r["name"])
            f = next(n for n in nodes if n["id"] == fid)
            f.update(in_use=(r.get("in_use") or {}).get("classification", {}).get("in_use"), basis=(r.get("in_use") or {}).get("basis"),
                     tool=r["tool"], event=r["event"], raw=r["raw"], raw_sha256=r["raw_sha256"], parameters=r.get("parameters", {}))
            if not any(e["from"] == iid and e["to"] == fid for e in edges):
                edge(iid, fid, "holds")
    for row in sheet:
        sid = node(f"sheet:{row['system']}", "sheet", row["system"], says=row["says"], owner=row["owner"],
                   evidence=bool(row.get("service") and row["service"] in services))
        if row.get("service") in services:
            edge(sid, services[row["service"]], "is")
    return {"nodes": nodes, "edges": edges, "run": view.get("run"), "scope_hash": view.get("scope_hash")}


def probe_checks(verdict_events: list[dict], lookup, *, events: list[dict] | None = None,
                 runner_log: list[dict] | None = None, run_id: str | None = None, read_raw=None) -> dict[str, dict]:
    """Each probe a verdict cites, checked against the runner's own record of the job.

    A probe passes when the runner logged that job with the same raw output hash, the same
    start and end and the same container, and no other verdict cites it. Given the run's
    events and the runner's log of applies, it must also be the job the check prescribes —
    that profile, those parameters, that address — started after the runner finished the
    apply or recreate the verdict answers, against the container the runner created then.
    Given `read_raw`, the runner's raw output must say what the verdict says, probe by probe,
    and the status must be the one those outputs give. Results are keyed by job id; a
    verdict's own result is keyed `verdict:<event id>`.
    """
    from pqch import verifier

    ids = [p.get("job_id") for v in verdict_events for p in v["payload"].get("probes", []) if p.get("job_id")]
    if not ids:
        return {}
    logged = lookup(set(ids)) if lookup else None
    if logged is None:
        return {i: {"ok": None, "why": "runner log unreachable"} for i in ids}
    by_id = {e["job_id"]: e for e in logged}
    seen: dict[str, int] = {}
    for i in ids:
        seen[i] = seen.get(i, 0) + 1
    by_event = {e["id"]: e for e in events or []}
    proposals = {e["payload"]["change_id"]: e for e in events or [] if e["type"] == "change.proposed"}
    out = {}
    for v in verdict_events:
        vp = v["payload"]
        prop = proposals.get(vp.get("change_id"))
        check = prop and dict(prop["payload"].get("check") or {})
        override = vp.get("target_override")
        if check and override:
            check["target"] = {**check["target"], **override}
        after = by_event.get(vp.get("after_event"))
        entry, context = None, events is not None and runner_log is not None
        if context and after is not None:
            kind = "apply" if after["type"] == "change.applied" else "recreate"
            entry = next((e for e in runner_log if e.get("run") == run_id and e.get("kind") == kind
                          and e.get("change_id") == vp.get("change_id")
                          and e.get("containers") == after["payload"].get("containers")), None)
        want = verifier.expected_jobs(check) if check and check.get("must_accept") else {}
        parsed, all_ok = {}, True
        for p in vp.get("probes", []):
            i = p.get("job_id")
            if not i:
                all_ok = False
                continue
            e = by_id.get(i)
            why = []
            if e is None:
                why.append("no such job in the runner's log")
            else:
                if e.get("raw_sha256") != p.get("raw_sha256"):
                    why.append("raw output hash differs")
                if e.get("started_at") != p.get("started_at") or e.get("ended_at") != p.get("ended_at"):
                    why.append("times differ")
                if (e.get("binding") or {}).get("container_id") != p.get("container_id"):
                    why.append("container differs")
                if context and p.get("name") in want:
                    profile, params = want[p["name"]]
                    if e.get("profile") != profile or (e.get("params") or {}) != params:
                        why.append("not the job the check prescribes: the runner ran "
                                   f"{e.get('profile')} {e.get('params') or ''}".rstrip())
                    t = check["target"]
                    if (e.get("target") or {}).get("host") != t["host"] or (e.get("target") or {}).get("port") != t["port"]:
                        why.append("the job probed another address")
                    if entry is None:
                        why.append("the apply or recreate this verdict answers is not in the runner's log")
                    else:
                        if e.get("started_at", "") < entry["ended_at"]:
                            why.append(f"the job started before the runner finished the {entry['kind']}")
                        made = (entry.get("containers") or [{}])[0].get("after")
                        if not override and (e.get("binding") or {}).get("container_id") != made:
                            why.append(f"the job reached another container than the one the runner's {entry['kind']} made")
                if read_raw is not None and not why and e.get("raw") and check:
                    try:
                        raw = read_raw(e)
                        got = verifier.parse(p.get("name"), raw, check)
                        parsed[p.get("name")] = got
                        if got["result"] != p.get("result") or (p.get("name") == "witness" and
                                                                 got["accepted_groups"] != p.get("accepted_groups")):
                            said = got["result"] + (f" {got['accepted_groups']}" if p.get("name") == "witness" else "")
                            why.append(f"the runner's raw output says {said}, not what the verdict records")
                    except (OSError, ValueError) as err:
                        why.append(f"raw output unreadable: {err}"[:120])
            if seen[i] > 1:
                why.append(f"cited by {seen[i]} verdicts")
            out[i] = {"ok": not why, "why": "; ".join(why)}
            all_ok = all_ok and not why
        if context:
            why = []
            if not all_ok:
                why.append("a probe does not match the runner's record")
            elif read_raw is not None and check and set(parsed) == set(verifier.expected_jobs(check)) and not vp.get("reasons"):
                status, _also, disagreement = verifier.decide(check, parsed)
                if disagreement:
                    status = "inconclusive"
                if status != vp.get("status"):
                    why.append(f"the runner's raw outputs give {status}, and the verdict says {vp.get('status')}")
            out[f"verdict:{v['id']}"] = {"ok": not why, "why": "; ".join(why)}
    return out


def change_view(run: Run, signer=None, runner_log: list[dict] | None = None, jobs_lookup=None) -> dict:
    """One change run: the policy, each proposal, its approval, verdicts, and time-to-change."""
    from pqch.migrator import intervals
    from pqch.scout import read_raw

    events = list(run.ledger.events())
    if not events:
        return {}
    check = verify(events)
    if not check.ok:
        return {"run": run.id, "broken": True, "error": check.error, "at_seq": check.at_seq}
    policy = next((e for e in events if e["type"] == "policy.changed"), None)
    log = {(e.get("run"), e.get("change_id"), e.get("kind")): e for e in (runner_log or [])}
    checks = probe_checks([e for e in events if e["type"] == "verdict.issued"], jobs_lookup, events=events,
                          runner_log=runner_log, run_id=run.id, read_raw=lambda job: read_raw(run.var, job))
    changes = []
    for prop in (e for e in events if e["type"] == "change.proposed"):
        cid = prop["payload"]["change_id"]
        related = [e for e in events if e["payload"].get("change_id") == cid and e["id"] != prop["id"]]
        actions = []
        for e in related:
            if e["type"] in ("change.applied", "service.recreated"):
                kind = "apply" if e["type"] == "change.applied" else "recreate"
                logged = log.get((run.id, cid, kind))
                actions.append({"type": e["type"], "ts": e["ts"], "event": e["id"], "payload": e["payload"],
                                "in_runner_log": None if runner_log is None else
                                bool(logged and logged.get("containers") == e["payload"]["containers"])})
        mine = [e for e in related if e["type"] == "verdict.issued"]
        # A verdict whose probes name no job cannot be checked at all, and counts as unchecked.
        marks = [a["in_runner_log"] for a in actions] + \
                [checks.get(f"verdict:{e['id']}", {}).get("ok") if all(
                    p.get("job_id") for p in e["payload"].get("probes", [])) and e["payload"].get("probes")
                 else None for e in mine]
        changes.append({
            # Borne out by the runner's own record: every apply and recreate, and every verdict
            # whose probes carry job ids. None when the runner's log could not be read.
            "confirmed": False if False in marks else (None if None in marks else True),
            "change_id": cid, "proposal": prop["payload"], "proposed_ts": prop["ts"], "event": prop["id"],
            "approvals": [{"type": e["type"], "ts": e["ts"], "event": e["id"], **e["payload"]}
                          for e in related if e["type"] in ("approval.granted", "approval.denied")],
            "actions": actions,
            "verdicts": [{"ts": e["ts"], "event": e["id"], **e["payload"]} for e in related
                         if e["type"] == "verdict.issued"],
            "rehearsals": [{"ts": e["ts"], "event": e["id"], **e["payload"]} for e in related
                           if e["type"] == "rehearsal.completed"],
            "matrices": [{"ts": e["ts"], "event": e["id"], **e["payload"]} for e in related
                         if e["type"] == "matrix.completed"],
            "drafted_by": prop["actor"] if prop["actor"]["kind"] == "model" else None,
        })
    # The run as a strip for the timeline figure: every event's stamp and kind, and for a checkpoint
    # the signer's own time and what it covers.
    timeline = [{"seq": e["seq"], "ts": e["ts"], "type": e["type"], "change_id": e["payload"].get("change_id"),
                 "signed_at": e["payload"].get("signed_at"), "through_seq": e["payload"].get("through_seq"),
                 "status": e["payload"].get("status"), "target_override": bool(e["payload"].get("target_override"))}
                for e in events]
    no_draft = [{"event": e["id"], "service": e["payload"]["subject"]["service"], "basis": e["payload"]["basis"],
                 "calls": e["payload"]["drafted"]["calls"], "actor": e["actor"]}
                for e in events if e["type"] == "assessment.made" and e["payload"].get("purpose") == "change-plan"]
    return {
        "run": run.id, "started": events[0]["ts"], "closed": events[-1]["type"] == "run.closed",
        "no_draft": no_draft,
        "timeline": timeline,
        "policy": policy and {"ts": policy["ts"], **policy["payload"]},
        "changes": changes, "intervals": {t["change_id"]: t for t in intervals(events)},
        "probe_checks": checks,
        "signed": signed_view(run, events, signer),
    }


# ------------------------------------------------------------------ the lab estate (passive capture)
_STRENGTH = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "X25519Kyber768Draft00", "X448", "X25519",
             "secp521r1", "secp384r1", "secp256r1", "ffdhe8192", "ffdhe4096", "ffdhe3072", "ffdhe2048"]


def _domain(name: str | None) -> str | None:
    if not name:
        return None
    parts = name.lower().rstrip(".").split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "ac", "gov") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def capture_view(run: Run) -> dict:
    """The lab estate as one capture run shows it: every listener's observed posture, every client's
    capability, the outside world by name, the hours, and the edges between them. Read from the ledger
    only; the figures draw from this."""
    events = list(run.ledger.events())
    if not events:
        return {}
    check = verify(events)
    if not check.ok:
        return {"run": run.id, "broken": True, "ledger": {"events": len(events), "ok": False, "error": check.error,
                                                        "at_seq": check.at_seq}}
    started = events[0]["payload"]
    scope = started["scope"]
    finds = {e["id"]: e for e in events if e["type"] == "finding.observed"}
    servers: dict[tuple[str, int], dict] = {}
    clients: dict[str, dict] = {}
    ssh: dict[tuple[str, int], dict] = {}
    for fe in finds.values():
        f = fe["payload"]
        s, a, p = f["subject"], f["asset"], f["asset"].get("parameters", {})
        if s["kind"] == "client":
            c = clients.setdefault(s["host"], {"host": s["host"], "vlan": s.get("vlan"), "inside": p.get("inside", True),
                                               "handshakes": p.get("handshakes", 0), "offers": [], "versions": [],
                                               "capability": None, "event": fe["id"]})
            if a["type"] == "algorithm":
                c["offers"].append({"name": a["name"], "n": p.get("offered", 0), "first": p.get("first_choice", 0),
                                    "hybrid": bool(p.get("hybrid")), "chosen": p.get("chosen_by_servers", 0), "event": fe["id"]})
            else:
                c["versions"].append({"name": a["name"], "n": p.get("offered", 0)})
        elif s["kind"] == "endpoint" and s["protocol"] == "tls":
            k = (s["host"], s["port"])
            sv = servers.setdefault(k, {"host": s["host"], "port": s["port"], "sni": s.get("sni"), "vlan": s.get("vlan"),
                                        "inside": p.get("inside", False), "handshakes": p.get("handshakes", 0),
                                        "chosen": [], "versions": [], "posture": None, "event": fe["id"]})
            if a["type"] == "algorithm":
                sv["chosen"].append({"name": a["name"], "n": p.get("chosen", 0), "hybrid": bool(p.get("hybrid")), "event": fe["id"]})
                sv["hybrid_offered"] = p.get("clients_offered_hybrid", 0)
            else:
                sv["versions"].append({"name": a["name"], "n": p.get("negotiated", 0)})
        elif s["kind"] == "endpoint" and s["protocol"] == "ssh":
            k = (s["host"], s["port"])
            sh = ssh.setdefault(k, {"host": s["host"], "port": s["port"], "vlan": s.get("vlan"), "sessions": p.get("sessions", 0),
                                    "kex": [], "hostkeys": [], "server_software": p.get("server_software"),
                                    "client_software": p.get("client_software"), "event": fe["id"]})
            (sh["kex"] if a["role"] == "key-establishment" else sh["hostkeys"]).append(
                {"name": a["name"], "n": p.get("negotiated", 0), "hybrid": any(k in a["name"] for k in ("MLKEM", "sntrup"))})
    for e in events:
        if e["type"] != "assessment.made":
            continue
        pl, c = e["payload"], e["payload"]["classification"]
        if pl["rule_id"] == "posture/observed/1":
            k = (pl["subject"]["host"], pl["subject"]["port"])
            if k in servers:
                servers[k]["posture"] = {**c, "event": e["id"]}
        elif pl["rule_id"] == "capability/observed/1" and pl["subject"]["host"] in clients:
            clients[pl["subject"]["host"]]["capability"] = {**c, "event": e["id"]}

    summary = next((e["payload"] for e in reversed(events)
                    if e["type"] == "scan.completed" and e["payload"].get("profile") == "capture-summary"), {})
    hours = []
    for e in events:
        if e["type"] == "scan.completed" and e["payload"].get("tally"):
            hours.append({"t": e["payload"]["started_at"], "end": e["payload"]["ended_at"], **e["payload"]["tally"]})
    hours.sort(key=lambda h: h["t"])

    # The outside world, by registered name.
    outside: dict[str, dict] = {}
    for (host, _port), sv in servers.items():
        if sv["inside"]:
            continue
        d = _domain(sv["sni"]) or host
        o = outside.setdefault(d, {"domain": d, "handshakes": 0, "hybrid": 0, "classical": 0, "servers": 0})
        o["servers"] += 1
        o["handshakes"] += sv["handshakes"]
        for ch in sv["chosen"]:
            o["hybrid" if ch["hybrid"] else "classical"] += ch["n"]
    outside_rows = sorted(outside.values(), key=lambda o: -o["handshakes"])

    # Edges: client to inside listener, or client to outside name; what the pair negotiated.
    edges: dict[tuple[str, str], dict] = {}
    for ed in summary.get("edges", []):
        if ed["inside"]:
            target, kind = f"{ed['server']}:{ed['port']}", "listener"
        else:
            target, kind = _domain(ed["sni"]) or ed["server"], "domain"
        ag = edges.setdefault((ed["client"], target), {"client": ed["client"], "target": target, "kind": kind,
                                                       "n": 0, "hybrid": 0, "refused": 0})
        ag["n"] += ed["n"]
        ag["hybrid"] += ed["hybrid"]
        ag["refused"] += ed["refused"]

    # A listener's VLAN, inferred: the tag most of the clients on its /24 carried. Marked as inferred.
    subnet_vlan: dict[str, Counter] = {}
    for c in clients.values():
        if c["vlan"] is not None:
            subnet_vlan.setdefault(c["host"].rsplit(".", 1)[0], Counter())[c["vlan"]] += 1
    for sv in list(servers.values()) + list(ssh.values()):
        guess = subnet_vlan.get(sv["host"].rsplit(".", 1)[0])
        sv["vlan"] = guess.most_common(1)[0][0] if guess else None
        sv["vlan_inferred"] = True

    def vl(c):
        return c["vlan"] if c["vlan"] is not None else 0
    vlans: dict[int, dict] = {}
    for c in clients.values():
        if not c["inside"]:
            continue
        v = vlans.setdefault(vl(c), {"vlan": vl(c), "clients": 0, "hybrid": 0, "classical13": 0, "legacy": 0, "handshakes": 0})
        v["clients"] += 1
        v["handshakes"] += c["handshakes"]
        cap = (c["capability"] or {}).get("capability")
        v["hybrid" if cap == "hybrid" else "classical13" if cap == "classical-1.3" else "legacy"] += 1
    for c in clients.values():
        c["offers"].sort(key=lambda o: (_STRENGTH.index(o["name"]) if o["name"] in _STRENGTH else 99, -o["n"]))
    for sv in servers.values():
        sv["chosen"].sort(key=lambda o: -o["n"])
    group_names = sorted({o["name"] for c in clients.values() for o in c["offers"]},
                         key=lambda n: (_STRENGTH.index(n) if n in _STRENGTH else 99, n))
    inside = sorted((sv for sv in servers.values() if sv["inside"]), key=lambda s: -s["handshakes"])
    for sv in inside:
        sv["refused_share"] = round(100 * sv["posture"]["hybrid_refused"] / sv["handshakes"]) if sv.get("posture") and sv["handshakes"] else 0
    cap_sum = summary.get("capture_loss", {})
    return {
        "run": run.id, "started": events[0]["ts"], "closed": events[-1]["ts"] if events[-1]["type"] == "run.closed" else None,
        "span": [summary.get("started_at"), summary.get("ended_at")], "hardware": summary.get("hardware"),
        "scope": {"hash": started["scope_hash"], "authorized_by": scope.get("authorized_by"),
                  "captures": scope.get("captures", []), "vlans": sorted({v for c in scope.get("captures", []) for v in c["vlans"]})},
        "loss": cap_sum, "files": summary.get("files", []),
        "ledger": {"events": len(events), "head": check.head, "ok": True},
        "handshakes": sum(h["handshakes"] for h in hours), "hybrid": sum(h["hybrid"] for h in hours),
        "inside_servers": inside,
        "outside": outside_rows,
        "clients": sorted((c for c in clients.values() if c["inside"]), key=lambda c: (vl(c), -c["handshakes"])),
        "outside_clients": [c for c in clients.values() if not c["inside"]],
        "ssh": sorted(ssh.values(), key=lambda s: -s["sessions"]),
        "hours": hours,
        "vlans": sorted(vlans.values(), key=lambda v: v["vlan"]),
        "groups": group_names,
        "edges": sorted(edges.values(), key=lambda e: -e["n"]),
        "findings": len(finds),
    }


def _trace_row(t: dict | None, run_id: str, manifests: dict | None = None) -> dict | None:
    if t is None:
        return None
    p = t["payload"]
    now = (manifests or {}).get(p["service"])
    if now is not None and {f["path"]: f["sha256"] for f in p["files"]} != now:
        return None         # traced over files that have since changed: not this configuration's cause
    return {"event": t["id"], "run": t["run"], "ts": t["ts"], "actor": t["actor"], "settings": p["settings"],
            "answer": p["answer"], "line_text": p["line_text"], "outcome": p["outcome"], "used": p["used"],
            "budget": p["budget"], "latency_ms": p["latency_ms"], "steps": p["steps"], "key_check": p["key_check"],
            "service": p["service"], "replayed": p["finding"]["run"] != run_id, "from_run": p["finding"]["run"]}


def runs_of_kind(var: Path, kind: str) -> list[Run]:
    """Every run of one kind under var, oldest first, found by its first event alone."""
    out = []
    runs = Path(var) / "runs"
    if not runs.is_dir():
        return out
    for d in sorted(p for p in runs.iterdir() if p.is_dir()):
        led = d / "ledger.jsonl"
        if not led.is_file():
            continue
        with led.open(encoding="utf-8") as f:
            first = f.readline()
        try:
            ev = json.loads(first)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "run.started" and ev.get("payload", {}).get("kind") == kind:
            out.append(Run(var, d.name))
    return out


def traces_by_fingerprint(var: Path) -> dict[str, dict]:
    """The latest trace of each finding fingerprint across every investigate run whose ledger verifies.
    A trace made on an earlier scan of the same observation is shown on a later scan, marked replayed."""
    out: dict[str, dict] = {}
    for run in runs_of_kind(var, "investigate"):
        events = list(run.ledger.events())
        if not verify(events).ok:
            continue
        for e in events:
            if e["type"] == "trace.completed":
                out[e["payload"]["finding"]["fingerprint"]] = {**e, "run": run.id}
    return out


MANAGED_RULES = ("queue/m-26-15/1", "priority/m-26-15/1", "blocker/supplier/1", "blocker/validated-module/1",
                 "deadline/tls13/1", "pack/scope/1", "quantum/vulnerable/1")


def queues_view(var: Path, events: list[dict]) -> dict | None:
    """The Managed rung: each migration item with its owner, queue, deadline, the criteria that put
    it there, its blockers, and the approval state of any change that answers it — a decision
    record per item, read from this run's rules and every change run's ledger."""
    by_rule: dict[str, list[dict]] = {}
    for e in events:
        if e["type"] == "assessment.made" and e["payload"].get("rule_id") in MANAGED_RULES:
            by_rule.setdefault(e["payload"]["rule_id"], []).append(e)
    if not by_rule.get("queue/m-26-15/1"):
        return None
    facts: dict[str, dict] = {}
    for e in events:
        if e["type"] == "link.asserted" and e["payload"].get("status") == "supplied":
            facts.setdefault(e["payload"]["from"]["name"], {})[e["payload"]["kind"]] = {"value": e["payload"]["to"]["value"], "event": e["id"]}
    prio = {e["payload"]["subject"]["name"]: e for e in by_rule.get("priority/m-26-15/1", [])}
    blockers: dict[tuple[str, str], dict] = {}
    for rule in ("blocker/supplier/1", "blocker/validated-module/1"):
        for e in by_rule.get(rule, []):
            sj = e["payload"]["subject"]
            blockers.setdefault((sj["service"], sj["function"]), {})[rule] = {
                **e["payload"]["classification"], "basis": e["payload"]["basis"], "event": e["id"]}
    # Changes that answer an item: a change run's proposal names the service it targets, and the
    # crypto policy it renders is key establishment.
    approvals: dict[str, dict] = {}
    for run in change_runs(var):
        evs = list(run.ledger.events())
        if not evs or not verify(evs).ok:
            continue
        for prop in (e for e in evs if e["type"] == "change.proposed"):
            cid, svc = prop["payload"]["change_id"], (prop["payload"].get("target") or {}).get("service")
            rel = [e for e in evs if e["payload"].get("change_id") == cid]
            verdict = next((e for e in reversed(rel) if e["type"] == "verdict.issued"), None)
            state = ("verified " + verdict["payload"]["status"]) if verdict else \
                ("applied" if any(e["type"] == "change.applied" for e in rel) else
                 "approved" if any(e["type"] == "approval.granted" for e in rel) else
                 "denied" if any(e["type"] == "approval.denied" for e in rel) else "proposed")
            by = next((e["payload"].get("by") for e in rel if e["type"] in ("approval.granted", "approval.denied")), None)
            approvals[svc] = {"run": run.id, "change_id": cid, "state": state, "intent": prop["payload"].get("intent"),
                              "by": by, "ts": (verdict or rel[-1] if rel else prop)["ts"]}
    # A model's explanation is shown only while the deployment binds the role: a role below its
    # floor is unbound, and then the page shows the rule's basis alone.
    explained = explanations_by_item(var) if role_bound("explain-queue") else {}
    items, met = [], []
    for e in by_rule["queue/m-26-15/1"]:
        p, c = e["payload"], e["payload"]["classification"]
        svc, fn = p["subject"]["service"], p["subject"]["function"]
        f = facts.get(svc, {})
        pr = prio.get(svc)
        row = {"service": svc, "function": fn, "event": e["id"], **c, "basis": p["basis"], "section": p["source"]["section"],
               "owner": (f.get("owner") or {}).get("value"), "owner_event": (f.get("owner") or {}).get("event"),
               "criteria": pr and pr["payload"]["classification"]["criteria"], "priority_event": pr and pr["id"],
               "priority_basis": pr and pr["payload"]["basis"],
               "blockers": blockers.get((svc, fn), {}),
               "approval": approvals.get(svc) if fn == "key-establishment" else None,
               "explained": explained.get(e["id"]) or explained.get((svc, fn, c.get("queue")))}
        (items if c["state"] == "open" else met).append(row)
    order = {"kex-2030": 0, "sig-2031": 1, "remaining-2035": 2}
    items.sort(key=lambda r: (order.get(r["queue"], 9), r["service"], r["function"]))
    tls = [{**e["payload"]["classification"], "address": f"{e['payload']['subject']['host']}:{e['payload']['subject']['port']}",
            "basis": e["payload"]["basis"], "event": e["id"]} for e in by_rule.get("deadline/tls13/1", [])]
    vuln = [{**e["payload"]["subject"], **e["payload"]["classification"], "basis": e["payload"]["basis"], "event": e["id"]}
            for e in by_rule.get("quantum/vulnerable/1", [])]
    queues = {}
    for r in items:
        queues.setdefault(r["queue"], []).append(r)
    src = by_rule["queue/m-26-15/1"][0]["payload"]["source"]
    return {
        "pack": src["pack"], "pdf_sha256": src.get("pdf_sha256"), "queues": queues, "rows": items, "met": met,
        "tls13": sorted(tls, key=lambda t: (t["state"], t["address"])),
        "vulnerable": sorted(vuln, key=lambda v: (v["role"], not v["quantum_vulnerable"], v["name"])),
        "counts": {"open": len(items), "met": len(met),
                   "supplier_blocked": sum(1 for r in items if (r["blockers"].get("blocker/supplier/1") or {}).get("state") == "blocked"),
                   "replace": sorted({r["service"] for r in items if (r["blockers"].get("blocker/supplier/1") or {}).get("replace_priority")}),
                   "validated_none": sum(1 for r in items if (r["blockers"].get("blocker/validated-module/1") or {}).get("state") == "none-validated"),
                   "validated_available": sum(1 for r in items if (r["blockers"].get("blocker/validated-module/1") or {}).get("state") == "available-not-in-use"),
                   "tls13_open": sum(1 for t in tls if t["state"] == "open"),
                   "prioritized": sorted(s for s, e in prio.items() if e["payload"]["classification"]["prioritized"]),
                   "not_prioritized": sorted(s for s, e in prio.items() if not e["payload"]["classification"]["prioritized"])},
        "pack_scope": [{"service": e["payload"]["subject"]["name"], **e["payload"]["classification"]}
                       for e in by_rule.get("pack/scope/1", [])],
    }


def role_bound(role: str) -> bool:
    """Whether the deployment's inference config binds a role. False when it cannot be read."""
    from pqch import inference

    try:
        roles = inference.default().config.get("roles") or {}
    except Exception:
        return False
    return role in roles


def explanations_by_item(var: Path) -> dict:
    """The latest model explanation of each queue item, keyed by the item's event and, for a later
    scan of the same item, by (service, function, queue), marked replayed."""
    out: dict = {}
    for run in runs_of_kind(var, "explain"):
        events = list(run.ledger.events())
        if not verify(events).ok:
            continue
        for e in events:
            p = e["payload"]
            if e["type"] != "assessment.made" or p.get("purpose") != "explain-queue":
                continue
            row = {"run": run.id, "event": e["id"], "actor": e["actor"], "passed": p["classification"]["passed"],
                   "explanation": p["classification"]["explanation"], "calls": len(p["calls"]),
                   "passes": sum(1 for c in p["calls"] if c["pass"]), "retrieved": [t["id"] for t in p["retrieval"]["top"]],
                   "item_run": p["item"]["run"]}
            out[p["item"]["event"]] = row
            out[(p["subject"]["service"], p["subject"]["function"], p["item"]["queue"])] = {**row, "replayed": True}
    return out


def _rederives(var: Path, vp: dict, prop: dict | None) -> bool:
    """Whether a verdict's status is the one its probes' raw outputs give. A verdict whose raw outputs
    cannot be read here (moved, or from before the runner kept them) is taken as recorded."""
    from pqch import verifier

    if prop is None:
        return False
    if vp.get("reasons"):
        return True        # an inconclusive verdict with its reasons is a statement about itself
    check = dict(prop["payload"].get("check") or {})
    if not check.get("must_accept"):
        return True
    if vp.get("target_override"):
        check["target"] = {**check["target"], **vp["target_override"]}
    parsed = {}
    for p in vp.get("probes", []):
        path = Path(var) / str(p.get("raw", "")).removeprefix("var/")
        if not path.is_file():
            return True
        try:
            parsed[p["name"]] = verifier.parse(p["name"], path.read_bytes(), check)
        except (OSError, ValueError):
            return True
    if set(parsed) != set(verifier.expected_jobs(check)):
        return True
    return verifier.decide(check, parsed)[0] == vp.get("status")


def change_runs(var: Path) -> list[Run]:
    """Every change run under var, oldest first, found by its first event alone."""
    out = []
    runs = Path(var) / "runs"
    if not runs.is_dir():
        return out
    for d in sorted(p for p in runs.iterdir() if p.is_dir()):
        led = d / "ledger.jsonl"
        if not led.is_file():
            continue
        with led.open(encoding="utf-8") as f:
            first = f.readline()
        try:
            ev = json.loads(first)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "run.started" and ev.get("payload", {}).get("kind") == "change":
            out.append(Run(var, d.name))
    return out


def receipts_view(var: Path, view: dict) -> dict:
    """The receipts: the score by layer beside both baselines (from the run), the chains, the entries
    no verifier can confirm, the conflicts and how each was settled, and every change ever run on
    this deployment — proposed, approved, applied, verified, not landed — as the ledgers record it."""
    from pqch.migrator import intervals

    changes = {"runs": 0, "proposed": 0, "approved": 0, "denied": 0, "applied": 0, "recreated": 0,
               "verdicts": 0, "enforced": 0, "enabled_not_enforced": 0, "not_landed": 0, "inconclusive": 0,
               "landed": 0, "durable": 0, "broken": 0, "not_borne_out": 0, "rehearsals": 0, "drafted": 0,
               "latest": None}
    for run in change_runs(var):
        events = list(run.ledger.events())
        if not events or not verify(events).ok:
            changes["broken"] += 1
            continue
        changes["runs"] += 1
        props = {e["payload"]["change_id"]: e for e in events if e["type"] == "change.proposed"}
        for e in events:
            t = e["type"]
            if t == "change.proposed":
                changes["proposed"] += 1
                changes["drafted"] += int(e["actor"]["kind"] == "model")
            elif t == "rehearsal.completed":
                changes["rehearsals"] += 1
            elif t == "approval.granted":
                changes["approved"] += 1
            elif t == "approval.denied":
                changes["denied"] += 1
            elif t == "change.applied":
                changes["applied"] += 1
            elif t == "service.recreated":
                changes["recreated"] += 1
            elif t == "verdict.issued":
                changes["verdicts"] += 1
                st = e["payload"].get("status")
                # A verdict is counted by what its own raw output gives, not by what it says: one
                # that does not re-derive (the review's forgeries are such) is counted apart.
                if not _rederives(var, e["payload"], props.get(e["payload"].get("change_id"))):
                    changes["not_borne_out"] += 1
                    continue
                key = {"enforced": "enforced", "enabled-not-enforced": "enabled_not_enforced",
                       "not-landed": "not_landed", "inconclusive": "inconclusive"}.get(st)
                if key:
                    changes[key] += 1
        for t in intervals(events):
            if t.get("landed"):
                changes["landed"] += 1
            if t.get("durable"):
                changes["durable"] += 1
        last = events[-1]
        changes["latest"] = {"run": run.id, "events": len(events), "head": last["hash"], "ts": last["ts"],
                             "closed": last["type"] == "run.closed"}
    score = (view or {}).get("score") or {}
    wb = (score.get("columns") or {}).get("workbench") or {}
    verifiers = wb.get("verifiers") or {}
    entries = sum(verifiers.values())
    return {
        "chains": (view or {}).get("chains"),
        "supplied": wb.get("supplied"),
        "verifiers": {"by_kind": verifiers, "entries": entries, "none": verifiers.get("none", 0),
                      "classes": (view or {}).get("verifiers") or []},
        "conflicts": {"total": len((view or {}).get("conflicts") or []),
                      "by_outcome": dict(Counter((c["in_force"], c["reason"]) for c in (view or {}).get("conflicts") or [])),
                      "explained": sum(1 for c in (view or {}).get("conflicts") or [] if c.get("explanation"))},
        "changes": changes,
        "traces": (view or {}).get("traces"),
    }


def packages_view(run: Run | None) -> dict | None:
    """The latest change packages: one per item blocked on its supplier, read from a package run's
    ledger, which must verify."""
    if not run or not run.ledger.exists():
        return None
    events = list(run.ledger.events())
    check = verify(events)
    if not check.ok:
        return {"run": run.id, "broken": True, "error": check.error}
    pk = [{**e["payload"], "event": e["id"], "ts": e["ts"]} for e in events if e["type"] == "package.issued"]
    return {"run": run.id, "scan_run": pk[0]["item"]["run"] if pk else None, "packages": pk,
            "closed": events[-1]["type"] == "run.closed", "events": len(events),
            "by_service": sorted({p["item"]["service"] for p in pk})}


def house_graph(house: dict | None) -> dict | None:
    """The lab's CBOM as the same chain view: subnet, host, listener, then every entry on the listener —
    what it accepts when asked and what it chose in real handshakes, certificates among them. The lab
    has no spreadsheet and no service names, so the first two columns are where the listener is."""
    if not house:
        return None
    nodes, edges, seen = [], [], set()

    def node(nid, kind, label, **extra):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "kind": kind, "label": label, **extra})
        return nid

    posture = {r["address"]: ("pq" if r["hybrid_chosen"] else ("mixed" if r["hybrid_accepted"] else "classical"))
               for r in house["listeners"]}
    reading = {r["address"]: r["reading"] for r in house["listeners"]}
    for c in house["doc"]["components"]:
        props = {}
        for p in c.get("properties", []):
            props.setdefault(p["name"], []).append(p["value"])
        sj = json.loads(props.get("pqch:subject", ["{}"])[0])
        if sj.get("kind") != "endpoint":
            continue
        host, port = sj["host"], sj["port"]
        net = ".".join(host.split(".")[:3]) + ".0/24"
        addr = f"{host}:{port}"
        sn = node(f"net:{net}", "sheet", net, evidence=True, subnet=True)
        hn = node(f"host:{host}", "service", host, posture=None, evidence=True, linked=True, facts={}, host=True)
        ln = node(f"ln:{addr}", "listener", f"{port} · {sj.get('protocol', '')}", address=addr, posture=posture.get(addr),
                  bound=True, scan=None, reading=reading.get(addr))
        if not any(e["from"] == sn and e["to"] == hn for e in edges):
            edges.append({"from": sn, "to": hn, "kind": "holds"})
        if not any(e["from"] == hn and e["to"] == ln for e in edges):
            edges.append({"from": hn, "to": ln, "kind": "listens"})
        hnode = next(n for n in nodes if n["id"] == hn)
        rank = {"pq": 2, "mixed": 1, "classical": 0}
        if posture.get(addr) and rank[posture[addr]] >= rank.get(hnode["posture"] or "classical", 0):
            hnode["posture"] = posture[addr]
        params = [json.loads(v) for v in props.get("pqch:parameters", [])]
        merged = {k: v for pm in params for k, v in pm.items()}
        aid = node(f"asset:{c['bom-ref']}", "asset", c["name"], asset_type=c["cryptoProperties"]["assetType"],
                   role=(props.get("pqch:role") or [""])[0], posture=None,
                   pq=bool(re.search(r"mlkem|kyber|sntrup", c["name"], re.I)), parameters=merged,
                   tool=", ".join(props.get("pqch:tools", [])), raw=None, raw_sha256=None,
                   event=", ".join(props.get("pqch:evidence", [])), observed_at=None)
        edges.append({"from": ln, "to": aid, "kind": "negotiates"})
    for n in nodes:
        if n["kind"] == "listener" and not n["posture"]:
            n["posture"] = None
    nodes.sort(key=lambda n: (n["kind"], [int(x) if x.isdigit() else x for x in re.split(r"[.:/ ]", n["label"])]))
    return {"nodes": nodes, "edges": edges, "run": None,
            "columns": [["sheet", "subnet"], ["service", "host"], ["mid", "listeners"], ["asset", "what each accepts or chose"]],
            "intro": f"The house's CBOM, {house['entries']:,} entries; here the {len(house['listeners'])} listeners and what each accepts "
                     "when asked or chose in real handshakes, certificates among them. Click a host to follow it; anything for its evidence."}


def imports_view(var: Path) -> list[dict]:
    """Every import run on this deployment, newest first: the tool, its documents, what was placed,
    and its score against the key beside the workbench's own on the same estate."""
    out = []
    runs = Path(var) / "runs"
    if not runs.is_dir():
        return out
    for d in sorted((p for p in runs.iterdir() if p.is_dir()), reverse=True):
        led = d / "ledger.jsonl"
        if not led.is_file():
            continue
        with led.open(encoding="utf-8") as f:
            first = f.readline()
        try:
            if json.loads(first).get("payload", {}).get("kind") != "import":
                continue
        except json.JSONDecodeError:
            continue
        run = Run(var, d.name)
        events = list(run.ledger.events())
        if not verify(events).ok:
            out.append({"run": run.id, "broken": True})
            continue
        done = next((e for e in events if e["type"] == "import.completed"), None)
        if done:
            out.append({"run": run.id, "ts": done["ts"], **done["payload"]})
    return out
