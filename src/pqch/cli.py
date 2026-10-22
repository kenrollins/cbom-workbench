"""Command line: `pqch <command>`."""

from __future__ import annotations

import argparse
import json
import sys


def _ledger_verify(args: argparse.Namespace) -> int:
    from pathlib import Path

    from pqch.ledger import Ledger, verify
    from pqch.ledger.checkpoints import verify_signed

    events = list(Ledger(args.path).events())
    if not args.signed:
        res = verify(events)
        print(json.dumps(res.__dict__))
        return 0 if res.ok else 1
    pub = Path(args.pub) if args.pub else Path(args.path).parent / "ledger.pub"
    known = json.loads(Path(args.known).read_text()) if args.known else None
    res = verify_signed(events, pub.read_bytes() if pub.exists() else None, known=known)
    out = dict(res.__dict__)
    if args.key_id:
        out["key_checked"] = res.key_id == args.key_id
        if not out["key_checked"]:
            out["ok"], out["error"] = False, f"the key is {res.key_id}, not the expected {args.key_id}"
    elif not args.pub:
        out["key_checked"] = False
        print("warning: the public key was taken from beside the ledger and checked against nothing. "
              "A ledger rewritten and re-signed with another key passes this. Give --key-id (shown on the "
              "page) or --pub from the signer, and --known.", file=sys.stderr)
    print(json.dumps(out))
    return 0 if out["ok"] else 1


def _scope_generate(args: argparse.Namespace) -> int:
    from pathlib import Path

    from pqch import scope

    s = scope.generate(args.compose, network=args.network)
    text = json.dumps(s, indent=2) + "\n"
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text)
        print(f"{args.out}  sha256 {scope.scope_hash(s)}", file=sys.stderr)
    else:
        sys.stdout.write(text)
    return 0


def _scan(args: argparse.Namespace) -> int:
    import os
    from pathlib import Path

    from pqch.pipeline import run_once
    from pqch.runner.client import RunnerClient

    var = Path(os.environ.get("PQCH_VAR", "var"))
    client = RunnerClient(os.environ.get("PQCH_RUNNER_SOCKET", "/run/pqch/runner.sock"))
    key = Path(os.environ.get("PQCH_KEY", "agency/answer-key.yaml"))

    def show(line: dict) -> None:
        tg = line["target"]
        t = f"{tg['host']}:{tg['port']}" if "host" in tg else tg["image"].split("@")[0]
        tag = " (replayed)" if line["replayed"] else ""
        print(f"{line['profile']:<14} {t:<40} {line['status']:<8} {line['duration_ms']:>7} ms "
              f"{line['findings']:>3} findings{tag}", flush=True)

    run, summary = run_once(var, client, key, host=args.host, classify=args.classify_one,
                            explain=args.explain_conflicts, progress=show)
    print(f"run {run.id}: {len(summary['jobs'])} jobs, wall {summary['wall_ms']} ms; rules {summary['rules']}")
    if summary.get("classification"):
        print("classification:", json.dumps(summary["classification"]))
    return 0


def _investigate(args: argparse.Namespace) -> int:
    import os
    from pathlib import Path

    from pqch.investigator import investigate
    from pqch.pipeline import signer_from_env
    from pqch.run import Run

    var = Path(os.environ.get("PQCH_VAR", "var"))
    scan = Run(var, args.run) if args.run else Run.latest(var, "scan")
    if scan is None or not scan.ledger.exists():
        print("no scan run to investigate", file=sys.stderr)
        return 1

    def show(ev: dict) -> None:
        p = ev["payload"]
        a = p["answer"] or {}
        where = (f"{a['file']}:{a['line_start']}-{a['line_end']}" if a.get("file") else
                 ("default" if a.get("cause") == "default" else "no answer"))
        kc = p["key_check"]
        agree = "not keyed" if kc is None else ("agrees with the key" if kc["agrees"] else f"differs from the key ({kc['why']})")
        print(f"{p['finding']['subject']['host']}:{p['finding']['subject']['port']:<6} {p['finding']['asset']['name']:<18} "
              f"{p['outcome']:<16} {where:<48} {p['used']['steps']} steps {p['used']['tokens']:>6} tok "
              f"{p['latency_ms'] / 1000:6.1f} s  {agree}", flush=True)

    run, events = investigate(var, scan, agency_dir=Path(os.environ.get("PQCH_AGENCY_DIR", "agency")),
                              signer=signer_from_env(), finding_ids=args.finding, step_budget=args.steps,
                              token_budget=args.tokens, key_path=Path(os.environ.get("PQCH_KEY", "agency/answer-key.yaml")),
                              progress=show)
    print(f"investigate run {run.id if run else '(none: nothing to trace)'} over scan {scan.id}: {len(events)} traces")
    return 0


def _package(args: argparse.Namespace) -> int:
    import os
    from pathlib import Path

    from pqch.migrator.package import build
    from pqch.pipeline import signer_from_env
    from pqch.run import Run

    var = Path(os.environ.get("PQCH_VAR", "var"))
    scan = Run(var, args.run) if args.run else Run.latest(var, "scan")
    run, pkgs = build(var, scan, pack_path=os.environ.get("PQCH_PACK", "policy/packs/m-26-15.yaml"),
                      snapshots_dir=args.snapshots, signer=signer_from_env())
    if not run:
        print("no item is blocked on its supplier; no package")
        return 0
    for p in pkgs:
        up = "; upgrade path in the estate: " + ", ".join(u["service"] + " (" + u["software"] + ")" for u in p["unblock"]) if p["unblock"] else ""
        print(f"{p['item']['service']:<12} {p['item']['function']:<18} {p['why']['software']}: {len(p['entries'])} entries{up}")
    print(f"package run {run.id}: {len(pkgs)} packages")
    return 0


def _import(args: argparse.Namespace) -> int:
    """Any tool's CycloneDX CBOM as evidence, on a run of its own; scored when a key is given."""
    import os
    from pathlib import Path

    from pqch.pipeline import signer_from_env
    from pqch.run import Run
    from pqch.scout.imported import run_import

    var = Path(os.environ.get("PQCH_VAR", "var"))
    scan = Run.latest(var, "scan")
    scope = next(scan.ledger.events())["payload"]["scope"]
    docs = [(Path(d.split("=", 1)[0]), d.split("=", 1)[1] if "=" in d else None) for d in args.documents]
    run, s = run_import(var, docs, scope, repo=args.repo, commit=args.commit, tool=args.tool,
                        key_path=Path(args.key) if args.key else None, signer=signer_from_env())
    print(f"{s['tool']}: {sum(s['assets'].values())} assets in {len(s['documents'])} documents; "
          f"{s['findings']} findings placed ({', '.join(f'{k} {v}' for k, v in s['by_layer'].items()) or 'none'}), {s['unplaced']} unplaced")
    for layer, r in (s.get("score") or {}).items():
        if r["scanned"]:
            print(f"  {layer}: {r['covered']} of {r['present']} keyed items, {len(r['flagged_decoys'])} of {r['decoys']} decoys flagged")
    print(f"import run {run.id}")
    return 0


def _explain_queues(args: argparse.Namespace) -> int:
    import os
    import statistics
    from pathlib import Path

    from pqch.assessor.explain_queue import explain
    from pqch.pipeline import signer_from_env
    from pqch.run import Run

    var = Path(os.environ.get("PQCH_VAR", "var"))
    scan = Run(var, args.run) if args.run else Run.latest(var, "scan")

    def show(subject, passed, calls):
        marks = "".join("+" if c["pass"] else ("!" if c["harmful"] else "-") for c in calls)
        print(f"{subject['service']:<12} {subject['function']:<18} {marks}  {'pass' if passed else 'FAIL'}  "
              + "; ".join(c["why"] for c in calls if not c["pass"])[:160], flush=True)

    run, s = explain(var, scan, pack_path=os.environ.get("PQCH_PACK", "policy/packs/m-26-15.yaml"),
                     repeats=args.repeats, signer=signer_from_env(), progress=show)
    lat = s.pop("latency_ms")
    print(f"explain run {run.id if run else '(none)'} over scan {scan.id}: {s['passed']} of {s['items']} items pass; "
          f"{s['harmful_calls']} harmful of {s['calls']} calls; median {statistics.median(lat) / 1000 if lat else 0:.1f} s per call")
    return 0


def _watch(args: argparse.Namespace) -> int:
    import os
    from pathlib import Path

    from pqch.pipeline import signer_from_env
    from pqch.runner.client import RunnerClient
    from pqch.watch import watch

    out = watch(Path(os.environ.get("PQCH_VAR", "var")),
                RunnerClient(os.environ.get("PQCH_RUNNER_SOCKET", "/run/pqch/runner.sock")),
                Path(os.environ.get("PQCH_KEY", "agency/answer-key.yaml")),
                agency_dir=Path(os.environ.get("PQCH_AGENCY_DIR", "agency")), signer=signer_from_env(),
                trace=not args.no_trace, explain=not args.no_explain)
    print(json.dumps(out))
    return 0


def _scan_code(args: argparse.Namespace) -> int:
    """The thin code layer: one pinned repository, candidates by rule, judged by call-site-read."""
    import os
    import statistics
    from pathlib import Path

    import yaml

    from pqch.pipeline import signer_from_env, write_cboms
    from pqch.scout.code import scan

    pins = {p["name"]: p for p in yaml.safe_load(Path(args.pins).read_text())["repositories"]}
    pin = pins[args.name]
    var = Path(os.environ.get("PQCH_VAR", "var"))

    def show(c, m):
        print(f"{c['path']}:{c['line']:<5} {c['rule']:<22} {('USE ' + m['family'] + ' ' + m['role']) if m and m['is_crypto_use'] else ('not a use' if m else 'no reply')}", flush=True)

    run, s = scan(var, Path(args.targets) / args.name, repo=pin["repo"], commit=pin["commit"],
                  rules_path=Path(args.rules or f"policy/code-rules/{pin['language']}.yaml"),
                  authorized_by="a public repository, read at a pinned commit; nothing in it is run",
                  signer=signer_from_env(), progress=show, workers=args.workers)
    write_cboms_ok = True
    try:
        write_cboms(run)
    except ValueError as e:
        write_cboms_ok = False
        print(f"CBOM not written: {e}")
    lat = s.pop("latencies_ms")
    print(f"scan-code run {run.id}: {json.dumps(s)}; median {statistics.median(lat) / 1000 if lat else 0:.1f} s a call; CBOM {'written' if write_cboms_ok else 'not written'}")
    return 0


def _cbom_build(args: argparse.Namespace) -> int:
    import os

    from pqch.pipeline import write_cboms
    from pqch.run import Run

    var = os.environ.get("PQCH_VAR", "var")
    run = Run(var, args.run) if args.run else Run.latest(var)
    for name, path in write_cboms(run).items():
        print(f"{name:<20} {path}")
    return 0


def _scanners_pull(args: argparse.Namespace) -> int:
    import docker

    from pqch.runner import load_profiles

    client = docker.from_env()
    for name, prof in sorted(load_profiles().items()):
        if prof["image"] == "self":     # the runner's own image: built, not pulled
            continue
        repo, digest = prof["image"].split("@", 1)
        client.images.pull(repo, tag=digest)
        print(f"{name:<14} {prof['image']}")
    return 0


def _env_paths():
    import os
    from pathlib import Path

    return (Path(os.environ.get("PQCH_VAR", "var")),
            Path(os.environ.get("PQCH_CRYPTO_POLICY", "policy/crypto-policy.yaml")),
            Path(os.environ.get("PQCH_AGENCY_DIR", "agency")))


def _clients():
    import os

    from pqch.pipeline import signer_from_env
    from pqch.runner.client import RunnerClient

    signer = signer_from_env()
    if signer is None:
        raise SystemExit("PQCH_SIGNER_SOCKET is not set: changes need the signer")
    return RunnerClient(os.environ.get("PQCH_RUNNER_SOCKET", "/run/pqch/runner.sock")), signer


def _change_run(args):
    from pqch.run import Run

    var, _, _ = _env_paths()
    run = Run(var, args.run) if args.run else Run.latest(var, "change")
    if run is None:
        raise SystemExit("no change run")
    return run


def _policy_render(args: argparse.Namespace) -> int:
    """Building the estate: write each target's TLS configuration from the policy, outside any run."""
    from pqch.migrator import render

    _, policy_path, agency = _env_paths()
    policy = render.load(policy_path)
    for t in policy["targets"]:
        sw = t.get("software", "nginx")
        path = render.target_path(agency, t["service"], sw)
        if path.exists() and not args.force:
            print(f"{path} exists; changes to a built estate go through propose and approve "
                  f"(--force only when building it)")
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        if sw in render.RENDERED:
            path.write_text(render.render_for(sw, policy, t["intent"]))
        elif t["intent"] == "none":
            path.write_text(render.base(sw))
        else:
            print(f"{path}: {sw} has no renderer; build it at intent none and propose the change")
            continue
        print(f"{path}  intent {t['intent']}")
    return 0


def _change_propose(args: argparse.Namespace) -> int:
    from pqch.migrator import propose

    var, policy_path, agency = _env_paths()
    runner, signer = _clients()
    run, props = propose(var, runner, policy_path, agency, by=args.by,
                         authenticated_by="command line in the harness container", signer=signer)
    print(f"run {run.id}")
    for p in props:
        pl = p["payload"]
        print(f"change {pl['change_id']}  {pl['target']['service']} {pl['target']['address']}:{pl['target']['port']}"
              f"  intent {pl['intent']}\n{pl['diff']}")
    if not props:
        print("nothing to change: every target already matches the policy")
    return 0


def _change_approve(args: argparse.Namespace) -> int:
    from pqch.migrator import approve, execute

    run = _change_run(args)
    runner, signer = _clients()
    how = "command line in the harness container" + (f"; {args.via}" if args.via else "")
    ev = approve(run, args.change_id, by=args.by, authenticated_by=how,
                 signer=signer, deny=args.deny)
    print(f"{ev['type']} by {args.by} at {ev['ts']} (event {ev['id']})")
    if args.deny or args.no_execute:
        return 0
    out = execute(run, runner, signer, args.change_id, close=not args.keep_open)
    for k in ("verdict", "durable"):
        p = out[k]["payload"]
        print(f"{k:<8} {p['status']:<22} meets intent {p['meets_intent']}  durable {p['durable']}"
              f"  container {str(p['binding']['container_id'])[:12]}  {'; '.join(p['reasons'])}")
    return _change_status(args)


def _change_rehearse(args: argparse.Namespace) -> int:
    """Prove a proposal on a copy of the service in the twin, before anyone approves it."""
    import os

    from pqch.migrator import rehearse

    run = _change_run(args)
    runner, signer = _clients()
    ev = rehearse(run, runner, signer, args.change_id, hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"))
    v = ev["payload"]["verdict"]
    print(f"rehearsal on {ev['payload']['twin']}: {v['status']}  meets intent {v['meets_intent']}"
          + (f"  also accepts {', '.join(v.get('also_accepts') or [])}" if v.get("also_accepts") else "")
          + (f"  {'; '.join(v.get('reasons') or [])}" if v.get("reasons") else "")
          + (f"\n{v.get('logs_tail', '')}" if v["status"] == "did-not-start" else ""))
    return 0 if v["meets_intent"] else 1


def _change_matrix(args: argparse.Namespace) -> int:
    """Kinds of client against the listener as deployed and a copy with the proposed file."""
    import os

    from pqch.verifier.matrix import run_matrix

    run = _change_run(args)
    runner, signer = _clients()
    ev = run_matrix(run, runner, signer, args.change_id, hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"))
    for r in ev["payload"]["rows"]:
        print(f"{r['label']:<34} today {r['today']['result']:<9} proposed {r['proposed']['result']:<9} {r['effect']}")
    return 0


def _change_verify(args: argparse.Namespace) -> int:
    """Run a change's check again, optionally against another address (to show a wrong container fails)."""
    from pqch.migrator import verify_now

    run = _change_run(args)
    runner, signer = _clients()
    events = list(run.ledger.events())
    applied = [e for e in events if e["type"] in ("change.applied", "service.recreated")
               and e["payload"]["change_id"] == args.change_id]
    if not applied:
        raise SystemExit("the change has not been applied")
    last = applied[-1]
    c = last["payload"]["containers"][0]
    override = None
    if args.address:
        host, _, port = args.address.partition(":")
        override = {"host": host, "port": int(port or 443)}
        if args.sni:
            override["sni"] = args.sni
    ev = verify_now(run, runner, signer, args.change_id, after_event=last,
                    expect={"container_id": c["after"], "image_digest": c["image_digest"]}, target_override=override)
    p = ev["payload"]
    print(f"{p['status']}  meets intent {p['meets_intent']}  container {str(p['binding']['container_id'])[:12]}")
    for r in p["reasons"]:
        print(f"  - {r}")
    return 0


def _change_close(args: argparse.Namespace) -> int:
    run = _change_run(args)
    _, signer = _clients()
    ev = run.close(signer)
    print(f"run {run.id} closed at {ev['ts']}")
    return 0


def _change_status(args: argparse.Namespace) -> int:
    from pqch.migrator import intervals

    run = _change_run(args)
    for t in intervals(list(run.ledger.events())):
        fmt = lambda ms: "—" if ms is None else f"{ms / 1000:.1f} s"  # noqa: E731
        print(f"{t['change_id']}  {t['target']['service']}  intent {t['intent']}  verdicts {t['statuses']}"
              f"  durable {t['durable']}")
        if t["landed"]:
            print(f"  time-to-change: policy to verdict {fmt(t['policy_to_verdict_ms'])}"
                  f"  approval to verdict {fmt(t['approval_to_verdict_ms'])}  on {t['hardware']}"
                  f"  (ledger clock)")
            if t["signer_policy_to_verdict_max_ms"] is not None:
                print(f"  by the signer's clock: policy to verdict no more than {fmt(t['signer_policy_to_verdict_max_ms'])}"
                      f"  approval to verdict no more than {fmt(t['signer_approval_to_verdict_max_ms'])}"
                      f"  (last signature before each event to first signature over the verdict)")
            else:
                print(f"  by the signer's clock, first seen: policy to verdict {fmt(t['signer_policy_to_verdict_ms'])}"
                      f"  approval to verdict {fmt(t['signer_approval_to_verdict_ms'])}"
                      f"  (no signature precedes the policy event)")
            if t["clocks_disagree_ms"] is not None:
                print(f"  the ledger's timestamps and the signer's clock disagree by {fmt(t['clocks_disagree_ms'])}")
        else:
            print(f"  did not land: no time-to-change. Elapsed to the last verdict "
                  f"{fmt(t['policy_to_verdict_ms'])} on {t['hardware']}")
    return 0


def _scan_external(args: argparse.Namespace) -> int:
    import os
    from pathlib import Path

    from pqch.pipeline import scan_external
    from pqch.runner.client import RunnerClient

    var = Path(os.environ.get("PQCH_VAR", "var"))
    client = RunnerClient(args.runner_socket or os.environ.get("PQCH_LAB_RUNNER_SOCKET", "/run/pqch-lab/runner.sock"))

    def show(line: dict) -> None:
        tg = line["target"]
        print(f"{line['profile']:<14} {tg['host']}:{tg['port']:<6} {line['status']:<8} {line['duration_ms']:>7} ms "
              f"{line['findings']:>3} findings" + (f"  {line['error']}" if line.get("error") else ""), flush=True)

    run, summary = scan_external(var, client, progress=show)
    print(f"run {run.id}: {len(summary['jobs'])} jobs, wall {summary['wall_ms']} ms; rules {summary['rules']}")
    return 0


def _capture_ingest(args: argparse.Namespace) -> int:
    import os
    from pathlib import Path

    from pqch import scope as scope_mod
    from pqch.scout import capture

    var = Path(os.environ.get("PQCH_VAR", "var"))
    scope, h = scope_mod.load(args.scope)
    try:
        run, summary = capture.ingest(var, scope, args.capture_dir,
                                      hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"))
    except ValueError as e:
        print(str(e), file=sys.stderr)
        return 2
    print(json.dumps({"scope_hash": h, **summary}))
    return 0


def _capture_prune(args: argparse.Namespace) -> int:
    import os
    from pathlib import Path

    from pqch.scout import capture

    removed = capture.prune(Path(os.environ.get("PQCH_VAR", "var")), Path(args.capture_dir))
    print(json.dumps({"removed": len(removed)}))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pqch")
    sub = p.add_subparsers(dest="cmd", required=True)

    led = sub.add_parser("ledger", help="ledger tools").add_subparsers(dest="sub", required=True)
    v = led.add_parser("verify", help="verify a ledger's hash chain and binding rules")
    v.add_argument("path")
    v.add_argument("--signed", action="store_true", help="also check every checkpoint's ML-DSA signature")
    v.add_argument("--pub", help="public key PEM (default: ledger.pub beside the ledger)")
    v.add_argument("--known", help="JSON list of {through_seq, head_hash} recorded outside the ledger")
    v.add_argument("--key-id", help="the signer's key id, recorded outside the ledger")
    v.set_defaults(func=_ledger_verify)

    sc = sub.add_parser("scope", help="scope tools").add_subparsers(dest="sub", required=True)
    g = sc.add_parser("generate", help="generate an owned, colocated scope from a compose file")
    g.add_argument("compose", nargs="+", help="compose file, then any overlays")
    g.add_argument("--network", default=None)
    g.add_argument("--out", default=None)
    g.set_defaults(func=_scope_generate)

    se = sub.add_parser("scan-external", help="targeted scan of the listeners an external scope names, through its own runner")
    se.add_argument("--runner-socket", help="the external estate's runner socket (default PQCH_LAB_RUNNER_SOCKET)")
    se.set_defaults(func=_scan_external)

    cap = sub.add_parser("capture", help="passive capture").add_subparsers(dest="sub", required=True)
    ci = cap.add_parser("ingest", help="read Zeek's rotated handshake logs into a new capture run")
    ci.add_argument("--scope", required=True, help="the external scope with the capture point and the authorization")
    ci.add_argument("--capture-dir", required=True, help="where Zeek writes its logs")
    ci.set_defaults(func=_capture_ingest)
    cp = cap.add_parser("prune", help="delete the connection logs of hours already ingested")
    cp.add_argument("--capture-dir", required=True)
    cp.set_defaults(func=_capture_prune)

    scn = sub.add_parser("scanners", help="scanner images").add_subparsers(dest="sub", required=True)
    pl = scn.add_parser("pull", help="pull every runner profile's scanner image by its pinned digest")
    pl.set_defaults(func=_scanners_pull)

    pol = sub.add_parser("policy", help="crypto policy").add_subparsers(dest="sub", required=True)
    rn = pol.add_parser("render", help="render the policy into the estate's configuration, when building it")
    rn.add_argument("--force", action="store_true")
    rn.set_defaults(func=_policy_render)

    ch = sub.add_parser("change", help="propose, approve, apply and verify a policy change")
    chs = ch.add_subparsers(dest="sub", required=True)
    pr = chs.add_parser("propose", help="record the policy as it stands and propose what it changes")
    pr.add_argument("--as", dest="by", required=True, help="who changed the policy")
    pr.set_defaults(func=_change_propose)
    ap = chs.add_parser("approve", help="approve a change; then the runner applies it and the verifier checks it")
    ap.add_argument("change_id")
    ap.add_argument("--as", dest="by", required=True, help="who approves")
    ap.add_argument("--via", help="how the approval reached the command line, when someone other than the approver typed it")
    ap.add_argument("--run")
    ap.add_argument("--deny", action="store_true")
    ap.add_argument("--no-execute", action="store_true")
    ap.add_argument("--keep-open", action="store_true", help="leave the run open for further checks")
    ap.set_defaults(func=_change_approve)
    rh = chs.add_parser("rehearse", help="prove a proposal on a copy of the service in the twin, before approval")
    rh.add_argument("change_id")
    rh.add_argument("--run")
    rh.set_defaults(func=_change_rehearse)
    mx = chs.add_parser("matrix", help="kinds of client against the listener as deployed and a copy with the proposed file: who the change shuts out")
    mx.add_argument("change_id")
    mx.add_argument("--run")
    mx.set_defaults(func=_change_matrix)
    vf = chs.add_parser("verify", help="run a change's check again")
    vf.add_argument("change_id")
    vf.add_argument("--run")
    vf.add_argument("--address", help="probe this address instead, to show a wrong container fails")
    vf.add_argument("--sni")
    vf.set_defaults(func=_change_verify)
    cl = chs.add_parser("close", help="checkpoint and close a change run")
    cl.add_argument("--run")
    cl.set_defaults(func=_change_close)
    st = chs.add_parser("status", help="verdicts and time-to-change for a change run")
    st.add_argument("--run")
    st.set_defaults(func=_change_status)

    inv = sub.add_parser("investigate", help="trace wire findings to their configuration lines with the model bound to trace-to-cause, in a run of its own")
    inv.add_argument("--run", help="the scan run to trace from (default: the latest scan)")
    inv.add_argument("--finding", action="append", help="a finding event id to trace (repeatable; default: one key-establishment finding per bound listener)")
    inv.add_argument("--steps", type=int, default=8, help="step budget per trace")
    inv.add_argument("--tokens", type=int, default=60000, help="token budget per trace")
    inv.set_defaults(func=_investigate)

    ex = sub.add_parser("explain-queues", help="have the model bound to explain-queue explain each open item's queue over the policy pack, checked against the rule")
    ex.add_argument("--run", help="the scan run (default: the latest scan)")
    ex.add_argument("--repeats", type=int, default=3)
    ex.set_defaults(func=_explain_queues)

    im = sub.add_parser("import", help="bring your own scanner: any tool's CycloneDX CBOM as evidence, scored against the answer key")
    im.add_argument("documents", nargs="+", help="CBOM files; PATH=IMAGE names the image a document describes")
    im.add_argument("--tool", help="the tool's name, when the document's metadata does not give it")
    im.add_argument("--repo", help="for call sites: the repository the document's paths are in")
    im.add_argument("--commit", help="for call sites: the pinned commit")
    im.add_argument("--key", help="an answer key to score against (the mini-agency's: agency/answer-key.yaml)")
    im.set_defaults(func=_import)

    pk = sub.add_parser("package", help="a change package for each item blocked on its supplier: why no configuration change can do it, with the evidence, and what would unblock it")
    pk.add_argument("--run", help="the scan run (default: the latest scan)")
    pk.add_argument("--snapshots", default="policy/snapshots")
    pk.set_defaults(func=_package)

    scd = sub.add_parser("scan-code", help="the thin code layer: one pinned repository, candidate call sites by rule, judged by the call-site-read role")
    scd.add_argument("name", help="a repository name in eval/pins.yaml")
    scd.add_argument("--pins", default="eval/pins.yaml")
    scd.add_argument("--targets", default="targets", help="where the pinned checkouts are (default targets/)")
    scd.add_argument("--rules")
    scd.add_argument("--workers", type=int, default=4)
    scd.set_defaults(func=_scan_code)

    w = sub.add_parser("watch", help="scan, record what changed since the last scan, and send only the changed records to the model jobs")
    w.add_argument("--no-trace", action="store_true")
    w.add_argument("--no-explain", action="store_true")
    w.set_defaults(func=_watch)

    cb = sub.add_parser("cbom", help="CBOM tools").add_subparsers(dest="sub", required=True)
    b = cb.add_parser("build", help="rebuild a run's CBOMs from its ledger (default: the latest run)")
    b.add_argument("run", nargs="?")
    b.set_defaults(func=_cbom_build)

    imf = sub.add_parser("image-files", help="read the key material in a docker archive (the runner's own host profile)")
    imf.add_argument("archive")
    imf.add_argument("image", nargs="?", default="")
    imf.set_defaults(func=lambda a: __import__("pqch.scout.imagefiles", fromlist=["main"]).main([a.archive, a.image]))

    sc = sub.add_parser("scan", help="run the slice: scope, key, scans, CBOM, score")
    sc.add_argument("--host", choices=["live", "replay", "skip"], default="replay",
                    help="image scans: run live, replay the latest earlier scan, or skip")
    sc.add_argument("--classify-one", action="store_true",
                    help="also make one fast-tier typed classification through the inference seam")
    sc.add_argument("--explain-conflicts", action="store_true",
                    help="also have the model bound to the resolve-conflict role explain each conflict beside the rule's answer")
    sc.set_defaults(func=_scan)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
