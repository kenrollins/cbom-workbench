"""The 2026-11-21 review's findings in the assessor, the policy data and the planner, each held by a test:
absence of evidence is never `met`; an unidentified algorithm gets no verdict; the post-quantum hybrid no
standard defines is said to be exactly that by every rule; a plan's counts are the CBOM's; a change that
was rolled back is not done."""

import json
from datetime import date
from pathlib import Path

from pqch import planning
from pqch import scope as scope_mod
from pqch.assessor import chains, load_policy, managed, structure
from pqch.cbom import project
from pqch.common import hash_object
from pqch.policy import PQ_NOT_STANDARDISED, family_of, identified, load_families, load_pack, vulnerability
from pqch.run import Run

from .conftest import SCOPE, binding_for, make_run

POLICY = load_policy("policy/pq-algorithms.yaml")
PACK = "policy/packs/m-26-15.yaml"
FAM = "policy/algorithm-families.yaml"
CAPS = sorted(Path("policy/snapshots").glob("capabilities-*.json"))[-1]
CMVP = sorted(Path("policy/snapshots").glob("cmvp-*.json"))[-1]
PORTAL = "172.16.106.10"


def rule(run, rid):
    return [e for e in run.ledger.events() if e["type"] == "assessment.made" and e["payload"].get("rule_id") == rid]


def assessed(run, *, caps=CAPS, cmvp=CMVP, context="agency/context.yaml", as_of=date(2026, 10, 20)):
    structure(run, POLICY)
    chains.link_services(run)
    chains.supply(run, context, author="owner")
    return managed.assess(run, pack_path=PACK, families_path=FAM, capabilities_path=caps, cmvp_path=cmvp, as_of=as_of)


def items(run):
    return {(e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]): e["payload"] for e in rule(run, "queue/m-26-15/1")}


# ------------------------------------------------------------------ the queue rule

def test_a_service_with_no_evidence_attributed_to_it_is_not_assessed_never_met(tmp_path):
    # The portal's container changed during the scan: no binding, so no finding is joined to the service.
    run = make_run(tmp_path, bind=lambda t: binding_for(t, stable=t.get("host") != PORTAL))
    counts = assessed(run)
    q = items(run)
    for fn in ("key-establishment", "signature"):
        c = q[("portal", fn)]["classification"]
        assert c["state"] == "not-assessed" and c["deadline"] is None and c["post_quantum"] == [] and c["enforced"] is False
        assert "not assessed" in q[("portal", fn)]["basis"] and "not the same as met" in q[("portal", fn)]["basis"]
    assert counts["items_not_assessed"] == 2 and counts["items_met"] == 0 and counts["items_open"] == 6
    assert all(c["classification"]["state"] in ("open", "met", "not-assessed") for c in q.values())


def test_met_needs_an_acceptable_algorithm_observed_and_enforced_needs_the_verifiers_word(slice_run):
    assessed(slice_run)
    for p in items(slice_run).values():
        c = p["classification"]
        # Nothing in the slice is met; and no scan's enumeration alone makes an item enforced.
        assert c["state"] == "open" and c["only_resistant_observed"] is False and c["enforced"] is False and c["enforced_by"] is None


def test_the_ntru_prime_hybrid_is_said_to_be_post_quantum_and_not_standardised_by_every_rule(slice_run):
    fam, pack, cnsa = load_families(FAM), load_pack(PACK), load_pack("policy/packs/cnsa-2.0.yaml")
    # The two data files agree: the posture rule's names are the pack's resistant families, and the names it
    # lists apart are the family no rule calls vulnerable or acceptable.
    for name in POLICY["key_establishment"]:
        assert vulnerability(pack, family_of(fam, "key-establishment", name), "key-establishment")[0] is False, name
    assert POLICY["key_establishment_not_standardised"] == ["sntrup761x25519"]
    for name in POLICY["key_establishment_not_standardised"]:
        assert family_of(fam, "key-establishment", name) == PQ_NOT_STANDARDISED
    assert {n for n, v in fam["key-establishment"].items() if v["family"] == PQ_NOT_STANDARDISED} == set(POLICY["key_establishment_not_standardised"])
    f = {"asset": {"type": "algorithm", "role": "key-establishment", "name": "sntrup761x25519", "parameters": {}}}
    for p in (pack, cnsa):
        c = managed.entry_compatibility(p, fam, f)
        assert c["status"] == "not-compatible" and "quantum-vulnerable:" not in c["basis"] and "post-quantum by design" in c["basis"]
    assessed(slice_run)
    v = next(e["payload"] for e in rule(slice_run, "quantum/vulnerable/1") if e["payload"]["subject"]["name"] == "sntrup761x25519")
    assert v["classification"]["quantum_vulnerable"] is None and v["classification"]["post_quantum_by_design"] is True
    assert v["classification"]["standardised"] is False and v["classification"]["acceptable"] is False
    posture = next(e["payload"] for e in rule(slice_run, "posture/kex-auth/1") if e["payload"]["subject"]["host"] == "172.16.106.21")
    pc = posture["classification"]
    assert pc["kex_pq_not_standardised"] == ["sntrup761x25519"] and "sntrup761x25519" not in pc["kex_pq"] + pc["kex_classical"]
    assert "not a NIST-standardised" in posture["basis"]
    bastion = items(slice_run)[("bastion", "key-establishment")]
    assert bastion["classification"]["state"] == "open" and bastion["classification"]["not_standardised"] == ["sntrup761x25519"]
    assert "sntrup761x25519" not in bastion["classification"]["vulnerable"] + bastion["classification"]["post_quantum"]


def test_a_listener_offering_only_the_ntru_prime_hybrid_is_not_mixed(slice_run):
    # With the ML-KEM hybrid taken off the list, what the bastion offers is classical key exchange beside the
    # NTRU Prime hybrid: listed apart, and not the post-quantum key establishment a posture rests on.
    policy = {**POLICY, "key_establishment": [k for k in POLICY["key_establishment"] if k != "X25519MLKEM768"]}
    structure(slice_run, policy)
    p = next(e["payload"] for e in rule(slice_run, "posture/kex-auth/1") if e["payload"]["subject"]["host"] == "172.16.106.21")
    pc = p["classification"]
    assert pc["posture"] == "classical" and pc["kex_pq"] == [] and pc["kex_pq_not_standardised"] == ["sntrup761x25519"]
    assert "sntrup761x25519" not in pc["kex_classical"] and "listed apart" in p["basis"]


def test_an_unidentified_algorithm_gets_unknown_from_both_rules_and_a_parameter_set_is_its_family():
    fam, pack = load_families(FAM), load_pack(PACK)
    assert not identified("unknown") and not identified("unspecified") and identified("RSA")
    for asset in ({"type": "certificate", "role": "signature", "name": "unknown", "parameters": {}},
                  {"type": "algorithm", "role": "signature", "name": "unspecified", "parameters": {}}):
        c = managed.entry_compatibility(pack, fam, {"asset": asset})
        assert c["status"] == "unknown" and "did not identify" in c["basis"]
    # An identified name no family holds is still footnote 13's.
    c = managed.entry_compatibility(pack, fam, {"asset": {"type": "algorithm", "role": "signature", "name": "SomethingNew", "parameters": {}}})
    assert c["status"] == "not-compatible" and "footnote 13" in c["basis"]
    c = managed.entry_compatibility(pack, fam, {"asset": {"type": "certificate", "role": "signature", "name": "SLH-DSA-SHA2-128s", "parameters": {}}})
    assert c["status"] == "compatible" and c["family"] == "slh-dsa"
    assert family_of(fam, "key-establishment", "ffdhe8192") == family_of(fam, "key-establishment", "DH-8192") == "finite-field-dh"


def _add_finding(run, host, port, protocol, asset, tool="testssl.sh"):
    scan = next(e for e in run.ledger.events() if e["type"] == "scan.completed" and e["payload"]["target"].get("host") == host)
    subject = {"kind": "endpoint", "host": host, "port": port, "protocol": protocol}
    fp = hash_object({"layer": "wire", "subject": subject, "type": asset["type"], "role": asset["role"], "name": asset["name"], "identity": None})
    return run.ledger.append("finding.observed", {"kind": "scanner", "id": tool}, {
        "schema": "pqch.finding/1", "id": "01M40W6W873YWJMWPKGMK3Y" + fp[:3].upper(), "observed_at": "2026-10-03T12:00:10Z", "layer": "wire",
        "source": {"tool": tool, "version": "x", "image_digest": scan["payload"]["image_digest"], "profile": "tls-targeted"},
        "subject": subject, "asset": asset, "evidence": {"raw": "var/raw/x.json", "sha256": "0" * 64, "excerpt": "x"},
        "fingerprint": fp}, inputs=[scan["id"]])


def test_a_certificate_no_tool_could_name_leaves_the_item_not_judged_on_it(slice_run):
    _add_finding(slice_run, PORTAL, 443, "tls", {"type": "certificate", "role": "signature", "name": "unknown", "parameters": {}})
    assessed(slice_run)
    v = next(e["payload"] for e in rule(slice_run, "quantum/vulnerable/1") if e["payload"]["subject"]["name"] == "unknown")
    assert v["classification"]["quantum_vulnerable"] is None and v["classification"]["identified"] is False
    sig = items(slice_run)[("portal", "signature")]["classification"]
    assert "unknown" not in sig["vulnerable"] and sig["unidentified"] == ["unknown"]


def test_the_tls13_rule_reads_only_tls_versions_and_says_when_tls_was_refused(slice_run):
    assert [managed.tls_version(n) for n in ("TLS 1.3", "TLSv1.3", "TLSv13", "TLSv12", "SSLv3", "DTLSv12", "PostgreSQL", "SSH 2.0")] == \
        ["TLS 1.3", "TLS 1.3", "TLS 1.3", "TLS 1.2", "SSL 3.0", "DTLS 1.2", None, None]
    _add_finding(slice_run, PORTAL, 443, "tls", {"type": "protocol", "role": "other", "name": "PostgreSQL", "parameters": {"tls_offered": False}},
                 tool="pqch-postgres-tls-offer")
    assessed(slice_run)
    t = next(e["payload"] for e in rule(slice_run, "deadline/tls13/1") if e["payload"]["subject"]["host"] == PORTAL)
    assert t["classification"]["state"] == "open" and t["classification"]["versions"] == [] and t["classification"]["tls_refused"] is True
    assert "refused TLS" in t["basis"] and "PostgreSQL" not in t["basis"]


def test_the_validated_module_basis_is_whole_names_whose_module_it_is_and_reads_status(slice_run, tmp_path):
    caps = json.loads(CAPS.read_text())
    caps["services"]["sftp-legacy"]["fips"]["module_present"] = True             # a FIPS provider present, not active
    (tmp_path / "caps.json").write_text(json.dumps(caps))
    cmvp = json.loads(CMVP.read_text())
    took = sorted(int(k) for k, v in cmvp["certificates"].items() if v.get("approved_ml_kem") and "openssl" in v["module"].lower())
    assert took
    for k in took[1:]:
        cmvp["certificates"][str(k)]["status"] = "Historical"                     # no longer active: not a module to count
    (tmp_path / "cmvp.json").write_text(json.dumps(cmvp))
    assessed(slice_run, caps=tmp_path / "caps.json", cmvp=tmp_path / "cmvp.json")
    vm = {(e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]): e["payload"] for e in rule(slice_run, "blocker/validated-module/1")}
    sftp = vm[("sftp-legacy", "key-establishment")]
    assert sftp["classification"]["state"] == "none-validated"
    assert sftp["basis"] == ("no active certificate in the CMVP snapshot of 2026-10-20 for an openssh module lists ML-KEM among its "
                             "approved algorithms; the image carries a FIPS provider that is not active")
    portal = vm[("portal", "key-establishment")]
    assert portal["classification"]["certificates"] == took[:1] and portal["classification"]["snapshot_age_days"] == 0
    m = portal["classification"]["modules"][0]
    assert m["module"] in portal["basis"] and m["vendor"] in portal["basis"] and "not established" in portal["basis"]
    assert portal["classification"]["snapshot_stale"] is False


def test_an_old_cmvp_snapshot_is_said_to_be_old(tmp_path):
    run = make_run(tmp_path)
    assessed(run, as_of=date(2027, 10, 20))
    vm = rule(run, "blocker/validated-module/1")[0]["payload"]
    assert vm["classification"]["snapshot_stale"] is True and vm["classification"]["snapshot_age_days"] == 365 and "365 days old" in vm["basis"]


def test_one_file_is_judged_not_served_once_however_many_certificates_it_holds(slice_run):
    structure(slice_run, POLICY)
    judged = [e["payload"]["finding"] for e in rule(slice_run, "in-use/not-served/1")]
    assert len(judged) == len(set(judged))


# ------------------------------------------------------------------ the planner

def _change_run(var, *changes, close=False):
    """A change run with one proposal per (service, intent, outcome): outcome `landed`, `denied` or None."""
    scope = {**SCOPE, "id": "01M40W6W873YWJMWPKGMK3YBMC"}
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="change", kind="change")
    for n, (svc, intent, outcome) in enumerate(changes):
        cid = f"01CHANGE{n:02d}{svc.upper().replace('-', '')}"[:26]
        run.ledger.append("change.proposed", {"kind": "rule", "id": "t"}, {"change_id": cid, "target": {"service": svc}, "intent": intent})
        if outcome == "landed":
            run.ledger.append("approval.granted", {"kind": "human", "id": "ken"}, {"change_id": cid, "by": "ken"})
            run.ledger.append("verdict.issued", {"kind": "verifier", "id": "v"},
                              {"change_id": cid, "status": "enforced", "meets_intent": True, "durable": True, "hardware": "t"})
        elif outcome == "denied":
            run.ledger.append("approval.denied", {"kind": "human", "id": "ken"}, {"change_id": cid, "by": "ken"})
    if close:
        run.close()
    return run


def _planned(run):
    assessed(run)
    run.close()
    return run


def test_a_change_rolled_back_or_reset_since_is_not_standing_and_its_step_is_not_done(slice_run):
    _planned(slice_run)
    var = slice_run.var
    _change_run(var, ("api", "require", "landed"))
    assert planning.standing_changes(var)["api"]["intent"] == "require"
    plan = planning.build(var, slice_run)
    api = next(s for s in plan["order"] if s["id"] == "require:api")
    assert api["state"] == "done" and api["status"] == "landed" and plan["done"] == 1
    # Rolled back: a landed `none` is what stands now.
    _change_run(var, ("api", "none", "landed"))
    assert planning.standing_changes(var)["api"]["intent"] == "none"
    plan = planning.build(var, slice_run)
    assert next(s for s in plan["order"] if s["id"] == "require:api")["state"] != "done" and plan["done"] == 0
    # Required again, then the estate is reset from its baseline: nothing stands.
    _change_run(var, ("api", "require", "landed"))
    assert planning.build(var, slice_run)["done"] == 1
    reset = Run.start(var, SCOPE, runner_scope_hash=scope_mod.scope_hash(SCOPE), profile="estate-reset", kind="reset")
    reset.ledger.append("estate.reset", {"kind": "runner", "id": "pqch-runner"}, {"services": ["api"]})
    assert planning.resets(var) and "api" not in planning.standing_changes(var)
    assert planning.build(var, slice_run)["done"] == 0


def test_a_denied_or_closed_proposal_is_not_offered_as_the_step_to_carry_out(slice_run):
    _planned(slice_run)
    var = slice_run.var
    _change_run(var, ("portal", "enable", "denied"))
    en = next(s for s in planning.build(var, slice_run)["order"] if s["id"] == "enable:portal")
    assert en["status"] == "denied" and en["resolve"] == "/resolve"              # no link into the denied change
    assert en["change"]["predates_scan"] is False
    _change_run(var, ("portal", "enable", None), close=True)                      # a reset closes an open change run
    en = next(s for s in planning.build(var, slice_run)["order"] if s["id"] == "enable:portal")
    assert en["status"] == "open" and en["change"] is None and en["resolve"] == "/resolve"


def test_a_step_is_due_no_later_than_the_step_that_waits_for_it():
    steps = {"replace:a": {"id": "replace:a", "kind": "replace", "depends_on": [], "due": "2030-12-31", "state": "ready",
                           "why": "so it starts now for a 2030-12-31 deadline"},
             "tls13:a": {"id": "tls13:a", "kind": "tls13", "depends_on": ["replace:a"], "due": "2030-01-02", "state": "ready"},
             "enable:a": {"id": "enable:a", "kind": "enable", "depends_on": ["tls13:a"], "due": "2030-12-31", "state": "ready"}}
    planning._propagate_due(steps)
    assert steps["replace:a"]["due"] == "2030-01-02" and steps["replace:a"]["due_needed_by"] == "tls13:a"
    assert steps["replace:a"]["due_set_by"] == ["needed by tls13:a, due 2030-01-02"] and "for 2030-01-02" in steps["replace:a"]["why"]
    assert steps["enable:a"]["due"] == "2030-12-31"
    assert all(steps[d]["due"] <= s["due"] for s in steps.values() for d in s["depends_on"])


def test_the_plans_counts_are_the_cboms_and_the_register_says_what_holds_each_row(slice_run):
    _planned(slice_run)
    events = list(slice_run.ledger.events())
    plan = planning.build(slice_run.var, slice_run)
    bom = project(events)
    assert plan["cbom_entries"] == planning.cbom_entries(events) == sum(
        1 for c in bom["components"] if any(p["name"] == "pqch:fingerprint" for p in c["properties"]))
    # The register's per-service counts are counted over the CBOM's entries: with the entries no service holds,
    # they sum to the plan header's number, which is the CBOM page's.
    by = planning.compatibility_by_service(events)
    unowned = {}
    svc_of = {e["payload"]["subject"]["fingerprint"]: e["payload"]["classification"]["service"] for e in rule(slice_run, "compatibility/entry/1")}
    for c in bom["components"]:
        pr = {p["name"]: p["value"] for p in c["properties"]}
        if "pqch:compatibility" in pr and not svc_of.get(pr.get("pqch:fingerprint")):
            st = json.loads(pr["pqch:compatibility"])["status"]
            unowned[st] = unowned.get(st, 0) + 1
    for status in ("compatible", "not-compatible", "unknown", "outside-pack"):
        assert sum(v.get(status, 0) for v in by.values()) + unowned.get(status, 0) == plan["compatibility"][status], status
    reg = planning.register(plan, events)
    col = {c: i for i, c in enumerate(reg["columns"])}
    rows = {r[col["step"]]: r for r in reg["rows"]}
    assert rows["replace:sftp-legacy"][col["not_compatible_entries"]] == by["sftp-legacy"]["not-compatible"]
    # A row is counted in distinct fingerprints, and every row a replacement holds says so and names it.
    for r in reg["rows"]:
        assert r[col["entries"]] == len((r[col["fingerprints"]] or "").split(",")) if r[col["fingerprints"]] else r[col["entries"]] == 0
    assert rows["replace:sftp-legacy"][col["blocked_on_supplier"]] == "yes" and rows["replace:sftp-legacy"][col["blocked_by"]] is None
    held = rows["reissue:sftp-legacy"]
    assert held[col["blocked_on_supplier"]] == "yes" and held[col["blocked_by"]] == "replace:sftp-legacy"
    assert rows["require:api"][col["blocked_on_supplier"]] is None
    assert rows["replace:sftp-legacy"][col["entries"]] > 0                         # a replacement names the entries it moves


def test_a_remaining_systems_steps_sit_in_the_2035_wave(slice_run):
    _planned(slice_run)
    plan = planning.build(slice_run.var, slice_run)
    bastion = [s for s in plan["order"] if s.get("service") == "bastion" and s["kind"] in ("enable", "require", "reissue")]
    assert bastion and all(s["wave"] == "2035" and s["due"] == "2035-12-31" for s in bastion)
    assert plan["wave_labels"]["2035"] == "by 2035" and "2035" in [w["id"] for w in plan["waves"]]
    assert all(s["wave"][:4] <= (s["due"] or "9999")[:4] for s in plan["order"] if s["wave"].isdigit())


def test_the_estates_plan_is_built_only_from_a_scan_of_the_estate(tmp_path, monkeypatch):
    from pqch.ui import view

    run = make_run(tmp_path)
    assessed(run)
    run.close()
    assert planning.build(run.var, run) is not None

    # The same run under another kind (a copy's scan) is not the estate's plan, whatever its queue holds.
    class Copy:
        id, var, dir = run.id, run.var, run.dir

        class ledger:
            exists = staticmethod(run.ledger.exists)

            @staticmethod
            def events():
                evs = list(run.ledger.events())
                return iter([{**evs[0], "payload": {**evs[0]["payload"], "kind": "scan-copy"}}, *evs[1:]])
    monkeypatch.setattr(view, "run_view", lambda r: {"listeners": [], "image_chains": {}})
    assert view.queues_view(run.var, list(Copy.ledger.events())) is not None       # it has queue items
    assert planning.build(run.var, Copy) is None
    assert planning.build(run.var, run) is not None                                # the kind alone made the difference


def test_the_lab_plan_raises_a_weak_certificate_on_a_listener_no_capture_reached():
    capture = {"run": "R", "inside_servers": [], "ssh": [], "vlans": []}
    weak = {"name": "RSA", "bits": 1024, "not_after": "2031-01-01"}
    house = {"entries": 2, "doc": {"components": []}, "listeners": [
        {"address": "10.0.0.9:443", "protocol": "tls", "layers": ["scan"], "hybrid_accepted": [], "hybrid_chosen": 0,
         "certs": [weak, {**weak, "bits": 1536}, {"name": "RSA", "bits": 2048, "not_after": "2031-01-01"}]}]}
    p = planning.lab_build(capture, house)
    certs = {s["id"]: s for s in p["order"] if s["kind"] == "cert"}
    assert set(certs) == {"cert:10.0.0.9:443", "cert:10.0.0.9:443:2"}            # both weak certificates, not the first only
    assert "RSA-1024" in certs["cert:10.0.0.9:443"]["title"] and "RSA-1536" in certs["cert:10.0.0.9:443:2"]["title"]


def test_the_ca_trap_quotes_its_own_ca_step_and_a_cycle_is_said():
    deps = [{"kind": "certificate-authority", "id": "ca:x", "name": "CN=X", "services": ["a"], "what": "", "consequence": ""},
            {"kind": "certificate-authority", "id": "ca:y", "name": "CN=Y", "services": ["b", "c"], "what": "", "consequence": ""}]
    steps = {"ca:x": {"id": "ca:x", "kind": "ca", "depends_on": ["replace:a"], "state": "waiting"},
             "ca:y": {"id": "ca:y", "kind": "ca", "depends_on": ["replace:c"], "state": "waiting"}}
    traps = {t["dependency"]: t["cbom"] for t in planning._traps(deps, steps, [], set())}
    assert "a cannot verify ML-DSA" in traps["ca:x"] and "c cannot verify ML-DSA" in traps["ca:y"]
    loop = {"a": {"id": "a", "depends_on": ["b"], "due": None, "service": None}, "b": {"id": "b", "depends_on": ["a"], "due": None, "service": None}}
    assert planning._topo(loop, {}) == ["a", "b"] and loop["a"]["cycle"] and loop["b"]["cycle"]


def test_a_service_is_offered_the_hybrid_group_only_when_every_listener_accepts_it(slice_run, monkeypatch):
    _planned(slice_run)
    from pqch.ui import view

    real = view.run_view

    def one_listener_more(run):
        v = real(run)
        api = next(ln for ln in v["listeners"] if (ln.get("service") or {}).get("name") == "api" or ln.get("service_named") == "api")
        v["listeners"].append({**api, "address": "172.16.106.11:8443", "posture": {"posture": "classical", "kex_pq": []}})
        return v
    assert "enable:api" not in {s["id"] for s in planning.build(slice_run.var, slice_run)["order"]}
    monkeypatch.setattr(view, "run_view", one_listener_more)
    plan = {s["id"]: s for s in planning.build(slice_run.var, slice_run)["order"]}
    assert "1 of its 2 listeners already offer it" in plan["enable:api"]["why"]
    assert "already offers the hybrid group" not in plan["require:api"]["why"]


def test_a_package_quotes_the_snapshot_its_blocker_cited_and_skips_a_service_no_snapshot_holds(slice_run, tmp_path):
    from pqch.migrator import package

    _planned(slice_run)
    snaps = tmp_path / "snaps"
    snaps.mkdir()
    cited = json.loads(CAPS.read_text())
    (snaps / CAPS.name).write_text(json.dumps(cited))
    newer = json.loads(CAPS.read_text())
    newer["taken_at"] = "2027-01-01T00:00:00Z"
    del newer["services"]["sftp-legacy"]                                           # a later snapshot without the service
    (snaps / "capabilities-2027-01-01.json").write_text(json.dumps(newer))
    assert package.unblock("sftp-legacy", "key-establishment", newer) == []
    _, pkgs = package.build(slice_run.var, slice_run, pack_path=PACK, snapshots_dir=snaps)
    sftp = [p for p in pkgs if p["item"]["service"] == "sftp-legacy"]
    assert sftp and all(p["why"]["snapshot"]["taken_at"] == cited["taken_at"] for p in sftp)


def test_a_date_folded_into_a_list_is_read_as_its_latest():
    assert planning._latest_date(["2026-10-19T00:00:00Z", "2038-01-01"]) == "2038-01-01"
    assert planning._latest_date("2026-10-19T00:00:00Z") == "2026-10-19" and planning._latest_date(None) == ""
