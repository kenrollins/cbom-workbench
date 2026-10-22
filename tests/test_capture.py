"""Passive capture: Zeek's handshake logs become findings and rule assessments on a capture run."""

import json

import pytest

from pqch.cbom import build_all
from pqch.ledger import verify
from pqch.run import Run
from pqch.scout import capture

SCOPE = {
    "schema": "pqch.scope/1", "id": "01M4GKYAX5FJ1WGFV4789SVWD6", "estate": "external", "owned": False,
    "authorized_by": "the operator, in a test", "endpoints": [], "images": [], "sources": [],
    "reach": {"kind": "local"},
    "captures": [{"interface": "mirror0", "host": "sensor", "vlans": [10, 28], "mirror": "test"}],
}


def _line(**kw):
    return json.dumps(kw) + "\n"


def make_logs(d):
    # conn: VLAN tags by uid
    (d / "conn.2026-10-09-00-00-00.log").write_text(
        _line(ts=1.0, uid="c1", vlan=10) + _line(ts=2.0, uid="c2", vlan=28) + _line(ts=3.0, uid="c3", vlan=28))
    # posture: a server in the house that refuses hybrid, one that takes it, a legacy IoT client
    (d / "posture.2026-10-09-00-00-00.log").write_text(
        _line(ts=1.0, uid="c1", client="10.20.30.5", server="10.20.30.222", server_port=8007,
              offered_groups=[4588, 29, 23, 2570], client_key_shares=[4588, 29], server_key_share=29,
              client_versions=[772, 771], version="TLSv13", cipher="TLS_AES_128_GCM_SHA256", established=True)
        + _line(ts=2.0, uid="c2", client="172.30.1.27", server="93.184.216.34", server_port=443, sni="example.com",
                offered_groups=[9, 10, 23], server_ecdh_curve=23, client_versions=[771], version="TLSv12",
                cipher="ECDHE-RSA-AES128-GCM-SHA256", established=True)
        + _line(ts=3.0, uid="c3", client="10.20.30.5", server="10.20.33.3", server_port=443, sni="auth.test",
                offered_groups=[4588, 29], client_key_shares=[4588], server_key_share=4588,
                client_versions=[772, 771], version="TLSv13", cipher="TLS_AES_256_GCM_SHA384", established=True))
    (d / "posture.log").write_text(_line(ts=99.0, uid="live", client="1.1.1.1", server="2.2.2.2", server_port=443))
    (d / "ssh.2026-10-09-00-00-00.log").write_text(
        _line(**{"ts": 4.0, "uid": "s1", "id.orig_h": "10.20.30.5", "id.orig_p": 50000, "id.resp_h": "10.20.30.200",
                 "id.resp_p": 22, "kex_alg": "curve25519-sha256", "host_key_alg": "ssh-ed25519",
                 "client": "SSH-2.0-OpenSSH_9.6", "server": "SSH-2.0-OpenSSH_10.3"}))
    (d / "capture_loss.2026-10-09-00-00-00.log").write_text(
        _line(ts=2.0, ts_delta=900.0, peer="zeek", gaps=1, acks=100, percent_lost=1.0))


def test_ingest_builds_a_verifiable_capture_run(tmp_path):
    cap = tmp_path / "capture"
    cap.mkdir()
    make_logs(cap)
    run, summary = capture.ingest(tmp_path, SCOPE, cap, hardware="test")
    events = list(run.ledger.events())
    assert verify(events).ok
    assert events[0]["payload"]["kind"] == "capture" and events[0]["payload"]["scope"]["captures"]
    assert summary["servers"] == 3 and summary["clients"] == 2 and summary["ssh_servers"] == 1
    assert summary["capture_loss"]["median_bp"] == 100
    finds = [e["payload"] for e in events if e["type"] == "finding.observed"]
    # the backup server: chose X25519 while the client offered a hybrid group
    bk = [f for f in finds if f["subject"].get("port") == 8007 and f["asset"]["role"] == "key-establishment"]
    assert len(bk) == 1 and bk[0]["asset"]["name"] == "X25519"
    assert bk[0]["asset"]["parameters"]["clients_offered_hybrid"] == 1 and "vlan" not in bk[0]["subject"]
    assert bk[0]["asset"]["parameters"]["client_vlans"] == {"10": 1}
    # the front door chose the hybrid group
    fd = [f for f in finds if f["subject"].get("port") == 443 and f["subject"]["host"] == "10.20.33.3"
          and f["asset"]["role"] == "key-establishment"]
    assert fd[0]["asset"]["name"] == "X25519MLKEM768" and fd[0]["asset"]["parameters"]["hybrid"]
    # the IoT client: sect curves offered, no TLS 1.3, a client subject with its VLAN
    iot = [f for f in finds if f["subject"]["kind"] == "client" and f["subject"]["host"] == "172.30.1.27"]
    assert {f["asset"]["name"] for f in iot} == {"sect283k1", "sect283r1", "secp256r1", "TLS 1.2"}
    assert iot[0]["subject"]["vlan"] == 28
    # GREASE never becomes a finding
    assert not [f for f in finds if "2570" in f["asset"]["name"] or f["asset"]["name"].startswith("group-")]
    # SSH from Zeek's log, normalized like ssh-audit's
    ssh = [f for f in finds if f["subject"].get("protocol") == "ssh"]
    assert {f["asset"]["name"] for f in ssh} == {"X25519", "Ed25519"}
    # rules: posture per listener, capability per client, each citing its findings
    rules = [e for e in events if e["type"] == "assessment.made"]
    post = {e["payload"]["subject"]["host"]: e["payload"]["classification"] for e in rules
            if e["payload"]["rule_id"] == "posture/observed/1"}
    assert post["10.20.30.222"]["posture"] == "classical" and post["10.20.30.222"]["hybrid_refused"] == 1
    assert post["10.20.33.3"]["posture"] == "pq"
    caps = {e["payload"]["subject"]["host"]: e["payload"]["classification"]["capability"] for e in rules
            if e["payload"]["rule_id"] == "capability/observed/1"}
    assert caps == {"10.20.30.5": "hybrid", "172.30.1.27": "legacy"}
    assert all(e["inputs"] for e in rules)
    # the live file was not read; every finding names the scan events of its files
    assert all("posture.log" not in e["payload"]["target"].get("file", "") for e in events if e["type"] == "scan.completed")
    # the CBOM projects, with client subjects as components and listeners as before
    summ = next(e for e in events if e["payload"].get("profile") == "capture-summary")["payload"]
    assert {(e["client"], e["server"]) for e in summ["edges"]} == {("10.20.30.5", "10.20.30.222"), ("172.30.1.27", "93.184.216.34"), ("10.20.30.5", "10.20.33.3")}
    assert next(e for e in summ["edges"] if e["server"] == "10.20.30.222")["refused"] == 1
    boms = build_all(events)
    assert any(c["name"] == "TLS 10.20.30.222:8007" for c in boms["workbench"]["components"])


def test_a_second_ingest_reads_only_new_files(tmp_path):
    cap = tmp_path / "capture"
    cap.mkdir()
    make_logs(cap)
    capture.ingest(tmp_path, SCOPE, cap)
    with pytest.raises(ValueError):
        capture.ingest(tmp_path, SCOPE, cap)
    (cap / "posture.2026-10-09-01-00-00.log").write_text(
        _line(ts=10.0, uid="c9", client="10.20.30.7", server="10.20.30.222", server_port=8007,
              offered_groups=[29], server_key_share=29, client_versions=[772], version="TLSv13"))
    run2, s2 = capture.ingest(tmp_path, SCOPE, cap)
    assert s2["files"] == 1 and s2["servers"] == 1
    assert Run.latest(tmp_path, "capture").id == run2.id


def test_capture_run_needs_an_external_scope_with_a_capture_point(tmp_path):
    with pytest.raises(ValueError):
        Run.start_capture(tmp_path, {**SCOPE, "captures": []})


def test_prune_removes_only_ingested_hours_connection_logs(tmp_path):
    cap = tmp_path / "capture"
    cap.mkdir()
    make_logs(cap)
    (cap / "conn.2026-10-09-01-00-00.log").write_text("")   # an hour not yet ingested
    (cap / "conn.log").write_text("")                        # the live file
    assert capture.prune(tmp_path, cap) == []
    capture.ingest(tmp_path, SCOPE, cap)
    assert capture.prune(tmp_path, cap) == ["conn.2026-10-09-00-00-00.log"]
    names = {p.name for p in cap.iterdir()}
    assert "conn.2026-10-09-01-00-00.log" in names and "conn.log" in names
    assert "posture.2026-10-09-00-00-00.log" in names and "ssh.2026-10-09-00-00-00.log" in names


def test_scan_external_runs_the_scoped_listeners_without_a_key(tmp_path, monkeypatch):
    """A stub runner: the external scope with two listeners; each job answers with an empty raw file."""
    from pqch import scope as scope_mod
    from pqch.pipeline import scan_external

    scope = {**SCOPE, "endpoints": [
        {"host": "10.20.30.222", "port": 8007, "transport": "tcp", "protocol": "tls"},
        {"host": "10.20.30.200", "port": 22, "transport": "tcp", "protocol": "ssh"}]}
    h = scope_mod.scope_hash(scope)
    (tmp_path / "raw").mkdir()

    class Stub:
        def scope(self):
            return scope, h

        def job(self, profile, target, scope_hash):
            assert scope_hash == h
            raw = tmp_path / "raw" / f"{target['host']}-{target['port']}.json"
            raw.write_text("[]" if profile.startswith("tls") else "{}")
            from pqch.common import sha256_hex, utc_now
            return {"profile": profile, "target": target, "tool": "testssl.sh" if profile.startswith("tls") else "ssh-audit",
                    "version": "t", "image_digest": "sha256:" + "a" * 64, "started_at": utc_now(), "ended_at": utc_now(),
                    "duration_ms": 1, "hardware": "test", "status": "ok", "exit_code": 0,
                    "raw": f"var/raw/{raw.name}", "raw_sha256": sha256_hex(raw.read_bytes())}

    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    monkeypatch.setenv("PQCH_POLICY", "policy/pq-algorithms.yaml")
    run, summary = scan_external(tmp_path, Stub())
    events = list(run.ledger.events())
    assert events[0]["payload"]["kind"] == "scan-external" and events[0]["payload"]["scope"]["estate"] == "external"
    assert len(summary["jobs"]) == 2 and all(j["status"] == "ok" for j in summary["jobs"])
    assert not any(e["type"] == "key.committed" for e in events) and not (run.dir / "score.json").exists()
    assert (run.dir / "workbench.cdx.json").exists()
    assert Run.latest(tmp_path, "scan") is None   # the demonstration's latest scan is untouched

    with pytest.raises(ValueError):
        class Owned(Stub):
            def scope(self):
                s = {**scope, "estate": "colocated", "authorized_by": None}
                return s, scope_mod.scope_hash(s)
        scan_external(tmp_path, Owned())
