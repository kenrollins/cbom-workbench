"""M3: a change drafted by a model from the CBOM, checked for shape, and refused unrehearsed."""

import json
from pathlib import Path

import httpx
import pytest

from pqch.inference import Seam
from pqch.migrator import plan, render

PG_BASE = render.base("postgresql")


def seam(replies):
    sent = []

    def handler(req):
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "g"}]})
        sent.append(json.loads(req.content))
        r = replies[min(len(sent) - 1, len(replies) - 1)]
        return httpx.Response(200, json={"model": "g", "usage": {"total_tokens": 100},
                                         "choices": [{"message": {"content": json.dumps(r)}, "finish_reason": "stop"}]})
    cfg = {"schema": "pqch.inference/1", "profile": "t", "roles": {"change-plan": {"tier": "fast"}},
           "tiers": {"fast": {"base_url": "http://x.test/v1", "api_key_env": "K", "model": "g", "hardware": "l4"}}}
    return Seam(cfg, transport=httpx.MockTransport(handler)), sent


def test_postgresql_shape_admits_its_tls_settings_and_nothing_else():
    ok = PG_BASE + "ssl_groups = 'X25519MLKEM768'\nssl_min_protocol_version = 'TLSv1.3'\n"
    assert render.is_rendered_shape(ok, "postgresql")
    for bad in ["ssl_groups = 'X25519'; DROP", "shared_preload_libraries = 'x'", "ssl_groups = 'a'\r", "include '/etc/x'"]:
        assert not render.is_rendered_shape(PG_BASE + bad + "\n", "postgresql"), bad
    assert not render.is_rendered_shape(ok, "mysql")        # no shape, no write


def test_edits_apply_from_the_bottom_up():
    text = "a\nb\nc\n"
    assert plan.apply_edits(text, [{"line_start": 4, "line_end": 3, "replacement": "d"},
                                   {"line_start": 1, "line_end": 1, "replacement": "A"}]) == "A\nb\nc\nd\n"
    with pytest.raises(ValueError):
        plan.apply_edits(text, [{"line_start": 9, "line_end": 9, "replacement": "x"}])


@pytest.fixture
def estate(tmp_path):
    agency = tmp_path / "agency"
    (agency / "records-db").mkdir(parents=True)
    (agency / "records-db" / "postgresql.conf").write_text(Path("agency/records-db/postgresql.conf").read_text())
    (agency / "generated" / "records-db").mkdir(parents=True)
    (agency / "generated" / "records-db" / "tls.conf").write_text(PG_BASE)
    return agency


class FakeRun:
    def __init__(self):
        self.events = []

        class L:
            def append(_, type, actor, payload, inputs=(), evidence=()):
                e = {"type": type, "actor": actor, "payload": payload, "id": f"E{len(self.events)}"}
                self.events.append(e)
                return e
        self.ledger = L()
        self.id = "R"


class FakeScan:
    id = "S"

    class ledger:
        @staticmethod
        def events():
            return [{"id": "F1", "type": "finding.observed", "payload": {
                "layer": "wire", "subject": {"kind": "endpoint", "host": "172.16.106.30", "port": 5432, "protocol": "postgres"},
                "asset": {"type": "algorithm", "role": "key-establishment", "name": "RSA", "parameters": {"mode": "key-transport"}},
                "evidence": {"excerpt": "cipher-x: TLSv1.2 TLS_RSA_WITH_AES_256_GCM_SHA384"}}}]


TARGET = {"service": "records-db", "address": "172.16.106.30", "port": 5432, "protocol": "postgres", "software": "postgresql"}


def test_the_first_usable_reply_is_the_proposal_and_every_call_is_kept(estate):
    good = {"blocked": "none", "edits": [{"file": "agency/generated/records-db/tls.conf", "line_start": 3, "line_end": 2,
                                          "replacement": "ssl_groups = 'X25519MLKEM768'\nssl_min_protocol_version = 'TLSv1.3'\n"}]}
    elsewhere = {"blocked": "none", "edits": [{"file": "agency/records-db/postgresql.conf", "line_start": 21, "line_end": 21,
                                               "replacement": "ssl_groups = 'X25519MLKEM768'"}]}
    s, sent = seam([elsewhere, good, good])
    d = plan.draft(FakeRun(), scan_run=FakeScan(), target=TARGET, intent="require", agency_dir=estate, inputs=[], seam=s)
    assert "type" not in d and "ssl_min_protocol_version = 'TLSv1.3'" in d["new"]
    calls = d["drafted"]["calls"]
    assert [c["usable"] for c in calls] == [False, True, True] and "edits a file other than" in calls[0]["why"]
    assert d["drafted"]["context"]["findings"] == ["F1"]
    # The model saw the CBOM's entry for the listener and the one file it may edit.
    user = sent[0]["messages"][1]["content"]
    assert "TLS_RSA_WITH_AES_256_GCM_SHA384" in user and "agency/generated/records-db/tls.conf" in sent[0]["messages"][0]["content"]


def test_no_usable_reply_is_recorded_and_proposes_nothing(estate):
    bad = {"blocked": "none", "edits": [{"file": "agency/generated/records-db/tls.conf", "line_start": 3, "line_end": 2,
                                         "replacement": "shared_preload_libraries = 'evil'\n"}]}
    s, _ = seam([bad])
    run = FakeRun()
    ev = plan.draft(run, scan_run=FakeScan(), target=TARGET, intent="require", agency_dir=estate, inputs=[], seam=s)
    assert ev["type"] == "assessment.made" and ev["payload"]["classification"] == {"proposal": None}
    assert "does not write for postgresql" in ev["payload"]["basis"]


def test_the_runner_applies_a_models_draft_only_after_a_rehearsal_of_that_file_met_its_intent(tmp_path):
    from pqch import scope as scope_mod
    from pqch.common import sha256_hex
    from pqch.run import Run
    from pqch.runner import Refused
    from pqch.runner.apply import Applier

    from .conftest import SCOPE
    var = tmp_path / "var"
    run = Run.start(var, SCOPE, runner_scope_hash=scope_mod.scope_hash(SCOPE), profile="t", kind="change")
    new = PG_BASE + "ssl_groups = 'X25519MLKEM768'\n"
    sha = sha256_hex(new.encode())
    from .test_checkpoints import PySigner
    signer = PySigner(tmp_path / "signer", var / "runs")
    signer.ensure_key()
    applier = Applier(None, runs_dir=var / "runs", agency_dir=tmp_path, log_dir=tmp_path / "log", signer=signer)
    with pytest.raises(Refused, match="no rehearsal that met its intent"):
        applier._rehearsed(run.id, "C1", sha)
    run.ledger.append("rehearsal.completed", {"kind": "verifier", "id": "pqch-verifier"},
                      {"change_id": "C1", "config_sha256": sha, "verdict": {"meets_intent": False}})
    with pytest.raises(Refused, match="no rehearsal that met its intent"):
        applier._rehearsed(run.id, "C1", sha)
    run.ledger.append("rehearsal.completed", {"kind": "verifier", "id": "pqch-verifier"},
                      {"change_id": "C1", "config_sha256": sha, "verdict": {"meets_intent": True}})
    with pytest.raises(Refused, match="no record of rehearsing"):
        applier._rehearsed(run.id, "C1", sha)      # the harness's word alone is not enough
    applier._append_log({"kind": "rehearse", "run": run.id, "change_id": "C1", "config_sha256": sha, "listening": True})
    applier._rehearsed(run.id, "C1", sha)
    with pytest.raises(Refused):
        applier._rehearsed(run.id, "C1", sha256_hex(b"another file"))
