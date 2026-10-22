"""M1: the investigator's loop — typed tools, budgets, the recorded claim and the check against the key."""

import json
from pathlib import Path

import httpx

from pqch.assessor import load_policy, structure
from pqch.investigator import Workspace, investigate, pick_findings
from pqch.inference import Seam
from pqch.ledger import verify


POLICY = load_policy("policy/pq-algorithms.yaml")
AGENCY = Path("agency")


def scripted_seam(replies: list[str]) -> tuple[Seam, list[dict]]:
    """A fake engine that answers from a script, one reply per call, and records what it was sent."""
    sent = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "m-big"}]})
        body = json.loads(req.content)
        sent.append(body)
        reply = replies[min(len(sent) - 1, len(replies) - 1)]
        return httpx.Response(200, headers={"x-litellm-model-api-base": "http://gb10.test:8014/v1"},
                              json={"model": "m-big", "usage": {"total_tokens": 1000},
                                    "choices": [{"message": {"content": reply}, "finish_reason": "stop"}]})
    cfg = {"schema": "pqch.inference/1", "profile": "test",
           "tiers": {"deliberate": {"base_url": "http://seam.test/v1", "api_key_env": "K", "model": "m-big",
                                    "hardware": "test-gb10"}},
           "roles": {"trace-to-cause": {"tier": "deliberate", "reasoning": False}}}
    return Seam(cfg, transport=httpx.MockTransport(handler)), sent


def test_the_workspace_tools_are_fixed_functions_over_the_service_files():
    ws = Workspace(AGENCY, "bastion")
    assert "agency/bastion/sshd_config" in ws.files and "agency/bastion/Dockerfile" in ws.files
    assert "KexAlgorithms" in ws.read("agency/bastion/sshd_config", 8, 8)
    assert ws.grep("^KexAlgorithms").startswith("agency/bastion/sshd_config:8:")
    assert ws.read("agency/portal/nginx.conf", None, None).startswith("error: no such file")   # another service's file
    assert ws.grep("(").startswith("error: bad pattern")
    assert ws.line_text("agency/bastion/sshd_config", 8, 8).startswith("KexAlgorithms")


def test_one_key_establishment_finding_per_bound_listener_is_picked(slice_run):
    structure(slice_run, POLICY)
    picked = pick_findings(list(slice_run.ledger.events()))
    assert len(picked) == 4 and all(e["payload"]["asset"]["role"] == "key-establishment" for e in picked)
    # The classical group is traced first where a listener negotiates both kinds.
    api = next(e for e in picked if e["payload"]["subject"]["host"] == "172.16.106.11")
    assert api["payload"]["asset"]["name"] == "X25519"


def test_a_trace_records_the_steps_the_budgets_the_engine_and_the_claim(slice_run, tmp_path):
    structure(slice_run, POLICY)
    slice_run.close()
    events = list(slice_run.ledger.events())
    bastion = next(e for e in events if e["type"] == "finding.observed" and e["payload"]["subject"]["host"] == "172.16.106.21"
                   and e["payload"]["asset"]["name"] == "X25519")
    seam, sent = scripted_seam([
        '{"action": "grep", "pattern": "KexAlgorithms", "note": "where is the key exchange set"}',
        '{"action": "read", "path": "agency/bastion/sshd_config", "start": 1, "end": 10}',
        '{"action": "answer", "file": "agency/bastion/sshd_config", "line_start": 8, "line_end": 8}',
    ])
    run, traces = investigate(slice_run.var, slice_run, agency_dir=AGENCY, seam=seam, finding_ids=[bastion["id"]],
                              key_path=Path("agency/answer-key.yaml"))
    assert len(traces) == 1 and verify(list(run.ledger.events())).ok
    p = traces[0]["payload"]
    assert traces[0]["type"] == "trace.completed" and traces[0]["actor"]["kind"] == "model"
    assert p["service"] == "bastion" and p["outcome"] == "answered"
    assert [s["action"] for s in p["steps"]] == ["grep", "read", "answer"]
    assert p["used"] == {"steps": 3, "tokens": 3000} and p["budget"] == {"steps": 8, "tokens": 60000}
    assert p["settings"]["model"] == "m-big" and p["settings"]["served_by"] == "http://gb10.test:8014/v1"
    assert p["answer"] == {"file": "agency/bastion/sshd_config", "line_start": 8, "line_end": 8, "cause": None}
    assert p["line_text"].startswith("KexAlgorithms mlkem768x25519-sha256")
    assert p["finding"] == {"run": slice_run.id, "event": bastion["id"], "fingerprint": bastion["payload"]["fingerprint"],
                            "subject": bastion["payload"]["subject"], "asset": bastion["payload"]["asset"]}
    assert p["key_check"]["agrees"] is True and p["key_check"]["item"] == "bastion-kex-x25519"
    # The model saw the tool results and the budget line, never a shell.
    assert "agency/bastion/sshd_config:8:" in sent[1]["messages"][-1]["content"]
    assert "steps left" in sent[2]["messages"][-1]["content"]
    # Nothing in the scan run changed: the trace is a claim in its own run.
    assert list(slice_run.ledger.events()) == events


def test_a_trace_stops_at_the_step_budget_and_says_so(slice_run):
    structure(slice_run, POLICY)
    slice_run.close()
    seam, sent = scripted_seam(['{"action": "grep", "pattern": "ssl"}'])
    _, traces = investigate(slice_run.var, slice_run, agency_dir=AGENCY, seam=seam, step_budget=3,
                              finding_ids=[pick_findings(list(slice_run.ledger.events()))[0]["id"]])
    p = traces[0]["payload"]
    assert p["outcome"] == "budget-exhausted" and p["answer"] is None and p["used"]["steps"] == 3 and len(sent) == 3
    assert p["key_check"] is None


def test_a_wrong_line_is_recorded_as_differing_from_the_key(slice_run):
    structure(slice_run, POLICY)
    slice_run.close()
    events = list(slice_run.ledger.events())
    bastion = next(e for e in events if e["type"] == "finding.observed" and e["payload"]["subject"]["host"] == "172.16.106.21"
                   and e["payload"]["asset"]["role"] == "key-establishment")
    seam, _ = scripted_seam(['{"action": "answer", "file": "agency/bastion/sshd_config", "line_start": 2, "line_end": 2}'])
    _, traces = investigate(slice_run.var, slice_run, agency_dir=AGENCY, seam=seam, finding_ids=[bastion["id"]],
                            key_path=Path("agency/answer-key.yaml"))
    kc = traces[0]["payload"]["key_check"]
    assert kc["agrees"] is False and "do not contain" in kc["why"]


def test_the_page_shows_the_trace_as_the_models_claim(slice_run, monkeypatch):
    import warnings

    from pqch.pipeline import enrich, write_cboms, write_score
    structure(slice_run, POLICY)
    enrich(slice_run, author="owner")
    slice_run.close()
    write_cboms(slice_run)
    write_score(slice_run, Path("eval/answer-keys/mini-agency-m0.yaml"))
    events = list(slice_run.ledger.events())
    bastion = next(e for e in events if e["type"] == "finding.observed" and e["payload"]["subject"]["host"] == "172.16.106.21"
                   and e["payload"]["asset"]["role"] == "key-establishment")
    seam, _ = scripted_seam(['{"action": "answer", "file": "agency/bastion/sshd_config", "line_start": 8, "line_end": 8}'])
    investigate(slice_run.var, slice_run, agency_dir=AGENCY, seam=seam, finding_ids=[bastion["id"]],
                key_path=Path("agency/answer-key.yaml"))
    monkeypatch.setenv("PQCH_VAR", str(slice_run.var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        monkeypatch.setattr(ui, "VAR", slice_run.var)
        html = TestClient(ui.app).get("/walkthrough").text
    assert "The model's claim, not a verification" in html and "sshd_config</code> lines 8–8" in html
    assert "Traces to cause" in html and "Agrees with the answer key" in html


def test_a_key_that_names_no_live_line_agrees_with_default():
    from pqch.investigator import key_check
    key = {"items": [{"id": "x", "class": "present", "layer": "wire",
                      "subject": {"host": "h", "port": 5432}, "asset": {"role": "key-establishment", "name": "DH-2048"},
                      "trace": {"cause": "default"}}]}
    f = {"layer": "wire", "subject": {"kind": "endpoint", "host": "h", "port": 5432, "protocol": "postgres"},
         "asset": {"type": "algorithm", "role": "key-establishment", "name": "DH-2048"}}
    assert key_check(key, f, {"cause": "default", "file": None}, None)["agrees"] is True
    assert key_check(key, f, {"file": "a.conf", "line_start": 1, "line_end": 1}, "x")["agrees"] is False


def test_a_trace_over_files_that_have_since_changed_is_not_shown_as_current():
    from pqch.ui.view import _trace_row
    t = {"id": "T", "run": "R", "ts": "t", "actor": {}, "payload": {
        "service": "bastion", "files": [{"path": "agency/bastion/sshd_config", "sha256": "a"}],
        "finding": {"run": "S0"}, "settings": {}, "answer": {}, "line_text": "", "outcome": "answered", "used": {},
        "budget": {}, "latency_ms": 1, "steps": [], "key_check": None}}
    assert _trace_row(t, "S1", {"bastion": {"agency/bastion/sshd_config": "a"}}) is not None
    assert _trace_row(t, "S1", {"bastion": {"agency/bastion/sshd_config": "b"}}) is None
    assert _trace_row(t, "S1", {}) is not None        # a scan without a manifest: nothing to compare
