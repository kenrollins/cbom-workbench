"""An optional model step never leaves a run open, a failed call never writes an address, and the seam
records what it did: the attempts it made, their summed usage, and reasoning only where it switched it on."""

import json
import warnings
from pathlib import Path

import httpx
import pytest
import yaml

from pqch import inference
from pqch.assessor import conflicts, load_policy, structure
from pqch.assessor.explain import explain
from pqch.inference import CallFailed, Seam, SchemaViolation, TierUnavailable, failure_text, load_config
from pqch.investigator import Workspace, investigate
from pqch.ledger import verify

POLICY = load_policy("policy/pq-algorithms.yaml")
GATEWAY = "http://10.99.0.7:8014/v1"        # stands for an internal gateway address: it must reach no record
SCHEMA = {"type": "object", "required": ["label"], "properties": {"label": {"enum": ["a", "b"]}},
          "additionalProperties": False}


def _cfg(roles=None, **fast):
    tier = {"base_url": GATEWAY, "api_key_env": "K", "model": "m", "hardware": "box", "engine": "vllm"}
    cfg = {"schema": "pqch.inference/1", "profile": "t",
           "tiers": {"fast": {**tier, **fast}, "embed": {**tier, "model": "e"}}}
    if roles is not None:
        cfg["roles"] = roles
    return cfg


def _down(kind="connect"):
    def handler(req: httpx.Request) -> httpx.Response:
        if kind == "connect":
            raise httpx.ConnectError(f"connection refused to {req.url}", request=req)
        if kind == "timeout":
            raise httpx.ReadTimeout(f"timed out reading {req.url}", request=req)
        if kind == "500":
            return httpx.Response(500, text="upstream error")
        if kind == "error-body":
            return httpx.Response(200, json={"error": {"message": f"no such model at {req.url}"}})
        return httpx.Response(200, text="<html>not json</html>")
    return httpx.MockTransport(handler)


@pytest.mark.parametrize("kind", ["connect", "timeout", "500", "error-body", "not-json"])
def test_every_way_a_call_gets_no_reply_is_one_exception_that_names_no_address(kind):
    seam = Seam(_cfg(), transport=_down(kind))
    for call in (lambda: seam.complete("fast", [{"role": "user", "content": "x"}], purpose="t"),
                 lambda: seam.embed("embed", ["x"])):
        with pytest.raises(CallFailed) as e:
            call()
        assert isinstance(e.value, TierUnavailable)        # a caller that skips an unavailable tier skips an outage
        assert "10.99.0.7" not in str(e.value) and "10.99.0.7" not in failure_text(e.value)
        assert e.value.__cause__ is None                   # the cause's text carries the URL; it is not chained
    assert failure_text(RuntimeError(f"boom at {GATEWAY}")) == "RuntimeError"
    assert Seam(_cfg(), transport=_down("500")).complete.__self__ is not None
    with pytest.raises(CallFailed) as e:
        Seam(_cfg(), transport=_down("500")).complete("fast", [], purpose="t")
    assert e.value.status == 500 and e.value.kind == "status"


def test_a_reply_asked_for_twice_counts_both_calls(monkeypatch):
    replies = [("not json", 5000), ('{"label": "a"}', 700)]
    sent = []

    def handler(req):
        text, tokens = replies[len(sent)]
        sent.append(req)
        return httpx.Response(200, json={"model": "m", "usage": {"total_tokens": tokens, "completion_tokens": tokens // 10},
                                         "choices": [{"message": {"content": text}, "finish_reason": "stop"}]})
    seam = Seam(_cfg(structured=False), transport=httpx.MockTransport(handler))
    c = seam.complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t")
    assert len(sent) == 2 and c.attempts == 2
    assert c.usage == {"total_tokens": 5700, "completion_tokens": 570}
    assert c.actor()["attempts"] == 2
    # One clean call says nothing about attempts.
    sent.clear()
    replies[0] = ('{"label": "b"}', 9)
    c = seam.complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t")
    assert c.attempts == 1 and "attempts" not in c.actor() and c.usage["total_tokens"] == 9
    # Both replies bad: the failure carries what both calls cost.
    sent.clear()
    replies[:] = [("nope", 100), ("still nope", 200)]
    with pytest.raises(SchemaViolation) as e:
        seam.complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t")
    assert e.value.raw["usage"]["total_tokens"] == 300 and e.value.attempts == 2


def test_reasoning_is_recorded_only_where_the_tier_says_how_it_is_switched_on(tmp_path):
    bodies = []

    def handler(req):
        bodies.append(json.loads(req.content))
        return httpx.Response(200, json={"model": bodies[-1]["model"], "usage": {},
                                         "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]})
    plain = {"chat_template_kwargs": {"enable_thinking": False}, "truncate": "END"}
    # No reasoning block: the request is the tier's plain one, kept whole, and the call is not labelled reasoning.
    cfg = _cfg({"ask-cbom": {"tier": "fast", "reasoning": True}}, request=plain)
    c = Seam(cfg, transport=httpx.MockTransport(handler)).complete_role("ask-cbom", [], purpose="t")
    assert c.reasoning is False and "reasoning" not in c.actor()
    assert bodies[-1]["truncate"] == "END" and bodies[-1]["chat_template_kwargs"] == {"enable_thinking": False}
    # The file still loads (a deployment's own config is not broken by the check), with a warning; strict refuses it.
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    with pytest.warns(UserWarning, match="asks for reasoning on tier fast, which has no reasoning block"):
        load_config(p)
    with pytest.raises(ValueError, match="no reasoning block"):
        load_config(p, strict=True)
    # An empty block states that the lane itself reasons: recorded as reasoning, nothing extra sent.
    cfg["tiers"]["fast"]["reasoning"] = {}
    c = Seam(cfg, transport=httpx.MockTransport(handler)).complete_role("ask-cbom", [], purpose="t")
    assert c.reasoning is True and c.actor()["reasoning"] is True and "truncate" not in bodies[-1]
    p.write_text(yaml.safe_dump(cfg))
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        load_config(p, strict=True)


def test_a_tier_without_an_engine_is_warned_about_and_refused_when_strict(tmp_path):
    cfg = _cfg()
    del cfg["tiers"]["embed"]["engine"]
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    with pytest.warns(UserWarning, match="tier embed names no engine"):
        load_config(p)
    with pytest.raises(ValueError, match="tier embed names no engine"):
        load_config(p, strict=True)


@pytest.mark.parametrize("path", ["config/inference.example.yaml", "kit/inference.yaml"])
def test_the_configs_shipped_as_examples_name_an_engine_on_every_tier(path):
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        cfg = load_config(path, strict=True)
    assert all(t.get("engine") for t in cfg["tiers"].values())


def test_a_config_with_no_roles_section_says_the_seam_chose_the_tier():
    def handler(req):
        return httpx.Response(200, json={"model": "m", "usage": {}, "choices": [{"message": {"content": "ok"}}]})
    c = Seam(_cfg(), transport=httpx.MockTransport(handler)).complete_role("anything", [], purpose="t")
    assert c.tier == "fast" and c.actor()["role_binding"] == "default"
    c = Seam(_cfg({"x": {"tier": "fast"}}), transport=httpx.MockTransport(handler)).complete_role("x", [], purpose="t")
    assert "role_binding" not in c.actor()


def test_the_module_level_embed_passes_the_purpose(monkeypatch):
    seen = []

    def handler(req):
        seen.append(json.loads(req.content))
        return httpx.Response(200, json={"data": [{"embedding": [1.0]}]})
    cfg = _cfg()
    cfg["tiers"]["embed"]["purpose_field"] = "input_type"
    monkeypatch.setattr(inference, "_default", Seam(cfg, transport=httpx.MockTransport(handler)))
    inference.embed("embed", ["q"], purpose="query")
    assert seen[-1]["input_type"] == "query"


# ───────── the callers ─────────

def test_an_outage_while_explaining_conflicts_is_recorded_and_the_scan_still_closes(slice_run):
    structure(slice_run, POLICY)
    conflicts.resolve(slice_run)
    n_conflicts = sum(1 for e in slice_run.ledger.events() if e["payload"].get("rule_id") == "conflict/resolve/1")
    assert n_conflicts >= 1
    for kind in ("connect", "error-body"):
        out = explain(slice_run, seam=Seam(_cfg({"resolve-conflict": {"tier": "fast"}}), transport=_down(kind)))
        assert out["explained"] == 0 and out["failed"] == n_conflicts
    failed = [e for e in slice_run.ledger.events() if e["payload"].get("rule_id") == "explain/failed"]
    assert len(failed) == 2 * n_conflicts
    assert all(e["payload"]["basis"].startswith("not explained: ") and e["payload"]["used_by_rules"] is False for e in failed)
    assert "10.99.0.7" not in slice_run.ledger.path.read_text()
    slice_run.close()                                    # what pipeline.run_once does next
    events = list(slice_run.ledger.events())
    assert events[-1]["type"] == "run.closed" and verify(events).ok


def test_after_one_outage_the_remaining_conflicts_are_not_asked(slice_run):
    structure(slice_run, POLICY)
    conflicts.resolve(slice_run)
    rule = next(e for e in slice_run.ledger.events() if e["payload"].get("rule_id") == "conflict/resolve/1")
    # a second conflict on the record, so there is a "remaining" one
    slice_run.ledger.append("assessment.made", rule["actor"], rule["payload"], inputs=rule.get("inputs") or [])
    calls = []

    def handler(req):
        calls.append(req)
        raise httpx.ConnectError("refused", request=req)
    out = explain(slice_run, seam=Seam(_cfg({"resolve-conflict": {"tier": "fast"}}), transport=httpx.MockTransport(handler)))
    assert out["failed"] == 2 and len(calls) == 1
    bases = [e["payload"]["basis"] for e in slice_run.ledger.events() if e["payload"].get("rule_id") == "explain/failed"]
    assert bases[1].startswith("not explained: not asked; an earlier call failed")


def test_a_config_that_cannot_be_read_skips_the_step_instead_of_raising(slice_run, monkeypatch):
    monkeypatch.setattr(inference, "_default", None)
    monkeypatch.setenv("PQCH_INFERENCE_CONFIG", "/nonexistent/inference.yaml")
    out = explain(slice_run)
    assert out["explained"] == 0 and "could not be read" in out["skipped"]


def _queue_run(slice_run):
    from .test_managed import prepared
    prepared(slice_run)
    slice_run.close()
    return slice_run


def test_an_outage_while_explaining_queues_leaves_a_closed_run_and_labels_the_embedding(slice_run):
    import inspect

    from pqch.assessor import explain_queue as xq
    _queue_run(slice_run)
    purposes, chats = [], []

    def handler(req):
        body = json.loads(req.content)
        if req.url.path.endswith("/embeddings"):
            purposes.append(body.get("input_type"))
            return httpx.Response(200, json={"data": [{"embedding": [1.0, float(len(t) % 7)]} for t in body["input"]]})
        chats.append(body)
        raise httpx.ReadTimeout(f"timed out at {req.url}", request=req)
    cfg = _cfg({"explain-queue": {"tier": "fast"}})
    cfg["tiers"]["embed"]["purpose_field"] = "input_type"
    run, s = xq.explain(slice_run.var, slice_run, pack_path="policy/packs/m-26-15.yaml",
                        seam=Seam(cfg, transport=httpx.MockTransport(handler)))
    events = list(run.ledger.events())
    assert events[-1]["type"] == "run.closed" and verify(events).ok           # closed, not left dangling
    assert len(chats) == 1 and s["calls"] == 1 and "timed out" in s["stopped"]  # one timeout, not one per call
    assert purposes[0] == "passage" and purposes[1] == "query"               # the item is embedded as the question
    made = [e for e in events if e["payload"].get("purpose") == "explain-queue"]
    assert made and made[0]["payload"]["retrieval"]["embed"] == {"tier": "embed", "model": "e", "engine": "vllm", "hardware": "box"}
    assert made[0]["payload"]["calls"][0]["why"].startswith("no answer: ")
    assert "10.99.0.7" not in run.ledger.path.read_text()
    assert "budget_s" in inspect.signature(xq.explain).parameters


def test_a_trace_that_gets_no_reply_is_recorded_and_its_run_is_closed(slice_run, tmp_path):
    structure(slice_run, POLICY)
    slice_run.close()
    seam = Seam({"schema": "pqch.inference/1", "profile": "t",
                 "tiers": {"deliberate": {"base_url": GATEWAY, "api_key_env": "K", "model": "m", "hardware": "box"}},
                 "roles": {"trace-to-cause": {"tier": "deliberate"}}}, transport=_down("connect"))
    run, traces = investigate(slice_run.var, slice_run, agency_dir=Path("agency"), seam=seam)
    assert len(traces) == 1                                # the engine is not asked again for every finding
    p = traces[0]["payload"]
    assert p["outcome"] == "no-answer" and p["answer"] is None and "CallFailed" in p["steps"][0]["error"]
    events = list(run.ledger.events())
    assert events[-1]["type"] == "run.closed" and verify(events).ok
    assert "10.99.0.7" not in run.ledger.path.read_text()


def test_the_trace_says_whether_the_answered_lines_were_ever_shown(slice_run):
    structure(slice_run, POLICY)
    slice_run.close()
    from .test_investigator import scripted_seam
    read_then_answer = ['{"action": "read", "path": "agency/bastion/sshd_config", "start": 1, "end": 20}',
                        '{"action": "answer", "file": "agency/bastion/sshd_config", "line_start": 8, "line_end": 8}']
    blind = ['{"action": "answer", "file": "agency/bastion/sshd_config", "line_start": 8, "line_end": 8}']
    fid = next(e["id"] for e in slice_run.ledger.events() if e["type"] == "finding.observed"
               and e["payload"]["subject"].get("host") == "172.16.106.21" and e["payload"]["asset"]["role"] == "key-establishment")
    for script, want in ((read_then_answer, True), (blind, False)):
        seam, _ = scripted_seam(script)
        _, traces = investigate(slice_run.var, slice_run, agency_dir=Path("agency"), seam=seam, finding_ids=[fid])
        assert traces[0]["payload"]["outcome"] == "answered" and traces[0]["payload"]["answer_lines_seen"] is want
        assert "engine" in traces[0]["payload"]["settings"]


def test_a_runaway_pattern_is_stopped_and_a_link_out_of_the_service_is_not_read(tmp_path):
    svc = tmp_path / "agency" / "svc"
    svc.mkdir(parents=True)
    (svc / "a.conf").write_text("ssl_ecdh_curve X25519;\n" + "a" * 60 + "b\n")
    outside = tmp_path / "secret.conf"
    outside.write_text("password = hunter2\n")
    (svc / "leak.conf").symlink_to(outside)
    (svc / "inside.conf").symlink_to(svc / "a.conf")
    ws = Workspace(tmp_path / "agency", "svc")
    assert "agency/svc/leak.conf" not in ws.files and "agency/svc/inside.conf" in ws.files
    assert ws.grep("ssl_ecdh").startswith("agency/svc/a.conf:1:")
    assert ws.lines_seen("agency/svc/a.conf", 1, 1) and not ws.lines_seen("agency/svc/a.conf", 1, 2)
    out = ws.grep("(a+)+$", timeout_s=1)                   # exponential on the second line
    assert out.startswith("error: the pattern did not finish in 1 s")
    assert ws.grep("(").startswith("error: bad pattern")
