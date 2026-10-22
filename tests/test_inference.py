import json

import httpx
import pytest

from pqch.inference import Seam, SchemaViolation, TierUnavailable, load_config

CFG = {
    "schema": "pqch.inference/1",
    "profile": "test",
    "tiers": {
        "fast": {"base_url": "http://seam.test/v1", "api_key_env": "PQCH_TEST_KEY", "model": "m-fast",
                 "hardware": "test-box", "residency": "resident"},
        "deliberate": {"base_url": "http://seam.test/v1", "api_key_env": "PQCH_TEST_KEY", "model": "m-big",
                       "hardware": "test-box", "residency": "on-demand"},
    },
}
SCHEMA = {"type": "object", "required": ["label"], "properties": {"label": {"enum": ["a", "b"]}},
          "additionalProperties": False}


def transport(reply: str, loaded=("m-fast",)):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": m} for m in loaded]})
        body = json.loads(req.content)
        return httpx.Response(200, headers={"x-litellm-model-api-base": "http://upstream.test:8013/v1"},
                              json={"model": body["model"], "usage": {"total_tokens": 7},
                                    "choices": [{"message": {"content": reply}, "finish_reason": "stop"}]})
    return httpx.MockTransport(handler), seen


def test_typed_completion_carries_tier_model_and_hardware(monkeypatch):
    monkeypatch.setenv("PQCH_TEST_KEY", "k")
    t, seen = transport('{"label": "a"}')
    c = Seam(CFG, transport=t).complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t")
    assert c.parsed == {"label": "a"} and c.model == "m-fast" and c.hardware == "test-box"
    assert c.actor() == {"kind": "model", "id": "fast:m-fast", "tier": "fast", "model": "m-fast", "hardware": "test-box",
                         "served_by": "http://upstream.test:8013/v1"}
    assert c.finish_reason == "stop"
    assert seen[0].headers["authorization"] == "Bearer k"


def test_reply_outside_the_schema_raises():
    t, _ = transport('{"label": "zzz"}')
    with pytest.raises(SchemaViolation):
        Seam(CFG, transport=t).complete("fast", [], schema=SCHEMA, purpose="t")


def test_unloaded_on_demand_tier_raises_at_once_and_never_completes():
    t, seen = transport('{"label": "a"}', loaded=("m-fast",))
    with pytest.raises(TierUnavailable):
        Seam(CFG, transport=t).complete("deliberate", [], purpose="t")
    assert all(not r.url.path.endswith("/chat/completions") for r in seen)


def test_example_config_loads():
    assert set(load_config("config/inference.example.yaml")["tiers"]) == {"fast", "deliberate", "embed"}


CFG_ROLES = {
    **CFG,
    "tiers": {**CFG["tiers"], "fast": {**CFG["tiers"]["fast"], "timeout_s": 30,
              "reasoning": {"model": "m-fast-thinking", "timeout_s": 300, "request": {"chat_template_kwargs": {"enable_thinking": True}}}}},
    "roles": {"classify-algorithm": {"tier": "fast", "reasoning": True}, "trace-to-cause": {"tier": "deliberate"}},
}


def test_reasoning_reaches_the_engine_as_the_config_says(monkeypatch):
    t, seen = transport('{"label": "b"}', loaded=("m-fast", "m-fast-thinking"))
    c = Seam(CFG_ROLES, transport=t).complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t", reasoning=True)
    body = json.loads(seen[-1].content)
    assert body["model"] == "m-fast-thinking" and body["chat_template_kwargs"] == {"enable_thinking": True}
    assert c.reasoning and c.actor()["reasoning"] is True and c.actor()["model"] == "m-fast-thinking"


def test_a_role_is_bound_by_the_config_not_the_code():
    t, seen = transport('{"label": "a"}', loaded=("m-fast", "m-fast-thinking"))
    s = Seam(CFG_ROLES, transport=t)
    assert s.for_role("classify-algorithm") == ("fast", True) and s.for_role("trace-to-cause") == ("deliberate", False)
    c = s.complete_role("classify-algorithm", [], schema=SCHEMA, purpose="t")
    assert c.role == "classify-algorithm" and c.actor()["role"] == "classify-algorithm" and json.loads(seen[-1].content)["model"] == "m-fast-thinking"
    with pytest.raises(TierUnavailable):
        s.for_role("a-role-nobody-measured")
    # a config with no roles section binds every role to fast, without reasoning
    assert Seam(CFG, transport=t).for_role("anything") == ("fast", False)


def test_config_refuses_a_role_bound_to_no_tier(tmp_path):
    import yaml

    bad = {**CFG, "roles": {"x": {"tier": "huge"}}}
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(bad))
    with pytest.raises(ValueError):
        load_config(p)


def test_example_config_binds_the_measured_roles():
    cfg = load_config("config/inference.example.yaml")
    assert cfg["roles"]["trace-to-cause"]["tier"] == "deliberate" and cfg["roles"]["classify-algorithm"]["reasoning"] is True
