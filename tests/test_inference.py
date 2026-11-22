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
                         "served_by": "http://upstream.test:8013/v1", "transport": c.transport}
    assert c.transport in ("plain", "listed-subnet", "loopback")
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


# ---- TLS and model origin in the seam (M8: FR-03 part, FR-07)

def _cfg(**extra):
    import copy
    c = copy.deepcopy(CFG)
    c.update(extra)
    return c


def test_transport_is_classified_from_the_url_and_the_listed_subnets():
    from pqch.inference import transport_of
    assert transport_of("https://gateway.example/v1") == "tls"
    assert transport_of("http://127.0.0.1:8000/v1") == "loopback"
    assert transport_of("http://localhost:8000/v1") == "loopback"
    # A routable address is plain unless the operator listed its subnet; nothing is read from the routing table.
    assert transport_of("http://10.255.255.1:8000/v1") == "plain"
    assert transport_of("http://10.255.255.1:8000/v1", ("10.255.255.0/24",)) == "listed-subnet"
    assert transport_of("http://10.255.255.1:8000/v1", ("10.255.254.0/24",)) == "plain"


def _plain(**tls):
    c = _cfg(tls=tls) if tls else _cfg()
    c["tiers"]["fast"]["base_url"] = "http://10.255.255.1:8000/v1"
    return c


def test_with_tls_required_plain_http_to_an_unlisted_host_is_refused():
    t, _ = transport('{"label": "a"}')
    with pytest.raises(TierUnavailable, match="requires TLS"):
        Seam(_plain(require=True), transport=t).complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t")
    with pytest.raises(TierUnavailable, match="requires TLS"):     # a listed subnet that does not hold the host
        Seam(_plain(require=True, allow_plain_subnets=["10.255.254.0/24"]), transport=t).complete(
            "fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t")
    # Without the setting, the same call goes through as before, and the actor says how it travelled.
    c = Seam(_plain(), transport=t).complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t")
    assert c.actor()["transport"] == "plain" and "plain_subnets" not in c.actor()


def test_with_tls_required_loopback_a_listed_subnet_and_https_are_allowed():
    t, _ = transport('{"label": "a"}')
    for url, tls, how in (("http://127.0.0.1:8000/v1", {"require": True}, "loopback"),
                          ("http://10.255.255.1:8000/v1", {"require": True, "allow_plain_subnets": ["10.255.255.0/24"]}, "listed-subnet"),
                          ("https://gateway.example/v1", {"require": True}, "tls")):
        cfg = _cfg(tls=tls)
        cfg["tiers"]["fast"]["base_url"] = url
        a = Seam(cfg, transport=t).complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t").actor()
        assert a["transport"] == how
        assert a.get("plain_subnets") == (["10.255.255.0/24"] if how == "listed-subnet" else None)


def test_a_bad_subnet_or_an_unknown_tls_key_is_refused_when_the_config_loads(tmp_path):
    import yaml

    from pqch.inference import load_config
    for tls, msg in (({"allow_plain_subnets": ["not-a-network"]}, "allow_plain_subnets"), ({"verify": False}, "tls takes only")):
        p = tmp_path / "c.yaml"
        p.write_text(yaml.safe_dump(_cfg(tls=tls)))
        with pytest.raises(ValueError, match=msg):
            load_config(p)


def test_a_ca_file_is_what_an_https_tier_is_verified_against(tmp_path):
    ca = tmp_path / "ca.pem"
    ca.write_text("not a certificate")
    cfg = _cfg(tls={"ca_file": str(ca)})
    cfg["tiers"]["fast"]["base_url"] = "https://gateway.example/v1"
    import ssl
    with pytest.raises((ssl.SSLError, OSError)):      # httpx loads the CA file when the client is built: a bad one fails
        Seam(cfg)._client(cfg["tiers"]["fast"], 5)


def test_the_origin_allowlist_refuses_a_model_of_another_origin_or_none(tmp_path):
    import yaml

    from pqch.inference import load_config
    cfg = _cfg(origins={"allowed": ["US"]})
    for t in cfg["tiers"].values():
        t["provenance"] = {"origin": "US", "licence": "test", "weights_sha256": "a" * 64}
    p = tmp_path / "ok.yaml"
    p.write_text(yaml.safe_dump(cfg))
    load_config(p)
    cfg["tiers"]["fast"]["provenance"]["origin"] = "XX"
    p.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ValueError, match="origin XX"):
        load_config(p)
    del cfg["tiers"]["fast"]["provenance"]
    with pytest.raises(TierUnavailable, match="declares no origin"):
        Seam(cfg).admit("fast", cfg["tiers"]["fast"])


def test_the_actor_records_origin_and_weights_digest(monkeypatch):
    t, _ = transport('{"label": "a"}')
    cfg = _cfg(origins={"allowed": ["US"]})
    cfg["tiers"]["fast"]["provenance"] = {"origin": "US", "weights_sha256": "b" * 64}
    a = Seam(cfg, transport=t).complete("fast", [{"role": "user", "content": "x"}], schema=SCHEMA, purpose="t").actor()
    assert a["origin"] == "US" and a["weights_sha256"] == "b" * 64
