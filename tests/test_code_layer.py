"""The thin code layer: candidates by rule, judged by the call-site-read role, carried by the CBOM."""

import json

import httpx

from pqch.cbom import build_all
from pqch.inference import Seam
from pqch.scout.code import candidates, head_commit, load_rules, scan

SRC = '''class Signer
  # OpenSSL::PKey::RSA.new(2048) -- a comment, not a use
  def key
    OpenSSL::PKey::RSA.new(2048)
  end
end
'''


def repo(tmp_path):
    r = tmp_path / "repo"
    (r / "app").mkdir(parents=True)
    (r / "app" / "signer.rb").write_text(SRC)
    (r / ".git").mkdir()
    (r / ".git" / "HEAD").write_text("a" * 40 + "\n")
    return r


def seam():
    def handler(req):
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "g"}]})
        user = json.loads(req.content)["messages"][1]["content"]
        line = int(user.split("Flagged line: ")[1].split()[0])
        use = line == 4
        reply = {"is_crypto_use": use, "family": "RSA" if use else "none", "role": "other", "key_bits": 2048 if use else None}
        return httpx.Response(200, json={"model": "g", "usage": {"total_tokens": 10},
                                         "choices": [{"message": {"content": json.dumps(reply)}, "finish_reason": "stop"}]})
    cfg = {"schema": "pqch.inference/1", "profile": "t", "roles": {"call-site-read": {"tier": "fast", "reasoning": True}},
           "tiers": {"fast": {"base_url": "http://x.test/v1", "api_key_env": "K", "model": "g", "hardware": "l4",
                              "engine": "test-engine", "reasoning": {"model": "g-think"}}}}
    return Seam(cfg, transport=httpx.MockTransport(handler))


def test_candidates_are_lines_a_rule_matches_with_their_context(tmp_path):
    r = repo(tmp_path)
    c = candidates(r, load_rules("policy/code-rules/ruby.yaml"))
    assert [(x["line"], x["rule"], x["family_hint"]) for x in c] == [(2, "ruby/openssl-pkey", "RSA"), (4, "ruby/openssl-pkey", "RSA")]
    assert "    4      OpenSSL::PKey::RSA.new(2048)" in c[1]["context"]
    assert head_commit(r) == "a" * 40


def test_the_model_judges_each_candidate_and_the_cbom_carries_the_judgement(tmp_path):
    r = repo(tmp_path)
    run, s = scan(tmp_path / "var", r, repo="x/y", commit="a" * 40, rules_path="policy/code-rules/ruby.yaml",
                  seam=seam(), authorized_by="test")
    assert s["candidates"] == 2 and s["uses"] == 1 and s["not_uses"] == 1
    events = list(run.ledger.events())
    judged = [e for e in events if e["payload"].get("purpose") == "call-site-read"]
    assert all(e["actor"]["kind"] == "model" and e["payload"]["used_by_rules"] is False for e in judged)
    assert {e["payload"]["agreement"] for e in judged} == {"3 of 3"}
    bom = build_all(events)["workbench"]
    code = {json.loads(p["value"])["line"]: c for c in bom["components"] for p in c.get("properties", [])
            if p["name"] == "pqch:subject" and '"call-site"' in p["value"]}
    in_use = {line: {p["name"]: p["value"] for p in c["properties"]}["pqch:in-use"] for line, c in code.items()}
    assert in_use == {2: "false", 4: "true"}


def test_a_checkout_not_at_its_pin_is_refused(tmp_path):
    import pytest
    r = repo(tmp_path)
    with pytest.raises(ValueError, match="not the pinned"):
        scan(tmp_path / "var", r, repo="x/y", commit="b" * 40, rules_path="policy/code-rules/ruby.yaml",
             seam=seam(), authorized_by="test")


def test_a_model_set_in_use_says_which_model_engine_and_hardware_and_by_what_agreement(tmp_path):
    r = repo(tmp_path)
    run, _ = scan(tmp_path / "var", r, repo="x/y", commit="a" * 40, rules_path="policy/code-rules/ruby.yaml",
                  seam=seam(), authorized_by="test")
    bom = build_all(list(run.ledger.events()))["workbench"]
    code = [{p["name"]: p["value"] for p in c["properties"]} for c in bom["components"]
            if any(p["name"] == "pqch:layer" and p["value"] == "code" for p in c.get("properties", []))]
    assert code and all("pqch:in-use-by" in p and p["pqch:in-use-agreement"] == "3 of 3" for p in code)
    by = json.loads(code[0]["pqch:in-use-by"])
    assert by["model"] == "g" and by["hardware"] == "l4" and by["role"] == "call-site-read"
    assert by.get("engine") == "test-engine" and "served_by" not in by      # the engine is declared, never a URL
    assert by["reasoning"] is True
    assert all("pqch:in-use-rule" not in p for p in code)


def test_a_rule_set_in_use_carries_no_model_label():
    from pqch.cbom import _model_label

    assert _model_label({"kind": "rule", "id": "in-use/served/1"}) is None
    lab = _model_label({"kind": "model", "id": "fast:m", "tier": "fast", "model": "m", "hardware": "gb10",
                        "served_by": "http://engine:8000"})
    assert lab["served_by"] == "http://engine:8000" and "engine" not in lab   # a URL is not an engine
    assert _model_label({"kind": "model", "id": "fast:m", "tier": "fast", "model": "m", "hardware": "gb10",
                         "engine": "vllm"})["engine"] == "vllm"


def test_every_cbom_field_a_model_can_set_is_labelled_in_fields_yaml():
    import yaml
    fields = yaml.safe_load(open("src/pqch/cbom/fields.yaml"))
    flat = {k: v for sec in fields.values() if isinstance(sec, dict) for k, v in sec.items() if isinstance(v, dict)}
    by_model = [k for k, v in flat.items() if "model:" in str(v.get("from", "")) and not k.endswith(("-by", "-agreement"))]
    assert by_model == ["pqch:in-use"]
    for k in by_model:
        assert f"{k}-by" in flat and f"{k}-agreement" in flat
