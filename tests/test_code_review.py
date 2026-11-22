"""The code layer after the 2026-11 review: a true majority on the one question, a reading that fails
without ending the scan, literals masked, and which files a rule pack reads."""

import json
import os

import httpx
import pytest

from pqch.inference import Seam
from pqch.scout.code import candidates, load_rules, mask_literals, scan, source_files, tally

RULES = "policy/code-rules/ruby.yaml"
USE = {"is_crypto_use": True, "family": "HMAC", "role": "mac", "key_bits": None}
NOT = {"is_crypto_use": False, "family": "none", "role": "other", "key_bits": None}


def repo(tmp_path, files):
    r = tmp_path / "repo"
    for rel, text in files.items():
        (r / rel).parent.mkdir(parents=True, exist_ok=True)
        (r / rel).write_text(text)
    (r / ".git").mkdir(exist_ok=True)
    (r / ".git" / "HEAD").write_text("a" * 40 + "\n")
    return r


def seam(replies):
    """A seam whose successive completions are `replies`: a dict is the model's answer, an
    exception is raised from the transport, a string is sent as the body."""
    it = iter(replies)

    def handler(req):
        if req.url.path.endswith("/models"):
            return httpx.Response(200, json={"data": [{"id": "g"}]})
        r = next(it)
        if isinstance(r, Exception):
            raise r
        if isinstance(r, int):
            return httpx.Response(r, text="upstream error")
        body = r if isinstance(r, str) else json.dumps(r)
        return httpx.Response(200, json={"model": "g", "usage": {"total_tokens": 10},
                                         "choices": [{"message": {"content": body}, "finish_reason": "stop"}]})
    cfg = {"schema": "pqch.inference/1", "profile": "t", "roles": {"call-site-read": {"tier": "fast", "reasoning": True}},
           "tiers": {"fast": {"base_url": "http://x.test/v1", "api_key_env": "K", "model": "g", "hardware": "l4",
                              "engine": "test-engine", "reasoning": {"model": "g-think"}}}}
    return Seam(cfg, transport=httpx.MockTransport(handler))


def judged(tmp_path, replies):
    r = repo(tmp_path, {"app/a.rb": "OpenSSL::HMAC.hexdigest('SHA256', key, data)\n"})
    run, summary = scan(tmp_path / "var", r, repo="x/y", commit="a" * 40, rules_path=RULES, seam=seam(replies),
                        authorized_by="test", workers=1)
    events = list(run.ledger.events())
    made = [e for e in events if e["payload"].get("purpose") == "call-site-read"]
    assert len(made) == 1
    return made[0]["payload"], summary, events


# ------------------------------------------------------------ the majority
def test_two_of_three_saying_use_is_a_use_whatever_they_call_the_family():
    """The review's case: (not a use), (use, HMAC), (use, SHA-2) was recorded as not in use, '1 of 3'."""
    v = tally([NOT, USE, {**USE, "family": "SHA-2"}], 3, role_hint="mac")
    assert v["classification"] == {"in_use": True, "family": "unspecified", "role": "mac"}      # the family is a tie: neither
    assert v["agreement"] == "2 of 3" and v["votes"] == {"use": 2, "not_a_use": 1, "failed": 0, "of": 3}
    assert "2 of 3 calls say it is a live use" in v["basis"]
    v = tally([USE, {**USE, "family": "SHA-2", "role": "hash"}, USE], 3)
    assert v["classification"] == {"in_use": True, "family": "HMAC", "role": "mac"} and v["agreement"] == "3 of 3"
    v = tally([NOT, NOT, USE], 3)
    assert v["classification"]["in_use"] is False and v["classification"]["family"] == "none" and v["agreement"] == "2 of 3"


@pytest.mark.parametrize("replies", [[USE], [NOT], [USE, NOT], []])
def test_fewer_than_a_majority_of_the_calls_made_is_not_read(replies):
    v = tally(replies, 3)
    assert v["classification"] == {"in_use": None} and v["basis"].startswith("not read: no majority")
    assert v["votes"]["failed"] == 3 - len(replies)


def test_the_ledger_carries_the_counts_and_the_cbom_the_agreement(tmp_path):
    p, summary, _ = judged(tmp_path, [NOT, USE, {**USE, "family": "SHA-2"}])
    assert p["classification"]["in_use"] is True and p["agreement"] == "2 of 3" and summary["uses"] == 1
    assert p["votes"] == {"use": 2, "not_a_use": 1, "failed": 0, "of": 3}


# ------------------------------------------------------------ a reading that fails
@pytest.mark.parametrize("failure,word", [(httpx.ReadTimeout("timed out"), "ReadTimeout"), (httpx.ConnectError("refused"), "ConnectError"),
                                          (502, "502"), ("not json at all", "")])
def test_a_gateway_failure_degrades_one_candidate_to_not_read_and_the_run_is_closed(tmp_path, failure, word):
    p, summary, events = judged(tmp_path, [failure, failure, failure])
    assert p["classification"] == {"in_use": None} and summary == {"candidates": 1, "failed": 1, "latencies_ms": []}
    assert p["basis"].startswith("not read: no majority") and word in p["basis"]
    assert all(c["reply"] is None and c["error"] for c in p["calls"])
    assert events[-1]["type"] == "run.closed" or any(e["type"] == "run.closed" for e in events)
    assert sum(1 for e in events if e["type"] == "finding.observed") == 1          # the scanner's finding stands


def test_one_failed_call_among_three_still_leaves_a_majority(tmp_path):
    p, summary, _ = judged(tmp_path, [USE, httpx.ReadTimeout("timed out"), USE])
    assert p["classification"]["in_use"] is True and p["agreement"] == "2 of 3" and p["votes"]["failed"] == 1
    assert "ReadTimeout" in p["basis"] and summary["uses"] == 1


def test_a_single_reply_is_not_a_majority_of_three(tmp_path):
    p, summary, _ = judged(tmp_path, [httpx.ReadTimeout("t"), NOT, 500])
    assert p["classification"] == {"in_use": None} and p["agreement"] == "1 of 3" and summary["failed"] == 1


# ------------------------------------------------------------ what goes on the ledger
def test_a_long_literal_on_a_matched_line_is_masked_on_the_ledger_and_whole_in_the_private_file(tmp_path):
    key = "0123456789abcdef0123456789abcdef"
    line = f'OpenSSL::HMAC.hexdigest("SHA256", "{key}", data)'
    assert mask_literals(line) == 'OpenSSL::HMAC.hexdigest("SHA256", "<32 characters>", data)'
    assert mask_literals("Digest::SHA256.hexdigest('short one')") == "Digest::SHA256.hexdigest('short one')"
    assert mask_literals('x("it\'s \\" quoted and long enough")') == 'x("<30 characters>")'
    r = repo(tmp_path, {"app/a.rb": line + "\n"})
    run, _ = scan(tmp_path / "var", r, repo="x/y", commit="a" * 40, rules_path=RULES, seam=seam([USE, USE, USE]),
                  authorized_by="test", workers=1)
    assert key not in (run.dir / "ledger.jsonl").read_text()
    f = next(e["payload"] for e in run.ledger.events() if e["type"] == "finding.observed")
    assert f["asset"]["parameters"]["line_text"] == mask_literals(line) and f["evidence"]["excerpt"] == mask_literals(line)
    assert key in (run.dir / "code-candidates.json").read_text()


def test_a_hash_is_named_as_every_other_layer_names_it(tmp_path):
    r = repo(tmp_path, {"app/a.rb": "Digest::SHA256.hexdigest(x)\nDigest::SHA1.digest(y)\nOpenSSL::PKey::EC.new('prime256v1')\n"})
    assert [c["family_hint"] for c in candidates(r, load_rules(RULES))] == ["SHA-256", "SHA-1", "EC"]


# ------------------------------------------------------------ which files are read
def test_an_exclusion_is_a_directory_not_a_substring_and_the_pack_names_its_globs(tmp_path):
    use = "OpenSSL::PKey::RSA.new(2048)\n"
    r = repo(tmp_path, {"lib/latest/b.rb": use, "lib/inspec/c.rb": use, "app/x/spec/d.rb": use, "test/e.rb": use,
                        "lib/tasks/keys.rake": use, "app/views/v.erb": use, "vendor/v.rb": use})
    rules = load_rules(RULES)
    assert source_files(r, rules) == ["lib/inspec/c.rb", "lib/latest/b.rb", "lib/tasks/keys.rake"]
    assert source_files(r, {**rules, "globs": ["*.erb"]}) == ["app/views/v.erb"]


def test_a_link_out_of_the_checkout_is_never_read(tmp_path):
    r = repo(tmp_path, {"app/real.rb": "OpenSSL::PKey::RSA.new(2048)\n"})
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.rb").write_text("OpenSSL::HMAC.hexdigest('SHA256', 'the key', data)\n")
    os.symlink(outside / "secret.rb", r / "app" / "link.rb")
    os.symlink(outside, r / "app" / "linked_dir")
    assert [c["path"] for c in candidates(r, load_rules(RULES))] == ["app/real.rb"]


def test_the_pack_finds_the_uses_the_review_found_missing(tmp_path):
    lines = ["client = Aws::KMS::Client.new(region: r)", "ROTP::TOTP.new(secret, digits: 6)", "ctx = OpenSSL::SSL::SSLContext.new",
             "OpenSSL::PKCS7.sign(cert, key, data)", "OpenSSL::PKey.generate_key('ED25519')",
             "ActiveSupport::MessageEncryptor.new(k)", "RbNaCl::SecretBox.new(k)", "JSON::JWK.new(k)",
             "Digest::RMD160.hexdigest(x)", "has_secure_password"]
    r = repo(tmp_path, {"app/a.rb": "\n".join(lines) + "\n"})
    got = [c["rule"] for c in candidates(r, load_rules(RULES))]
    assert got == ["ruby/aws-kms", "ruby/rotp", "ruby/openssl-ssl", "ruby/openssl-pkcs", "ruby/openssl-pkey-generate",
                   "ruby/active-support-crypto", "ruby/rbnacl", "ruby/json-jwt", "ruby/digest-other", "ruby/secure-password"]
