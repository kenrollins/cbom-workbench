import pytest

from pqch import scope as scope_mod
from pqch.ledger import verify
from pqch.run import Run

COMPOSE = """
name: t
services:
  a:
    image: t/a:1
    networks: {net: {ipv4_address: 10.9.0.10}}
    x-pqch: {endpoints: [{port: 443, protocol: tls, sni: a.test}]}
  b:
    image: t/b:1
    networks: {net: {ipv4_address: 10.9.0.11}}
    x-pqch: {endpoints: [{port: 22, protocol: ssh}]}
networks:
  net: {internal: true}
"""


class FakeImage:
    def __init__(self, ref):
        self.attrs = {"RepoDigests": [ref.split(":")[0] + "@sha256:" + "a" * 64]}


class FakeImages:
    def get(self, ref):
        return FakeImage(ref)


class FakeDocker:
    images = FakeImages()


def make_scope(tmp_path):
    p = tmp_path / "compose.yaml"
    p.write_text(COMPOSE)
    return scope_mod.generate(p, docker_client=FakeDocker())


def test_generate_reads_endpoints_and_digests(tmp_path):
    s = make_scope(tmp_path)
    assert [(e["host"], e["port"], e["protocol"]) for e in s["endpoints"]] == [
        ("10.9.0.10", 443, "tls"), ("10.9.0.11", 22, "ssh")]
    assert s["images"] == ["t/a@sha256:" + "a" * 64, "t/b@sha256:" + "a" * 64]
    assert s["endpoints"][0]["image"] == "t/a@sha256:" + "a" * 64
    assert s["owned"] is True and s["estate"] == "colocated"
    assert scope_mod.endpoint(s, "10.9.0.10", 443)
    assert scope_mod.endpoint(s, "10.9.0.10", 8443) is None
    assert scope_mod.image(s, "t/a") and scope_mod.image(s, "t/c") is None


def test_scope_is_event_zero_of_a_run(tmp_path):
    s = make_scope(tmp_path)
    run = Run.start(tmp_path / "var", s, runner_scope_hash=scope_mod.scope_hash(s), profile="m0")
    first = next(run.ledger.events())
    assert first["seq"] == 0 and first["type"] == "run.started"
    assert first["payload"]["scope_hash"] == scope_mod.scope_hash(s)
    assert verify(run.ledger.events()).ok


def test_run_refuses_a_scope_the_runner_does_not_hold(tmp_path):
    s = make_scope(tmp_path)
    with pytest.raises(ValueError, match="scope mismatch"):
        Run.start(tmp_path / "var", s, runner_scope_hash="0" * 64, profile="m0")
