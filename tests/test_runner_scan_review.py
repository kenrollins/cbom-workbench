"""The runner after the 2026-11 review: an IPv6 target, a listener under several names, a binding
that says nothing when no container was seen, a wait that failed without timing out, and the record
of a system read over SSH."""

import json

import pytest

from pqch import scope as scope_mod
from pqch.runner import Refused, Runner, load_profiles

SCOPE = {
    "schema": "pqch.scope/1", "id": "01M40W6W873YWJMWPKGMK3YBMM", "estate": "external", "owned": False,
    "authorized_by": "owner",
    "endpoints": [
        {"host": "172.16.106.10", "port": 443, "transport": "tcp", "protocol": "tls", "sni": "a.agency.test"},
        {"host": "172.16.106.10", "port": 443, "transport": "tcp", "protocol": "tls", "sni": "b.agency.test"},
        {"host": "172.16.106.20", "port": 22, "transport": "tcp", "protocol": "ssh"},
    ],
    "images": [], "sources": [], "reach": {"kind": "local"},
    "systems": [{"name": "srv9", "addresses": ["10.0.0.9"], "paths": ["/etc/ssh"],
                 "via": {"kind": "ssh", "host": "srv9.example", "user": "scan", "known_hosts": "/run/ssh/known_hosts"}}],
}
H = scope_mod.scope_hash(SCOPE)


class FakeContainer:
    id = "job-container"

    def __init__(self, wait):
        self._wait, self.archives, self.killed = wait, [], False

    def put_archive(self, path, data):
        self.archives.append((path, data))

    def start(self):
        pass

    def wait(self, timeout=None):
        if isinstance(self._wait, Exception):
            raise self._wait
        return {"StatusCode": self._wait}

    def kill(self):
        self.killed = True

    def logs(self, stdout=True, stderr=True):
        return b"{}" if stdout else b""

    def reload(self):
        pass

    def remove(self, force=False):
        pass


class FakeNetwork:
    def __init__(self, containers):
        self.attrs = {"Containers": containers}


class FakeDocker:
    """Enough of Docker for one job: the scanner's container, the target network, the runner itself."""

    def __init__(self, wait=0, on_network=None, network_error=None):
        self.wait, self.on_network, self.network_error = wait, on_network or {}, network_error
        self.containers, self.networks = self, self
        self.created = []

    def create(self, image, **kw):
        self.created.append(FakeContainer(self.wait))
        return self.created[-1]

    def get(self, ref):
        if ref == "net":
            if self.network_error:
                raise self.network_error
            return FakeNetwork(self.on_network)

        class C:
            id, name = ref, "held"
            attrs = {"Config": {"Image": "pqch/harness:test"}, "Image": "sha256:" + "a" * 64}  # noqa: RUF012 - a stand-in, read once
        return C()


def runner(tmp_path, docker):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(SCOPE))
    return Runner(p, tmp_path / "raw", target_network="net", docker_client=docker, log_dir=tmp_path / "log")


def test_an_ipv6_literal_is_bracketed_where_a_port_follows_it_and_bare_where_it_stands_alone():
    profiles = load_profiles()
    ep = {"host": "fd00::10", "port": 443, "protocol": "tls"}
    args = Runner._args(profiles["tls-targeted"], ep)
    assert args[-1] == "https://[fd00::10]:443"
    assert Runner._args(profiles["ssh-targeted"], {"host": "fd00::10", "port": 22}) == ["-j", "-p", "22", "fd00::10"]
    probe = {"layer": "wire", "args": ["openssl", "s_client", "-connect", "{hostport}", "-servername", "{sni}"]}
    assert Runner._args(probe, ep)[3] == "[fd00::10]:443"
    assert Runner._args(probe, {"host": "172.16.106.10", "port": 443})[3] == "172.16.106.10:443"
    # With a name, the URL carries the name and --ip the bare address.
    named = Runner._args(profiles["tls-targeted"], {**ep, "sni": "v6.agency.test"})
    assert named[-1] == "https://v6.agency.test:443" and "fd00::10" in named


def test_the_binding_finds_a_container_by_its_ipv6_address_however_it_is_spelled(tmp_path):
    docker = FakeDocker(on_network={"c1": {"IPv4Address": "172.16.106.10/24", "IPv6Address": "fd00:0:0:0::10/64"}})
    r = runner(tmp_path, docker)
    assert r.binding(docker, "fd00::10")["container_id"] == "c1"
    assert r.binding(docker, "172.16.106.10")["container_id"] == "c1"
    assert r.binding(docker, "fd00::11")["container_id"] is None


def test_a_listener_under_several_names_is_resolved_by_the_name_the_job_gives(tmp_path):
    r = runner(tmp_path, FakeDocker())
    _, _, ep = r.check("tls-targeted", {"host": "172.16.106.10", "port": 443, "sni": "b.agency.test"}, H)
    assert ep["sni"] == "b.agency.test"
    _, _, ep = r.check("tls-targeted", {"host": "172.16.106.10", "port": 443}, H)
    assert ep["sni"] == "a.agency.test"                        # no name given: the first entry, as before
    with pytest.raises(Refused) as e:
        r.check("tls-targeted", {"host": "172.16.106.10", "port": 443, "sni": "elsewhere.example"}, H)
    assert e.value.code == 403 and "under the name" in e.value.reason


def test_two_lookups_that_found_no_container_are_not_a_stable_binding(tmp_path):
    # An external address no container holds, and a Docker lookup that fails twice the same way.
    job = runner(tmp_path, FakeDocker()).run("ssh-targeted", {"host": "172.16.106.20", "port": 22}, H)
    assert job.binding["container_id"] is None and job.binding["stable"] is False
    job = runner(tmp_path, FakeDocker(network_error=RuntimeError("docker is down"))).run(
        "ssh-targeted", {"host": "172.16.106.20", "port": 22}, H)
    assert "error" in job.binding and job.binding["stable"] is False
    held = FakeDocker(on_network={"c1": {"IPv4Address": "172.16.106.20/24"}})
    assert runner(tmp_path, held).run("ssh-targeted", {"host": "172.16.106.20", "port": 22}, H).binding["stable"] is True


def test_a_wait_that_fails_without_timing_out_is_an_error_not_a_timeout(tmp_path):
    class ReadTimeout(Exception):
        pass

    slow = runner(tmp_path, FakeDocker(wait=ReadTimeout("read timed out"))).run("ssh-targeted", {"host": "172.16.106.20", "port": 22}, H)
    assert slow.status == "timeout"
    broken = runner(tmp_path, FakeDocker(wait=RuntimeError("the daemon went away"))).run(
        "ssh-targeted", {"host": "172.16.106.20", "port": 22}, H)
    assert broken.status == "error" and "the daemon went away" in broken.stderr_tail


def test_a_system_read_over_ssh_says_so_in_the_job_result_and_the_runners_log(tmp_path, monkeypatch):
    docker = FakeDocker()
    r = runner(tmp_path, docker)
    monkeypatch.setattr(r, "system_archive", lambda sysdef: b"archive")
    job = r.run("system-files", {"system": "srv9"}, H)
    assert job.status == "ok" and job.container == {"read_via": "ssh scan@srv9.example", "id": "job-container", "network": "none"}
    logged = [json.loads(line) for line in (tmp_path / "log" / "jobs.jsonl").read_text().splitlines()]
    assert logged[-1]["read_via"] == "ssh scan@srv9.example"
    # A read that failed still says which route failed.
    monkeypatch.setattr(r, "system_archive", lambda sysdef: (_ for _ in ()).throw(RuntimeError("ssh to scan@srv9.example failed (255)")))
    failed = r.run("system-files", {"system": "srv9"}, H)
    assert failed.status == "error" and failed.container["read_via"] == "ssh scan@srv9.example"
