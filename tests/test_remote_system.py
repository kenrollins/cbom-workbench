"""M10 item 7: a system's files packed on the remote over SSH, the same archive as a local read."""

import io
import json
import os
import stat
import tarfile
from pathlib import Path

import pytest

from pqch import schemas
from pqch.scout import system as system_mod


def fake_ssh(tmp_path: Path, remote_root: Path) -> Path:
    """An `ssh` that runs the remote command locally the way sshd does: the words after the
    destination are joined with spaces and handed to a shell. A stand-in that ran them as an argument
    list hid that the remote shell re-reads every word."""
    exe = tmp_path / "bin" / "ssh"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text(f"""#!/usr/bin/env python3
import os, subprocess, sys
args = sys.argv[1:]
log = open({str(tmp_path / 'ssh.log')!r}, 'a'); log.write(' '.join(args) + '\\n'); log.close()
# options come in pairs and end at `--`; then user@host, then the remote command
i = 0
while i < len(args) and args[i] != '--':
    if not args[i].startswith('-'):
        sys.stderr.write('an argument before -- that is not an option: ' + args[i]); sys.exit(255)
    i += 2
cmd = args[i + 2:]
env = dict(os.environ, PQCH_REMOTE_ROOT={str(remote_root)!r})
sys.exit(subprocess.run(['sh', '-c', ' '.join(cmd)], stdin=sys.stdin, env=env).returncode)
""")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return exe


def test_the_remote_pack_is_the_local_pack_made_over_there(tmp_path):
    root = tmp_path / "remote"
    (root / "etc" / "ssh").mkdir(parents=True)
    (root / "etc" / "ssh" / "ssh_host_ed25519_key.pub").write_text("ssh-ed25519 AAAA test\n")
    (root / "etc" / "ssh" / "ssh_host_ed25519_key").write_text("private\n")
    os.chmod(root / "etc" / "ssh" / "ssh_host_ed25519_key", 0)
    system = {"name": "srv9", "addresses": ["10.0.0.9"], "paths": ["/etc/ssh"], "firmware": False,
              "via": {"kind": "ssh", "host": "srv9.example", "user": "scan", "port": 2222, "identity": "/run/ssh/id", "known_hosts": "/run/ssh/known_hosts"}}
    ssh = fake_ssh(tmp_path, root)
    try:
        remote = system_mod.remote_pack(system, prefix="scan/root/", ssh=str(ssh))
        local = system_mod.pack(root, {k: v for k, v in system.items() if k != "via"}, prefix="scan/root/")
    finally:
        os.chmod(root / "etc" / "ssh" / "ssh_host_ed25519_key", 0o600)
    names = lambda data: sorted(tarfile.open(fileobj=io.BytesIO(data)).getnames())  # noqa: E731
    assert names(remote) == names(local)
    with tarfile.open(fileobj=io.BytesIO(remote)) as tar:
        manifest = json.loads(tar.extractfile("scan/root/" + system_mod.MANIFEST).read())
    assert manifest["files"] == 1 and manifest["unreadable"] == ["/etc/ssh/ssh_host_ed25519_key"] and manifest["read_as_uid"] == os.getuid()
    # Strict host-key checking against the scope's file, the identity only, the port: all on the command line.
    line = (tmp_path / "ssh.log").read_text()
    assert "StrictHostKeyChecking=yes" in line and "UserKnownHostsFile=/run/ssh/known_hosts" in line
    assert "-i /run/ssh/id" in line and "IdentitiesOnly=yes" in line and "-p 2222" in line
    # No configuration file, no system-wide known hosts; the destination after `--`; and the remote
    # command is the interpreter and `-` alone: nothing of the scope is on it.
    assert line.startswith("-F none ") and "GlobalKnownHostsFile=/dev/null" in line
    assert line.rstrip("\n").endswith("-- scan@srv9.example python3 -")


def test_a_scoped_value_is_never_read_by_the_remote_shell(tmp_path):
    """A path a shell would run, a name with quotes and spaces: each reaches the remote packer as the
    string it is, because the definition travels inside the program on stdin."""
    root = tmp_path / "remote"
    (root / "etc").mkdir(parents=True)
    marker = tmp_path / "RAN"
    hostile = f"/etc/$(touch${{IFS}}{marker})"
    system = {"name": "srv \"9\" `id`", "addresses": [], "paths": ["/etc", hostile, "/etc/it's here"], "firmware": False,
              "via": {"kind": "ssh", "host": "srv9.example", "user": "scan", "known_hosts": "/run/ssh/known_hosts"}}
    data = system_mod.remote_pack(system, prefix="scan/root/", ssh=str(fake_ssh(tmp_path, root)))
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        manifest = json.loads(tar.extractfile("scan/root/" + system_mod.MANIFEST).read())
    assert not marker.exists()
    assert manifest["system"] == system["name"] and manifest["paths"] == system["paths"]
    assert f"{hostile} (absent)" in manifest["unreadable"]
    # An empty prefix is not a word that can vanish from a command line either.
    names = tarfile.open(fileobj=io.BytesIO(system_mod.remote_pack(system, ssh=str(fake_ssh(tmp_path, root))))).getnames()
    assert system_mod.MANIFEST in names


@pytest.mark.parametrize("field,value", [
    ("user", "-oProxyCommand=touch /tmp/x"), ("user", "scan;id"), ("host", "-oProxyCommand=id"), ("host", "h example"),
    ("python", "python3; id"), ("python", "-c"), ("known_hosts", "relative/known_hosts"), ("known_hosts", "/a /b"),
    ("identity", "-oProxyCommand=id"), ("port", "22; id"), ("known_hosts", None),
])
def test_a_route_that_would_read_as_an_option_or_a_command_is_refused_before_ssh_runs(tmp_path, field, value):
    via = {"kind": "ssh", "host": "srv9.example", "user": "scan", "known_hosts": "/run/ssh/known_hosts", field: value}
    exe = tmp_path / "ssh"
    exe.write_text(f"#!/bin/sh\ntouch {tmp_path}/SSH_RAN\n")
    exe.chmod(0o755)
    with pytest.raises(ValueError, match="SSH route"):
        system_mod.remote_pack({"name": "s", "addresses": [], "paths": ["/etc"], "via": via}, ssh=str(exe))
    assert not (tmp_path / "SSH_RAN").exists()


def test_the_program_sent_runs_on_a_python_older_than_its_annotations():
    src = system_mod.remote_source({"name": "s", "paths": ["/etc"], "via": {"kind": "ssh"}}, prefix="scan/root/")
    assert src.startswith("from __future__ import annotations\n") and "via" not in src.split("SYSTEM = ")[1].split("\n")[0]
    compile(src, "<remote>", "exec")


def test_a_failed_ssh_is_an_error_not_an_empty_inventory(tmp_path):
    exe = tmp_path / "bin" / "ssh"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\necho 'Host key verification failed.' >&2\nexit 255\n")
    exe.chmod(0o755)
    system = {"name": "s", "addresses": [], "paths": ["/etc"], "via": {"kind": "ssh", "host": "h", "user": "u", "known_hosts": "/k"}}
    with pytest.raises(RuntimeError, match="Host key verification failed"):
        system_mod.remote_pack(system, ssh=str(exe))


def test_the_scope_carries_the_route_and_refuses_one_without_known_hosts():
    scope = {"schema": "pqch.scope/1", "id": "01M40W6W873YWJMWPKGMK3YBMN", "estate": "external", "owned": False,
             "authorized_by": "owner", "endpoints": [], "images": [], "sources": [], "reach": {"kind": "local"},
             "systems": [{"name": "srv9", "addresses": ["10.0.0.9"], "paths": ["/etc/ssh"],
                          "via": {"kind": "ssh", "host": "srv9.example", "user": "scan", "known_hosts": "/run/ssh/known_hosts"}}]}
    schemas.validate(scope)
    del scope["systems"][0]["via"]["known_hosts"]
    with pytest.raises(Exception, match="known_hosts"):
        schemas.validate(scope)


def test_the_runner_packs_locally_or_over_ssh_as_the_scope_says(tmp_path, monkeypatch):
    from pqch.runner import Runner

    root = tmp_path / "host"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "x.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    monkeypatch.setenv("PQCH_SYSTEM_ROOT", str(root))
    r = Runner.__new__(Runner)
    r.system_root = str(root)
    local = r.system_archive({"name": "a", "addresses": [], "paths": ["/etc"]})
    assert "scan/root/etc/x.pem" in tarfile.open(fileobj=io.BytesIO(local)).getnames()
    ssh = fake_ssh(tmp_path, root)
    monkeypatch.setenv("PATH", f"{ssh.parent}:{os.environ['PATH']}")
    remote = r.system_archive({"name": "a", "addresses": [], "paths": ["/etc"],
                               "via": {"kind": "ssh", "host": "h", "user": "u", "known_hosts": "/k"}})
    assert tarfile.open(fileobj=io.BytesIO(remote)).getnames() == tarfile.open(fileobj=io.BytesIO(local)).getnames()
