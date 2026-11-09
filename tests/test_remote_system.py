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
    """An `ssh` that runs the remote command locally: the test's stand-in for a host that answers."""
    exe = tmp_path / "bin" / "ssh"
    exe.parent.mkdir(parents=True, exist_ok=True)
    exe.write_text(f"""#!/usr/bin/env python3
import os, subprocess, sys
args = sys.argv[1:]
log = open({str(tmp_path / 'ssh.log')!r}, 'a'); log.write(' '.join(args) + '\\n'); log.close()
# options come in pairs; the first bare argument is user@host, then the remote command
i = 0
while i < len(args) and args[i].startswith('-'):
    i += 2
cmd = args[i + 1:]
env = dict(os.environ, PQCH_REMOTE_ROOT={str(remote_root)!r})
sys.exit(subprocess.run(cmd, stdin=sys.stdin, env=env).returncode)
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
    assert "-i /run/ssh/id" in line and "IdentitiesOnly=yes" in line and "-p 2222" in line and "scan@srv9.example python3 -" in line


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
