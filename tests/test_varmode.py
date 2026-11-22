"""M8, FR-08 (part): what the workbench keeps under var/ is 0600 and 0700 when the deployment asks."""

import json
import stat

from pqch import varmode
from pqch.cli import main


def mode(p):
    return stat.S_IMODE(p.stat().st_mode)


def test_with_the_setting_a_new_ledger_its_directories_and_latest_are_private(slice_run, tmp_path, monkeypatch):
    from .conftest import make_run

    monkeypatch.setenv("PQCH_VAR_PRIVATE", "1")
    run = make_run(tmp_path / "private")
    assert mode(run.ledger.path) == 0o600
    assert mode(run.dir) == 0o700 and mode(run.dir.parent) == 0o700
    assert mode(run.var / "runs" / "LATEST") == 0o600


def test_without_it_modes_are_as_before(tmp_path, monkeypatch):
    from .conftest import make_run

    monkeypatch.delenv("PQCH_VAR_PRIVATE", raising=False)
    import os
    um = os.umask(0)
    os.umask(um)
    run = make_run(tmp_path / "plain")
    assert mode(run.ledger.path) == 0o666 & ~um        # the umask's choice, as before


def test_harden_brings_what_was_written_before_into_line(tmp_path, capsys):
    (tmp_path / "var" / "runs" / "R").mkdir(parents=True)
    f = tmp_path / "var" / "runs" / "R" / "ledger.jsonl"
    f.write_text("{}\n")
    f.chmod(0o644)
    (tmp_path / "var").chmod(0o755)
    (tmp_path / "var" / "link").symlink_to("/etc/hostname")
    assert main(["var", "harden", "--var", str(tmp_path / "var")]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["files"] == 1 and out["dirs"] >= 1
    assert mode(f) == 0o600 and mode(tmp_path / "var") == 0o700
    assert varmode.harden(tmp_path / "var") == {"dirs": 0, "files": 0}


def test_the_runner_writes_raw_output_private_when_asked(tmp_path, monkeypatch):
    monkeypatch.setenv("PQCH_VAR_PRIVATE", "1")
    d = varmode.mkdir(tmp_path / "a" / "b")
    assert mode(tmp_path / "a") == 0o700 and mode(d) == 0o700
