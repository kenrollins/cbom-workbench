"""Modes for what the workbench keeps under `var/`: files 0600 and directories 0700 (FR-08, part).

A CBOM is a map of an estate's weakest cryptography; ledgers, raw scanner output, captures, imports
and recordings say the same in more detail. None of it should be readable by every user on the host.

Opt-in with `PQCH_VAR_PRIVATE=1`, on every service that writes under `var/`. It is not the default
because one deployment reads across users: the kit's system runner writes raw output as root and the
app reads it as the operator's uid, which 0600 would stop. With every writer and reader under one uid,
turn it on, and run `pqch var harden` once to bring files written before into line.

A process-wide umask is not used: the runner also renders the estate's configuration, which the
estate's own services (another uid) must read.
"""

from __future__ import annotations

import os
from pathlib import Path

ENV = "PQCH_VAR_PRIVATE"
FILE, DIR = 0o600, 0o700


def enabled() -> bool:
    return os.environ.get(ENV) == "1"


def private(path: str | Path) -> None:
    """0600 for a file, 0700 for a directory, when enabled. A path that is gone is left alone."""
    if not enabled():
        return
    p = Path(path)
    try:
        p.chmod(DIR if p.is_dir() else FILE)
    except FileNotFoundError:
        pass


def mkdir(path: str | Path) -> Path:
    """`mkdir -p`, with every directory it creates 0700 when enabled."""
    p = Path(path)
    missing = []
    q = p
    while not q.exists():
        missing.append(q)
        q = q.parent
    p.mkdir(parents=True, exist_ok=True)
    for d in missing:
        private(d)
    return p


def harden(root: str | Path) -> dict:
    """Every directory under `root` 0700 and every file 0600, whatever `enabled()` says. Symlinks are
    not followed. Returns what was changed."""
    root = Path(root)
    out = {"dirs": 0, "files": 0}
    for dirpath, _dirs, filenames in os.walk(root, followlinks=False):
        d = Path(dirpath)
        if d.stat().st_mode & 0o777 != DIR:
            d.chmod(DIR)
            out["dirs"] += 1
        for name in filenames:
            f = d / name
            if f.is_symlink():
                continue
            if f.stat().st_mode & 0o777 != FILE:
                f.chmod(FILE)
                out["files"] += 1
    return out
