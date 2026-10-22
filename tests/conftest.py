"""A run built from captured slice output, without Docker or a network.

The fixture records each captured raw output through the scout's own `record`
path, so the ledger, the rules and the CBOM projection under test are the ones
a live scan produces.
"""

import shutil
from pathlib import Path

import pytest

from pqch.common import sha256_hex
from pqch.run import Run
from pqch.scout import record

FIX = Path(__file__).parent / "fixtures"
SCANNER = "sha256:" + "e" * 64


def _img(name):
    return f"pqch-agency/{name}@sha256:" + sha256_hex(name.encode())


SCOPE = {
    "schema": "pqch.scope/1",
    "id": "01M40W6W873YWJMWPKGMK3YBMM",
    "estate": "colocated",
    "owned": True,
    "authorized_by": None,
    "endpoints": [
        {"host": "172.16.106.11", "port": 443, "transport": "tcp", "protocol": "tls", "sni": "api.agency.test", "image": _img("api"), "service": "api"},
        {"host": "172.16.106.21", "port": 22, "transport": "tcp", "protocol": "ssh", "image": _img("bastion"), "service": "bastion"},
        {"host": "172.16.106.10", "port": 443, "transport": "tcp", "protocol": "tls", "sni": "portal.agency.test", "image": _img("portal"), "service": "portal"},
        {"host": "172.16.106.20", "port": 22, "transport": "tcp", "protocol": "ssh", "image": _img("sftp-legacy"), "service": "sftp-legacy"},
    ],
    "images": [_img(n) for n in ("api", "bastion", "portal", "sftp-legacy")],
    "sources": [{"repo": "agency", "commit": "test"}],
    "reach": {"kind": "local"},
}

JOBS = [
    ("testssl-api.json", "tls-targeted", "testssl.sh", {"host": "172.16.106.11", "port": 443, "sni": "api.agency.test"}),
    ("testssl-portal.json", "tls-targeted", "testssl.sh", {"host": "172.16.106.10", "port": 443, "sni": "portal.agency.test"}),
    ("ssh-audit-legacy.json", "ssh-targeted", "ssh-audit", {"host": "172.16.106.20", "port": 22}),
    ("ssh-audit-bastion.json", "ssh-targeted", "ssh-audit", {"host": "172.16.106.21", "port": 22}),
    ("theia-api.json", "image-theia", "cbomkit-theia", {"image": _img("api")}),
    ("theia-portal.json", "image-theia", "cbomkit-theia", {"image": _img("portal")}),
    ("theia-legacy.json", "image-theia", "cbomkit-theia", {"image": _img("sftp-legacy")}),
    ("theia-bastion.json", "image-theia", "cbomkit-theia", {"image": _img("bastion")}),
]


IMAGE_AT = {e["host"]: e["image"] for e in SCOPE["endpoints"]}


def binding_for(target: dict, *, image: str | None = None, stable: bool = True) -> dict | None:
    """What the runner records for a wire scan: by default, the scope's own image at the address."""
    if "host" not in target:
        return None
    ref = image or IMAGE_AT[target["host"]]
    return {"address": target["host"], "container_id": "c" * 64, "container_name": "pqch-agency-x-1",
            "image": ref.split("@")[0] + ":m0", "image_digest": ref.split("@")[1], "stable": stable}


def make_run(tmp_path, bind=binding_for, jobs=None) -> Run:
    var = tmp_path / "var"
    (var / "raw").mkdir(parents=True, exist_ok=True)
    from pqch import scope as scope_mod

    run = Run.start(var, SCOPE, runner_scope_hash=scope_mod.scope_hash(SCOPE), profile="m0-targeted")
    run.commit_key(Path("eval/answer-keys/mini-agency-m0.yaml"), author="test")   # the recorded run is of the M0 slice
    for i, (fixture, profile, tool, target) in enumerate(jobs if jobs is not None else JOBS):
        data = (FIX / fixture).read_bytes()
        shutil.copy(FIX / fixture, var / "raw" / f"job{i}.json")
        record(run, {
            "job_id": f"job{i}", "profile": profile, "target": target, "tool": tool, "version": "fixture",
            "image": "scanner@" + SCANNER, "image_digest": SCANNER, "status": "ok", "exit_code": 0,
            "started_at": "2026-10-03T12:00:00.000Z", "ended_at": "2026-10-03T12:00:30.000Z",
            "duration_ms": 30000, "raw": f"var/raw/job{i}.json", "raw_sha256": sha256_hex(data),
            "stderr_tail": "", "container": {}, "binding": bind(target),
        })
    return run


@pytest.fixture
def slice_run(tmp_path) -> Run:
    return make_run(tmp_path)


@pytest.fixture
def key():
    import yaml

    return yaml.safe_load(Path("eval/answer-keys/mini-agency-m0.yaml").read_text())
