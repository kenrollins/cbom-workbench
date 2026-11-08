"""M8, FR-09 (part): every page of the workbench passes axe-core's WCAG 2.1 A and AA rules with no
serious or critical violation, in the light and the dark scheme.

axe runs in headless Chromium through Playwright, which this project does not depend on: the test
runs `tools/a11y_check.py` under the first Python found with Playwright (PQCH_PLAYWRIGHT_PYTHON, else
the system python3) and is skipped where there is none.
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

import pytest

PAGES = ["/", "/about", "/agency", "/plan", "/imports", "/packages", "/resolve", "/walkthrough", "/cbom",
         "/ask", "/demo", "/notes/ask"]


def _playwright_python() -> str | None:
    # python3 on PATH outside this environment (the system's, or pyenv's)
    outside = os.pathsep.join(d for d in os.environ.get("PATH", "").split(os.pathsep)
                              if d and not d.startswith(sys.prefix))
    for exe in (os.environ.get("PQCH_PLAYWRIGHT_PYTHON"), shutil.which("python3", path=outside)):
        if exe and subprocess.run([exe, "-c", "import playwright.sync_api"], capture_output=True).returncode == 0:
            return exe
    return None


PW = _playwright_python()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.mark.skipif(PW is None, reason="no Python with Playwright on this host")
def test_every_page_has_no_serious_accessibility_violation(slice_run):
    from pqch.assessor import chains, load_policy, managed, structure
    from pqch.pipeline import write_cboms, write_score

    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(slice_run)
    chains.supply(slice_run, "agency/context.yaml", author="owner")
    managed.assess(slice_run, pack_path="policy/packs/m-26-15.yaml", families_path="policy/algorithm-families.yaml",
                   capabilities_path=sorted(Path("policy/snapshots").glob("capabilities-*.json"))[-1],
                   cmvp_path=sorted(Path("policy/snapshots").glob("cmvp-*.json"))[-1], as_of=date(2026, 10, 20))
    slice_run.close()
    write_cboms(slice_run)
    write_score(slice_run, Path("eval/answer-keys/mini-agency-m0.yaml"))
    port = _free_port()
    env = {**os.environ, "PQCH_VAR": str(slice_run.var)}
    app = subprocess.Popen([sys.executable, "-m", "uvicorn", "pqch.ui.app:app", "--port", str(port), "--log-level", "warning"],
                           env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.1)
        r = subprocess.run([PW, "tools/a11y_check.py", "--base", f"http://127.0.0.1:{port}", *PAGES],
                           capture_output=True, text=True, timeout=600)
    finally:
        app.terminate()
        app.wait(10)
    res = json.loads(r.stdout)
    assert all(v["status"] == 200 for v in res.values()), {p: v["status"] for p, v in res.items()}
    bad = {p: [(v["id"], v["count"], v["detail"][:1]) for v in x["violations"] if v["impact"] in ("serious", "critical")]
           for p, x in res.items()}
    assert not any(bad.values()), {p: v for p, v in bad.items() if v}
