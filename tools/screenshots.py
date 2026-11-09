#!/usr/bin/env python
"""Screenshots of the running workbench's pages, for the field notes' "page by page" (ADR-0006).

    python3 tools/screenshots.py --var /path/to/deployment/var [--out docs/journal/img/pages] [--width 1440]

Run with a Python that has Playwright (on the authoring host, the system python3). The pages are served
by the app itself from a curated workspace holding only the mini-agency's runs (tools/build_public.py's
curate), in the live mode a reader of the lab would see, so a screenshot shows the working page and
nothing from the lab. Each page is captured once at the given width, the viewport's height, in the dark scheme the workbench shows by default.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

# The pages the public copy does not render, each with the file it becomes and its height in CSS pixels.
PAGES = {"/": ("overview", 1180), "/agency": ("test-agency", 1100), "/walkthrough": ("walkthrough", 1200),
         "/plan": ("plan", 1300), "/packages": ("packages", 1000), "/imports": ("imports", 1000),
         "/resolve": ("resolve", 1100)}


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def capture(var: Path, out: Path, width: int, python: str) -> list[Path]:
    from playwright.sync_api import sync_playwright

    from build_public import curate

    work = Path(tempfile.mkdtemp(prefix="pqch-shots-"))
    try:
        curate(var, work)
        port = _free_port()
        env = {k: v for k, v in os.environ.items() if not k.startswith("PQCH_")}
        env.update(PQCH_VAR=str(work), PQCH_TRUSTED_PROXIES="", PQCH_SITE_DIR="/nonexistent", PQCH_RUNNER_SOCKET="/nonexistent",
                   PQCH_HARDWARE="the lab's x86_64 server")
        app = subprocess.Popen([python, "-m", "uvicorn", "pqch.ui.app:app", "--port", str(port), "--log-level", "warning"],
                               cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(200):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.1)
            out.mkdir(parents=True, exist_ok=True)
            written = []
            with sync_playwright() as p:
                browser = p.chromium.launch()
                for path, (name, height) in PAGES.items():
                    page = browser.new_page(viewport={"width": width, "height": height}, reduced_motion="reduce",
                                            color_scheme="dark", device_scale_factor=1)
                    r = page.goto(f"http://127.0.0.1:{port}{path}", wait_until="networkidle")
                    if r is None or r.status != 200:
                        raise SystemExit(f"{path}: {r and r.status}")
                    page.wait_for_timeout(800)
                    dest = out / f"{name}.png"
                    page.screenshot(path=str(dest), full_page=False)
                    page.close()
                    written.append(dest)
                browser.close()
            return written
        finally:
            app.terminate()
            app.wait(10)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--var", required=True, type=Path)
    ap.add_argument("--out", type=Path, default=ROOT / "docs" / "journal" / "img" / "pages")
    ap.add_argument("--width", type=int, default=1440)
    ap.add_argument("--python", default=str(ROOT / ".venv" / "bin" / "python"), help="the project's Python, which serves the app")
    a = ap.parse_args()
    for p in capture(a.var, a.out, a.width, a.python):
        print(f"{p} {p.stat().st_size:,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
