"""Run axe-core over pages of a running workbench, in headless Chromium, and report WCAG 2.1 A and AA
violations (FR-09). Exit 1 when any violation's impact is serious or critical.

Run with a Python that has Playwright (on the authoring host, the system python3):

    python3 tools/a11y_check.py --base http://127.0.0.1:8089 / /walkthrough /cbom /demo

The axe build is the vendored test asset (tests/vendor/axe-core/axe.min.js); nothing is fetched.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

AXE = Path(__file__).resolve().parents[1] / "tests" / "vendor" / "axe-core" / "axe.min.js"
TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]
BLOCKING = {"serious", "critical"}


def check(base: str, paths: list[str], *, width: int = 1440, wait_ms: int = 600,
          schemes: tuple[str, ...] = ("light", "dark")) -> dict:
    from playwright.sync_api import sync_playwright

    axe = AXE.read_text()
    out = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for scheme in schemes:
            page = browser.new_page(viewport={"width": width, "height": 900}, reduced_motion="reduce", color_scheme=scheme)
            for path in paths:
                resp = page.goto(base.rstrip("/") + path, wait_until="networkidle")
                page.wait_for_timeout(wait_ms)
                page.add_script_tag(content=axe)
                res = page.evaluate("tags => axe.run(document, {runOnly: {type: 'tag', values: tags}})", TAGS)
                out[f"{path} ({scheme})"] = {
                    "status": resp.status if resp else None,
                    "violations": [{"id": v["id"], "impact": v["impact"], "help": v["help"],
                                    "nodes": [n["target"] for n in v["nodes"]][:8], "count": len(v["nodes"]),
                                    "detail": [((n["any"] or n["all"] or n["none"] or [{}])[0].get("message") or "")[:200]
                                               for n in v["nodes"][:3]]}
                                   for v in res["violations"]]}
            page.close()
        browser.close()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True)
    ap.add_argument("--width", type=int, default=1440)
    ap.add_argument("paths", nargs="+")
    a = ap.parse_args(argv)
    res = check(a.base, a.paths, width=a.width)
    print(json.dumps(res, indent=1))
    bad = [(p, v["id"]) for p, r in res.items() for v in r["violations"] if v["impact"] in BLOCKING]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
