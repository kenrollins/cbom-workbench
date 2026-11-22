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
          schemes: tuple[str, ...] = ("light", "dark"), headers: dict | None = None) -> dict:
    from playwright.sync_api import sync_playwright

    axe = AXE.read_text()
    out = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for scheme in schemes:
            page = browser.new_page(viewport={"width": width, "height": 900}, reduced_motion="reduce", color_scheme=scheme,
                                    extra_http_headers=headers or {})
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


def keyboard(base: str, paths: list[str], *, width: int = 1440, limit: int = 400, headers: dict | None = None) -> dict:
    """A keyboard-only pass, automated: press Tab until focus returns to the page's start, and report how
    many of the page's focusable controls were reached, and which took focus with no visible indicator
    (no outline and no box shadow). A person with a screen reader is a different test; this is not it."""
    from playwright.sync_api import sync_playwright

    # The controls a keyboard should reach: focusable, shown, and not inside a closed <details> (those
    # become reachable when their summary is opened, which is itself in the list).
    list_js = """() => { window.__tab = [...document.querySelectorAll('a[href],button,input,select,textarea,summary,[tabindex]')]
        .filter(e => { if (e.disabled || e.tabIndex < 0 || e.offsetParent === null) return false;
          for (let n = e.parentElement; n; n = n.parentElement) {
            if (getComputedStyle(n).visibility === 'hidden' || n.inert) return false;
            if (n.tagName === 'DETAILS' && !n.open) { const s = n.querySelector(':scope > summary'); if (!(s && s.contains(e))) return false; } }
          return true; });
        return {n: window.__tab.length, autofocus: window.__tab.indexOf(document.activeElement)}; }"""
    focus_js = """() => { const e = document.activeElement; if (!e || e === document.body) return null;
        const c = getComputedStyle(e);
        const sel = e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (e.className && typeof e.className === 'string' ? '.' + e.className.trim().split(/\\s+/).join('.') : '');
        return {i: window.__tab.indexOf(e), sel, visible: (c.outlineStyle !== 'none' && parseFloat(c.outlineWidth) > 0) || c.boxShadow !== 'none'}; }"""
    out = {}
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": width, "height": 900}, reduced_motion="reduce", extra_http_headers=headers or {})
        for path in paths:
            page.goto(base.rstrip("/") + path, wait_until="networkidle")
            page.wait_for_timeout(400)
            listed = page.evaluate(list_js)
            focusable = listed["n"]
            reached, unmarked, outside = set(), [], 0
            if listed["autofocus"] >= 0:
                reached.add(listed["autofocus"])        # the page puts focus on a control when it loads
            # Tab wraps through the browser's own chrome back to the top, so a page that starts with
            # focus part-way down is still walked in full.
            for _ in range(min(limit, 2 * focusable + 10)):
                if len(reached) >= focusable:
                    break
                page.keyboard.press("Tab")
                f = page.evaluate(focus_js)
                if f is None:
                    continue
                if f["i"] < 0:
                    outside += 1
                    continue
                reached.add(f["i"])
                if not f["visible"]:
                    unmarked.append(f["sel"])
            out[path] = {"focusable": focusable, "reached": len(reached), "focus_on_load": listed["autofocus"] >= 0,
                         "focused_outside_the_list": outside, "no_visible_focus": sorted(set(unmarked))[:12],
                         "no_visible_focus_count": len(unmarked)}
        browser.close()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--base", required=True)
    ap.add_argument("--width", type=int, default=1440)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--header", action="append", default=[], metavar="NAME=VALUE",
                    help="a request header, such as the front door's identity header, to see signed-on pages")
    ap.add_argument("--keyboard", action="store_true", help="the Tab-order pass instead of the axe rules")
    a = ap.parse_args(argv)
    headers = dict(h.split("=", 1) for h in a.header)
    if a.keyboard:
        res = keyboard(a.base, a.paths, width=a.width, headers=headers)
        print(json.dumps(res, indent=1))
        return 1 if any(r["no_visible_focus_count"] or r["reached"] < r["focusable"] for r in res.values()) else 0
    res = check(a.base, a.paths, width=a.width, headers=headers)
    print(json.dumps(res, indent=1))
    bad = [(p, v["id"]) for p, r in res.items() for v in r["violations"] if v["impact"] in BLOCKING]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
