#!/usr/bin/env python
"""Build the public, static demo for GitHub Pages: the mini-agency only, read-only, no lab.

    uv run --with mkdocs-material python tools/build_public.py --var /path/to/deployment/var --out public-build

1. A curated workspace: only the mini-agency's runs (scans, the code scan, packages, imports, the
   investigator's traces, changes) and only the raw outputs those runs reference. No capture run, no
   targeted scan of the lab, and nothing else from the deployment's state is copied, so a link the
   pages miss still has nothing from the lab to reach.
2. The demo's pages rendered by the app itself in public mode (PQCH_PUBLIC=1, PQCH_DEMO_MODE=snapshot),
   their links rewritten for the Pages path; a link to something not published is disabled.
3. The site built with the shared header pointing at the same path, without the lab's tab.
4. Identities and the lab's sign-on replaced by neutral words, and every file scanned for lab
   patterns: any match fails the build and nothing is left to publish.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import warnings
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

PUBLIC_KINDS = {"scan", "scan-code", "package", "import", "investigate", "change"}
# Identities to replace in rendered pages, and patterns that must never be published, come from a
# private file (workshop/public.yaml, git-ignored), so the public tools name nothing they protect.
# Built in: only an inference engine's private-network address, as a model's call records it.
PRIVATE_URL = (re.compile(r"https?://(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){3}(?::\d+)?(?:/[\w./-]*)?"), "an internal endpoint")


def private_rules(path: Path = ROOT / "workshop" / "public.yaml") -> dict:
    import yaml

    if not path.exists():
        print(f"warning: no {path}; publishing with the built-in rules only", file=sys.stderr)
        return {"leaks": [], "page_leaks": [], "scrub": []}
    d = yaml.safe_load(path.read_text()) or {}
    return {"leaks": d.get("leaks") or [], "page_leaks": d.get("page_leaks") or [],
            "scrub": [(re.compile(a), b) for a, b in d.get("scrub") or []]}


RULES = private_rules()
SCRUB = RULES["scrub"] + [PRIVATE_URL]
LEAKS = RULES["leaks"]


def runs_to_publish(var: Path) -> list[str]:
    from pqch.run import Run
    from pqch.watch import previous

    keep = []
    for d in sorted((var / "runs").iterdir()):
        led = d / "ledger.jsonl"
        if not d.is_dir() or not led.is_file():
            continue
        try:
            kind = json.loads(led.open().readline())["payload"].get("kind", "scan")
        except (json.JSONDecodeError, KeyError):
            continue
        if kind in PUBLIC_KINDS and kind != "scan":
            keep.append(d.name)
    latest = Run.latest(var, "scan")
    keep.append(latest.id)
    prev = previous(latest)
    if prev:
        keep.append(prev.id)
    return keep


def curate(var: Path, dst: Path) -> list[str]:
    ids = runs_to_publish(var)
    (dst / "runs").mkdir(parents=True)
    (dst / "raw").mkdir()
    raws = set()
    for rid in ids:
        shutil.copytree(var / "runs" / rid, dst / "runs" / rid)
        text = (var / "runs" / rid / "ledger.jsonl").read_text()
        raws |= set(re.findall(r"var/raw/([A-Za-z0-9._-]+)", text))
    for name in raws:
        if (var / "raw" / name).is_file():
            shutil.copy2(var / "raw" / name, dst / "raw" / name)
    for kind in ("SCAN", "SCAN-CODE", "PACKAGE", "CHANGE", "INVESTIGATE"):
        src = var / "runs" / f"LATEST_{kind}"
        if src.exists() and src.read_text().strip() in ids:
            shutil.copy2(src, dst / "runs" / src.name)
    (dst / "runs" / "LATEST").write_text((dst / "runs" / "LATEST_SCAN").read_text())
    return ids


def render(work: Path, out: Path, base: str) -> dict[str, str]:
    os.environ.update(PQCH_VAR=str(work), PQCH_PUBLIC="1", PQCH_DEMO_MODE="snapshot", PQCH_SITE_DIR="/nonexistent",
                      PQCH_RUNNER_SOCKET="/nonexistent", PQCH_TRUSTED_PROXIES="")
    os.environ.pop("PQCH_SIGNER_SOCKET", None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        c = TestClient(ui.app)
    code = (work / "runs" / "LATEST_SCAN-CODE").read_text().strip() if (work / "runs" / "LATEST_SCAN-CODE").exists() else None
    scan = (work / "runs" / "LATEST_SCAN").read_text().strip()
    pages = {"/": "index.html", "/walkthrough": "walkthrough/index.html", "/cbom": "cbom/index.html",
             "/plan": "plan/index.html", "/packages": "packages/index.html", "/imports": "imports/index.html",
             "/resolve": "resolve/index.html"}
    if code:
        pages[f"/cbom?run={code}"] = "cbom/code/index.html"
    html = {}
    for url, path in pages.items():
        r = c.get(url)
        if r.status_code != 200:
            raise SystemExit(f"{url}: {r.status_code}")
        html[path] = r.text
    # The scan's own CBOM, reached from the code layer's page, is the CBOM page itself.
    pages_alias = {f"/cbom?run={scan}": "cbom/index.html", f"/walkthrough?run={scan}": "walkthrough/index.html"}
    # Each CBOM entry another page links to — a change package's entries, a plan step's — gets a page of its own.
    # Followed to closure: an entry's page links to its listener, its assets, its files.
    find = lambda t: {m.group(1) for m in re.finditer(r'href="(/cbom\?[^"]*ref=[^"#]+)', t)}  # noqa: E731
    todo, k = sorted(set().union(*(find(t) for t in html.values()))), 0
    while todo and k < 600:
        url = todo.pop(0)
        if url in pages:
            continue
        r = c.get(url.replace("&amp;", "&"))
        if r.status_code != 200:
            continue
        k += 1
        path = f"cbom/entry/{k}/index.html"
        html[path] = r.text
        pages[url] = path
        todo += sorted(u for u in find(r.text) if u not in pages and u not in todo)
    pages.update(pages_alias)
    downloads = {}
    for proj in ("agency-inventory",):
        r = c.get(f"/runs/{scan}/projection/{proj}.csv")
        if r.status_code == 200:
            downloads[f"/runs/{scan}/projection/{proj}.csv"] = r.text
    for f in ("ledger.jsonl", "workbench.cdx.json", "baseline-cbomkit.cdx.json", "baseline-scanners.cdx.json", "score.json"):
        p = work / "runs" / scan / f
        if p.exists():
            downloads[f"/runs/{scan}/{f}"] = p.read_text()
    url_to_path = {u.replace("&amp;", "&"): p.removesuffix("index.html") for u, p in pages.items()}

    def link(m: re.Match) -> str:
        attr, url = m.group(1), m.group(2)
        if not url.startswith("/") or url.startswith("//"):
            return m.group(0)
        parts = urlsplit(url)
        frag = f"#{parts.fragment}" if parts.fragment else ""
        if parts.path.startswith(("/static/", "/site/")):
            return f'{attr}="{base}{parts.path[1:]}{frag}"'
        full = (parts.path + (f"?{parts.query}" if parts.query else "")).replace("&amp;", "&")
        if full in url_to_path or full in downloads:
            target = url_to_path.get(full, full.lstrip("/"))
            return f'{attr}="{base}{target.lstrip("/")}{frag}"'
        if parts.path in url_to_path and not parts.query.startswith("run="):
            return f'{attr}="{base}{url_to_path[parts.path].lstrip("/")}{frag}"'
        return f'{attr}="#" title="in the live workbench only" data-offline="1"'

    for path, text in html.items():
        text = re.sub(r'(href|src|action)="([^"]*)"', link, text)
        for rx, word in SCRUB:
            text = rx.sub(word, text)
        dest = out / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    for url, text in downloads.items():
        dest = out / url.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)
    static = ROOT / "src" / "pqch" / "ui" / "static"
    shutil.copytree(static, out / "static")
    for js in (out / "static").glob("*.js"):
        js.write_text(js.read_text().replace('href=\\"/', f'href=\\"{base}'))
    return pages


def build_site(out: Path, base: str, tree: Path) -> None:
    """The site from the exported tree (tools/export_public.py), whose journal has already lost every
    lab passage and lab-only entry: the public site can hold nothing the public repository does not."""
    env = {**os.environ, "PQCH_DEMO_BASE": base, "PQCH_SITE_LAB": "false", "PQCH_DEMO_MODE": "snapshot"}
    subprocess.run([sys.executable, str(tree / "tools" / "build_site.py")], check=True, cwd=tree, env=env)
    subprocess.run([sys.executable, "-m", "mkdocs", "build", "--strict", "-d", str(out / "site")], check=True, cwd=tree, env=env)
    site = out / "site"
    for page in site.rglob("*.html"):
        # The site's own links into the demo ("/", "/walkthrough", …) point at the Pages path.
        text = re.sub(r'href="/(walkthrough|cbom|plan|packages|imports|resolve)?(/?)(["#?])',
                      lambda m: f'href="{base}{m.group(1) + "/" if m.group(1) else ""}{m.group(3)}', page.read_text())
        page.write_text(text)


def leak_check(out: Path) -> list[str]:
    """Every file against the leak patterns; the demo's rendered pages also against the page patterns
    (signs that lab data got into a render), which the docs may name as commands and terms."""
    everywhere = re.compile("|".join(LEAKS)) if LEAKS else None
    demo_only = re.compile("|".join(RULES["page_leaks"])) if RULES["page_leaks"] else None
    hits = []
    for p in out.rglob("*"):
        if not (p.is_file() and p.suffix in (".html", ".js", ".json", ".css", ".txt", ".xml", ".jsonl", ".md")):
            continue
        rel = p.relative_to(out)
        checks = [rx for rx in (everywhere, None if rel.parts[0] == "site" else demo_only) if rx]
        for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
            for rx in checks:
                hits += [f"{rel}:{n}: {m.group(0)}" for m in rx.finditer(line)]
    return hits


def clear(out: Path) -> None:
    """Empty the output folder in place: a running container that bind-mounts it (the lab's /preview/)
    keeps seeing it, where a deleted and recreated folder would leave the mount pointing at nothing."""
    if out.exists():
        for child in out.iterdir():
            shutil.rmtree(child) if child.is_dir() else child.unlink()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--var", required=True, type=Path, help="the deployment's state directory, read only")
    ap.add_argument("--out", default=ROOT / "public-build", type=Path)
    ap.add_argument("--base", default="/cbom-workbench/", help="the path the Pages site is served at")
    ap.add_argument("--tree", type=Path, default=ROOT.parent / "cbom-workbench-export", help="the exported public tree (tools/export_public.py)")
    args = ap.parse_args()
    out = args.out.resolve()
    clear(out)
    work = out.parent / (out.name + ".work")
    if work.exists():
        shutil.rmtree(work)
    ids = curate(args.var, work)
    out.mkdir(parents=True, exist_ok=True)
    pages = render(work, out, args.base)
    build_site(out, args.base, args.tree.resolve())
    (out / ".nojekyll").write_text("")
    shutil.rmtree(work)
    hits = leak_check(out)
    if hits:
        print("\n".join(hits[:60]))
        print(f"LEAK CHECK FAILED: {len(hits)} matches; nothing to publish", file=sys.stderr)
        clear(out)
        return 1
    print(f"{len(pages)} demo pages from {len(ids)} mini-agency runs, the site, and no lab pattern in {sum(1 for _ in out.rglob('*'))} files: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
