#!/usr/bin/env python
"""Build the public, static copy for GitHub Pages: a recording, a record and notes (ADR-0006).

    uv run --with mkdocs-material python tools/build_public.py --var /path/to/deployment/var --out public-build

1. A curated workspace: only the mini-agency's runs (scans, packages, imports, the investigator's
   traces, changes — each kept only when its scope is of the same estate as a scan that goes out and
   is not a copy of one), the code scan of a named public repository, and only the raw outputs those
   runs reference. No capture run, no targeted scan of the lab, no scan or import of a copy on
   another network, and nothing else from the deployment's state is copied, so a link the pages miss
   still has nothing from the lab to reach.
2. Four of the app's pages rendered by the app itself in public mode (PQCH_PUBLIC=1,
   PQCH_DEMO_MODE=snapshot): the stage (at the root), the CBOM viewer with the entries it and the
   stage link to, the recorded Ask answers, and About (PUBLIC_PAGES). Their links are rewritten for
   the Pages path; a link to anything else is disabled. No other page of the running workbench is
   rendered: the field notes show them as screenshots (site_src/pages.md, tools/screenshots.py).
3. The record: the recorded run's documents with their hashes, written as a page of the site.
4. The site built with the shared header pointing at the same path, without the lab's tabs.
5. Identities and the lab's sign-on replaced by neutral words, and every text file and every path
   scanned for lab patterns, whatever its suffix: any match fails the build and nothing is left to
   publish. The patterns are private (workshop/public.yaml, or the file PQCH_PUBLIC_RULES names);
   without them the build still runs, for someone building their own copy, and says that nothing
   was checked.
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
# The app's pages the public copy renders, and the file each becomes: the stage is the root (ADR-0006).
PUBLIC_PAGES = {"/demo": "index.html", "/cbom": "cbom/index.html", "/about": "about/index.html"}
# A code scan's scope is "external" with no listeners, so it cannot be recognised by its estate: it goes
# out only when every source it names is one of these public repositories, at a pinned commit.
PUBLIC_CODE_REPOS = {"18F/identity-idp"}
RECORD_FILES = ("ledger.jsonl", "workbench.cdx.json", "baseline-cbomkit.cdx.json", "baseline-scanners.cdx.json", "score.json")
# Identities to replace in rendered pages, and patterns that must never be published, come from a
# private file (workshop/public.yaml, git-ignored), so the public tools name nothing they protect.
# Built in: only an inference engine's private-network address, as a model's call records it.
PRIVATE_URL = (re.compile(r"https?://(?:10|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){3}(?::\d+)?(?:/[\w./-]*)?"), "an internal endpoint")


def rules_path() -> Path:
    """The private rules: workshop/public.yaml beside this tree, or the file PQCH_PUBLIC_RULES names
    (a git worktree or a second clone has no workshop/, which is git-ignored)."""
    return Path(os.environ.get("PQCH_PUBLIC_RULES") or ROOT / "workshop" / "public.yaml")


def private_rules(path: Path | None = None) -> dict:
    import yaml

    path = path or rules_path()
    if not path.exists():
        print(f"warning: no {path}: no leak patterns loaded, so nothing is checked against the lab's names and addresses",
              file=sys.stderr)
        return {"leaks": [], "page_leaks": [], "scrub": [], "exclude": [], "author": {}, "path": path, "found": False}
    d = yaml.safe_load(path.read_text()) or {}
    if not isinstance(d, dict):
        raise SystemExit(f"{path}: not a mapping of rules")
    if not d.get("leaks"):
        print(f"warning: {path} has no `leaks`: no leak patterns loaded, so nothing is checked against the lab's names and addresses",
              file=sys.stderr)
    return {"leaks": d.get("leaks") or [], "page_leaks": d.get("page_leaks") or [],
            "scrub": [(re.compile(a), b) for a, b in d.get("scrub") or []],
            "exclude": d.get("exclude") or [], "author": d.get("author") or {}, "path": path, "found": True}


def leak_regex(patterns) -> re.Pattern | None:
    """One expression for a list of leak patterns, or None when there is none. Matched without regard
    to case: a name written in lower case in a path, a comment or a repository name is the same name."""
    patterns = [p for p in patterns or [] if p]
    return re.compile("|".join(f"(?:{p})" for p in patterns), re.I) if patterns else None


def checked(patterns=None) -> str:
    """What a tool may say about its leak check: never "no lab pattern found" when none was loaded."""
    patterns = LEAKS if patterns is None else patterns
    return (f"no match for the {len(patterns)} leak patterns" if patterns
            else "NO LEAK PATTERNS LOADED: NOTHING WAS CHECKED against the lab's names and addresses")


RULES = private_rules()
SCRUB = RULES["scrub"] + [PRIVATE_URL]
LEAKS = RULES["leaks"]


def _listeners(scope: dict) -> set:
    return {(ep.get("host"), ep.get("port")) for ep in scope.get("endpoints") or []}


def _of_estate(scope: dict, published: list[dict]) -> bool:
    """Is this scope of an estate a published scan is of: the same kind of estate, and every listener it
    names one that scan's scope names. (pqch.watch's estate key is the kind and the listeners; a subset
    is allowed so the estate's earlier, smaller form — the four-service slice — stays with it.)"""
    mine = _listeners(scope)
    return bool(mine) and any(scope.get("estate") == s.get("estate") and mine <= _listeners(s) for s in published)


def _public_code_scan(scope: dict) -> bool:
    sources = scope.get("sources") or []
    return (bool(sources) and not scope.get("endpoints")
            and all(s.get("repo") in PUBLIC_CODE_REPOS and s.get("commit") for s in sources))


def runs_to_publish(var: Path) -> list[str]:
    from pqch.run import Run
    from pqch.watch import previous

    def started(rid: str) -> dict | None:
        """A run's first event's payload: its kind and the scope it was authorized under."""
        led = var / "runs" / rid / "ledger.jsonl"
        if not led.is_file():
            return None
        try:
            payload = json.loads(led.open().readline())["payload"]
        except (json.JSONDecodeError, KeyError, TypeError):
            return None
        return payload if isinstance(payload, dict) and isinstance(payload.get("scope"), dict) else None

    # The scans that go out: the latest and the one before it, and the two the overview's story of one
    # change reads (the scan that found the weakness and the one that shows it gone).
    latest = Run.latest(var, "scan")
    scans = [latest.id]
    prev = previous(latest)
    if prev:
        scans.append(prev.id)
    from pqch.ui.agility import _change_story
    story = _change_story(var)
    for rid in (story or {}).get("before"), (story or {}).get("after"):
        if rid and rid not in scans:
            scans.append(rid)
    for rid in scans:
        first = started(rid)
        if first is None or first.get("kind", "scan") != "scan" or first["scope"].get("copy") or first["scope"].get("captures"):
            raise SystemExit(f"run {rid} would be published as a scan of the mini-agency, but its ledger does not start as one")
    published = [started(rid)["scope"] for rid in scans]
    # Every other run goes out only when it is of an estate one of those scans is of — the same kind,
    # and no listener those scans' scopes do not name — and is not a copy of it: a scan or an import
    # under a copy's scope carries another network's addresses, whatever its kind says. A code scan has
    # no listeners to compare, so it is allowed by the repository it names.
    keep = []
    for d in sorted(p for p in (var / "runs").iterdir() if p.is_dir()):
        first = started(d.name)
        if first is None:
            continue
        kind, scope = first.get("kind", "scan"), first["scope"]
        if kind not in PUBLIC_KINDS or kind == "scan" or scope.get("copy") or scope.get("captures"):
            continue
        if _public_code_scan(scope) if kind == "scan-code" else _of_estate(scope, published):
            keep.append(d.name)
    return keep + scans


def curate(var: Path, dst: Path) -> list[str]:
    ids = runs_to_publish(var)
    (dst / "runs").mkdir(parents=True)
    (dst / "raw").mkdir()
    raws = set()
    for rid in ids:
        shutil.copytree(var / "runs" / rid, dst / "runs" / rid)
        text = (var / "runs" / rid / "ledger.jsonl").read_text()
        raws |= set(re.findall(r"var/raw/([A-Za-z0-9._-]+)", text))
    for rid in ids:  # recorded model output for the runs that go out: Ask's answers, the stage's narration
        for kind in ("ask", "demo"):
            rec = var / kind / f"{rid}.json"
            if rec.is_file():
                (dst / kind).mkdir(exist_ok=True)
                shutil.copy2(rec, dst / kind / rec.name)
    for name in raws:
        if (var / "raw" / name).is_file():
            shutil.copy2(var / "raw" / name, dst / "raw" / name)
    for kind in ("SCAN", "SCAN-CODE", "PACKAGE", "CHANGE", "INVESTIGATE"):
        src = var / "runs" / f"LATEST_{kind}"
        if src.exists() and src.read_text().strip() in ids:
            shutil.copy2(src, dst / "runs" / src.name)
    (dst / "runs" / "LATEST").write_text((dst / "runs" / "LATEST_SCAN").read_text())
    return ids


def journal_span(tree: Path) -> str:
    """The first and latest entry's dates in the exported journal, for the demo pages' header (the site's
    own header gets them from tools/build_site.py, which runs after the pages are rendered)."""
    dates = []
    for p in sorted((tree / "docs" / "journal").glob("*/[0-9][0-9]-*.md")):
        m = re.search(r"^date:\s*(\d{4}-\d{2}-\d{2})", p.read_text(encoding="utf-8")[:2000], re.M)
        if m:
            dates.append(m.group(1))
    dates.sort()
    return "" if not dates else (dates[0] if dates[0] == dates[-1] else f"{dates[0]} \u2192 {dates[-1]}")


def render(work: Path, out: Path, base: str, span: str = "") -> dict[str, str]:
    os.environ.update(PQCH_VAR=str(work), PQCH_PUBLIC="1", PQCH_DEMO_MODE="snapshot", PQCH_SITE_DIR="/nonexistent",
                      PQCH_RUNNER_SOCKET="/nonexistent", PQCH_TRUSTED_PROXIES="", PQCH_JOURNAL_SPAN=span)
    os.environ.pop("PQCH_SIGNER_SOCKET", None)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        c = TestClient(ui.app)
    scan = (work / "runs" / "LATEST_SCAN").read_text().strip()
    # The copy has no model to call, so what a model said is shown from recordings made for this scan. A new
    # scan has none until they are recorded; without this check the stage publishes "no answer was recorded".
    missing = [cmd for kind, cmd in (("ask", "pqch ask record"), ("demo", "pqch demo record")) if not (work / kind / f"{scan}.json").is_file()]
    if missing and not os.environ.get("PQCH_PUBLIC_WITHOUT_RECORDINGS"):
        raise SystemExit(f"the scan this copy shows ({scan}) has no recorded model output: run {' and '.join(missing)} in the deployment first, "
                         "or set PQCH_PUBLIC_WITHOUT_RECORDINGS=1 to publish the stage without them")
    pages = dict(PUBLIC_PAGES)
    html = {}
    for url, path in pages.items():
        r = c.get(url)
        if r.status_code != 200:
            raise SystemExit(f"{url}: {r.status_code}")
        html[path] = r.text
    # The stage is the root; the old /demo/ path keeps working for links already in the world.
    html["demo/index.html"] = html["index.html"]
    # Ask the CBOM: the page, and one page per example question whose answer was recorded (pqch ask record).
    if (work / "ask" / f"{scan}.json").is_file():
        r = c.get("/ask")
        html["ask/index.html"], pages["/ask"] = r.text, "ask/index.html"
        for i, url in enumerate(dict.fromkeys(m.group(1).replace("&amp;", "&")
                                              for m in re.finditer(r'href="(/ask\?[^"]*q=[^"]+)"', r.text)), 1):
            r = c.get(url)
            if r.status_code == 200:
                html[f"ask/{i}/index.html"], pages[url] = r.text, f"ask/{i}/index.html"
    # The scan's own CBOM is the CBOM page itself; the brand and the old root both lead to the stage.
    pages_alias = {f"/cbom?run={scan}": "cbom/index.html", "/": "index.html"}
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
    for f in RECORD_FILES:
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
        text = text.replace('window.__BASE = "/";', f'window.__BASE = "{base}";')
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


def record_page(work: Path, out: Path, base: str, tree: Path) -> Path:
    """The record (ADR-0006): the recorded run's documents, each with its size and SHA-256, the run's id,
    hardware and date, and its score against the answer key, written as a page of the site so what the
    stage shows can be checked against what the run produced."""
    import hashlib
    scan = (work / "runs" / "LATEST_SCAN").read_text().strip()
    run_dir = work / "runs" / scan
    first = json.loads(run_dir.joinpath("ledger.jsonl").open().readline())
    score = json.loads((run_dir / "score.json").read_text())
    wb = score["columns"]["workbench"]
    w, h = wb["layers"]["wire"], wb["layers"]["host"]
    hardware = score.get("labels", {}).get("hardware", "unlabelled")
    rows = []
    for f in [*RECORD_FILES, "projection/agency-inventory.csv"]:
        p = run_dir / f if not f.startswith("projection/") else None
        if p is not None and p.exists():
            data = p.read_bytes()
        elif p is None and (out / "runs" / scan / f).exists():
            data = (out / "runs" / scan / f).read_bytes()
        else:
            continue
        what = {"ledger.jsonl": "the ledger: every event of the run, hash-chained, with its signed checkpoint",
                "workbench.cdx.json": "the CBOM the workbench projects from the ledger (CycloneDX 1.6)",
                "baseline-cbomkit.cdx.json": "the baseline: CBOMkit alone, on the same estate",
                "baseline-scanners.cdx.json": "the baseline: the open-source scanners alone, merged with no harness",
                "score.json": "the score against the answer key, by layer, with the decoys",
                "projection/agency-inventory.csv": "an agency inventory projected from the same ledger"}[f]
        rows.append(f"| [`{f}`]({base}runs/{scan}/{f}) | {what} | {len(data):,} | `{hashlib.sha256(data).hexdigest()}` |")
    text = f"""---
title: The record
---

# The record

<!-- generated by tools/build_public.py from the recorded run; do not edit by hand -->

What the stage shows is a recording of one run; this page is what that run produced, so the one
can be checked against the other. Run `{scan}`, started {first["ts"][:19].replace("T", " ")} UTC
on {hardware}; every event on the ledger is chained to the one before it and the chain is signed
([how the record is kept](notes/12-what-an-auditable-record-contains.md)).

Against the answer key, by layer: on the wire {w["covered"]} of {w["present"]} keyed items present were found
({w["out_of_reach"]} out of reach, {w["false_positives"]} false positives); in the images {h["covered"]} of {h["present"]}
({h["false_positives"]} false positives); the posture of {wb["posture"]["correct"]} of {wb["posture"]["total"]} listeners correct.
The baselines beside it are in `score.json`.

| Document | What it is | Bytes | SHA-256 |
|---|---|---|---|
{chr(10).join(rows)}

To check a document: download it, take its SHA-256, and compare. To check the ledger's chain and its
checkpoint, the verifier is in the repository (`pqch ledger verify --signed --pub ledger.pub ledger.jsonl`,
with the public key the stage's run carries beside its ledger). The CBOM is a projection: rebuilding
it from the ledger gives the same document, byte for byte.
"""
    dest = tree / "site_src" / "record.md"
    dest.write_text(text)
    return dest


def build_site(out: Path, base: str, tree: Path) -> None:
    """The site from the exported tree (tools/export_public.py), whose journal has already lost every
    lab passage and lab-only entry: the public site can hold nothing the public repository does not."""
    env = {**os.environ, "PQCH_DEMO_BASE": base, "PQCH_SITE_LAB": "false", "PQCH_DEMO_MODE": "snapshot"}
    subprocess.run([sys.executable, str(tree / "tools" / "build_site.py")], check=True, cwd=tree, env=env)
    subprocess.run([sys.executable, "-m", "mkdocs", "build", "--strict", "-d", str(out / "site")], check=True, cwd=tree, env=env)
    site = out / "site"
    for page in site.rglob("*.html"):
        # The site's own links into the demo ("/", "/walkthrough", …) point at the Pages path.
        text = re.sub(r'href="/(cbom|ask|about|demo)?(/?)(["#?])',
                      lambda m: f'href="{base}{m.group(1) + "/" if m.group(1) else ""}{m.group(3)}', page.read_text())
        page.write_text(text)


def leak_check(out: Path, *, leaks=None, page_leaks=None, scrub=None) -> list[str]:
    """Every file that reads as text, whatever its suffix, and every path, against the leak patterns;
    the demo's rendered pages also against the page patterns (signs that lab data got into a render),
    which the docs may name as commands and terms. The run's documents and downloads under runs/ are
    published byte for byte with their hashes on the record page, so they are not scrubbed: a scrub
    pattern found in one fails the build instead."""
    everywhere = leak_regex(LEAKS if leaks is None else leaks)
    page_leaks = RULES["page_leaks"] if page_leaks is None else page_leaks
    demo_only = re.compile("|".join(page_leaks)) if page_leaks else None
    unscrubbed = [rx for rx, _ in (SCRUB if scrub is None else scrub)]
    hits = []
    for p in sorted(out.rglob("*")):
        rel = p.relative_to(out)
        if everywhere:
            hits += [f"{rel}: path: {m.group(0)}" for m in everywhere.finditer(p.name)]
        if not p.is_file():
            continue
        try:
            text = p.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue    # an image or a font: nothing here reads pixels
        checks = [rx for rx in (everywhere, None if rel.parts[0] == "site" else demo_only) if rx]
        if rel.parts[0] == "runs":
            checks += unscrubbed
        for n, line in enumerate(text.splitlines(), 1):
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
    pages = render(work, out, args.base, span=journal_span(args.tree.resolve()))
    record_page(work, out, args.base, args.tree.resolve())
    build_site(out, args.base, args.tree.resolve())
    (out / ".nojekyll").write_text("")
    shutil.rmtree(work)
    hits = leak_check(out)
    if hits:
        print("\n".join(hits[:60]))
        print(f"LEAK CHECK FAILED: {len(hits)} matches; nothing to publish", file=sys.stderr)
        clear(out)
        return 1
    print(f"{len(pages)} pages (the stage, the CBOM viewer and its entries, the recorded answers, About) from {len(ids)} curated runs "
          f"(the mini-agency's, and the code scan), the record, the site; {sum(1 for _ in out.rglob('*'))} files, {checked()}: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
