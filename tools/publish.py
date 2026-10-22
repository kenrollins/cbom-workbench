#!/usr/bin/env python
"""Publish: the public repository and the public demo, from the committed working tree, in one step.

    uv run --with mkdocs-material python tools/publish.py --var /path/to/deployment/var -m "what changed"

1. Export the committed tree (tools/export_public.py) into the public repository's working copy,
   with the lab left out and the tree leak-checked; any match and nothing more happens.
2. Build the static demo and site for GitHub Pages from that tree (tools/build_public.py), leak-checked.
3. Commit the tree to the public repository's main branch and push it.
4. Push the built site as the single commit of the gh-pages branch (it is generated: no history kept).

Work happens in this repository; the public repository's working copy is a cache this command owns.
Commits are authored with the GitHub noreply address in workshop/public.yaml (`author`), when set.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def sh(*args, cwd=None, check=True, capture=False):
    r = subprocess.run(list(args), cwd=cwd, check=check, text=True, capture_output=capture)
    return r.stdout.strip() if capture else r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--var", required=True, type=Path)
    ap.add_argument("--repo", default="kenrollins/cbom-workbench")
    ap.add_argument("--tree", type=Path, default=ROOT.parent / "cbom-workbench-export")
    ap.add_argument("--base", default="/cbom-workbench/")
    ap.add_argument("-m", "--message", default="Publish")
    ap.add_argument("--no-push", action="store_true")
    args = ap.parse_args()
    if sh("git", "status", "--porcelain", "--untracked-files=no", cwd=ROOT, capture=True):
        raise SystemExit("commit your changes first: only what is committed is published")
    priv = yaml.safe_load((ROOT / "workshop" / "public.yaml").read_text()) if (ROOT / "workshop" / "public.yaml").exists() else {}
    author = priv.get("author") or {}
    url = f"https://github.com/{args.repo}.git"
    tree = args.tree.resolve()
    if not (tree / ".git").exists():
        tree.mkdir(parents=True, exist_ok=True)
        sh("git", "init", "-q", "-b", "main", cwd=tree)
        sh("git", "remote", "add", "origin", url, cwd=tree)
        if sh("git", "ls-remote", "--heads", url, "main", cwd=tree, capture=True, check=False):
            sh("git", "fetch", "-q", "origin", "main", cwd=tree)
            sh("git", "reset", "-q", "--soft", "origin/main", cwd=tree)
    sh(sys.executable, str(ROOT / "tools" / "export_public.py"), "--out", str(tree))
    out = Path(tempfile.mkdtemp(prefix="cbom-pages-")) / "site"
    sh(sys.executable, str(ROOT / "tools" / "build_public.py"), "--var", str(args.var), "--base", args.base,
       "--tree", str(tree), "--out", str(out))
    ident = []
    if author.get("name") and author.get("email"):
        ident = ["-c", f"user.name={author['name']}", "-c", f"user.email={author['email']}"]
    src = sh("git", "rev-parse", "--short", "HEAD", cwd=ROOT, capture=True)
    sh("git", "add", "-A", cwd=tree)
    if sh("git", "status", "--porcelain", cwd=tree, capture=True):
        sh("git", *ident, "commit", "-q", "-m", args.message, cwd=tree)
    else:
        print("the public tree is unchanged; nothing to commit")
    pages = out.parent / "pages-repo"
    shutil.copytree(out, pages)
    sh("git", "init", "-q", "-b", "gh-pages", cwd=pages)
    sh("git", "add", "-A", cwd=pages)
    sh("git", *ident, "commit", "-q", "-m", f"The demo and site, built from the public tree ({args.message})", cwd=pages)
    if args.no_push:
        print(f"built; not pushed. tree: {tree}  pages: {pages}")
        return 0
    sh("git", "push", "-q", "origin", "main", cwd=tree)
    sh("git", "push", "-q", "--force", url, "gh-pages", cwd=pages)
    shutil.rmtree(out.parent)
    print(f"published {args.repo} (from {src}) and its Pages site")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
