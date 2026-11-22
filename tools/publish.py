#!/usr/bin/env python
"""Publish: the public repository and the public demo, from the committed working tree, in one step.

    uv run --with mkdocs-material python tools/publish.py --var /path/to/deployment/var -m "what changed"

1. Export the committed tree (tools/export_public.py) into the public repository's working copy,
   with the lab left out and the tree leak-checked; any match and nothing more happens.
2. Build the static demo and site for GitHub Pages from that tree (tools/build_public.py), leak-checked.
3. Commit the tree to the public repository's main branch and push it.
4. Push the built site as the single commit of the gh-pages branch (it is generated: no history kept).

Work happens in this repository; the public repository's working copy is a cache this command owns.
Commits are authored with the GitHub noreply address in the private rules (`author`).

This is the one tool that pushes, so it refuses to start without the private rules (workshop/public.yaml,
or the file PQCH_PUBLIC_RULES names — a git worktree or a second clone has no workshop/): the file must
exist, list `leaks`, and name the `author`. The commit message is public too and is checked against the
same patterns. `--without-private-rules` is for someone publishing their own copy, who has no such
file: nothing is then checked and the commits carry that machine's own git identity.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))


def preflight(rules: dict, message: str, *, without_rules: bool = False) -> list[str]:
    """Why this publish may not start; empty when it may. `rules` is build_public.private_rules()."""
    from build_public import leak_regex

    why = []
    if not without_rules:
        if not rules.get("found"):
            why.append(f"no private rules at {rules.get('path')}: nothing would be leak-checked")
        elif not rules.get("leaks"):
            why.append(f"{rules.get('path')} lists no `leaks`: nothing would be leak-checked")
        author = rules.get("author") or {}
        if not (author.get("name") and author.get("email")):
            why.append("the private rules name no `author` (name and email): the public commits would carry this machine's git identity")
    rx = leak_regex(rules.get("leaks"))
    if rx and rx.search(message):
        why.append(f"the commit message is public and matches a leak pattern: {rx.search(message).group(0)!r}")
    return why


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
    ap.add_argument("--without-private-rules", action="store_true",
                    help="publish with no leak patterns and this machine's git identity: for a copy that has no lab to protect")
    args = ap.parse_args()
    from build_public import RULES
    why = preflight(RULES, args.message, without_rules=args.without_private_rules)
    if why:
        raise SystemExit("PUBLISH REFUSED before anything was exported:\n  " + "\n  ".join(why)
                         + "\n(set PQCH_PUBLIC_RULES to the rules file, or pass --without-private-rules for a copy with no lab)")
    if sh("git", "status", "--porcelain", "--untracked-files=no", cwd=ROOT, capture=True):
        raise SystemExit("commit your changes first: only what is committed is published")
    author = RULES.get("author") or {}
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
    try:
        sh(sys.executable, str(ROOT / "tools" / "build_public.py"), "--var", str(args.var), "--base", args.base,
           "--tree", str(tree), "--out", str(out))
    except subprocess.CalledProcessError:
        print(f"PUBLISH STOPPED: the build failed after the export. Nothing was committed or pushed, but the public working copy "
              f"at {tree} now holds the new export, uncommitted, and differs from the public main branch until a publish succeeds.",
              file=sys.stderr)
        return 1
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
        print(f"built; not pushed. tree: {tree}  pages: {pages}\nThe public working copy now holds a commit the public main branch "
              "does not; the next publish pushes it with its own.")
        return 0
    sh("git", "push", "-q", "origin", "main", cwd=tree)
    sh("git", "push", "-q", "--force", url, "gh-pages", cwd=pages)
    shutil.rmtree(out.parent)
    print(f"published {args.repo} (from {src}) and its Pages site")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
