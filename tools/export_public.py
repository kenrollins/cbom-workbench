#!/usr/bin/env python
"""Export the public repository tree: the committed sources, less what is private, with every
lab-derived passage removed, scanned for anything from the lab before it is written.

    python tools/export_public.py --out ../cbom-workbench-export

What leaves out, and why:
- PLAN.md and CLAUDE.md: the working plan and the agent's instructions, full of the lab's own detail;
- docs/fable-review/: the design reviews — their findings are in the lessons, in general form;
- spikes/*/results/: the raw replies of every model call; the summaries and the method stay;
- journal entries marked `lab_only: true`: operations of the owner's lab;
- inside any Markdown file: blocks between `<!-- lab -->` and `<!-- /lab -->`, and in an entry's
  header, claims between `# lab` and `# /lab`.

The tree is written as a fresh directory; nothing is committed or pushed by this tool. The leak
check is the private list tools/build_public.py reads (workshop/public.yaml): one match and nothing is written.
"""

from __future__ import annotations

import argparse
import io
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from build_public import LEAKS  # noqa: E402

EXCLUDE = [re.compile(p) for p in (r"^PLAN\.md$", r"^CLAUDE\.md$", r"^docs/fable-review/", r"^spikes/[^/]+/results/")]
BODY = re.compile(r"^<!-- lab -->\n.*?^<!-- /lab -->\n?", re.S | re.M)
CLAIM = re.compile(r"^\s*# lab\n.*?^\s*# /lab\n", re.S | re.M)


def strip_lab(text: str) -> str:
    if text.startswith("---\n"):
        end = text.index("\n---\n", 4)
        front = CLAIM.sub("", text[:end + 1])
        text = front + text[end + 1:]
    text = BODY.sub("", text)
    return re.sub(r"\n{3,}", "\n\n", text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT.parent / "cbom-workbench-export")
    ap.add_argument("--rev", default="HEAD")
    args = ap.parse_args()
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        raise SystemExit("write the export outside the repository")
    tar = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar", args.rev], check=True, capture_output=True).stdout
    files: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        for m in t.getmembers():
            if m.isfile() and not any(rx.search(m.name) for rx in EXCLUDE):
                files[m.name] = t.extractfile(m).read()
    dropped = [n for n, b in files.items() if n.endswith(".md") and b.startswith(b"---\nlab_only: true\n")]
    for n in dropped:
        del files[n]
    gone = {Path(n).name[:2] for n in dropped}
    for n in list(files):
        if n.endswith(".md"):
            text = strip_lab(files[n].decode())
            if n in ("docs/journal/notes/README.md", "docs/journal/lessons/README.md"):
                text = "\n".join(l for l in text.splitlines() if not any(l.startswith(f"| {g} |") for g in gone)) + "\n"
            files[n] = text.encode()
    hits = []
    if LEAKS:
        rx = re.compile("|".join(LEAKS))
        hits = [f"{n}:{i}: {m.group(0)}" for n, b in files.items() for i, line in enumerate(b.decode(errors="replace").splitlines(), 1)
                for m in rx.finditer(line)]
    left = re.compile(rb"^(?:<!-- /?lab -->|\s*# /?lab)$", re.M)   # a marker on a line of its own, not one quoted in prose
    markers = [n for n, b in files.items() if n.endswith(".md") and left.search(b)]
    if hits or markers:
        print("\n".join(hits[:60] + [f"{m}: an unbalanced lab marker" for m in markers]))
        print(f"EXPORT REFUSED: {len(hits)} lab matches, {len(markers)} files with markers left", file=sys.stderr)
        return 1
    # Replace the tree's contents, keeping its .git: the export folder is also the public repository's
    # working copy (tools/publish.py), and its history must survive each export.
    if out.exists():
        for child in out.iterdir():
            if child.name in (".git", ".venv"):
                continue
            shutil.rmtree(child) if child.is_dir() else child.unlink()
    for n, b in files.items():
        p = out / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b)
    print(f"{len(files)} files exported to {out}; left out: PLAN.md, CLAUDE.md, the design reviews, raw spike results, "
          f"{len(dropped)} lab-only entries ({', '.join(sorted(dropped))}); no lab pattern found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
