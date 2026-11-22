#!/usr/bin/env python
"""Export the public repository tree: the committed sources, less what is private, with every
lab-derived passage removed, scanned for anything from the lab before it is written.

    python tools/export_public.py --out ../cbom-workbench-export

What leaves out, and why:
- PLAN.md and CLAUDE.md: the working plan and the agent's instructions, full of the lab's own detail;
- docs/fable-review/: the design reviews — their findings are in the lessons, in general form;
- docs/federal-review/: the federal readiness review of the workbench itself — private working material;
- spikes/*/results/: the raw replies of every model call; the summaries and the method stay;
- any path the private rules' `exclude` list names (regular expressions over the path);
- journal entries whose front matter says `lab_only: true`: operations of the owner's lab;
- inside any Markdown file: blocks between `<!-- lab -->` and `<!-- /lab -->`, and in an entry's
  header, claims between `# lab` and `# /lab`.

The markers have one form each (docs/journal/STYLE.md, "Lab material"): the whole line, spelled
exactly. Stripping and detection are separate: anything that looks like a marker and was not
stripped — indented, sharing its line, in another case, with a trailing space, unclosed, or in a
file that is not Markdown — refuses the export and names the file and line, so a marker never fails
open. A marker quoted in backticks in prose is not one.

The tree is written as a fresh directory; nothing is committed or pushed by this tool. The leak
check is the private list tools/build_public.py reads (workshop/public.yaml, or the file
PQCH_PUBLIC_RULES names), matched without regard to case over every file's text and every path: one
match and nothing is written. Without that list the export still runs, for someone exporting their
own copy, and says that nothing was checked.
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
from build_public import LEAKS, RULES, checked, leak_regex  # noqa: E402

EXCLUDE = [re.compile(p) for p in (r"^PLAN\.md$", r"^CLAUDE\.md$", r"^docs/fable-review/", r"^docs/federal-review/", r"^spikes/[^/]+/results/")]
BODY = re.compile(r"^<!-- lab -->\n.*?^<!-- /lab -->\n?", re.S | re.M)
CLAIM = re.compile(r"^\s*# lab\n.*?^\s*# /lab\n", re.S | re.M)
# What looks like a marker, however it is written. Searched after stripping, so a hit is a marker the
# strip did not take.
BODY_MARK = re.compile(r"<!--\s*/?\s*lab\s*-->", re.I)
CLAIM_MARK = re.compile(r"(?:^|\s)#\s*/?\s*lab\s*$", re.I)
QUOTED = re.compile(r"`[^`\n]*`")
LAB_ONLY_KEY = re.compile(r"^\s*[\"']?lab[_-]?only[\"']?\s*:", re.I | re.M)
READMES = {"docs/journal/notes/README.md": "notes", "docs/journal/lessons/README.md": "lessons"}


class Refused(ValueError):
    """A file the export cannot make safe; the message says what to change."""


def split_front(text: str) -> tuple[str, str]:
    """An entry's front matter (with its opening line, without its closing one) and the rest."""
    if not text.startswith("---\n"):
        if text.lstrip("﻿ \t\n").startswith("---\n") and re.match(r"[﻿ \t\n]+---\n(?:[\w\"'-]+\s*:|\s*#)", text):
            raise Refused("the front matter does not start on the file's first line, so its marks cannot be read")
        return "", text
    end = text.find("\n---\n", 3)
    if end < 0:
        if text.rstrip("\n").endswith("\n---"):
            end = text.rstrip("\n").rfind("\n---")
        else:
            raise Refused("the front matter opens with --- and never closes")
    return text[:end + 1], text[end + 1:]


def lab_only(text: str) -> bool:
    """Is this entry marked as all lab? Read from the front matter as YAML, wherever the key sits.
    A `lab_only` key that is not plainly true, or front matter that cannot be read and names the key,
    is refused: the mark means one thing."""
    import yaml

    front, _ = split_front(text.replace("\r\n", "\n"))
    if not front or not LAB_ONLY_KEY.search(front):
        return False
    try:
        meta = yaml.safe_load(front[4:])
    except yaml.YAMLError as e:
        raise Refused(f"the front matter names lab_only and does not parse as YAML ({str(e).splitlines()[0]})") from None
    value = meta.get("lab_only") if isinstance(meta, dict) else None
    if value is True or (isinstance(value, str) and value.strip().lower() in ("true", "yes", "on")):
        return True
    raise Refused("the front matter names lab_only, but not as `lab_only: true`: write exactly that, or remove the key")


def strip_lab(text: str) -> str:
    """The text with its lab blocks and lab claims removed. Raises Refused when a marker is left."""
    text = text.replace("\r\n", "\n")
    front, body = split_front(text)
    front, body = CLAIM.sub("", front), BODY.sub("", body)
    for n, line in enumerate(front.splitlines(), 1):
        if CLAIM_MARK.search(line):
            raise Refused(f"line {n} of the front matter: a `# lab` claim marker that was not stripped ({line.strip()!r}); "
                          "each of `# lab` and `# /lab` is a whole line, and they come in pairs")
    offset = front.count("\n")
    for n, line in enumerate(body.splitlines(), offset + 1):
        if BODY_MARK.search(QUOTED.sub("", line)):
            raise Refused(f"about line {n} after stripping: a lab block marker that was not stripped ({line.strip()[:60]!r}); each of "
                          "`<!-- lab -->` and `<!-- /lab -->` is a whole line starting in the first column, and they come in pairs")
    return re.sub(r"\n{3,}", "\n\n", front + body)


def stray_marker(text: str) -> str | None:
    """A lab marker on a line of its own in a file that is not Markdown, where nothing strips it."""
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if BODY_MARK.fullmatch(s) or re.fullmatch(r"(?:#|//|;|--)\s*/?\s*lab", s, re.I):
            return f"line {n}: a lab marker ({s!r}) in a file that is not Markdown; markers are stripped only from Markdown, so move the " \
                   "material out of the file or leave the file out (the private rules' `exclude`)"
    return None


def public_tree(files: dict[str, bytes], *, leaks=None, exclude=()) -> tuple[dict[str, bytes], list[str], list[str]]:
    """The public tree from the committed one: (files, dropped lab-only entries, problems). Nothing may
    be written while there is a problem."""
    problems: list[str] = []
    drop = [re.compile(p) for p in exclude]
    files = {n: b for n, b in files.items() if not any(rx.search(n) for rx in [*EXCLUDE, *drop])}
    dropped, unread = [], set()
    for n in [n for n in files if n.endswith(".md")]:
        try:
            if lab_only(files[n].decode()):
                dropped.append(n)
        except Refused as e:
            problems.append(f"{n}: {e}")
            unread.add(n)
    for n in dropped:
        del files[n]
    # A dropped entry's row leaves its own section's index, and its line leaves the site's menu; a note
    # and a lesson may share a number.
    gone = {(Path(n).parent.name, m.group(0)) for n in dropped if (m := re.match(r"\d+", Path(n).name))}
    names = {n.removeprefix("docs/journal/") for n in dropped}
    for n in list(files):
        if n in unread:
            continue
        if n.endswith(".md"):
            try:
                text = strip_lab(files[n].decode())
            except Refused as e:
                problems.append(f"{n}: {e}")
                continue
            if n in READMES:
                mine = {num for section, num in gone if section == READMES[n]}
                text = "\n".join(ln for ln in text.splitlines() if not ((m := re.match(r"\|\s*(\d+)\s*\|", ln)) and m.group(1) in mine)) + "\n"
            files[n] = text.encode()
        elif n == "mkdocs.yml" and names:
            files[n] = "".join(ln for ln in files[n].decode().splitlines(keepends=True)
                               if not any(ln.rstrip().endswith(f": {name}") for name in names)).encode()
        else:
            try:
                why = stray_marker(files[n].decode())
            except UnicodeDecodeError:
                continue    # an image or a font
            if why:
                problems.append(f"{n}: {why}")
    rx = leak_regex(LEAKS if leaks is None else leaks)
    if rx:
        for n, b in files.items():
            problems += [f"{n}: path: {m.group(0)}" for m in rx.finditer(n)]
            problems += [f"{n}:{i}: {m.group(0)}" for i, line in enumerate(b.decode(errors="replace").splitlines(), 1) for m in rx.finditer(line)]
    return files, sorted(dropped), problems


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, default=ROOT.parent / "cbom-workbench-export")
    ap.add_argument("--rev", default="HEAD")
    ap.add_argument("--force", action="store_true", help="replace the contents of --out even when it does not look like an earlier export")
    args = ap.parse_args()
    out = args.out.resolve()
    if out == ROOT or ROOT in out.parents:
        raise SystemExit("write the export outside the repository")
    tar = subprocess.run(["git", "-C", str(ROOT), "archive", "--format=tar", args.rev], check=True, capture_output=True).stdout
    committed: dict[str, bytes] = {}
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        for m in t.getmembers():
            if m.isfile():
                committed[m.name] = t.extractfile(m).read()
    files, dropped, problems = public_tree(committed, exclude=RULES.get("exclude") or [])
    if problems:
        print("\n".join(problems[:80]))
        print(f"EXPORT REFUSED: {len(problems)} lab matches or markers left; nothing written", file=sys.stderr)
        return 1
    # Replace the tree's contents, keeping its .git: the export folder is also the public repository's
    # working copy (tools/publish.py), and its history must survive each export. Everything else in it
    # is deleted, so it must be an earlier export (it holds this tool) or empty.
    old = [c for c in out.iterdir() if c.name not in (".git", ".venv")] if out.exists() else []
    if old and not (out / "tools" / "export_public.py").is_file() and not args.force:
        raise SystemExit(f"{out} is not empty and is not an earlier export; its contents would be deleted. Name another --out, or pass --force")
    # What a person should read before it goes out: the files this export adds to the last one.
    before = {str(p.relative_to(out)) for c in old for p in ([c] if c.is_file() else c.rglob("*")) if p.is_file()}
    new = sorted(n for n in files if n not in before) if before else []
    for child in old:
        shutil.rmtree(child) if child.is_dir() else child.unlink()
    for n, b in files.items():
        p = out / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b)
    print(f"{len(files)} files exported to {out}; left out: PLAN.md, CLAUDE.md, the design and federal reviews, raw spike results, "
          f"{len(dropped)} lab-only entries ({', '.join(dropped)}); {checked()}")
    if new:
        print(f"{len(new)} files are new since the last export; read them before they are published:\n  " + "\n  ".join(new[:200]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
