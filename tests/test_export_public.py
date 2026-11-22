"""The public export and build: what is marked as the lab's leaves, a near-miss mark refuses the export
rather than publishing the passage, the leak check reads every text file and path without regard to
case, only the mini-agency's runs are curated, and the tool that pushes refuses without its rules.
Every name and address here is invented."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

TOOLS = Path(__file__).resolve().parents[1] / "tools"
RULES = """
leaks:
  - 'Zebulon'
  - '\\bgrommet\\b'
  - '\\b10\\.99\\.7\\.\\d{1,3}\\b'
page_leaks: []
scrub:
  - ['\\bgrommet\\b', 'the owner']
exclude:
  - '^private/'
author:
  name: A Name
  email: 1+name@users.noreply.example
"""


def _load(name, monkeypatch, rules: Path | None):
    monkeypatch.setenv("PQCH_PUBLIC_RULES", str(rules) if rules else "/nonexistent/public.yaml")
    monkeypatch.syspath_prepend(str(TOOLS))
    for m in ("build_public", "export_public", "publish", "screenshots"):
        monkeypatch.delitem(sys.modules, m, raising=False)
    spec = importlib.util.spec_from_file_location(name, TOOLS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def rules(tmp_path):
    p = tmp_path / "public.yaml"
    p.write_text(RULES)
    return p


@pytest.fixture
def ex(monkeypatch, rules):
    return _load("export_public", monkeypatch, rules)


@pytest.fixture
def bp(monkeypatch, rules):
    return _load("build_public", monkeypatch, rules)


FRONT = "---\nid: lesson-01-x\nclaims:\n  - text: \"kept\"\n    provenance: \"p\"\n{claims}reuse: [talk]\n---\n\n# T\n\n"
OPEN, CLOSE = "<!-- lab -->", "<!-- /lab -->"


def test_marked_passages_and_claims_are_stripped(ex):
    text = (FRONT.format(claims="  # lab\n  - text: \"secret claim\"\n    provenance: \"lab\"\n  # /lab\n")
            + f"Public.\n\n{OPEN}\nA lab finding.\n{CLOSE}\n\nAlso public.\n")
    out = ex.strip_lab(text)
    assert "secret claim" not in out and "A lab finding" not in out and "lab -->" not in out and "# lab" not in out
    assert "kept" in out and "Public." in out and "Also public." in out
    # Windows line endings are the same marks.
    out = ex.strip_lab(text.replace("\n", "\r\n"))
    assert "secret claim" not in out and "A lab finding" not in out and "Also public." in out
    # A marker named in prose, in backticks, is not a marker.
    prose = FRONT.format(claims="") + f"Put a passage between `{OPEN}` and `{CLOSE}` lines.\n"
    assert ex.strip_lab(prose) == prose


@pytest.mark.parametrize("body", [
    f"1. A step.\n\n    {OPEN}\n    A lab finding.\n    {CLOSE}\n",          # indented under a list item
    f"Text {OPEN} A lab finding. {CLOSE} more.\n",                           # sharing a line
    f"{OPEN} \nA lab finding.\n{CLOSE} \n",                                  # trailing spaces
    "<!-- Lab -->\nA lab finding.\n<!-- /Lab -->\n",                         # another case
    "<!--lab-->\nA lab finding.\n<!--/lab-->\n",                             # no spaces
    f"{OPEN}\nA lab finding with no end.\n",                                 # unclosed
    f"A lab finding with no start.\n{CLOSE}\n",
    f"{OPEN}\nOne.\n{OPEN}\nTwo.\n{CLOSE}\nThree.\n{CLOSE}\n",               # nested
])
def test_a_marker_that_is_not_stripped_refuses_the_export(ex, body):
    with pytest.raises(ex.Refused):
        ex.strip_lab(FRONT.format(claims="") + body)
    _files, _, problems = ex.public_tree({"docs/journal/lessons/01-x.md": (FRONT.format(claims="") + body).encode()})
    assert len(problems) == 1 and problems[0].startswith("docs/journal/lessons/01-x.md: ")


@pytest.mark.parametrize("claims", [
    "  # lab \n  - text: \"secret claim\"\n    provenance: \"lab\"\n  # /lab \n",   # trailing spaces
    "  # Lab\n  - text: \"secret claim\"\n    provenance: \"lab\"\n  # /Lab\n",
    "  #lab\n  - text: \"secret claim\"\n    provenance: \"lab\"\n  #/lab\n",
    "  # lab\n  - text: \"secret claim\"\n    provenance: \"lab\"\n",                 # unclosed
])
def test_a_claim_marker_that_is_not_stripped_refuses_the_export(ex, claims):
    with pytest.raises(ex.Refused):
        ex.strip_lab(FRONT.format(claims=claims) + "Body.\n")


def test_front_matter_that_never_closes_is_refused_by_name(ex):
    _, _, problems = ex.public_tree({"docs/a.md": b"---\nid: x\n\n# No closing line\n"})
    assert problems == ["docs/a.md: the front matter opens with --- and never closes"]


@pytest.mark.parametrize("front", [
    "---\nlab_only: true\nid: x\n---\n",
    "---\nid: x\ntype: lesson\nlab_only: true\n---\n",       # not the first key
    "---\nid: x\nlab_only: True\n---\n",
    "---\nid: x\nlab_only: true \n---\n",
    "---\nid: x\nlab_only: \"true\"\n---\n",
    "---\nid: x\nlab_only: yes\n---\n",
    "---\r\nid: x\r\nlab_only: true\r\n---\r\n",
])
def test_a_lab_only_entry_is_dropped_wherever_the_key_sits(ex, front):
    files, dropped, problems = ex.public_tree({"docs/journal/lessons/23-switch.md": (front + "\nSwitch configuration.\n").encode(),
                                               "docs/journal/lessons/24-other.md": b"---\nid: y\n---\n\nPublic.\n"})
    assert dropped == ["docs/journal/lessons/23-switch.md"] and not problems
    assert list(files) == ["docs/journal/lessons/24-other.md"]


@pytest.mark.parametrize("front", ["---\nid: x\nlab_only: false\n---\n", "---\nid: x\nLab_Only: maybe\n---\n",
                                   "---\nid: x\nlab-only: true\n---\n", "---\nid: [x\nlab_only: true\n---\n"])
def test_a_lab_only_key_that_is_not_plainly_true_refuses_the_export(ex, front):
    _files, dropped, problems = ex.public_tree({"docs/journal/lessons/23-switch.md": (front + "\nSwitch configuration.\n").encode()})
    assert not dropped and len(problems) == 1 and "lab_only" in problems[0]


def test_a_dropped_entry_leaves_only_its_own_sections_index_and_its_menu_line(ex):
    row = "| {n} | {t} | x |"
    readme = lambda *rows: ("| # | Title | Reuse |\n|---|---|---|\n" + "\n".join(row.format(n=n, t=t) for n, t in rows) + "\n").encode()  # noqa: E731
    files, dropped, problems = ex.public_tree({
        "docs/journal/lessons/23-switch.md": b"---\nid: lesson-23\nlab_only: true\n---\n\nLab.\n",
        "docs/journal/lessons/100-tenant.md": b"---\nid: lesson-100\nlab_only: true\n---\n\nLab.\n",
        "docs/journal/lessons/10-public.md": b"---\nid: lesson-10\n---\n\nPublic.\n",
        "docs/journal/notes/23-attestation.md": b"---\nid: note-23\n---\n\nPublic.\n",
        "docs/journal/lessons/README.md": readme((10, "public lesson ten"), (23, "the switch"), (100, "the tenant")),
        "docs/journal/notes/README.md": readme((10, "note ten"), (23, "the attestation note"), (100, "note one hundred")),
        "mkdocs.yml": b"nav:\n  - Lessons:\n      - \"10\": lessons/10-public.md\n      - \"23 switch\": lessons/23-switch.md\n"
                      b"      - \"100\": lessons/100-tenant.md\n  - Notes:\n      - \"23\": notes/23-attestation.md\n",
    })
    assert not problems and len(dropped) == 2
    lessons, notes = files["docs/journal/lessons/README.md"].decode(), files["docs/journal/notes/README.md"].decode()
    assert "public lesson ten" in lessons and "the switch" not in lessons and "the tenant" not in lessons
    assert all(t in notes for t in ("note ten", "the attestation note", "note one hundred"))
    assert files["mkdocs.yml"].decode().split() == "nav: - Lessons: - \"10\": lessons/10-public.md - Notes: - \"23\": notes/23-attestation.md".split()


def test_the_leak_check_reads_every_file_and_path_whatever_the_case(ex):
    clean = {"README.md": b"# Hello\n", "tests/test_a.py": b"ADDR = '10.20.30.4'\n", "img/a.png": b"\x89PNG\r\n\x1a\n\xff\xfe"}
    files, _, problems = ex.public_tree(dict(clean))
    assert not problems and set(files) == set(clean)
    for name, data, hit in [("site_src/a.css", b"/* zebulon-notes */\n", "site_src/a.css:1: zebulon"),
                            ("tests/test_b.py", b"x = 1\nRANGE = '10.99.7.101'\n", "tests/test_b.py:2: 10.99.7.101"),
                            ("fixtures/zebulon-baseline.json", b"{}\n", "fixtures/zebulon-baseline.json: path: zebulon"),
                            ("docs/GROMMET.txt", b"ok\n", "docs/GROMMET.txt: path: GROMMET")]:
        _, _, problems = ex.public_tree({**clean, name: data})
        assert problems == [hit]
    # A mark in a file that is not Markdown strips nothing, so it is refused; a path the rules exclude is left out.
    _, _, problems = ex.public_tree({**clean, "policy/p.yaml": b"a: 1\n# lab\nb: 2\n# /lab\n"})
    assert len(problems) == 1 and problems[0].startswith("policy/p.yaml: line 2: a lab marker")
    files, _, problems = ex.public_tree({**clean, "private/notes.txt": b"Zebulon\n"}, exclude=["^private/"])
    assert not problems and "private/notes.txt" not in files


def test_without_patterns_the_tools_say_nothing_was_checked(monkeypatch, tmp_path, capsys):
    bp = _load("build_public", monkeypatch, None)
    assert bp.RULES["found"] is False and bp.LEAKS == [] and "no leak patterns loaded" in capsys.readouterr().err
    assert "NOTHING WAS CHECKED" in bp.checked() and "no lab pattern" not in bp.checked()
    assert bp.leak_regex([]) is None and bp.leak_regex(None) is None
    # A rules file with the key misspelt loads no pattern either, and says so.
    typo = tmp_path / "public.yaml"
    typo.write_text("leak:\n  - 'Zebulon'\n")
    assert bp.private_rules(typo)["leaks"] == [] and "has no `leaks`" in capsys.readouterr().err
    assert bp.checked(["a", "b"]) == "no match for the 2 leak patterns"


def test_publish_refuses_without_rules_leaks_or_author(monkeypatch, rules, tmp_path):
    pub = _load("publish", monkeypatch, rules)
    import build_public as bp
    assert pub.preflight(bp.RULES, "Add the notes") == []
    assert "leak pattern" in pub.preflight(bp.RULES, "Notes from zebulon")[0]
    missing = bp.private_rules(tmp_path / "absent.yaml")
    assert len(pub.preflight(missing, "m")) == 2 and "nothing would be leak-checked" in pub.preflight(missing, "m")[0]
    assert pub.preflight(missing, "m", without_rules=True) == []
    for text, word in (("leaks: []\nauthor: {name: A, email: a@b.example}\n", "`leaks`"), ("leaks: ['Zebulon']\n", "`author`"),
                       ("leaks: ['Zebulon']\nauthor: {name: A}\n", "`author`")):
        (tmp_path / "r.yaml").write_text(text)
        why = pub.preflight(bp.private_rules(tmp_path / "r.yaml"), "m")
        assert len(why) == 1 and word in why[0], (text, why)
    # The command itself stops before it exports anything.
    monkeypatch.setenv("PQCH_PUBLIC_RULES", str(tmp_path / "absent.yaml"))
    pub = _load("publish", monkeypatch, None)
    monkeypatch.setattr(pub, "sh", lambda *a, **k: pytest.fail(f"ran {a}"))
    monkeypatch.setattr(sys, "argv", ["publish.py", "--var", str(tmp_path)])
    with pytest.raises(SystemExit, match="PUBLISH REFUSED"):
        pub.main()


def _run(var: Path, rid: str, kind: str, scope: dict) -> None:
    d = var / "runs" / rid
    d.mkdir(parents=True)
    (d / "ledger.jsonl").write_text(json.dumps({"seq": 0, "type": "run.started", "payload": {"kind": kind, "scope": scope}}) + "\n")


def test_only_the_mini_agencys_runs_are_curated(bp, tmp_path, monkeypatch):
    import pqch.ui.agility
    import pqch.watch
    monkeypatch.setattr(pqch.watch, "previous", lambda run: None)
    monkeypatch.setattr(pqch.ui.agility, "_change_story", lambda var: None)
    ep = lambda *hosts: [{"host": h, "port": 443} for h in hosts]  # noqa: E731
    estate = {"estate": "colocated", "endpoints": ep("172.16.106.10", "172.16.106.11", "172.16.106.12")}
    var = tmp_path / "var"
    _run(var, "01A0SCAN", "scan", estate)
    _run(var, "01A1CHANGE", "change", estate)
    _run(var, "01A2SLICE", "change", {"estate": "colocated", "endpoints": ep("172.16.106.10")})      # the estate's smaller, earlier form
    _run(var, "01A3IMPORT", "import", estate)
    _run(var, "01A4CODE", "scan-code", {"estate": "external", "endpoints": [], "sources": [{"repo": "18F/identity-idp", "commit": "62cf387"}]})
    # What must stay behind: an import and a scan under a copy's scope, an import of another estate, a change
    # on a colocated estate with a listener the published scan does not name, a code scan of an unnamed
    # repository, a capture, and a run whose ledger cannot be read.
    copy = {"estate": "external", "endpoints": ep("10.99.7.101"), "copy": {"of": "mini-agency", "taken": "2026-01-01T00:00:00Z"}}
    _run(var, "01B0COPYIMPORT", "import", copy)
    _run(var, "01B1COPYSCAN", "scan-copy", copy)
    _run(var, "01B2COPYSAMEADDR", "import", {**estate, "copy": {"of": "mini-agency"}})
    _run(var, "01B3OTHERIMPORT", "import", {"estate": "external", "endpoints": ep("10.99.7.5")})
    _run(var, "01B4OTHERCHANGE", "change", {"estate": "colocated", "endpoints": ep("172.16.106.10", "10.99.7.9")})
    _run(var, "01B5PRIVATECODE", "scan-code", {"estate": "external", "endpoints": [], "sources": [{"repo": "someone/private", "commit": "abc"}]})
    _run(var, "01B6UNPINNED", "scan-code", {"estate": "external", "endpoints": [], "sources": [{"repo": "18F/identity-idp"}]})
    _run(var, "01B7CAPTURE", "capture", {"estate": "external", "endpoints": [], "captures": [{"interface": "eth9"}]})
    _run(var, "01B8NOSCOPE", "import", {"estate": "external"})
    (var / "runs" / "01B9BROKEN").mkdir()
    (var / "runs" / "01B9BROKEN" / "ledger.jsonl").write_text("not json\n")
    (var / "runs" / "LATEST_SCAN").write_text("01A0SCAN\n")
    (var / "runs" / "LATEST_IMPORT").write_text("01B0COPYIMPORT\n")
    assert sorted(bp.runs_to_publish(var)) == ["01A0SCAN", "01A1CHANGE", "01A2SLICE", "01A3IMPORT", "01A4CODE"]
    work = tmp_path / "work"
    assert sorted(bp.curate(var, work)) == sorted(p.name for p in (work / "runs").iterdir() if p.is_dir())
    assert not any("10.99.7." in p.read_text() for p in work.rglob("*") if p.is_file())
    # A copy's scan can never be the scan the public copy shows.
    (var / "runs" / "LATEST_SCAN").write_text("01B1COPYSCAN\n")
    with pytest.raises(SystemExit, match="01B1COPYSCAN"):
        bp.runs_to_publish(var)


def test_the_pages_leak_check_reads_every_text_file_and_path(bp, tmp_path):
    out = tmp_path / "out"
    for rel, data in {"index.html": b"<p>ok</p>", "site/a.css": b"/* ok */", "site/img/a.png": b"\x89PNG\r\n\x1a\n\xff\xfe zebulon",
                      "runs/01A/projection/agency-inventory.csv": b"system,owner\nportal,records office\n"}.items():
        (out / rel).parent.mkdir(parents=True, exist_ok=True)
        (out / rel).write_bytes(data)
    assert bp.leak_check(out) == []
    (out / "runs/01A/projection/agency-inventory.csv").write_text("system,owner\nportal,ZEBULON team\n")
    (out / "site/img/sketch.svg").write_text("<svg><text>10.99.7.101</text></svg>")
    (out / "site/zebulon-notes.map").write_text("{}")
    assert sorted(bp.leak_check(out)) == ["runs/01A/projection/agency-inventory.csv:2: ZEBULON", "site/img/sketch.svg:1: 10.99.7.101",
                                          "site/zebulon-notes.map: path: zebulon"]
    # A download is published byte for byte with its hash, so it is never scrubbed: what a page would have
    # had replaced fails the build when it is in a download.
    for p in ("site/img/sketch.svg", "site/zebulon-notes.map"):
        (out / p).unlink()
    (out / "runs/01A/projection/agency-inventory.csv").write_text("system,owner\nportal,http://10.1.2.3:8014/v1\n")
    (out / "about.html").write_text("<p>http://10.1.2.3:8014/v1</p>")      # a page's own text is the scrub's business, not this check's
    assert bp.leak_check(out) == ["runs/01A/projection/agency-inventory.csv:2: http://10.1.2.3:8014/v1"]


def test_a_screenshot_page_is_scrubbed_and_its_text_checked(monkeypatch, rules):
    shots = _load("screenshots", monkeypatch, rules)
    html = "<p>changed by grommet at http://10.1.2.3:8014/v1</p>"
    assert shots.scrubbed(html) == "<p>changed by the owner at an internal endpoint</p>"
    assert shots.leaks_shown(shots.scrubbed(html)) == []
    assert shots.leaks_shown("approved by Grommet on zebulon") == ["Grommet", "zebulon"]
