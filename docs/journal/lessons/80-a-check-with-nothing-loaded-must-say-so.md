---
id: lesson-80-a-check-with-nothing-loaded-must-say-so
type: lesson
title: "A check that had nothing to check must say so, and the tool that publishes must refuse without its rules"
date: 2026-11-21
audience: [engineer, architect]
rung: all
tags: [verification, publication, qa]
one_line: "A leak check whose pattern file is absent matches nothing and prints the sentence a clean result prints; the check reports how many patterns it held, the one tool that pushes refuses to start without them, and a mark is stripped in one exact form while anything that resembles a mark is refused."
claims:
  - text: "The export and the public build report their leak check as \"no match for the N leak patterns\" and, with none loaded, as \"NO LEAK PATTERNS LOADED: NOTHING WAS CHECKED\"; `tools/publish.py` refuses to start without the private rules file, without a `leaks` list in it, or without an `author`, unless `--without-private-rules` is given by someone publishing their own copy."
    provenance: "by reading tools/build_public.py (checked, private_rules) and tools/publish.py (preflight) at HEAD; tests/test_export_public.py (32 tests, passing on xr7620, 2026-11-21)"
  - text: "A lab mark is stripped only in its one exact form, and any line that resembles a mark and is not in that form (indented, with a trailing space, in another case, unpaired, nested, or in a file that is not Markdown) refuses the export with the file and line; `lab_only` is read as YAML wherever it sits in the front matter, and a value that is not plainly `true` refuses the export."
    provenance: "by reading tools/export_public.py at HEAD; tests/test_export_public.py (test_a_marker_that_is_not_stripped_refuses_the_export, test_a_lab_only_entry_is_dropped_wherever_the_key_sits, test_a_lab_only_key_that_is_not_plainly_true_refuses_the_export)"
  - text: "The leak patterns are matched without regard to case over every text file and every path, and a dropped entry removes only its own section's index row and menu line."
    provenance: "by reading tools/build_public.py (leak_regex, re.I) and tools/export_public.py; tests/test_export_public.py (test_the_leak_check_reads_every_file_and_path_whatever_the_case, test_a_dropped_entry_leaves_only_its_own_sections_index_and_its_menu_line)"
reuse: [runbook, whitepaper]
---

# A check that had nothing to check must say so, and the tool that publishes must refuse without its rules

## The rule

A check reports what it checked against, as a count, in the same line as its
result. With nothing loaded it says that nothing was checked, in words that
cannot be mistaken for a pass. A tool whose act cannot be undone, such as a
push to a public repository, does not start at all without the rules its
check needs.

## Why

A deny-list check is a loop over patterns. With no patterns the loop body
never runs, no match is found, and the code reaches the line that prints the
good news. "No lab pattern found" is then true and worthless: it was printed
by a check that looked for nothing.

The patterns go missing in the most ordinary way. The list of a private
environment's names and addresses is itself private, so it lives in a file
the repository ignores. Every fresh clone and every additional worktree of
the repository lacks that file. The check runs there exactly as it runs at
home and reports the same sentence.

The same failure has three more forms in an export that removes marked
passages:

- **Stripping and detecting use the same pattern.** A passage is removed when
  its markers match one exact form. A marker that is indented, has a trailing
  space or is in another case does not match, so it is not stripped, and
  because detection used the same strict pattern it is not reported either.
  The passage is published with its markers around it. Strip with the one
  exact form; detect with the loosest form that could have been meant; refuse
  on any difference between the two.
- **A deny-list is case-sensitive by default.** A name listed as it is
  usually written misses the same name in lower case in a comment or a path.
- **A flag is honoured only where it was first written.** A key that drops an
  entry when it is the first line of the front matter does nothing on the
  third line, silently. And a rule that removes "entry 23" from an index
  removes every row numbered 23, the note's as well as the lesson's.

Each is a check that reported success about a case it never examined.

## What is published is an export, never the working repository

A working repository built in a real environment carries that environment in
its history, its tests and its notes. What goes out is a fresh tree exported
from a commit (`git archive`, so what is published is what is committed), with
private passages marked where they are written and stripped on export, a scan
of the exported tree and of every built page that refuses the export on any
match, and the scan's own patterns kept in a private file the tools read. A
public site is built from the exported tree, so it can hold nothing the
repository does not. Private addresses in tests are remapped to ranges the
environment does not use, keeping their relationships, so the tests still
mean the same thing. The checks in this lesson are what make that export
trustworthy: each one is a way the scan could pass while checking nothing.

## When it applies

Any check driven by a list that can be empty or absent: leak patterns, lint
rule sets, allow-lists, policy packs, test selectors, a scanner's signature
file. It applies with most force to checks that guard an outward act. It is
the publishing tool's form of the rule that a positive verdict needs positive
evidence ([lesson 78](78-a-positive-verdict-needs-positive-evidence.md)).

## How to apply it

1. Print the count of what was loaded in the result line: "no match for the
   N leak patterns", with N printed, never "no pattern found".
2. Give the empty case its own loud wording, and test for that wording.
3. Separate tools that may run without rules from the tool that may not. A
   build someone runs on their own copy can proceed and say nothing was
   checked. The tool that pushes checks first:

    ```python
    # tools/publish.py, preflight()
    if not rules.get("found"):   why.append("no private rules at …: nothing would be leak-checked")
    elif not rules.get("leaks"): why.append("… lists no `leaks`: nothing would be leak-checked")
    ```

    The way round it is an explicit flag whose name says what is given up.
4. For anything that is removed by a marker, write two patterns: the exact
   one that removes, and a loose one that finds every near miss. A near miss
   stops the run and names the file and line.
5. Match deny-lists without regard to case, over file contents and over
   paths.
6. Read a flag with the parser of the format it lives in, wherever it sits,
   and refuse a value that is neither clearly on nor clearly off.
7. Run the check once with the rules deliberately absent and read what it
   prints.

    ```sh
    uv run python -m pytest tests/test_export_public.py
    ```

## Where the claim stops

A deny-list finds names and addresses. It does not find a finding written in
ordinary words, which is why material is marked as it is written
(`docs/journal/STYLE.md`, Lab material), and it does not read an image
([lesson 81](81-text-checks-do-not-read-pixels.md)). The count in the result
line says patterns were loaded, not that they are the right ones.
