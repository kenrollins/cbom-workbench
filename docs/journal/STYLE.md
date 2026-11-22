# Journal — style and standards

The journal is a **reference library**, not a diary. It exists so that someone
— a reader, or a language model answering a question from these files — can
find out how post-quantum migration works, what a CBOM is for, and what this
project established, and can reuse it in a whitepaper or a talk.

Two kinds of entry:

- **Notes** (`notes/`) explain a concept or a part of the process. One question
  per note, named in the title.
- **Lessons** (`lessons/`) record one piece of operational knowledge: a rule,
  the reason for it, and when it applies.

## What a reader should get

After a note, a reader can (a) explain the idea to a colleague, (b) check the
numbers, and (c) say where the claim stops. After a lesson, a reader knows what
to do and why.

## Voice

**Authoritative, precise, explanatory.** A senior engineer explaining something
they have measured to a capable colleague from an adjacent field.

- **State what is true now.** Describe the system, the standard or the result
  as it stands. Do not narrate how it was arrived at: no chronology, no
  attempts, no before-and-after. When something changes, rewrite the entry so
  it is correct today.
- **Lessons are standing guidance.** Write "Run targeted checks; a full scan
  takes minutes per host", not an account of the day that was learned.
- **Explain, then be precise.** Plain mechanism first, exact statement second.
- **Define every term on first use, in every entry.** KEM, hybrid key
  exchange, CBOM, high-value asset, harvest now decrypt later. Entries are read
  out of order and retrieved in pieces.
- **Numbers carry provenance.** Measured (on what, when, with what
  configuration), computed (show the arithmetic), or cited (name the source).
  A number without provenance does not go in.
- **Say where the claim stops.** Scope is part of a precise statement: what was
  covered, what was not examined, what is contested in the field.
- **First person plural, sparingly.** "We measured" is fine.

## Written to be retrieved

These files will be searched and quoted by tools as well as read by people.

- **Self-contained.** No entry depends on another to be understood. Link to
  related entries; do not rely on them.
- **One idea per section, with a heading that says what it is.**
- **Stable ids and filenames.** Never renumber.
- **Lead with the answer.** The first paragraph answers the title's question.
- **Prefer tables for comparisons** and short declarative sentences for facts.
- **Mark reuse.** The `reuse` field says where the entry is useful: a
  whitepaper section, a talk slide, a customer question.

## Note structure

1. **The answer**, in a paragraph.
2. **The concept**, plainly.
3. **The mechanism** — what actually happens, precisely.
4. **Worked example** — from the mini-agency or the standards, with the
   configuration stated.
5. **What follows** — for an agency planning its migration.
6. **Scope** — what this note covers and what it does not.
7. **References**, each with one line on what it supports.

## Lesson structure

1. **The rule**, in one sentence.
2. **Why** — the mechanism that makes it true.
3. **When it applies**, and when it does not.
4. **How to apply it** — the command, setting or check.

## Conventions

- No emojis.
- Standard names for algorithms and documents: ML-KEM-768, ML-DSA-65,
  X25519MLKEM768, FIPS 203, OMB M-26-15, CNSA 2.0.
- Code and configuration in fenced blocks, with the file path.
- At most one pull-quote per note, using `!!! quote ""`.

## Drawings

A drawing is a claim, held to the same standard as a sentence: every label and count in it comes
from the entry it illustrates, and its caption says what it shows. Two kinds, both drawn by
`tools/draw.py` (`uv run --with fonttools --with brotli python tools/draw.py`) and never by hand in
an editor, so they can be redrawn when the entry changes:

- **Sketches** explain a mechanism in the book's inks: ballpoint for what is written, stamp red for
  the point, graphite pencil for what is there but does not count. They live in `img/sketches/`,
  named for the entry (`20-four-clocks.svg`), and go in as `<figure class="sketch" markdown>` with
  the image, a full `alt` text that states the picture's claim, and a one-line `<figcaption>`.
- **Marks** annotate a screenshot: red rings on the screen, notes on paper slips. The screenshot is
  never edited; the marks are a transparent overlay of the same size in `site_src/img/marks/`, laid
  over it with `<figure class="marked">`.

Lettering is in two faces, as in an engineer's notebook. What is said is handwritten (Kalam). What
is data, any word with a digit in it (an address, a version, an algorithm name, a count in a running
label), is typed in the site's monospace, because a script face's digits are the hardest thing in a
drawing to read; a headline count in a stamp, and a title, stay handwritten. Pencil is for lines and
for what does not count; pencil lettering is drawn darker than pencil lines so it can be read. The
tool chooses the face and fits each label into the room the layout gives it; a sketch's function
only says what is written, where, and how large.

A drawing is read at the width of a note's column, about three quarters of its drawn size, so write
less in it than fits. The tool reports two things when it draws: a label that runs off the sheet, and
how many labels in a sketch came out too small to read at that width. The second is not fixed by a
smaller face. It means too much is written in too little room: cut words to the caption, or give the
sketch fewer things to say. About a dozen labels is a good drawing; thirty is a table.

No generated imagery: an illustration that cannot be checked against the ledger, the answer key or
the entry's own numbers does not go in. A drawing cannot be marked: the figure that shows a lab
finding goes inside a lab passage, and its file is named in the private rules' `exclude` list
(Lab material, below).

Look before committing: render each sketch (`python3 tools/render_sketch.py <svg> <png>`, headless
Chromium through Playwright, at the notes column's width by default, so the picture is what a reader's
browser shows and the faces are the ones embedded in the file) and check that every label can be read
at that size, nothing is clipped at any edge, no labels overlap, and exactly one red mark carries the
point.

## Lab material

The public repository and site are an export of this one (`tools/export_public.py`). The export
removes only what is marked, and its leak check knows names and addresses, not findings: a finding
from the owner's lab that is written without a mark is published. Mark as you write. There are three
marks, each with exactly one form; the export refuses, naming the file and line, anything that looks
like a mark and is not in that form, so a near miss stops the export instead of publishing the passage.

- **A lab passage in the body** goes between two lines that read exactly `<!-- lab -->` and
  `<!-- /lab -->`. Each is a whole line, starts in the first column, is in lower case with single
  spaces, has nothing after it, and they come in pairs, never nested. A marker cannot be indented, so
  a passage cannot be marked inside a list item or a table cell: move the passage out of the list
  into a paragraph of its own and mark that. A table row may be marked whole, with a marker line
  before and after it.
- **A lab claim in the header** goes between two comment lines that read `# lab` and `# /lab`,
  indented like the claims they enclose, each a whole line with nothing after it. They wrap whole
  `- text:` / `provenance:` items.
- **An entry that is all lab** has `lab_only: true` in its front matter: that key, that value, in
  lower case. The front matter starts on the file's first line. The entry, its row in its section's
  README and its line in the site's menu are left out; a link to it from another entry must be inside
  a lab passage, or the public build fails on the dangling link.

To name a marker in prose, put it in backticks on a line with other words, as this section does; a
marker alone on a line is read as a marker, quoted or not.

Only Markdown is stripped. A fixture, a code comment, a policy file, a drawing or a screenshot has no
marks: lab-derived material does not go in one. Use invented addresses, names and dates in tests and
examples (a documentation range, not the lab's), and draw a lab finding only in a `lab_only` entry.
A file that must stay private as a whole is named in the private rules' `exclude` list. New lab names
and addresses go into the private rules' `leaks` when they are first written down, whatever their case.

## Frontmatter

```yaml
---
id: note-NN-short-slug        # or lesson-NN-short-slug
type: note | lesson
title: "The question the note answers, or the rule the lesson states"
date: YYYY-MM-DD
audience: [leader, architect, engineer]
tags: [cbom, key-establishment, signatures, policy, discovery, verification, agility, inference]
rung: opaque | enumerated | structured | managed | agile | all
one_line: "The answer or the rule, in one sentence."
claims:
  - text: "A specific factual claim made in this entry."
    provenance: "measured 2026-10-04, mini-agency slice, x86_64 | cited: FIPS 203 | computed"
reuse: [whitepaper, talk, customer-question]
---
```
