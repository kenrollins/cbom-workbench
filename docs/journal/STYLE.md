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
