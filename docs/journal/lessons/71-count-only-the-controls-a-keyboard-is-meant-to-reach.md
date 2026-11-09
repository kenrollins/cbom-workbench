---
id: lesson-71-count-only-the-controls-a-keyboard-is-meant-to-reach
type: lesson
title: "An automated keyboard pass counts only the controls that are shown; a control inside a closed disclosure is reached through its summary, and a page that takes focus on load is walked from where it starts"
date: 2026-11-09
audience: [engineer]
rung: all
tags: [verification]
one_line: "A Tab-order check that compares the controls it reached with every focusable element in the page reports traps that do not exist: links inside a closed details element are not in the tab order until it is opened, and a page that focuses its input on load starts part-way down. Count what is shown, follow the wrap-around, and explain every difference before reporting one."
claims:
  - text: "A first keyboard pass over eleven pages reported 65 of 115 controls reached on the walkthrough and 7 of 26 on the Ask page. All 50 missed on the walkthrough were inside closed details elements, and the Ask page puts focus in its question box on load, so Tab began below the header's 18 links."
    provenance: "measured 2026-11-09, tools/a11y_check.py --keyboard in headless Chromium at 1440 px against the workbench served from recorded runs"
  - text: "Counting only shown controls and walking through the wrap-around, the pass reached 413 of 413 controls on the eleven pages, each with a visible focus indicator; the axe-core WCAG 2.1 A and AA rules found one violation in 26 page-and-scheme checks, a contrast ratio of 4.24 on an 11 px label in the light scheme, fixed."
    provenance: "measured 2026-11-09, same tool; docs/ACCESSIBILITY.md"
reuse: [talk]
---

# An automated keyboard pass counts only the controls that are shown; a control inside a closed disclosure is reached through its summary, and a page that takes focus on load is walked from where it starts

## The rule

A keyboard check presses Tab and records what takes focus. Compare that with
the controls a keyboard is meant to reach, not with every focusable element in
the page: leave out anything inside a closed `<details>` other than its
`<summary>`, anything hidden or inert, and anything disabled. Keep pressing
through the browser's own wrap-around until every counted control has had
focus, so a page that starts with focus part-way down is still walked in full.
Report a difference only after each missed control has been explained.

## Why

A **disclosure** (`<details>` with a `<summary>`) hides its content until the
summary is activated, and the browser leaves that content out of the tab order
while it is closed. That is correct behaviour: the summary is reachable, and
opening it makes the rest reachable. A check that counts the hidden links as
focusable reports a page where half the controls cannot be reached, which is
false, and a false alarm in an accessibility report costs the report its
credibility for the real findings. The same holds for a page that sets
`autofocus`: the first Tab moves on from the focused field, and a check that
stops when focus leaves the document has seen only the controls below it.

## When it applies

Any automated check of keyboard reach: a test in CI, an audit script, a crawler.
It does not replace a person walking a task with a keyboard, or a screen
reader; it shows that each control can take focus and shows that it has, and
nothing about whether the order makes sense.

## How to apply it

1. Build the list of expected controls in the page: focusable, not disabled,
   laid out, no hidden or inert ancestor, and no closed `<details>` ancestor
   unless the control is in that element's summary.
2. Note whether the page already has focus on one of them when it loads.
3. Press Tab up to twice the list's length, recording each control by its
   position in the list, and stop when all have been seen.
4. For each focused control, read the computed outline and box shadow; neither
   means no visible focus.
5. Before reporting a shortfall, classify every missed control. An unexplained
   one is a finding; an explained one is a correction to the check.

## Where the claim stops

Headless Chromium at one width. Focus order, pointer-free completion of a task
and what a screen reader announces were not tested and need a person.
