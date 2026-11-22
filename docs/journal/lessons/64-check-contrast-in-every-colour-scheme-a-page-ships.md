---
id: lesson-64-check-contrast-in-every-colour-scheme-a-page-ships
type: lesson
title: "Run the accessibility check in every colour scheme a page ships; a palette that passes in light can fail in dark, and the reverse"
date: 2026-11-06
audience: [engineer]
rung: all
tags: [agility]
one_line: "WCAG contrast is computed from the colours a reader is shown, so a page with a dark and a light scheme is two pages to the checker; run it once per scheme."
claims:
  - text: "With the dark scheme's dim text at rgba(196,207,221,.56), the workbench's pages fail WCAG 2.1 SC 1.4.3 on 9 of 12 pages in the dark scheme: that colour gives 4.48:1 on the page background (#0b0f17) and 4.41:1 on a card (#10161f). The light scheme's own failure is an opaque grey, --classical #6b7684 at 4.31:1 on #f6f7f9."
    provenance: "computed with the WCAG 2.1 relative-luminance formula, the translucent colour blended over its background and rounded to 8 bits per channel; the 9-page count measured 2026-11-06 on x86_64 with tools/a11y_check.py (axe-core 4.11.2, headless Chromium), branch m8-now"
  - text: "At alpha .62 the dim text gives 5.22:1 on the page background and 5.13:1 on a card, and --classical at #5f6a78 gives 5.13:1; with those two and four other colour edits in place, the same 12 pages have no serious or critical violation in either scheme."
    provenance: "computed as above; the pass measured 2026-11-06 with the same check, which reports violations only (a passing ratio is computed, not read from the tool); the four other edits are in src/pqch/ui/static/style.css and demo.css (ul.nist li, a.box.partial .small, .advance a, .advance a.primary)"
  - text: "WCAG 2.1 success criterion 1.4.3 asks for a contrast ratio of at least 4.5:1 for normal text and 3:1 for large text."
    provenance: "cited: W3C, WCAG 2.1, SC 1.4.3 Contrast (Minimum)"
reuse: [runbook, customer-question]
---

# Run the accessibility check in every colour scheme a page ships

## The rule

When a page follows the reader's colour scheme (`prefers-color-scheme`), run the automated
accessibility check once per scheme, and fail on a serious violation in either. The check here is
axe-core (Deque's open-source accessibility rule engine, run in headless Chromium) against WCAG 2.1
(the W3C's Web Content Accessibility Guidelines, version 2.1), whose success criterion 1.4.3 sets the
contrast minimum for text.

## Why

A contrast ratio is computed from the two colours the reader actually sees. A page with a dark and a
light scheme is two pages for this purpose: every text colour, every tinted background and every
translucent colour is a different pair in each. A checker running in a headless browser sees whichever
scheme the browser reports, which is light unless it is told otherwise, so one pass checks half of
what ships.

Translucent text is where the two diverge most. A colour such as `rgba(196,207,221,.56)` is blended
with whatever is behind it: the same declaration gives 4.48:1 on the page and 4.41:1 on a card, both
under the 4.5:1 that SC 1.4.3 asks of normal text; at `.62` it gives 5.22:1 and 5.13:1. The light
scheme's dim text is opaque and passes for that colour; its own failure is a different opaque grey
(`--classical`, 4.31:1 on the page background), which the checker finds only in the light pass. Each
scheme fails on a colour the other never shows.

## When it applies

Any page with more than one colour scheme, a high-contrast mode or a theme switch. It applies to the
public copy of a page as well as the served one when they share stylesheets. It does not replace a
person checking with a keyboard and a screen reader: axe-core finds what can be computed from the
page, not whether the page makes sense read aloud.

## How to apply it

Open one browser page per scheme and run the same check in each (Playwright's `color_scheme`):

```python
# tools/a11y_check.py
for scheme in ("light", "dark"):
    page = browser.new_page(color_scheme=scheme, reduced_motion="reduce")
    ...
    res = page.evaluate("tags => axe.run(document, {runOnly: {type: 'tag', values: tags}})",
                        ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"])
```

Fix a failing colour at its definition, not at each use: here one variable in each scheme's block
of `style.css` and `header.css`. Keep the check as a test (`tests/test_accessibility.py`) so a new
colour is measured before it ships.
