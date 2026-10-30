---
id: lesson-47-look-at-the-published-page-as-a-visitor-sees-it
type: lesson
title: "Before a demonstration, open the published page in a browser at each width it will be seen at, and read its network log"
date: 2026-10-30
audience: [engineer]
rung: all
tags: [cbom]
one_line: "A test suite, a link crawl and a leak check all pass on a page whose fonts never load and whose figure collapses on a phone; only a browser, rendering the published copy at desktop and phone width with the network log open, shows what a visitor sees."
claims:
  - text: "The public demo's three font files returned 404 on every page for eight days, because the stylesheet named them by a root-absolute path and the site is served under a base path; the crawler, the tests and the publish check all passed in that time."
    provenance: "measured 2026-10-30 against kenrollins.github.io/cbom-workbench; fixed the same day by naming the fonts relative to the stylesheet"
  - text: "At 390 px the overview's seven-column figure rendered as seven overlapping columns, because a later unguarded rule overrode the narrow-width rule; at 1440 px the CBOM page scrolled sideways by 265 px because one grid column had no minimum of zero."
    provenance: "measured 2026-10-30 with headless Chromium (Playwright 1.57) at 390 and 1440 px against the deployment's state"
reuse: [runbook]
---

# Before a demonstration, open the published page in a browser at each width it will be seen at, and read its network log

## The rule

Before showing a page, render the published copy, not the source tree, in a
real browser at every width it will be seen at, with the network log open, and
look at it.

## Why

The checks a project runs are blind to how a page looks. A test suite renders
templates and asserts on text. A crawler follows links and reports status
codes, but a stylesheet's `url()` references are not links, so a font that
fails to load is invisible to it. A leak check reads words. None of them
notice that a figure's columns overlap on a phone, that a page scrolls
sideways on a laptop, or that every heading is in a fallback face because
the fonts were named by a root-absolute path and the site is served under a
base path. A visitor notices all of it in the first second.

The published copy differs from the development copy in exactly the ways
that break these things: another base path, another mode (a static snapshot
instead of a live server, so a message about a missing sign-on reads as an
error), another viewport.

## When it applies

Any page served at a base path other than `/`, any page served from a static
build of a dynamic one, and any page that will be opened on a phone from a
link. It matters most before a demonstration, when the page will be seen by
people who will not report what they saw.

## How to apply it

- Render the published address, not the source, at 1440 px and 390 px, in
  the dark and the light scheme. Headless Chromium through Playwright does
  it in a script; keep the script.
- Record every failed request and every console error on each page; a font
  or a script that fails to load is a failed request, not a broken link.
- Measure `document.documentElement.scrollWidth` against the viewport on
  every page; anything wider scrolls sideways. Find the element that overflows
  its parent; the fix is usually `minmax(0, 1fr)` in a grid, `overflow-x:
  auto` on a table, or a media rule that a later rule overrides.
- Name assets relative to the stylesheet (`url(fonts/x.woff2)`), never by a
  root-absolute path, so one stylesheet works at any base.
- Read every message the static copy shows that a live server would not:
  a form's absence, a sign-on notice, "live state" on a snapshot.
