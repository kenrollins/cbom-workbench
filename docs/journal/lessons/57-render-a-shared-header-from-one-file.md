---
id: lesson-57-render-a-shared-header-from-one-file
type: lesson
title: "When two renderers must show the same header, give them one stylesheet and one markup shape, copied at build time; a second implementation that matches by description drifts"
date: 2026-11-04
audience: [engineer]
rung: all
tags: [agility]
one_line: "A header that an application renders from a template and a static-site generator renders from a theme override stays identical only when both load the same stylesheet file and emit the same element shape; a second stylesheet written to look the same is a second design, and the reader sees the whole band change when they cross from one to the other."
claims:
  - text: "With one header stylesheet copied into the site build and one markup shape in both templates, the demonstration's pages and the notes site render the brand row and the tab row at the same height, 58 px and 44 px, at 1920 px and 1366 px wide."
    provenance: "observed 2026-11-04, demo GB10, Firefox headless screenshots of / and /site/ at both widths"
reuse: [runbook]
---

# When two renderers must show the same header, give them one stylesheet and one markup shape, copied at build time; a second implementation that matches by description drifts

## The rule

Where an application and a static site are meant to read as one place, the
header is one file: one stylesheet, which the application serves and the site
build copies in, and one element shape, which the application's template and
the site's theme override both emit. The site's own theme styles the page
below the header and nothing above it. Nothing about the header is written
twice.

## Why

A header described twice — "boxed on the left, the notes on the right, the
same two rows" — is implemented twice, and two implementations agree only on
the day they are written. Each later change lands in one of them: a date line
under a label, a tighter gap, a kraft box. The reader does not see two
stylesheets; they see the band at the top of the page change colour, face and
height the moment they click from the demonstration into the notes, and read
that as leaving one site for another. That is the opposite of what the shared
header is for.

The static-site generator cannot read the application's stylesheet at serve
time, since it is served from another path and, on a published copy, from
another host. So the build copies the file in, beside the fonts it needs, and
the generator lists it before its own theme. Fonts referenced by a relative
path resolve in both places when a `fonts/` directory sits beside the
stylesheet on each side. The generator's own additions — the search box, the
drawer that opens the index on a narrow screen — are styled in the site's own
file in the header's colours, which the header stylesheet carries as custom
properties on the header element itself, so the site needs no copy of the
application's palette.

## When it applies

Any application that serves a documentation site beside itself and wants the
two to share a header: a server-rendered app with a mkdocs or similar site
under a sub-path. It also holds for a published static copy of both, where the
copy must carry the file. It does not apply where the two are meant to look
different, and it does not make the generator's chrome (sidebar, search,
footer) part of the shared file; those stay the site's own.

## How to apply it

- The header's rules live in one file the application serves
  (`src/pqch/ui/static/header.css`), imported first by the application's
  stylesheet. The palette it needs is declared on the header element, not on
  `:root`.
- The site build copies that file in (`tools/build_site.py`, `copy_header`),
  beside the fonts, into `site_src/stylesheets/`; the copy is generated and
  git-ignored, and `mkdocs.yml` lists it before the site's theme.
- The application's template (`src/pqch/ui/templates/_header.html`) and the
  site's override (`site_overrides/partials/header.html`) emit the same
  elements with the same classes; the site's override adds the generator's
  tools inside the brand row, and the site's stylesheet styles only those.
- After a change, open the application's page and a site page side by side at
  each width the demonstration will be seen at and compare the header's rows;
  a difference in height or face means something was written twice.
