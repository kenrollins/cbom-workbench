---
id: lesson-81-text-checks-do-not-read-pixels
type: lesson
title: "Text checks do not read pixels: scrub a page before the browser draws it, check what it shows, and choose what is published by the scope it was authorized under, not by its kind"
date: 2026-11-21
audience: [engineer, architect]
rung: all
tags: [publication, verification, qa]
one_line: "A screenshot carries whatever the page showed, and no pattern over text files reads it; the capture tool rewrites the page's HTML before it is drawn and stops on a leak match in the text shown, fixtures use invented addresses, and a run is public by the scope it ran under, never by its kind."
claims:
  - text: "`tools/screenshots.py` serves each page through a route that scrubs the HTML before the browser draws it, then matches the leak patterns against the page's visible text and stops before the picture is written on any match."
    provenance: "by reading tools/screenshots.py (scrubbed, leaks_shown, serve_scrubbed) at HEAD; tests/test_export_public.py::test_a_screenshot_page_is_scrubbed_and_its_text_checked, passing on xr7620, 2026-11-21"
  - text: "The public build curates a run only when it is a scan whose scope declares no `copy` and no `captures`, or a run of an estate one of those scans is of with no listener their scopes do not name; a scan or an import under a copy's scope is left out whatever its kind."
    provenance: "by reading tools/build_public.py (curate, _of_estate) at HEAD; tests/test_export_public.py::test_only_the_mini_agencys_runs_are_curated"
  - text: "Test fixtures use documentation address ranges and a neutral tool name, and the leak check reads every text file and path in the export."
    provenance: "commits b390fe9 and 1f86ca2; tests/test_export_public.py::test_the_leak_check_reads_every_file_and_path_whatever_the_case"
reuse: [runbook, whitepaper]
---

# Text checks do not read pixels: scrub a page before the browser draws it, check what it shows, and choose what is published by the scope it was authorized under, not by its kind

## The rule

Treat every artefact a text check cannot read as unchecked: an image, a
drawing, a binary fixture. Make such artefacts safe at the source. A
screenshot is taken of a page that was scrubbed before it was drawn, and the
text the page shows is checked before the picture is kept. Data is chosen for
publication by where it came from, which is the scope it was collected
under, and never by a label that describes what kind of operation made it.

## Why

A leak check is a set of patterns run over text. Three kinds of place are
outside it.

**Pixels.** A screenshot of a running application shows what the application
showed: the signed-in account in the header, the name of the identity
provider in a badge, a host name in a breadcrumb. In the image file those are
coloured dots. The export's patterns pass over the file without a match, the
build passes, and the name is published in a form any person can read and no
tool did. Scrubbing the image afterwards is unreliable; the dependable place
is before the browser lays the page out, where the content is still text.

**Fixtures.** Test data is copied from life because life is where the awkward
cases are. A fixture built from a real capture keeps the capture's addresses.
A leak check that reads only documentation, or only files of certain
extensions, never opens it.

**Comments and paths.** A name in a stylesheet comment, or in a file's path,
is text that many checks skip, and it is often in a different case from the
listed form ([lesson 80](80-a-check-with-nothing-loaded-must-say-so.md)).

A fourth place is not a file type at all. A public build has to decide which
runs it may show. The tempting test is the run's kind: scans of the
demonstration estate are public, captures of a private network are not, and
an "import" sounds harmless. But kind says what was done, not to what. An
import of another tool's document under the scope of a private network
carries that network's addresses. **Kind is not provenance.** The scope a run
was authorized under is, and it is recorded in the run's first event.

## When it applies

Whenever a project with private surroundings publishes: screenshots in
documentation, recorded demonstrations, sample data, test suites in a public
repository. It applies to drawings too: a figure cannot be marked for
removal, so a private finding is never drawn in an entry that is published
(`docs/journal/STYLE.md`, Drawings).

## How to apply it

1. Capture screenshots through a tool, never by hand, and have the tool
   rewrite each response before the browser draws it:

    ```python
    # tools/screenshots.py
    page.route("**/*", serve_scrubbed)          # the HTML is scrubbed on the way in
    shown = leaks_shown(page.inner_text("body"))  # then the visible text is checked
    ```

    A match stops the run before that page's picture is written.
2. Take screenshots from an estate built for showing, signed in as a
   placeholder identity, so that there is little to scrub.
3. Write fixtures with documentation ranges (192.0.2.0/24, 198.51.100.0/24,
   203.0.113.0/24, 2001:db8::/32), invented names and invented dates. When a
   real capture supplied the awkward case, keep its shape and replace its
   values.
4. Run the leak check over every text file and every path in what is
   published, without regard to case and without a list of extensions.
5. Select published data by provenance. Start from the scans of the estate
   built for publication; admit another run only if its scope is of that
   estate and names no listener those scans do not name; refuse anything
   whose scope declares a copy or a capture.
6. Look at each published picture once, as a reader. This step has no
   automation and is the only one that reads pixels.

## Where the claim stops

The visible-text check reads the page's text nodes. It does not read text
drawn inside a canvas, an embedded image or a font glyph substitution; a
page that draws a name that way still needs the look in step 6. The
selection in step 5 trusts the scope a run recorded; a run made under the
wrong scope is wrong at its source.

