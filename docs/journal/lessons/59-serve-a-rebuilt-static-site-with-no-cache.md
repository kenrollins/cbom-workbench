---
id: lesson-59-serve-a-rebuilt-static-site-with-no-cache
type: lesson
title: "Serve a static site that is rebuilt in place with Cache-Control: no-cache; without it the browser keeps old pages for a tenth of their age"
date: 2026-11-05
audience: [engineer]
rung: all
tags: [agility]
one_line: "A response with Last-Modified and no Cache-Control lets the browser choose its own freshness, typically a tenth of the time since the file last changed, so a page built days ago is reused for hours after a rebuild; send no-cache, and the ETag keeps the check cheap."
claims:
  - text: "HTTP caching allows a cache to assign heuristic freshness to a response with no explicit expiry, typically a fraction of the time since Last-Modified; RFC 9111 gives 10% as a typical fraction."
    provenance: "cited: RFC 9111, HTTP Caching, section 4.2.2"
  - text: "After the notes site's pages were rebuilt with a new header, Firefox went on showing the old header on pages it had visited before, while the server returned the new one; served with Cache-Control: no-cache, every visit revalidates and shows the current page."
    provenance: "observed 2026-11-05 on the demo GB10: curl against /site/notes/ returned the new header while the browser showed the old; src/pqch/ui/app.py, _Revalidated"
reuse: [runbook]
---

# Serve a static site that is rebuilt in place with Cache-Control: no-cache

## The rule

When an application serves a static site from a directory that is rebuilt in place, have it send
`Cache-Control: no-cache` with every file. A page whose header or content must change together with
the application's pages should never be left to the browser's own freshness guess.

## Why

A file server such as Starlette's `StaticFiles` sends `Last-Modified` and an `ETag` but no
`Cache-Control`. With no stated expiry, HTTP lets a browser choose a heuristic freshness, typically a
tenth of the time since the file last changed (RFC 9111, section 4.2.2). During that time the
browser does not ask the server at all. A page built three days ago is therefore reused for about seven
hours after a rebuild. The server is right, the reader sees the old page, and a reload shows the old
page again. Here the result was a site header that still had a removed tab and lacked a new one, on
some pages and not others, depending on which pages the reader had opened before.

`no-cache` does not stop caching. It makes the browser ask before reusing its copy. With an `ETag`
the answer is a `304 Not Modified` with no body, so the cost is one round trip per page.

## When it applies

Any static content the reader expects to change with the application: documentation served beside a
demonstration, a preview of a build, a generated report. It does not apply to fingerprinted assets
(file names that carry a content hash), which can be cached for a long time because a new build
gives them new names.

## How to apply it

Subclass the static handler and set the header (`src/pqch/ui/app.py`):

```python
class _Revalidated(StaticFiles):
    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response
```

Check it with `curl -sI <url> | grep -i cache-control`. Copies that a browser saved before the change
carry no such header and stay until they expire. Clear them once, with a hard reload of each page or
by clearing the browser's cache.
