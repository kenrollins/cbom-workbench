# Accessibility: what was tested, and what was found

*Tested 2026-11-09 at commit `ef9e117` plus the fix named below. This is a test report, not an
Accessibility Conformance Report: it records what an automated check and an automated keyboard pass
found on the workbench's pages. The VPAT 2.5 table a solicitation asks for needs the two tests this
report says were not done.*

## Result

| Test | Covered | Result |
|---|---|---|
| WCAG 2.1 level A and AA rules, axe-core 4.11.2 in headless Chromium | 13 pages, each in the light and the dark scheme: 26 checks | 0 violations after one fix |
| Keyboard only, automated: Tab through every shown control | 11 pages, 413 controls | 413 reached, each with a visible focus indicator |
| Screen reader, by a person | none | not tested |
| Keyboard walkthrough of a full task, by a person | none | not tested |

**The one defect found and fixed.** On the plan page in the light scheme, the label of a rehearsed
step (`.pill.rehearsed`, 11 px) had a contrast ratio of 4.24 against its tinted panel, below the 4.5
that WCAG 1.4.3 requires. The warning colour of the light scheme is now `#7a5c0f`, which gives 5.24
on that panel and 6.24 on white. The dark scheme passed unchanged.

## What was covered

The pages a reader reaches from the header, served from a deployment's recorded runs:

- Without a sign-on (9 pages): the overview `/`, the demo stage `/demo`, the walkthrough, the test
  agency, the CBOM, the plan, the imports page, Ask the CBOM, About.
- With a sign-on (4 pages): the hosts page, the page for a real network, a server's plan, and the
  change page with its approve, apply and reset buttons.

Width 1440 px, reduced motion on, each page loaded to network idle before the rules ran. The keyboard
pass ran on eleven of the thirteen: the page for a real network and the server's plan were left out.

## How to repeat it

```sh
# a Python with Playwright; the axe build is the vendored test asset, nothing is fetched
python3 tools/a11y_check.py --base http://127.0.0.1:8080 / /demo /walkthrough /agency /cbom /plan /imports /ask /about
python3 tools/a11y_check.py --base http://127.0.0.1:8080 --header X-Forwarded-User=NAME /hosts /resolve
python3 tools/a11y_check.py --base http://127.0.0.1:8080 --keyboard / /demo /walkthrough /agency /cbom /plan /imports /ask /about
```

The first two exit non-zero on any serious or critical violation; the third on any shown control the
Tab key did not reach or that took focus with no outline and no shadow.

## What the keyboard pass does and does not show

It presses Tab until every focusable, shown control on the page has had focus, and checks that each
one shows an outline or a shadow when it does. A control inside a closed disclosure (`<details>`) is
not counted until its summary, which is counted, is opened: the walkthrough has 50 of those and the
change page 2. The Ask page puts focus in its question box when it loads, so a keyboard user starts
below the header and the skip link; Shift+Tab reaches them. That is allowed, and worth a person's
judgement.

It does not show that the order makes sense, that a task can be finished without a pointer, that a
chart's content is available without sight, or that a status change is announced. Those need a
person.

## Not covered

- **A screen reader.** No page was read with one. The diagrams are SVG drawn by d3 (the overview's
  figure, the estate map, the plan's lanes); axe checks that they do not break a rule, not that their
  content is conveyed.
- **The notes site** (the pages under `/site/`), which is built by Material for MkDocs with this
  project's theme. Not checked here.
- **Narrow screens.** Checked at 1440 px only; lesson 47 records a phone-width layout defect that a
  render found and no test had.
- **Error responses.** A path the app does not serve answers with a bare status and no page, so it
  has no title and no language; a browser shows a line of text.
- **Other colour settings:** forced colours and 200% zoom were not checked.

## What an Accessibility Conformance Report still needs

1. A person walking the main task with a keyboard only: open the CBOM, find an entry, read the plan,
   approve and apply one change.
2. A screen-reader pass on the same task, with NVDA and with VoiceOver.
3. The VPAT 2.5 table (WCAG 2.1 A and AA, and the Revised Section 508 chapters that apply to a web
   application) filled from this report and those two, criterion by criterion.
