---
id: lesson-17-rebuild-what-must-match-the-source
type: lesson
title: "In a bundle build, always rebuild what must match the source and record the commit; reuse only what must not change"
date: 2026-10-05
audience: [engineer]
tags: [verification]
rung: all
one_line: "A build step that skips an image because its tag already exists ships whatever was built first; a test of the bundle then tests old code."
claims:
  - text: "An offline bundle tested as the committed build held a harness image built before the last three commits that changed the source; two source files in it differed from the commit, one of them the verifier."
    provenance: "measured 2026-10-05 by comparing the image's source tree with commit 427f9a0; image created 2026-10-04 13:38 UTC, the three commits 14:25 to 14:57 UTC; M0B review F-57"
  - text: "Rebuilding the harness for two architectures on every bundle build, with the dependency layers cached, takes about 75 s for the whole bundle build."
    provenance: "measured 2026-10-05, bundle/build.py, xr7620 (x86_64), arm64 under qemu-user"
reuse: [customer-question]
---

# In a bundle build, always rebuild what must match the source and record the commit; reuse only what must not change

## The rule

A packaging step decides, per artifact, whether reuse is correct. Artifacts
that must equal the current source are built every time and stamped with the
commit they came from. Artifacts that must stay the same from one package to
the next are reused, on purpose and by name.

## Why

"Skip it if it already exists" is added to a build to save time, and it is
keyed on a tag. A tag says nothing about what is behind it. The first build
populates the registry; every later build finds the tag and moves on. The
package's manifest gets a fresh timestamp, the test of the package passes,
and the code inside is from the first build.

The same build may hold artifacts for which reuse is the requirement. Test
targets that generate keys and certificates when built become different
targets on every rebuild; an answer key or a recorded scan then describes
something that no longer exists. Treating both kinds with one flag is the
error — whichever way the flag is set, one kind is wrong.

A layer cache already makes the always-rebuild path cheap: unchanged
dependency layers are reused by content, which is safe, where reuse by tag is
not.

## When it applies

Offline bundles, release archives, base images for a lab, any build with an
"if not present" shortcut. It applies whenever a package will be tested in
place of the source it is supposed to contain.

## How to apply it

- Build source-derived images unconditionally and let the builder's cache do
  the saving.
- Write the commit, and whether the tree was clean, into the package's
  manifest:

```python
# bundle/build.py
commit = sh("git", "rev-parse", "HEAD")
if sh("git", "status", "--porcelain", "--", "src", "Dockerfile", "pyproject.toml", "uv.lock"):
    commit += "-dirty"
```

- Reuse fixtures explicitly, with a flag that rebuilds them when that is
  what is meant.
- Before testing a package, compare the commit in its manifest with the one
  under test. A test report names both.
