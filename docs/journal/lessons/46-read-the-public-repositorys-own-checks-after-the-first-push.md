---
id: lesson-46-read-the-public-repositorys-own-checks-after-the-first-push
type: lesson
title: "After publishing a repository, read its own checks: they run in an environment the export was never tested in"
date: 2026-10-22
audience: [engineer]
rung: all
tags: [cbom]
one_line: "A repository published from a private working copy carries workflow files written for some earlier state of it; they run on every public push, and a red mark on the front page is the first thing a reader sees. Run the workflows' steps on a clean copy of the export before publishing, and read their result after."
claims:
  - text: "Both workflows in this project's public repository failed on its first two pushes: the CI job on 29 lint findings and a link checker that predates the demo's shared header, the Pages job because it deployed from the main branch while Pages is served from the gh-pages branch the publish command pushes."
    provenance: "measured 2026-10-22, GitHub Actions runs of kenrollins/cbom-workbench"
reuse: [runbook]
---

# After publishing a repository, read its own checks: they run in an environment the export was never tested in

## The rule

Before publishing, run each workflow's steps on a clean copy of the exported
tree; after publishing, read the repository's check results.

## Why

A working repository accumulates continuous-integration workflows (the
automated checks a hosting service runs on every push) written for the state
it was in when they were added. In private, a failing one is easy to stop
seeing. Published, every push runs it in a fresh machine against the export,
which differs from the working copy: files are left out, passages stripped,
another branch serves the site. A failure there is shown beside every commit,
and it is the first signal a reader gets of whether the project works.

## When it applies

Any repository published as an export or a fresh history from a private
copy, and any first push of a repository to a new host. It matters less for a
repository developed in public, where the checks already run on every change.

## How to apply it

- List the workflows the export carries; delete any that duplicate the
  publish step (here a Pages workflow, where Pages is published from a branch).
- Run each remaining step on a clean copy of the export, with a fresh
  environment: `uv sync --group dev`, the linter, the tests, the strict site
  build.
- After the push, read the result (`gh run list -R owner/repo`) before telling
  anyone where the repository is.
