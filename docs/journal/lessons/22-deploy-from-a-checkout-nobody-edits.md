---
id: lesson-22-deploy-from-a-checkout-nobody-edits
type: lesson
title: "Deploy from a checkout nobody edits"
date: 2026-10-08
audience: [engineer]
tags: [deployment, containers, operations]
rung: all
one_line: "A running container that bind-mounts a directory from a development tree breaks silently when a branch switch replaces that directory; run a deployment from its own detached checkout, with its state beside it, and move it to a commit on purpose."
claims: []
reuse: [runbook, customer-question]
---

# Deploy from a checkout nobody edits

## The rule

Run a deployment from a checkout that exists only to be run — a detached
worktree or a clone pinned to a commit — with its state in a directory of
its own beside it. Never from the tree where code is edited and branches are
switched. Deploying a change is an explicit step: move the checkout to the
commit, rebuild, recreate.

## Why

A container's bind mount is bound to a directory's inode, not its path. When
a branch switch deletes and recreates a directory that the running container
mounts — a policy directory, a configuration directory — the container keeps
the deleted one and sees it empty. Nothing restarts, nothing logs an error,
and a health check that only asks "is the process up" keeps answering yes. In
this project the page's scan and propose buttons were broken for an hour that
way, and the commit that recorded the page as working was made in the same
second as the switch that broke it
([lesson 14](14-do-not-replace-a-bind-mounted-directory.md) is the
mechanism; this lesson is the practice that avoids it).

A separate checkout also makes "the build being shown" a fact: the deployed
commit is whatever the checkout is at, and `git worktree list` says what that
is. Numbers shown on a page can then be tied to a commit without trusting
memory.

## When it applies

Any deployment that bind-mounts files from a source tree: compose projects
run from a repository, a static site served from a build directory, a
configuration directory mounted into a service. It applies doubly where a
coding agent works in the same tree, because an agent switches branches to
review and compare, and does so without the pause a person might take.

## How to apply it

- One checkout per deployment, detached at a commit; a worktree of the
  development repository is enough and shares its objects.
- State — ledgers, raw output, scope files, generated configuration — in a
  directory the checkout points at by configuration, not inside the checkout,
  so a change of commit never moves the record.
- Git-ignored working files the deployment needs (environment, overlays,
  rendered configuration) copied into the checkout and listed, so the next
  person knows what is there that the repository does not hold.
- A health check that reads the files the service depends on and names the
  one it cannot read, so the silent case cannot recur unnoticed.
- The deploy procedure written down as three commands: move the checkout,
  rebuild, recreate.
