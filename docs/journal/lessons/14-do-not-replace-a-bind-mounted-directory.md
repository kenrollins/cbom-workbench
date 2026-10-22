---
id: lesson-14-do-not-replace-a-bind-mounted-directory
type: lesson
title: "Do not switch branches under a running container that bind-mounts the tree; make the health check read the files"
date: 2026-10-05
audience: [engineer]
tags: [discovery]
rung: all
one_line: "A bind mount follows the directory that existed when the container started; when a checkout deletes and recreates that directory, the container keeps an empty one and a liveness check still passes."
claims:
  - text: "After a checkout to a branch without two directories and back, a running container that bind-mounted them saw both empty; its scan and propose actions failed and its health endpoint answered ok for about an hour."
    provenance: "measured 2026-10-05, lab deployment on the xr7620, Docker 29.1.5; M0B review F-59"
reuse: [customer-question]
---

# Do not switch branches under a running container that bind-mounts the tree; make the health check read the files

## The rule

A deployment that bind-mounts directories from a working tree must not share
that tree with branch switching. And a health check must open the files the
service needs, not only answer.

## Why

A bind mount attaches a directory by identity, not by path. When
`git checkout` moves to a commit in which a directory does not exist, git
removes it; coming back, git creates a new directory with the same name. The
container still holds the old, now deleted, one — and sees it empty. A
directory that exists in both commits survives, which is why the fault
touches some mounts and not others.

Nothing restarts and nothing logs. The service fails only when it next reads
a file from the lost mount, which may be minutes into a long operation. A
health endpoint that returns a constant reports a process, not a service.

## When it applies

Development and lab deployments run straight from a repository checkout:
Compose files with `./config:/app/config` style mounts. It applies equally to
any tool that replaces a directory instead of changing it in place — some
editors, `rsync --delete` with a rename, unpacking an archive over a tree.

It does not apply to named volumes, or to files copied into the image.

## How to apply it

- Deploy from a checkout nobody works in, or copy read-only configuration
  into the image and mount only what must change at run time.
- In the health endpoint, check that each file the service will need is
  readable, and answer 503 naming the missing one:

```python
# src/pqch/ui/app.py
missing = [str(p) for p in (KEY, POLICY, Path(os.environ.get("PQCH_POLICY", "policy/pq-algorithms.yaml")))
           if not p.is_file()]
if missing:
    return JSONResponse({"ok": False, "missing": missing}, status_code=503)
return {"ok": True}
```

- After any branch switch on a host with running containers, compare
  `ls` inside the container with `ls` on the host for each mounted directory,
  and recreate the container if they differ.
