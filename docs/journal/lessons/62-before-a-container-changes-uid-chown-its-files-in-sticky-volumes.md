---
id: lesson-62-before-a-container-changes-uid-chown-its-files-in-sticky-volumes
type: lesson
title: "Before a container changes the user it runs as, change the owner of the files it appends to in a shared, sticky directory; the kernel refuses even root"
date: 2026-11-05
audience: [engineer]
rung: all
tags: [agility]
one_line: "With fs.protected_regular set, as Ubuntu sets it, an open that may create a file in a world-writable sticky directory fails when the file belongs to someone other than the opener and the directory's owner, root included; a container switched from one uid to another over a kept volume cannot append to its own earlier log until the file is handed over."
claims:
  - text: "fs.protected_regular, when set, refuses an O_CREAT open of an existing regular file in a world-writable sticky directory unless the file is owned by the opener or by the directory's owner; at 2 it applies to group-writable sticky directories too."
    provenance: "cited: Linux kernel documentation, admin-guide/sysctl/fs.rst, protected_regular"
  - text: "On Ubuntu 24.04 with fs.protected_regular = 2, the system runner switched from uid 1001 to root could not append to the jobs.jsonl it had written as 1001 in its log volume (directory mode 1777, owned by root) until the file was given to root."
    provenance: "observed 2026-11-04 on the demo GB10; kit/compose.system.yaml comment; docker exec pqch-system-runner-1 chown 0:0 /var/pqch-runner/jobs.jsonl"
reuse: [runbook]
---

# Before a container changes the user it runs as, hand over the files it appends to in a sticky volume

## The rule

When a service that keeps a log or a state file in a shared, world-writable, sticky directory is
moved to another user (a container's `user:` changed, from the operator's uid to root or back),
change the owner of those files to the new user before it starts. Do not assume root can write
anything.

## Why

A sticky directory (mode `1777`, like `/tmp`) lets anyone create files in it but lets only a file's
owner remove or rename it. Linux's `protected_regular` setting goes further, against a class of
attacks in which a file is planted where a privileged program will open it. An open with `O_CREAT`
of an existing file in such a directory is refused when the file belongs to neither the process nor
the directory's owner. Appending with "create if missing" (Python's `open(path, "a")`, the shell's
`>>`) uses `O_CREAT`. Ubuntu sets the value to 2. So a runner that wrote `jobs.jsonl` as uid 1001 and
then restarts as root is refused on its own log, with `EACCES`. That reads like a permissions bug in
the runner and is the kernel working as intended.

## When it applies

A volume or bind mount whose directory is world-writable and sticky, a file in it owned by the
previous user, and a new user that is neither that owner nor the directory's owner. It does not
apply to a directory owned by the new user, or to a volume created fresh after the change.

## How to apply it

Hand the files over before the first write as the new user:

```sh
docker exec <container> chown 0:0 /var/pqch-runner/jobs.jsonl     # to root
docker exec <container> chown 1001:1001 /var/pqch-runner/jobs.jsonl  # and back
```

Better still, give each service a directory owned by the user it runs as, so the sticky bit is not
needed. The kit's `compose.system.yaml` records the step beside the setting that changes the user.
