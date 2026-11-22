---
id: lesson-84-a-test-double-applies-the-boundarys-transformation
type: lesson
title: "A test double must apply the one transformation the real boundary applies"
date: 2026-11-21
audience: [engineer]
rung: all
tags: [verification, discovery, qa]
one_line: "A fake ssh that executes its argument list is kinder than sshd, which joins the words and hands them to a shell; a route tested against the fake failed on a real server and would have run a scoped path's $() on it. The stand-in now does what the boundary does, and nothing of the scope travels on the remote command line."
claims:
  - text: "The SSH route sends the system's definition inside the program on stdin; the remote command is the interpreter and `-` alone, after `--` and the destination, with the interpreter's path quoted."
    provenance: "by reading src/pqch/scout/system.py (remote_pack, remote_source) at HEAD; commit 10320bb"
  - text: "The test stand-in for ssh joins the words after the destination with spaces and runs them through `sh -c`, as sshd does; with that one change and the route as it was, the existing route test failed."
    provenance: "by reading tests/test_remote_system.py (fake_ssh) at HEAD, 6 tests passing on xr7620, 2026-11-21; the failure of the earlier route against the corrected stand-in as recorded in commit 10320bb"
  - text: "A layer entry's path loses only a leading `./` or `/`; stripping the characters `.` and `/` instead turned a root-level whiteout `.wh.app` into `wh.app` and `.env` into `env`."
    provenance: "by reading src/pqch/scout/imagefiles.py (member_path) at HEAD; tests/test_imagefiles_review.py; commit 3884e4f"
reuse: [runbook, whitepaper]
---

# A test double must apply the one transformation the real boundary applies

## The rule

Before trusting a stand-in for an external program, name what the real thing
does to its input between your call and the far side: joins it, re-parses it,
re-encodes it, truncates it, reorders it. The stand-in does the same, even if
it does nothing else faithfully. A double that skips that step tests the code
against a boundary that does not exist.

## Why

`ssh host cmd arg1 arg2` looks like running `cmd` with two arguments on
another machine. It is not. The client joins every word after the destination
with spaces into one string and sends the string; the server hands that
string to the user's shell. The shell splits it again, by its own rules, and
expands what it finds: `$()`, backticks, globs, semicolons.

Code that passes a JSON document as one argument therefore works locally and
arrives on a real server as shell input: its quotes are consumed, its braces
and spaces split it, and the program at the far end is handed fragments. A
value inside it, such as a file path taken from a scope file, that contains
`$(…)` is executed on the remote host as the logged-in user. One defect is a
failure and the other is command injection, and they are the same defect.

A fake `ssh` written for the test, which takes its arguments as a list and
executes them as a list, never performs the join and the re-parse. Every
argument arrives intact. The test passes, and it passes *because* the double
is kinder than the boundary. The evidence that this is the whole story is
direct: change the stand-in to hand the joined words to `sh -c` and the
existing test fails with no other change.

The same shape appears inside one process, where a library function is the
boundary and the misreading is of what it does:

- `name.lstrip("./")` reads as "remove a leading `./`". It removes every
  leading character that is a `.` or a `/`. A container image marks a deleted
  directory with a whiteout entry named `.wh.<name>`; stripped this way,
  `.wh.app` becomes `wh.app`, the whiteout is no longer recognised, and a
  directory removed in a later layer stays in the inventory.
- A test that writes a configuration file and asserts only that the code
  under test accepted it passes on a file of any shape. If nothing in the
  test reads the file the way its real consumer does, the file is not
  tested.

In each case a check passed against something more forgiving than what the
code meets in use.

## When it applies

Every test that replaces a process, a network service, a shell, a parser or
a file format with something simpler: fake `ssh`, fake `docker`, a mocked
HTTP client, an in-memory database, a stub of a command-line tool. It
applies whenever untrusted or semi-trusted strings cross the boundary,
because the transformation the double skipped is usually the one that makes
them dangerous.

## How to apply it

1. Write down the boundary's transformation in the double's docstring. If you
   cannot say what it is, find out with one run against the real thing.
2. Implement that step in the double:

    ```python
    # tests/test_remote_system.py, fake_ssh
    subprocess.run(["sh", "-c", " ".join(cmd)], stdin=sys.stdin, env=env)
    ```

3. Send data across a shell boundary as data: on standard input, with the
   remote command reduced to an interpreter and `-`. Put `--` before the
   destination and quote the one word that remains.

    ```python
    # src/pqch/scout/system.py, remote_pack
    cmd += ["--", f"{via['user']}@{via['host']}", shlex.quote(via["python"]), "-"]
    subprocess.run(cmd, input=remote_source(system, prefix).encode(), …)
    ```

4. Add a hostile case to the test: a path containing `$(touch marker)`, and
   an assertion that no marker appears.
5. For string functions, test the case the name suggests and the case the
   semantics allow: a prefix remover against a name that merely begins with
   the same characters. Use `removeprefix`, or an explicit loop, for a
   prefix.
6. For a file a test writes, read it back in the test with the parser its
   real consumer uses.
7. Run the path once against the real boundary before calling it built.

## Where the claim stops

The stand-in applies the join and the shell; it does not reproduce a real
server's login shell, its environment, a restricted command in
`authorized_keys`, or an interpreter older than the program expects. The
corrected route is tested against the stand-in; a full run against a second
real server is still owed.
