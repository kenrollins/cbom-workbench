---
id: lesson-20-know-each-servers-precedence-rule
type: lesson
title: "Before reading a configuration, know which occurrence of a setting wins in that software"
date: 2026-10-05
audience: [engineer]
tags: [discovery, key-establishment]
rung: structured
one_line: "OpenSSH takes the first value it reads, PostgreSQL the last, nginx the innermost block; the same two lines in a different order, or an include in a different place, give a different listener."
claims:
  - text: "OpenSSH 10.0 with KexAlgorithms set twice in sshd_config offered the first line's algorithms; with an Include of a drop-in directory at the top of the file the drop-in's value won, and with the same Include at the bottom the main file's value won."
    provenance: "measured 2026-10-05, spike S3 lab, ssh-audit 3.9.0; items r5-s02, r5-s03, r5-s05"
  - text: "PostgreSQL 18 with ssl_groups set twice accepted the last line's groups; a value in a file included after the main file's own line replaced it, and included before it did not."
    provenance: "measured 2026-10-05, same lab; items r5-p02, r5-p03 and r4-34"
  - text: "nginx 1.28 with ssl_ecdh_curve at http level and again in a server block accepted only the server block's groups; a commented-out line and a file not matched by the include pattern had no effect."
    provenance: "measured 2026-10-05, same lab; items r5-n03, r5-n12, r5-n13"
reuse: [customer-question]
---

# Before reading a configuration, know which occurrence of a setting wins in that software

## The rule

Tracing a behaviour to "the line that sets it" requires the software's own
precedence rule. State the rule for each kind of server before reading its
files, and resolve includes in the order the server does.

## Why

Configuration grows by accretion: a hardening pass appends a line, a policy
tool drops a file into a directory, a base image ships defaults. The result
is a setting that appears more than once. Which occurrence takes effect is
not a convention shared across software.

| Software | A setting given twice | Included files |
|---|---|---|
| OpenSSH (`sshd_config`) | The **first** value read is used; later ones are ignored | Read at the point of the `Include` line: an include at the top beats the main file, at the bottom it loses |
| PostgreSQL (`postgresql.conf`) | The **last** value read is used | Read at the point of the `include`: after the main file's line it wins, before it loses |
| nginx | The **innermost** block that sets it wins: `server` over `http` | Inlined where the `include` stands; a file the pattern does not match is not read at all |

A reader — or a tool, or a language model — that carries one rule to all
three will name the wrong line with confidence, and a change made to that
line will apply cleanly and alter nothing. The verifier then reports that the
change did not land, which is the right answer to the wrong edit.

Two things that are never the cause: a commented-out line, however recent it
looks, and a file left in a configuration directory under a name the include
pattern does not match.

## When it applies

Any step that maps observed behaviour to configuration: a migration plan, an
audit finding that cites a line, an automated change. It matters most on
servers configured in layers — distribution defaults, drop-in directories,
generated files.

## How to apply it

- Ask the server for its effective configuration where it can tell you:
  `sshd -T`, `SHOW ssl_groups;` in PostgreSQL, `nginx -T` for the inlined
  text.
- When proposing an edit, edit the occurrence that wins, and say why it is
  that one.
- Confirm by observation: change that line's value and probe
  ([lesson 19](19-confirm-a-cause-by-changing-it.md)).
