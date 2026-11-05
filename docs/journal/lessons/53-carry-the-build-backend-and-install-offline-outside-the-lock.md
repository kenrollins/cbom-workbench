---
id: lesson-53-carry-the-build-backend-and-install-offline-outside-the-lock
type: lesson
title: "An offline install carries the build backend with the wheelhouse and installs outside the lock file; nothing in the runbook calls the package manager's run command"
date: 2026-11-04
audience: [engineer]
rung: all
tags: [verification, discovery]
one_line: "A wheelhouse of runtime wheels is not enough: the project's own build needs its backend, a locked sync fetches from the lock's recorded URLs even with every wheel on disk, and a loader that shells out to `uv run` re-resolves the project on every call; install with `uv pip --offline --no-index` and run tooling under the environment's own interpreter."
claims:
  - text: "A wheelhouse of the project's 38 locked runtime wheels, carried to a GB10 with no package index, failed `uv sync --frozen` twice: first for the missing build backend (hatchling), then for its editable-install helper (editables); on the second attempt uv downloaded three wheels from the lock file's PyPI URLs although the same versions were in the wheelhouse. A non-editable `uv pip install --offline --no-index --find-links` of the requirements and then of the project installed 113 packages with no network."
    provenance: "measured 2026-11-04 on the demo GB10 (Dell Pro Max GB10, aarch64, uv 0.12.23, /etc/uv/uv.toml no-index) from the carry built on the lab's x86_64 host with pip download --platform manylinux2014_aarch64"
  - text: "bundle/load.py's scope step, written as `uv run pqch scope generate`, failed on the same box with 'docker was not found in the provided package locations' after the environment was complete, because `uv run` re-resolves the project against the box's index configuration; UV_NO_SYNC=1 made the same command use the environment as it stood."
    provenance: "measured 2026-11-04 on the demo GB10, bundle/load.py at commit dc252fb"
reuse: [runbook]
---

# An offline install carries the build backend with the wheelhouse and installs outside the lock file; nothing in the runbook calls the package manager's run command

## The rule

To install a Python project on a machine with no package index, carry three things beside the
runtime wheels: the build backend the project's `pyproject.toml` names and its dependencies, the
editable-install helper if the install is to be editable, and a requirements list exported from the lock
without the project itself. Install with `uv pip install --offline --no-index --find-links <wheelhouse>`,
the requirements first and then the project with `--no-deps`. Every tool the runbook then runs starts
with the environment's own interpreter (`.venv/bin/python`), never with `uv run`.

## Why

Three mechanisms, each enough on its own to stop an offline install.

A wheelhouse built by downloading the lock's runtime requirements holds what the project imports, not
what builds it. `uv sync` builds the project itself from source, which needs the backend `pyproject.toml`
names (here `hatchling`, with `packaging`, `pathspec`, `pluggy`, `tomlkit` and `trove-classifiers`), and
an editable install needs `editables` as well. None of these is a runtime dependency, so none is in the
lock's export.

A lock file records, for every package, the URL it was resolved from. `uv sync --frozen` installs from
those records; a `--find-links` directory is an extra source, not a substitute, and when the locked
distribution is not matched there uv fetches the recorded URL. On a box whose policy is "no downloads"
that is a silent policy breach: the download hook watched for `curl`, not for the package manager.

`uv run <command>` is "sync, then run". It resolves the project against the box's own index
configuration on every call, and on a box whose configuration says `no-index` it cannot see the carried
wheelhouse and fails before the command starts. A loader or a runbook step that shells out to `uv run`
therefore fails on exactly the machine the offline bundle exists for. The environment's interpreter
runs the installed package without resolving anything.

## When it applies

Any install on a host with no package index, or with a local index that does not hold the project's
pins: an offline bundle, an air-gapped rehearsal, a venue machine. It does not apply where the index is
reachable and allowed; there `uv sync --frozen` is the right command and the lock is the point.

## How to apply it

On the build host, with the lock as it stands (an aarch64 target from an x86_64 host):

```sh
uv export --frozen --no-dev --no-hashes -o requirements.txt
grep -v '^-e \.$' requirements.txt > req-noself.txt
pip download -r requirements.txt -d wheelhouse --platform manylinux2014_aarch64 --platform any \
    --python-version 3.12 --implementation cp --abi cp312 --abi abi3 --abi none --only-binary=:all:
pip download hatchling editables -d wheelhouse --platform any --python-version 3.12 --only-binary=:all:
rm wheelhouse/<project>-*.zip      # pip's source archive of the project tree, not a wheel
```

On the target, in the checkout:

```sh
uv venv --clear
uv pip install --offline --no-index --find-links wheelhouse -r req-noself.txt
uv pip install --offline --no-index --no-deps --find-links wheelhouse .
.venv/bin/python -c "import <package>"
```

Tooling in the repository that runs the package (`bundle/load.py`) calls `sys.executable -m <package>`;
the runbook writes `.venv/bin/python tools.py`, never `uv run`. Where `uv run` cannot be avoided,
`UV_NO_SYNC=1 UV_OFFLINE=1` makes it use the environment as it stands.
