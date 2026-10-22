# Build specification

The specification a coding agent can rebuild the core of cbom-workbench from,
on a clean machine, without this repository's source.

It is written as the build proceeds and completed in PLAN milestone M4, ahead
of the dress rehearsal:

- `AGENTS.md` — the instructions an agent reads first
- `interfaces.md` — the scope, the finding schema, the ledger event schema
  with its hash chain and signing checkpoints, the inference seam, the
  verifier contract; each versioned
- `build-order.md` — stages in order, each with its done-check

The measure of the specification is the dress rehearsal in PLAN M4: the core
rebuilt from this directory and the offline bundle alone, timed, and then
scored by the evaluation kit. A coding assistant and the internet may be used
at build time; the rebuilt system uses neither at run time.
