# Evaluation kit

What the workbench is scored against.

- `answer-keys/` — the planted truth for the mini-agency, by layer (wire,
  host, code). Each item has a class and names the verifier that could confirm
  its fix:

  | Class | Meaning | In the score |
  |---|---|---|
  | `present` | Planted and within reach of the evidence | counted |
  | `decoy` | Looks like a finding and is not | flagging it is a false positive |
  | `out-of-reach` | Real, and outside what the workbench can see | in the denominator, reported as a known miss |
  | `supplied` | Typed in, not discovered | excluded from coverage |

  A key is committed, and its hash recorded on the ledger, before the scanner
  code it scores is written.
  The live key is [`agency/answer-key.yaml`](../agency/answer-key.yaml): 74 items for the eight
  services — 58 present, 9 decoys, 2 out of reach, 5 supplied. The demo's
  [test agency page](https://kenrollins.github.io/cbom-workbench/agency/) shows them by service.
- `answer-keys/mini-agency-m0.yaml` — the first, three-service slice's key, frozen when the estate
  grew to eight services (2026-10-19); the recorded runs of that slice and the tests score against it.
- `pins.yaml` — third-party repositories and the exact commits analyzed.
- `capabilities/<date>/` — what each service's runtime says it supports (key exchanges, signatures,
  the FIPS module), asked of the image with no network. A change package cites it when no setting can
  make a service post-quantum (lessons 32 and 33).
- `score.py` — coverage and false positives of a CBOM against an answer key, by layer. The logic is
  `src/pqch/score.py`; the matching rules are written in the key's header. Every scan scores itself;
  `uv run python eval/score.py var/runs/<run-id>` scores a recorded run again.

Every scan also writes two baselines beside the workbench's own CBOM, in the run's directory:

- `baseline-cbomkit.cdx.json` — CBOMkit alone on the same targets: cbomkit-theia on the images. The
  estate holds no Java, Python or Go source for CBOMkit's source scanners to read.
- `baseline-scanners.cdx.json` — every scanner the workbench uses, run alone with no harness, raw
  output unioned. The workbench's own contribution is the delta over this one: the rules, and the
  harness's own reader of key material in images (`pqch image-files`), which is in neither baseline.

A held-out variant of the estate — ports moved, configs renamed, plants changed, scored once and never
tuned against — is on the [roadmap](../ROADMAP.md), not yet built.

Both baselines are projected from the same run ledger as the workbench, using
the same normalizer, so they are scored on what the tools said in the key's
vocabulary. `score_raw_theia.py` checks that this costs the CBOMkit
baseline nothing and gives it nothing: it scores cbomkit-theia's own CBOMs, the
files whose hashes the run recorded, with no normalizer. Following theia's own
references from a certificate to its key, they score item for item as the
projected baseline (host 7 of 10, the decoy flagged, measured 2026-10-04 on the
M0 slice). Read by component name alone they score 5 of 10, because theia
names a certificate by its subject, not its algorithm. They carry no rule output: no links, no in-use judgement, no
posture. The difference between the scanners-alone column and the workbench is
exactly what the harness's rules add.

Every published number comes from `score.py` run on a recorded CBOM, and is
labelled with the build and the hardware it was produced on.
