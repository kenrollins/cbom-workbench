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
- `answer-keys/mini-agency-m0.yaml` — the M0 slice's key, frozen when the
  estate grew to M1 (2026-10-19); the recorded M0 runs and the tests score
  against it. The live key is `agency/answer-key.yaml`
- `answer-keys/held-out/` — a variant of the mini-agency with ports moved,
  configs renamed and plants changed. It is scored once, at the dress
  rehearsal, and never tuned against.
- `pins.yaml` — third-party repositories and the exact commits analyzed
- `score.py` — coverage and false positives of a CBOM against an answer key,
  by layer. The logic is `src/pqch/score.py`; the matching rules are written
  in the key's header. The M0 key is `agency/answer-key.yaml`
- `baseline/cbomkit/` — CBOMkit alone on the same targets. On the M0 slice
  this is cbomkit-theia on the images: the slice holds no Java, Python or Go
  source for CBOMkit's source scanners to read
- `baseline/scanners/` — every scanner the workbench uses, run alone with no
  harness, raw output unioned. The workbench's own contribution is the delta
  over this one: the rules, and from M1 the harness's own reader of key
  material in images (`pqch image-files`), which is in neither baseline

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
