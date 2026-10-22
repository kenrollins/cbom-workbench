# The second reader's check

Six scored items per role, chosen by seeded shuffle (`sample.py`), read against their labels
and evidence by someone who did not write them. A scored run is refused until every role is
recorded here.

| Role | Items | Read by | Date | Result |
|---|---|---|---|---|
| R1 | r1-024, r1-036, r1-061, r1-096, r1-097, r1-111 | Ken Rollins | 2026-10-06 | All six agree; no label changed. The judgment call on r1-097 (a token-library call with verification off is a use, with no algorithm) stands |
| R2 | r2-04, r2-06, r2-16, r2-17, r2-25, r2-32 | A review session on Claude Opus 5.5 that had not seen the labels, 2026-10-06 | 2026-10-06 | All six agree |
| R3 | r3-13, r3-15, r3-18, r3-26, r3-33, r3-35 | same | 2026-10-06 | All six agree; the reader counted the memo's table rows and the citations are right |
| R4 | r4-07, r4-22, r4-23, r4-28, r4-30, r4-35 | same | 2026-10-06 | All six agree on the truth. r4-22 raised: the deciding fact (HTTP 400 without a client certificate) was in the evidence and not shown to the model — **taken out of scoring** (`set: excluded`). r4-28: the model was not shown which block the line sits in — the four other-listener items now say so. r4-07: wire and the winning line agree; answering `config / overridden` is defensible, the prompt's wire-first rule settles it; left as is |
| R5 | r5-k03, r5-n13, r5-p02, r5-p06, r5-s02, r5-s04 | same | 2026-10-06 | All six agree. r5-p06: the mutation changed the certificate and key lines together; the label is the certificate line alone, as the prompt's "one directive" asks; left as is |
| R6 | r6-a-require, r6-e-enable, r6-j-require, r6-l-enable, r6-m-enable, r6-n-enable | same | 2026-10-06 | All six agree; none of the six is a blocked item, so the runtime evidence files were not in the sample |

The reader's full report is kept in the session that produced it; the points above are its
substance. It changed nothing and ran nothing.
