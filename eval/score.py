"""Score a run's CBOMs against an answer key: coverage and false positives, by layer.

    uv run python eval/score.py var/runs/<run-id> [--key agency/answer-key.yaml] [--json]

Three columns: CBOMkit alone, the scanners alone, the workbench. The key's hash
must equal the one the run recorded in its key.committed event. The score is
the one the run wrote (score.json): the same columns, then the remediated rule
read from the change runs beside it.
"""

import argparse
import json
import sys
from pathlib import Path

from pqch.ledger import Ledger
from pqch.pipeline import score_with_remediation
from pqch.score import table


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--key", type=Path, default=Path("agency/answer-key.yaml"))
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    recorded = next((e["payload"]["sha256"] for e in Ledger(args.run_dir / "ledger.jsonl").events()
                     if e["type"] == "key.committed"), None)
    result = score_with_remediation(args.run_dir.resolve().parent.parent, args.run_dir, args.key, recorded_sha256=recorded)
    print(json.dumps(result, indent=1) if args.json else table(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
