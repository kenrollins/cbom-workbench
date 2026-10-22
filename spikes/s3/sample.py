"""Print the second reader's sample: six scored items per role, by seeded shuffle, with label and evidence.

    uv run python spikes/s3/sample.py [r1 ...]
"""

import json
import random
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SEED = "pqch-s3-2026-10-05/second-reader"

for role in sys.argv[1:] or ["r1", "r2", "r3", "r4", "r5", "r6"]:
    items = [i for i in map(json.loads, (HERE / "items" / f"{role}.jsonl").read_text().splitlines()) if i["set"] == "scored"]
    labels = {x["id"]: x for x in map(json.loads, (HERE / "labels" / f"{role}.jsonl").read_text().splitlines())}
    picked = random.Random(f"{SEED}/{role}").sample(sorted(i["id"] for i in items), 6)
    print(f"\n{'=' * 100}\n{role.upper()} — check these six: {', '.join(picked)}\n{'=' * 100}")
    for item in (i for i in items if i["id"] in picked):
        lab = labels[item["id"]]
        print(f"\n--- {item['id']}")
        if role == "r1":
            print(f"{item['repo']} {item['path']}:{item['line']}\n  flagged: {item['flagged']}")
        elif role == "r2":
            print(f"{item['tool']} / {item['field']}: {item['spelling']!r}")
        elif role == "r3":
            print(json.dumps(item["finding"]["asset"]))
        elif role == "r4":
            print(f"{item['service']} — {item['asset']}")
            for f in item["findings"]:
                print(f"  [{f['layer']}] {json.dumps(f['subject'])}: {f['statement']}" + "".join(
                    f"  ({k}: {v})" for k, v in f.items() if k not in ("layer", "tool", "subject", "statement")))
        elif role == "r5":
            print(f"{item['service']}\n  finding: {json.dumps(item['finding']['asset'])}")
            for f in item["files"]:
                print(f"  {f['path']}\n" + "\n".join("    " + ln for ln in f["text"].splitlines()))
        else:
            print(f"{item['service']} — intent {item['intent']}; files: {', '.join(f['path'] for f in item['files'])}")
        print(f"  LABEL: {json.dumps(lab['label'])}")
        print(f"  WHY:   {lab.get('citation') or json.dumps(lab.get('evidence'))[:400]}")
