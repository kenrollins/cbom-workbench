"""Mark six of a role's 36 items as development items, by seeded shuffle. Used for R4, R5 and R6,
whose builders write items without the mark (make_r123.py does it for R1 to R3).

    uv run python spikes/s3/split.py r5
"""

import json
import sys
from pathlib import Path

from make_r123 import split_dev

HERE = Path(__file__).resolve().parent
for role in sys.argv[1:]:
    p = HERE / "items" / f"{role}.jsonl"
    items = [json.loads(x) for x in p.read_text().splitlines()]
    dev = split_dev([i["id"] for i in items], role)
    for i in items:
        i["set"] = "dev" if i["id"] in dev else "scored"
    p.write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in items))
    print(role, len(items), "items;", sorted(dev))
