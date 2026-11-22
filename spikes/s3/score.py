"""Spike S3: score the replies and apply the README's rule. No model.

    uv run python spikes/s3/score.py --set scored

Per role and arm: accuracy on the items (an item is correct when at least two of its three replies
are), harmful errors, unstable items, schema failures; between fast and deliberate, the discordant
pairs and the exact sign test; then the outcome. R6 replies are run in the lab (change_check).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import roles  # noqa: E402


def plan_runner():
    """R6 only: apply the reply to the item's files in the lab and verify. Cached by the resulting files."""
    import re

    import change_check
    # Each plan is run once: the cache is on disk, keyed by item and edits, so scoring can be
    # repeated as arms finish without running the same plan again.
    store = HERE / "results" / "r6-plan-cache.json"
    cache: dict[str, dict] = json.loads(store.read_text()) if store.exists() else {}
    services = {"nginx": "nginx", "PostgreSQL": "postgres", "RabbitMQ": "rabbitmq", "Apache Kafka": "kafka"}

    def run(item: dict, edits: list[dict]) -> dict:
        service = next(v for k, v in services.items() if item["service"].startswith(k))
        files = {f["path"]: "\n".join(re.sub(r"^ {0,3}\d+  ", "", ln) for ln in f["text"].splitlines()) + "\n" for f in item["files"]}
        key = hashlib.sha256(json.dumps([item["id"], edits], sort_keys=True).encode()).hexdigest()
        if key not in cache:
            sni = next((x["subject"].get("sni") for x in item["findings"] if x["subject"].get("sni")), None)
            cache[key] = {"edits": edits, "item": item["id"], **change_check.run_plan(service, files, edits, item["intent"], sni=sni)}
            store.write_text(json.dumps(cache, indent=1) + "\n")
        return cache[key]
    return run


def score_arm(role: str, arm_dir: Path, items: dict, labels: dict, run_plan) -> dict:
    by_item: dict[str, list[dict]] = {}
    for line in (arm_dir / f"{role}.jsonl").read_text().splitlines():
        rec = json.loads(line)
        by_item.setdefault(rec["id"], []).append(rec)
    correct, harmful, unstable, failures = set(), 0, 0, 0
    for iid, recs in by_item.items():
        marks = [roles.score(role, r["reply"], labels[iid], item=items[iid], run_plan=run_plan) for r in recs]
        failures += sum(r["reply"] is None for r in recs)
        if sum(m["correct"] for m in marks) * 2 > len(marks):
            correct.add(iid)
        elif sum(m["harmful"] for m in marks) * 2 > len(marks):
            harmful += 1
        if len({json.dumps(r["reply"], sort_keys=True) for r in recs}) > 1:
            unstable += 1
    return {"correct": correct, "harmful": harmful, "unstable": unstable, "schema_failures": failures, "items": len(by_item)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--set", choices=["dev", "scored"], required=True)
    ap.add_argument("--role", action="append", choices=sorted(roles.SCHEMAS))
    args = ap.parse_args()
    results = HERE / "results" / args.set
    report = {}
    for role in args.role or sorted(roles.SCHEMAS):
        items = {i["id"]: i for i in map(json.loads, (HERE / "items" / f"{role}.jsonl").read_text().splitlines())}
        labels = {i["id"]: i for i in map(json.loads, (HERE / "labels" / f"{role}.jsonl").read_text().splitlines())}
        runner = plan_runner() if role == "r6" else None
        arms = {d.name: score_arm(role, d, items, labels, runner) for d in sorted(results.iterdir()) if (d / f"{role}.jsonl").exists()}
        row = {a: {**v, "correct": len(v["correct"])} for a, v in arms.items()}
        if {"fast", "deliberate"} <= set(arms):
            n = arms["fast"]["items"]
            row["decision"] = roles.outcome(role, arms, n) if args.set == "scored" else "development items decide nothing"
        report[role] = row
        print(role, json.dumps(row), flush=True)
    (results / "report.json").write_text(json.dumps(report, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
