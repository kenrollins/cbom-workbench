"""Spike S3: run one arm over a role's items, through the inference seam. Three calls per item.

    uv run python spikes/s3/run.py --config workshop/inference.s3.yaml --arm fast --role r1 --set dev
    uv run python spikes/s3/run.py --config ... --arm fast --arm fast-thinking --arm deliberate --set scored

An arm is `fast`, `deliberate` or `fast-thinking`. The seam knows only the tiers `fast`, `deliberate` and
`embed` and refuses any other name, so the third arm is given as `fast-thinking:<config>`: a second
configuration file whose `fast` tier is bound to the fast engine with thinking on. The reply records
the model id either way. (That the seam has no way to say "this role, thinking on" is what the
README's "fast, thinking" outcome would have to add.) A scored run is refused until the label files'
hashes are the ones recorded in README.md and the second reader's check is recorded.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

import roles  # noqa: E402

REPEATS = 3


def frozen_ok() -> str | None:
    """None when a scored run may start; otherwise why not."""
    readme = (HERE / "README.md").read_text()
    for p in sorted([*(HERE / "labels").glob("r?.jsonl"), *(HERE / "items").glob("r?.jsonl"), *(HERE / "prompts").glob("r?.md")]):
        h = hashlib.sha256(p.read_bytes()).hexdigest()
        if h not in readme:
            return f"{p.relative_to(HERE)} hashes to {h[:16]}…, which README.md does not record"
    if not (HERE / "labels" / "SECOND-READER.md").exists():
        return "the second reader's check is not recorded (labels/SECOND-READER.md)"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True, help="a pqch.inference/1 file naming each arm as a tier")
    ap.add_argument("--arm", action="append", required=True)
    ap.add_argument("--role", action="append", choices=sorted(roles.SCHEMAS))
    ap.add_argument("--set", choices=["dev", "scored"], required=True)
    ap.add_argument("--resume", action="store_true", help="keep replies already on disk; make only the calls still missing")
    args = ap.parse_args()
    if args.set == "scored":
        why = frozen_ok()
        if why:
            raise SystemExit(f"a scored run is refused: {why}")
    from pqch import inference

    seams = {}
    for spec in args.arm:
        arm, _, cfg = spec.partition(":")
        seams[arm] = (inference.Seam(inference.load_config(cfg or args.config)), "deliberate" if arm == "deliberate" else "fast")
    for arm, (seam, tier) in seams.items():
        for role in args.role or sorted(roles.SCHEMAS):
            items = [json.loads(x) for x in (HERE / "items" / f"{role}.jsonl").read_text().splitlines()]
            out = HERE / "results" / args.set / arm
            out.mkdir(parents=True, exist_ok=True)
            path = out / f"{role}.jsonl"
            done = set()
            if args.resume and path.exists():
                done = {(json.loads(x)["id"], json.loads(x)["repeat"]) for x in path.read_text().splitlines() if x.strip()}
            with path.open("a" if args.resume else "w") as f:
                for item in (i for i in items if i["set"] == args.set):
                    if all((item["id"], n) in done for n in range(REPEATS)):
                        continue
                    messages = roles.render(role, item)
                    for n in range(REPEATS):
                        if (item["id"], n) in done:
                            continue
                        rec = {"id": item["id"], "arm": arm, "repeat": n, "reply": None, "error": None}
                        started = time.monotonic()
                        try:
                            c = seam.complete(tier, messages, schema=roles.SCHEMAS[role], max_tokens=roles.MAX_TOKENS[role],
                                              purpose=f"s3-{role}")
                            rec.update(reply=c.parsed, model=c.model, hardware=c.hardware, latency_ms=c.latency_ms,
                                       usage={k: v for k, v in c.usage.items() if isinstance(v, int)},
                                       finish_reason=c.raw["choices"][0].get("finish_reason"))
                        except Exception as e:  # a schema failure, a timeout, a refusal: a wrong reply, recorded
                            rec.update(error=f"{type(e).__name__}: {e}"[:300], latency_ms=round((time.monotonic() - started) * 1000))
                            if hasattr(e, "raw"):
                                rec["finish_reason"] = e.raw["choices"][0].get("finish_reason")
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                        f.flush()
            print(f"{arm} {role}: written to {out.relative_to(ROOT)}/{role}.jsonl", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
