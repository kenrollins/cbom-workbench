"""Score Ask the CBOM against its floor (README.md): retrieval recall@8, the answer's expected
phrase, and the citation rule, three repeats per item, on one run's CBOM.
    PQCH_VAR=... PQCH_INFERENCE_CONFIG=... uv run python eval/ask/score.py [--run ID] [--repeats 3] [--out results/<arm>.json]
"""
from __future__ import annotations
import argparse, json, os, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "src"))
from pqch import ask as askmod
from pqch.cbom import project
from pqch.inference import Seam, load_config
from pqch.ledger import verify
from pqch.run import Run

FLOOR = {"retrieval": 11, "phrase": 10, "citations": 12}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run"); ap.add_argument("--repeats", type=int, default=3); ap.add_argument("--out")
    a = ap.parse_args()
    var = os.environ["PQCH_VAR"]
    r = Run(var, a.run) if a.run else Run.latest(var, "scan")
    events = list(r.ledger.events()); assert verify(events).ok, "ledger does not verify"
    seam = Seam(load_config(os.environ["PQCH_INFERENCE_CONFIG"]))
    index = askmod.Index(seam, r.dir, project(events), events)
    items = [json.loads(x) for x in (HERE / "items.jsonl").read_text().splitlines()]
    per_item, records = {}, []
    for it in items:
        shown = index.retrieve(it["q"])
        got = {p["ref"] for p in shown}
        recall_ok = all(x in got for x in it["refs"])
        phrase_ok, cite_ok, lat = [], [], []
        for n in range(a.repeats):
            t0 = time.monotonic()
            try:
                res = askmod.ask(seam, index, it["q"], events)
                phrase_ok.append(it["phrase"].lower() in res["reply"]["answer"].lower())
                cite_ok.append(bool(res["reply"]["citations"]) and res["check"]["ok"])
                lat.append(res["latency_ms"])
                records.append({"id": it["id"], "repeat": n, "reply": res["reply"], "check": res["check"],
                                "model": res["model"], "hardware": res["hardware"], "latency_ms": res["latency_ms"]})
            except Exception as e:
                phrase_ok.append(False); cite_ok.append(False)
                records.append({"id": it["id"], "repeat": n, "error": f"{type(e).__name__}: {e}"[:300],
                                "latency_ms": round((time.monotonic() - t0) * 1000)})
        per_item[it["id"]] = {"retrieval": recall_ok, "phrase": all(phrase_ok), "citations": all(cite_ok),
                              "shown": [p["ref"] for p in shown], "latency_ms": lat}
        print(it["id"], "retrieval", "ok" if recall_ok else "MISS", "phrase", sum(phrase_ok), "/", a.repeats,
              "citations", sum(cite_ok), "/", a.repeats, "ms", lat, flush=True)
    totals = {k: sum(1 for v in per_item.values() if v[k]) for k in FLOOR}
    clears = all(totals[k] >= FLOOR[k] for k in FLOOR)
    tiers = seam.config["tiers"]; tier, reasoning = seam.for_role(askmod.ROLE)
    summary = {"run": r.id, "items": len(items), "repeats": a.repeats, "totals": totals, "floor": FLOOR, "clears": clears,
               "role_tier": tier, "reasoning": reasoning, "model": tiers[tier].get("model"), "hardware": tiers[tier].get("hardware"),
               "embed_model": index.model, "embed_hardware": index.hardware, "per_item": per_item}
    print(json.dumps({k: v for k, v in summary.items() if k != "per_item"}, indent=1))
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps({"summary": summary, "records": records}, indent=1))
    return 0 if clears else 1


if __name__ == "__main__":
    sys.exit(main())
