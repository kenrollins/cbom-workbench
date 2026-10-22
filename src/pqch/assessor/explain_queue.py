"""Why an item sits in its queue, explained by a model over the policy pack — and checked.

The rule `queue/m-26-15/1` decides the queue; this job only explains it, the way a person asking
"why is the records database in the 2030 queue" wants to hear it. The pack's passages (each queue,
each prioritization criterion, each row of the memo's table, the replacement and enforcement
clauses) are embedded by the `embed` tier; for each open item the three nearest are retrieved and
put to the model bound to `explain-queue` with the item's facts. The reply names a queue and cites
passages by id. It passes when the queue is the one the rule placed the item in and every cited
passage was retrieved, one of them that queue's own. Every item is asked three times.

The floor was written before the first call (PLAN.md, M2). Each item's result is an
`assessment.made` with the model actor, `used_by_rules: false`, the three calls, the retrieval
with its scores (in thousandths: hashed objects carry no floats), and the check. It runs in a
run of kind `explain` over a scan run, never in the scan run itself.
"""

from __future__ import annotations

import math
import time
from collections import Counter
from pathlib import Path

from pqch import inference, schemas
from pqch import scope as scope_mod
from pqch.policy import load_pack
from pqch.run import Run

ROLE = "explain-queue"
PURPOSE = "explain-queue"
TOP_K = 3
SCHEMA = {
    "type": "object", "required": ["queue", "cites", "explanation"],
    "properties": {"queue": {"type": "string"}, "cites": {"type": "array", "items": {"type": "string"}, "maxItems": 5},
                   "explanation": {"type": "string", "maxLength": 800}},
    "additionalProperties": False,
}
SYSTEM = ("You explain to an agency's system owner why one migration item sits in the queue it is in, "
          "from the passages of OMB M-26-15 you are given. Name the queue by its id, cite the passages you rely on "
          "by their ids, and explain in two or three sentences, in plain words. Use only the passages given. "
          "Answer with JSON only: {\"queue\": ..., \"cites\": [...], \"explanation\": ...}.")


def passages(pack: dict) -> list[dict]:
    out = []
    for q in pack["queues"]:
        out.append({"id": f"queue:{q['id']}", "section": q["section"], "text": f"Queue {q['id']} (deadline {q['deadline']}): {q['quote']}"})
    for c in pack["prioritize"]["criteria"]:
        out.append({"id": f"prioritize:{c['id']}", "section": pack["prioritize"]["section"],
                    "text": f"Prioritize ({c['id']}): {c['quote']}. {pack['prioritize']['quote']}"})
    for fam, row in pack["quantum_vulnerable"]["families"].items():
        out.append({"id": f"vulnerable:{fam}", "section": pack["quantum_vulnerable"]["section"],
                    "text": f"Quantum-vulnerable, {row['function']}: {row['row']}"})
    out.append({"id": "replace", "section": pack["replace"]["section"], "text": pack["replace"]["quote"]})
    out.append({"id": "enforce", "section": pack["enforce"]["section"], "text": pack["enforce"]["quote"]})
    return out


def _cos(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b, strict=False))
    return dot / (math.sqrt(sum(x * x for x in a)) * math.sqrt(sum(y * y for y in b)) or 1.0)


def _query(item: dict, criteria: list[str]) -> str:
    c = item["classification"]
    return (f"{item['subject']['service']} {item['subject']['function']}: still offers {', '.join(c['vulnerable'])}"
            + (f" beside {', '.join(c['post_quantum'])}" if c["post_quantum"] else "")
            + f"; prioritized: {', '.join(criteria) if criteria else 'no'}")


def check(reply: dict, item_queue: str, retrieved: list[str]) -> dict:
    cites = reply.get("cites") or []
    why = []
    if reply.get("queue") != item_queue:
        why.append(f"names queue {reply.get('queue')!r}, the rule placed it in {item_queue!r}")
    stray = [c for c in cites if c not in retrieved]
    if stray:
        why.append(f"cites passages not retrieved: {', '.join(stray)}")
    if f"queue:{item_queue}" not in cites:
        why.append(f"does not cite queue:{item_queue}")
    return {"pass": not why, "harmful": reply.get("queue") != item_queue, "why": "; ".join(why)}


def explain(var: Path, scan_run: Run, *, pack_path: str | Path, seam: inference.Seam | None = None,
            repeats: int = 3, signer=None, progress=None, only_items: set | None = None) -> tuple[Run | None, dict]:
    s = seam or inference.default()
    tier, _ = s.for_role(ROLE)      # raises TierUnavailable when the role is unbound
    pack = load_pack(pack_path)
    events = list(scan_run.ledger.events())
    scope = events[0]["payload"]["scope"]
    schemas.validate(scope)
    prio = {e["payload"]["subject"]["name"]: e["payload"]["classification"]["criteria"] for e in events
            if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "priority/m-26-15/1"}
    items = [e for e in events if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "queue/m-26-15/1"
             and e["payload"]["classification"]["state"] == "open"
             and (only_items is None or (e["payload"]["subject"]["service"], e["payload"]["subject"]["function"]) in only_items)]
    if not items:
        return None, {"items": 0, "passed": 0, "harmful_calls": 0, "calls": 0, "latency_ms": []}
    ps = passages(pack)
    t0 = time.monotonic()
    vecs = s.embed("embed", [p["text"] for p in ps])
    embed_ms = round((time.monotonic() - t0) * 1000)
    summary = {"items": 0, "passed": 0, "harmful_calls": 0, "calls": 0, "embed_ms_passages": embed_ms, "latency_ms": []}
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="explain-queue",
                    kind="explain", runner_id="pqch-explainer")
    for it in items:
        p = it["payload"]
        q = _query(p, prio.get(p["subject"]["service"], []))
        t1 = time.monotonic()
        qv = s.embed("embed", [q])[0]
        q_ms = round((time.monotonic() - t1) * 1000)
        ranked = sorted(((round(_cos(qv, v) * 1000), ps[i]) for i, v in enumerate(vecs)), key=lambda x: -x[0])[:TOP_K]
        retrieved = [r[1]["id"] for r in ranked]
        ctx = "\n".join(f"[{r[1]['id']}] (M-26-15 §{r[1]['section']}) {r[1]['text']}" for r in ranked)
        user = (f"Item: {p['subject']['service']}, {p['subject']['function']}. {p['basis']}. "
                f"Prioritized by: {', '.join(prio.get(p['subject']['service'], [])) or 'none of the criteria'}.\n"
                f"Queues: kex-2030, sig-2031, remaining-2035, tls13-2030.\n\nPassages:\n{ctx}")
        calls, actor = [], {"kind": "rule", "id": "explain-queue/failed"}
        for _ in range(repeats):
            try:
                c = s.complete_role(ROLE, [{"role": "system", "content": SYSTEM}, {"role": "user", "content": user}],
                                    schema=SCHEMA, max_tokens=1200, purpose=PURPOSE)
                res = check(c.parsed, p["classification"]["queue"], retrieved)
                calls.append({"reply": c.parsed, **res, "latency_ms": c.latency_ms, "finish_reason": c.finish_reason,
                              "tokens": int(c.usage.get("total_tokens") or 0)})
                actor = c.actor()
                summary["latency_ms"].append(c.latency_ms)
            except inference.SchemaViolation as e:
                calls.append({"reply": None, "pass": False, "harmful": False, "why": f"schema: {e}"[:200]})
            summary["calls"] += 1
            summary["harmful_calls"] += int(calls[-1]["harmful"])
        votes = Counter(x["pass"] for x in calls)
        passed = votes[True] > votes[False]
        best = next((x for x in calls if x["pass"]), calls[0])
        run.ledger.append("assessment.made", actor, {
            "subject": p["subject"], "purpose": PURPOSE, "rule_id": None,
            "item": {"run": scan_run.id, "event": it["id"], "queue": p["classification"]["queue"]},
            "classification": {"passed": passed, "explanation": (best.get("reply") or {}).get("explanation")},
            "calls": calls, "retrieval": {"query": q, "top": [{"id": r[1]["id"], "score_milli": r[0]} for r in ranked],
                                          "embed_ms": q_ms},
            "used_by_rules": False,
        })
        summary["items"] += 1
        summary["passed"] += int(passed)
        if progress:
            progress(p["subject"], passed, calls)
    run.close(signer)
    return run, summary
