"""A model may explain a conflict beside the rule's answer. It never settles one.

Spike S3's role R4 (`resolve-conflict`): every arm measured was under its floor,
so the rule `conflict/resolve/1` decides. When a deployment binds the role in
its inference config, each conflict the rule recorded is also put to the model
with the spike's prompt, and its reply is recorded as an `assessment.made` with
the model actor, `used_by_rules: false` and whether it agreed with the rule.
When the role is not bound, nothing is called and the count says so.
"""

from __future__ import annotations

from pqch import inference
from pqch.run import Run

ROLE = "resolve-conflict"
PURPOSE = "explain-conflict"
IN_FORCE = ["wire", "host", "config", "cannot-tell"]
REASONS = ["not-served", "default-applies", "overridden", "other-listener", "stale-file", "tool-limit"]
SCHEMA = {
    "type": "object",
    "required": ["in_force", "reason"],
    "properties": {"in_force": {"enum": IN_FORCE}, "reason": {"anyOf": [{"enum": REASONS}, {"type": "null"}]},
                   "explanation": {"type": "string"}},
    "additionalProperties": False,
}
PROMPT = (
    "You are given two or three findings about one cryptographic asset of one service. They disagree. "
    "Say which layer's statement is in force for that asset, and why.\n\n"
    "Layers: wire (what a scanner observed on a listener), host (a file in the running image), "
    "config (a line in a configuration or source file).\n\n"
    "Give in_force (wire, host, config, or cannot-tell) and reason (not-served, default-applies, overridden, "
    "other-listener, stale-file, tool-limit, or null with cannot-tell), and one sentence of explanation. "
    "A wire observation of the asset's own listener, taken after the last change, is what is in force. "
    "Answer cannot-tell when the evidence shown does not decide it. Answer with JSON only."
)


def explain(run: Run, *, seam: inference.Seam | None = None) -> dict:
    s = seam or inference.default()
    try:
        s.for_role(ROLE)
    except inference.TierUnavailable as e:
        return {"explained": 0, "skipped": str(e)}
    events = list(run.ledger.events())
    findings = {e["id"]: e["payload"] for e in events if e["type"] == "finding.observed"}
    counts = {"explained": 0, "agreed": 0, "failed": 0}
    for ev in [e for e in events if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "conflict/resolve/1"]:
        p = ev["payload"]
        lines = []
        for fid in [p["finding"], *p.get("disagrees_with", [])]:
            f = findings[fid]
            lines.append(f"- {f['layer']} ({f['source']['tool']} {f['source']['version']}): {f['evidence']['excerpt']}")
        messages = [{"role": "system", "content": PROMPT},
                    {"role": "user", "content": "Findings:\n" + "\n".join(lines)}]
        try:
            c = s.complete_role(ROLE, messages, schema=SCHEMA, max_tokens=4000, purpose=PURPOSE)
        except (inference.SchemaViolation, inference.TierUnavailable, OSError) as e:
            counts["failed"] += 1
            run.ledger.append("assessment.made", {"kind": "rule", "id": "explain/failed"}, {
                "finding": p["finding"], "purpose": PURPOSE, "rule_id": "explain/failed",
                "classification": {}, "basis": f"{type(e).__name__}: {e}"[:300], "used_by_rules": False,
            }, inputs=[ev["id"]])
            continue
        agreed = (c.parsed["in_force"] == p["classification"]["in_force"]
                  and c.parsed.get("reason") == p["classification"]["reason"])
        run.ledger.append("assessment.made", c.actor(), {
            "finding": p["finding"], "purpose": PURPOSE, "conflict": ev["id"],
            "classification": {"in_force": c.parsed["in_force"], "reason": c.parsed.get("reason")},
            "explanation": c.parsed.get("explanation", ""),
            "used_by_rules": False, "agrees_with_rule": agreed,
            "latency_ms": c.latency_ms, "finish_reason": c.finish_reason,
            "usage": {k: v for k, v in c.usage.items() if isinstance(v, int)},
        }, inputs=[ev["id"], p["finding"]])
        counts["explained"] += 1
        counts["agreed"] += int(agreed)
    return counts
