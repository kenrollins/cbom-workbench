"""One fast-tier typed classification, to prove the inference seam is wired.

It classifies the key-establishment family of one wire finding and records the
answer as an `assessment.made` event with the model actor (tier, model,
hardware) and the measured latency. No rule reads it: posture comes from
`posture/kex-auth/1` and policy data. The event says whether the model agreed
with that policy data, which is all it is for.
"""

from __future__ import annotations

from pqch import inference
from pqch.run import Run

PURPOSE = "classify-kex-family"
ROLE = "classify-algorithm"   # S3's R3
FAMILIES = ["classical-ecdh", "classical-finite-field-dh", "hybrid-post-quantum", "post-quantum"]
SCHEMA = {
    "type": "object",
    "required": ["family"],
    "properties": {"family": {"enum": FAMILIES}},
    "additionalProperties": False,
}


def classify_one(run: Run, policy: dict, *, seam: inference.Seam | None = None) -> dict | None:
    events = list(run.ledger.events())
    pick = next((ev for ev in events if ev["type"] == "finding.observed"
                 and ev["payload"]["layer"] == "wire"
                 and ev["payload"]["asset"]["name"] in policy.get("key_establishment", [])), None)
    pick = pick or next((ev for ev in events if ev["type"] == "finding.observed"
                         and ev["payload"]["asset"]["role"] == "key-establishment"), None)
    if pick is None:
        return None
    f = pick["payload"]
    messages = [
        {"role": "system", "content": "You classify cryptographic key-establishment algorithms. "
                                      "Answer with JSON only."},
        {"role": "user", "content": f"A {f['subject']['protocol'].upper()} listener offers the "
                                    f"key-establishment algorithm {f['asset']['name']!r} "
                                    f"(tool spelling: {f['asset']['parameters']}). "
                                    f"Which family is it? One of: {', '.join(FAMILIES)}."},
    ]
    s = seam or inference.default()
    # The role's tier and reasoning setting come from the config's `roles` section (spike S3:
    # classification needs the small engine with reasoning on), never from here.
    c = s.complete_role(ROLE, messages, schema=SCHEMA, max_tokens=4000, purpose=PURPOSE)
    policy_pq = f["asset"]["name"] in policy.get("key_establishment", [])
    model_pq = c.parsed["family"] in ("hybrid-post-quantum", "post-quantum")
    return run.ledger.append("assessment.made", c.actor(), {
        "finding": pick["id"],
        "purpose": PURPOSE,
        "classification": {"kex_family": c.parsed["family"]},
        "used_by_rules": False,
        "agrees_with_policy_data": policy_pq == model_pq,
        "latency_ms": c.latency_ms,
        "finish_reason": c.finish_reason,
        "usage": {k: v for k, v in c.usage.items() if isinstance(v, int)},
    }, inputs=[pick["id"]])
