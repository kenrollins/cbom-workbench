"""S3's six roles: the reply schema, how an item becomes a prompt, and how a reply is scored.

Shared by run.py and score.py. Scoring is field comparison, except R6, which is run (change_check).
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SIX_ROLES = ["key-establishment", "signature", "encryption", "hash", "mac", "other"]
R1_FAMILIES = ["RSA", "ECDSA", "EC", "Ed25519", "DSA", "DH", "AES", "3DES", "ChaCha20", "SHA-1", "SHA-2", "SHA-3", "MD5",
               "HMAC", "PBKDF2", "scrypt", "bcrypt", "X.509", "unspecified", "none"]
R2_NAMES = yaml.safe_load((HERE / "sources" / "r2-names.yaml").read_text())
R3_FAMILIES = ["ecdh", "mqv", "finite-field-dh", "rsa", "ecdsa", "dsa", "eddsa", "ml-kem", "ml-dsa", "slh-dsa", "hybrid",
               "symmetric-cipher", "hash-or-mac"]
R4_REASONS = ["not-served", "default-applies", "overridden", "other-listener", "stale-file", "tool-limit"]


def _obj(props: dict, required: list[str] | None = None) -> dict:
    return {"type": "object", "properties": props, "required": required or list(props), "additionalProperties": False}


SCHEMAS = {
    "r1": _obj({"is_crypto_use": {"type": "boolean"}, "family": {"enum": R1_FAMILIES}, "role": {"enum": SIX_ROLES},
                "key_bits": {"type": ["integer", "null"]}}),
    "r2": _obj({"name": {"enum": [*R2_NAMES["names"], "unknown"]}, "asset_type": {"enum": R2_NAMES["asset_types"]},
                "role": {"enum": SIX_ROLES}}),
    "r3": _obj({"quantum_vulnerable": {"type": "boolean"}, "function": {"enum": ["key-establishment", "signature", "neither"]},
                "family": {"enum": R3_FAMILIES}}),
    "r4": _obj({"in_force": {"enum": ["wire", "host", "config", "cannot-tell"]}, "reason": {"enum": R4_REASONS}}),
    "r5": _obj({"cause": {"enum": ["line", "default"]}, "file": {"type": ["string", "null"]},
                "line_start": {"type": ["integer", "null"]}, "line_end": {"type": ["integer", "null"]}}),
    "r6": _obj({"blocked": {"enum": ["none", "supplier", "protocol"]},
                "edits": {"type": "array", "items": _obj({"file": {"type": "string"}, "line_start": {"type": "integer"},
                                                         "line_end": {"type": "integer"}, "replacement": {"type": "string"}})}}),
}
# A cap, the same for every arm, set well above what any reply needs: a thinking engine's reasoning
# counts against it (with 300 the thinking arm returned nothing), and a cap that is never reached is
# not a difference between arms.
MAX_TOKENS = {"r1": 16000, "r2": 16000, "r3": 16000, "r4": 16000, "r5": 16000, "r6": 20000}


def _files(files: list[dict]) -> str:
    return "\n\n".join(f"--- {f['path']}\n{f['text']}" for f in files)


def render(role: str, item: dict) -> list[dict]:
    """The one prompt for the role — the same text for every arm — filled from the item."""
    system, _, user = (HERE / "prompts" / f"{role}.md").read_text().partition("\n---\n")
    j = lambda o: json.dumps(o, indent=1, ensure_ascii=False)  # noqa: E731
    fields = {
        "r1": lambda: {"repo": item["repo"], "path": item["path"], "language": item["language"], "line": item["line"], "context": item["context"]},
        "r2": lambda: {"tool": item["tool"], "field": item["field"], "spelling": item["spelling"]},
        "r3": lambda: {"policy": (HERE / item["policy"]).read_text(), "finding": j(item["finding"])},
        "r4": lambda: {"service": item["service"], "asset": item["asset"], "findings": j(item["findings"])},
        "r5": lambda: {"service": item["service"], "finding": j(item["finding"]), "files": _files(item["files"])},
        "r6": lambda: {"service": item["service"], "intent": item["intent"], "findings": j(item["findings"]), "files": _files(item["files"])},
    }[role]()
    if role == "r2":
        system = system.replace("{names}", ", ".join(R2_NAMES["names"]))
    for k, v in fields.items():
        user = user.replace("{" + k + "}", str(v))
    return [{"role": "system", "content": system.strip()}, {"role": "user", "content": user.strip()}]


# ----------------------------------------------------------------------------------- scoring
def score(role: str, reply: dict | None, label: dict, *, item: dict | None = None, run_plan=None) -> dict:
    """{"correct": bool, "harmful": bool}. `reply` is None when the call failed its schema, timed out or was refused."""
    if reply is None:
        return {"correct": False, "harmful": False}
    lab = label["label"]
    if role == "r1":
        if not lab["is_crypto_use"]:
            return {"correct": reply["is_crypto_use"] is False, "harmful": False}
        ok = reply["is_crypto_use"] is True and reply["family"] == lab["family"] and reply["role"] == lab["role"] and \
            (lab["key_bits"] is None or reply["key_bits"] == lab["key_bits"])
        return {"correct": ok, "harmful": reply["is_crypto_use"] is False}
    if role == "r2":
        if lab["name"] == "unknown":
            return {"correct": reply["name"] == "unknown", "harmful": reply["name"] != "unknown"}
        roles = lab["role"] if isinstance(lab["role"], list) else [lab["role"]]
        ok = reply["name"] == lab["name"] and reply["asset_type"] == lab["asset_type"] and reply["role"] in roles
        return {"correct": ok, "harmful": reply["name"] not in (lab["name"], "unknown")}
    if role == "r3":
        ok = all(reply[k] == lab[k] for k in ("quantum_vulnerable", "function", "family"))
        return {"correct": ok, "harmful": lab["quantum_vulnerable"] and reply["quantum_vulnerable"] is False}
    if role == "r4":
        if lab["in_force"] == "cannot-tell":
            return {"correct": reply["in_force"] == "cannot-tell", "harmful": reply["in_force"] != "cannot-tell"}
        ok = reply["in_force"] == lab["in_force"] and reply["reason"] == lab["reason"]
        return {"correct": ok, "harmful": reply["in_force"] not in (lab["in_force"], "cannot-tell")}
    if role == "r5":
        if lab.get("cause") == "default":
            return {"correct": reply["cause"] == "default", "harmful": reply["cause"] != "default"}
        ok = reply["cause"] == "line" and reply["file"] == lab["file"] and reply["line_start"] is not None and \
            reply["line_end"] is not None and lab["line_start"] <= reply["line_start"] <= reply["line_end"] <= lab["line_end"]
        return {"correct": ok, "harmful": False}
    if role == "r6":
        if lab["blocked"] != "none":
            return {"correct": reply["blocked"] == lab["blocked"] and not reply["edits"], "harmful": False}
        if reply["blocked"] != "none":
            return {"correct": False, "harmful": False}
        res = run_plan(item, reply["edits"])
        return {"correct": bool(res["meets_intent"]), "harmful": res["status"] == "service-down", "status": res["status"]}
    raise ValueError(role)


FLOORS = {"r1": (27, 1), "r2": (28, 0), "r3": (28, 0), "r4": (24, 2), "r5": (24, 3), "r6": (24, 2)}   # (floor of 30, harmful allowed)


def sign_test_p(b: int, c: int) -> float:
    """Exact one-sided sign test: the chance of b or more of b + c discordant pairs going one way by luck."""
    from math import comb
    n = b + c
    return sum(comb(n, k) for k in range(b, n + 1)) / 2 ** n if n else 1.0


def clears(role: str, correct: int, harmful: int, n: int = 30) -> bool:
    floor, allowed = FLOORS[role]
    return correct >= -(-floor * n // 30) and harmful <= allowed


def outcome(role: str, per_arm: dict[str, dict], n: int = 30) -> dict:
    """The README's rule. per_arm[arm] = {"correct": set of item ids, "harmful": int}."""
    fast, delib = per_arm["fast"], per_arm["deliberate"]
    f_ok, d_ok = clears(role, len(fast["correct"]), fast["harmful"], n), clears(role, len(delib["correct"]), delib["harmful"], n)
    b, c = len(delib["correct"] - fast["correct"]), len(fast["correct"] - delib["correct"])
    p = sign_test_p(b, c)
    better = b - c >= 5 and p <= 0.05
    think = per_arm.get("fast-thinking")
    if f_ok:
        result = "fast"
    elif think and clears(role, len(think["correct"]), think["harmful"], n):
        result = "fast, thinking"
    elif d_ok and better:
        result = "needs the larger model"
    elif d_ok:
        result = "undecided"
    else:
        result = "neither"
    return {"outcome": result, "fast_clears": f_ok, "deliberate_clears": d_ok, "b": b, "c": c, "sign_test_p": round(p, 4)}
