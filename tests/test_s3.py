"""Spike S3's scoring and decision rule (spikes/s3/roles.py), against the README's threshold."""

import json
import sys
from pathlib import Path

import pytest

S3 = Path(__file__).resolve().parent.parent / "spikes" / "s3"
sys.path.insert(0, str(S3))

import roles  # noqa: E402


def arm(n_correct, harmful=0, start=0):
    return {"correct": {f"i{k}" for k in range(start, start + n_correct)}, "harmful": harmful}


def test_the_sign_test_thresholds_the_readme_states():
    assert roles.sign_test_p(5, 0) <= 0.05 < roles.sign_test_p(4, 0)
    assert roles.sign_test_p(7, 1) <= 0.05 < roles.sign_test_p(6, 1)
    assert roles.sign_test_p(9, 2) <= 0.05 < roles.sign_test_p(8, 2)


def test_fast_clearing_the_floor_decides_fast_whatever_deliberate_scores():
    assert roles.outcome("r1", {"fast": arm(27, 1), "deliberate": arm(30)})["outcome"] == "fast"


def test_needs_the_larger_model_takes_all_three_conditions():
    fast, delib = arm(20), arm(27)                      # 7 items only deliberate gets, none the other way
    assert roles.outcome("r1", {"fast": fast, "deliberate": delib})["outcome"] == "needs the larger model"
    # deliberate clears, but only four more than fast: not separated
    assert roles.outcome("r5", {"fast": arm(23), "deliberate": arm(27)})["outcome"] == "undecided"
    # neither clears
    assert roles.outcome("r2", {"fast": arm(20), "deliberate": arm(27)})["outcome"] == "neither"
    # too many harmful errors is not clearing, whatever the accuracy
    assert roles.outcome("r3", {"fast": arm(29, harmful=1), "deliberate": arm(22)})["outcome"] == "neither"


def test_the_thinking_arm_is_tried_before_the_larger_model():
    out = roles.outcome("r4", {"fast": arm(20), "fast-thinking": arm(25), "deliberate": arm(29)})
    assert out["outcome"] == "fast, thinking"


def test_a_failed_call_is_a_wrong_reply():
    assert roles.score("r3", None, {"label": {}}) == {"correct": False, "harmful": False}


@pytest.mark.parametrize("role,reply,label,correct,harmful", [
    ("r1", {"is_crypto_use": False, "family": "none", "role": "other", "key_bits": None},
     {"is_crypto_use": True, "family": "RSA", "role": "signature", "key_bits": None}, False, True),
    ("r1", {"is_crypto_use": True, "family": "RSA", "role": "signature", "key_bits": 4096},
     {"is_crypto_use": True, "family": "RSA", "role": "signature", "key_bits": None}, True, False),
    ("r1", {"is_crypto_use": True, "family": "RSA", "role": "signature", "key_bits": None},
     {"is_crypto_use": False, "family": "none", "role": "other", "key_bits": None}, False, False),
    ("r2", {"name": "ffdhe3072", "asset_type": "algorithm", "role": "key-establishment"},
     {"name": "DH-3072", "asset_type": "algorithm", "role": "key-establishment"}, False, True),
    ("r2", {"name": "RSA", "asset_type": "algorithm", "role": "encryption"},
     {"name": "RSA", "asset_type": "algorithm", "role": ["signature", "encryption"]}, True, False),
    ("r2", {"name": "RSA", "asset_type": "algorithm", "role": "other"},
     {"name": "unknown", "asset_type": None, "role": None}, False, True),
    ("r3", {"quantum_vulnerable": False, "function": "signature", "family": "eddsa"},
     {"quantum_vulnerable": True, "function": "signature", "family": "eddsa"}, False, True),
    ("r4", {"in_force": "wire", "reason": "overridden"}, {"in_force": "cannot-tell", "reason": None}, False, True),
    ("r4", {"in_force": "cannot-tell", "reason": "stale-file"}, {"in_force": "wire", "reason": "stale-file"}, False, False),
    ("r5", {"cause": "line", "file": "/a", "line_start": 4, "line_end": 4}, {"file": "/a", "line_start": 4, "line_end": 4}, True, False),
    ("r5", {"cause": "line", "file": "/a", "line_start": 3, "line_end": 4}, {"file": "/a", "line_start": 4, "line_end": 4}, False, False),
    ("r5", {"cause": "line", "file": "/a", "line_start": 4, "line_end": 4}, {"cause": "default"}, False, True),
    ("r6", {"blocked": "supplier", "edits": []}, {"blocked": "supplier"}, True, False),
    ("r6", {"blocked": "protocol", "edits": []}, {"blocked": "none"}, False, False),
])
def test_scoring_by_role(role, reply, label, correct, harmful):
    assert roles.score(role, reply, {"label": label}) == {"correct": correct, "harmful": harmful}


def test_a_change_plan_is_scored_by_running_it():
    ran = []
    def run_plan(item, edits):
        ran.append(edits)
        return {"meets_intent": False, "status": "service-down"}
    out = roles.score("r6", {"blocked": "none", "edits": [{"file": "/x", "line_start": 1, "line_end": 1, "replacement": "y"}]},
                      {"label": {"blocked": "none"}}, item={}, run_plan=run_plan)
    assert ran and out["correct"] is False and out["harmful"] is True


def test_every_item_renders_and_every_label_fits_its_schema():
    """Each committed item fills its role's prompt, and each label is a reply the schema allows."""
    from jsonschema import Draft202012Validator
    for role in sorted(roles.SCHEMAS):
        ip, lp = S3 / "items" / f"{role}.jsonl", S3 / "labels" / f"{role}.jsonl"
        if not ip.exists():
            continue
        items = [json.loads(x) for x in ip.read_text().splitlines()]
        labels = {x["id"]: x for x in map(json.loads, lp.read_text().splitlines())}
        assert len(items) == 36 and sum(i["set"] == "dev" for i in items) == 6, role
        for item in items:
            text = roles.render(role, item)[1]["content"]
            assert "{" + "service}" not in text and "{finding" not in text
            lab = labels[item["id"]]["label"]
            if role == "r5":
                lab = {"cause": "default", "file": None, "line_start": None, "line_end": None} if lab.get("cause") == "default" \
                    else {"cause": "line", **lab}
            elif role == "r6":
                lab = {"blocked": lab["blocked"], "edits": []}
            elif role == "r2":
                lab = {"name": lab["name"], "asset_type": lab["asset_type"] or "algorithm",
                       "role": (lab["role"][0] if isinstance(lab["role"], list) else lab["role"]) or "other"}
            elif role == "r4" and lab["in_force"] == "cannot-tell":
                lab = {"in_force": "cannot-tell", "reason": lab.get("reason") or "tool-limit"}
            assert not list(Draft202012Validator(roles.SCHEMAS[role]).iter_errors(lab)), (role, item["id"], lab)
            assert roles.score(role, lab, labels[item["id"]], item=item,
                               run_plan=lambda i, e: {"meets_intent": True, "status": "enforced"})["correct"], (role, item["id"])
