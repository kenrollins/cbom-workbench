import json

import pytest

from pqch.common import canonical, hash_object, ulid
from pqch.ledger import GENESIS, Ledger, event_hash, verify

ACTOR = {"kind": "human", "id": "test"}
RUNNER = {"kind": "runner", "id": "test"}
SCOPE = {"schema": "pqch.scope/1", "id": "01M40W6W873YWJMWPKGMK3YBMM", "estate": "colocated", "owned": True,
         "authorized_by": None, "endpoints": [], "images": [], "sources": [], "reach": {"kind": "local"}}


def start(tmp_path):
    led = Ledger(tmp_path / "ledger.jsonl")
    led.append("run.started", RUNNER, {"scope": SCOPE, "scope_hash": hash_object(SCOPE), "profile": "t",
                                       "schemas": []})
    return led


def rewrite(led, events):
    """Write events back with seq, prev and hash recomputed: what anyone with the file can do."""
    prev = GENESIS
    lines = []
    for i, ev in enumerate(events):
        ev = {**ev, "seq": i, "prev": prev}
        try:
            ev["hash"] = event_hash(ev)
        except TypeError:  # a float: no canonical form, so no hash to forge
            ev["hash"] = "0" * 64
        prev = ev["hash"]
        lines.append(json.dumps(ev))
    led.path.write_text("\n".join(lines) + "\n")


def test_canonical_sorts_keys_and_rejects_floats():
    assert canonical({"b": 1, "a": "é"}) == '{"a":"é","b":1}'.encode()
    with pytest.raises(TypeError):
        canonical({"x": 1.5})


def test_ulid_shape():
    a, b = ulid(), ulid()
    assert len(a) == 26 and a != b


def test_chain_appends_and_verifies(tmp_path):
    led = start(tmp_path)
    e0 = next(led.events())
    e1 = led.append("key.committed", ACTOR, {"path": "k", "sha256": "1" * 64}, inputs=[e0["id"]])
    assert e0["seq"] == 0 and e0["prev"] == GENESIS
    assert e1["seq"] == 1 and e1["prev"] == e0["hash"]
    res = verify(led.events())
    assert res.ok and res.count == 2 and res.head == e1["hash"]


def test_any_edit_breaks_the_chain(tmp_path):
    led = start(tmp_path)
    for i in range(3):
        led.append("key.committed", ACTOR, {"n": i})
    lines = led.path.read_text().splitlines()
    ev = json.loads(lines[1])
    ev["payload"]["n"] = 99
    lines[1] = json.dumps(ev)
    led.path.write_text("\n".join(lines) + "\n")
    res = verify(led.events())
    assert not res.ok and res.at_seq == 1 and "hash" in res.error


def test_removal_breaks_the_chain(tmp_path):
    led = start(tmp_path)
    for i in range(3):
        led.append("key.committed", ACTOR, {"n": i})
    lines = led.path.read_text().splitlines()
    led.path.write_text(lines[0] + "\n" + lines[2] + "\n")
    assert not verify(led.events()).ok


def test_apply_without_approval_is_invalid(tmp_path):
    led = start(tmp_path)
    led.append("change.applied", {"kind": "runner", "id": "r"}, {"change_id": "c1"})
    res = verify(led.events())
    assert not res.ok and "approval" in res.error


def test_hash_excludes_hash_field():
    ev = {"a": 1}
    assert hash_object(ev) == hash_object({"a": 1})


def test_event_zero_must_be_run_started(tmp_path):
    led = Ledger(tmp_path / "ledger.jsonl")
    led.append("key.committed", ACTOR, {"n": 0})
    assert "run.started" in verify(led.events()).error


@pytest.mark.parametrize("mutate,expect", [
    (lambda e: e[1].update(inputs=["01ZZZZZZZZZZZZZZZZZZZZZZZZ"]), "not an earlier event"),
    (lambda e: e[2].update(id=e[1]["id"]), "already used"),
    (lambda e: e[2].update(ts="1999-01-01T00:00:00.000Z"), "earlier than"),
    (lambda e: e[1].update(type="verdict.issued"), "verdict.issued from a human"),
    (lambda e: e[1].update(type="approval.granted"), "names no change id"),
    (lambda e: e[1]["payload"].update(n=1.5), "float"),
])
def test_a_rewritten_chain_still_has_to_make_sense(tmp_path, mutate, expect):
    led = start(tmp_path)
    for i in range(2):
        led.append("key.committed", ACTOR, {"n": i})
    events = list(led.events())
    mutate(events)
    rewrite(led, events)
    res = verify(led.events())
    assert not res.ok and expect in res.error


def test_garbage_and_torn_lines_fail_without_raising(tmp_path):
    led = start(tmp_path)
    led.append("key.committed", ACTOR, {"n": 0})
    good = led.path.read_text()
    for tail in ("{not json\n", good.splitlines()[-1][:40]):
        led.path.write_text(good + tail)
        res = verify(led.events())
        assert not res.ok and res.at_seq == 2


def test_a_finding_whose_fingerprint_is_wrong_fails(slice_run):
    events = list(slice_run.ledger.events())
    i = next(n for n, e in enumerate(events) if e["type"] == "finding.observed")
    events[i]["payload"]["fingerprint"] = "0" * 64
    rewrite(slice_run.ledger, events)
    assert "fingerprint" in verify(slice_run.ledger.events()).error


def test_truncation_is_not_visible_to_the_chain_alone(slice_run):
    """The chain cannot see a cut-back ledger; tests/test_checkpoints.py shows the checkpoint does."""
    lines = slice_run.ledger.path.read_text().splitlines()
    slice_run.ledger.path.write_text("\n".join(lines[:5]) + "\n")
    assert verify(slice_run.ledger.events()).ok


def test_nothing_is_appended_after_run_closed(tmp_path):
    from pqch.ledger import LedgerError
    led = start(tmp_path)
    led.append("run.closed", RUNNER, {})
    with pytest.raises(LedgerError, match="closed"):
        led.append("key.committed", ACTOR, {"n": 1})
    events = list(led.events())
    events.append({**events[-1], "type": "key.committed", "actor": ACTOR, "id": "01M40W6W873YWJMWPKGMK3YBMZ"})
    rewrite(led, events)
    assert "after run.closed" in verify(led.events()).error
