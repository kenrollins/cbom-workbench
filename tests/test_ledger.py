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


def test_a_torn_last_line_refuses_the_append_and_names_where(tmp_path):
    from pqch.ledger import LedgerError
    led = start(tmp_path)
    led.append("key.committed", ACTOR, {"n": 0})
    good = led.path.read_bytes()
    for tail in (good.splitlines()[-1][:40], b"{not json\n", good.splitlines()[-1][:40] + b"\n"):
        led.path.write_bytes(good + tail)
        with pytest.raises(LedgerError, match=f"at byte {len(good)} of {len(good) + len(tail)}"):
            led.append("key.committed", ACTOR, {"n": 1})
        assert led.path.read_bytes() == good + tail          # nothing written, nothing removed


def test_a_whole_last_event_without_its_newline_gets_it_back_before_the_next(tmp_path):
    led = start(tmp_path)
    led.append("key.committed", ACTOR, {"n": 0})
    led.path.write_bytes(led.path.read_bytes().rstrip(b"\n"))
    assert verify(led.events()).ok
    e = led.append("key.committed", ACTOR, {"n": 1})
    res = verify(led.events())
    assert res.ok and res.count == 3 and e["seq"] == 2
    # Blank lines after the last event are not an event either.
    with led.path.open("ab") as f:
        f.write(b"\n\n")
    assert led.append("key.committed", ACTOR, {"n": 2})["seq"] == 3 and verify(led.events()).ok


def test_the_head_is_read_from_the_end_whatever_the_last_line_s_size(tmp_path):
    import pqch.ledger as ledger_mod
    led = start(tmp_path)
    for n in (10, ledger_mod._BLOCK - 300, ledger_mod._BLOCK * 3):       # shorter than, about, and several blocks
        led.append("key.committed", ACTOR, {"pad": "é" * n})
        led.append("key.committed", ACTOR, {"n": n})
    res = verify(led.events())
    assert res.ok and res.count == 7


def test_a_clock_stepped_back_is_clamped_to_the_head_and_said_so(tmp_path, monkeypatch):
    import pqch.ledger as ledger_mod
    led = start(tmp_path)
    head = led.append("key.committed", ACTOR, {"n": 0}, ts="2031-01-01T10:00:00.500Z")
    monkeypatch.setattr(ledger_mod, "utc_now", lambda: "2031-01-01T09:00:00.000Z")
    e = led.append("key.committed", ACTOR, {"n": 1})
    assert e["ts"] == head["ts"] and e["ts_clamped_from"] == "2031-01-01T09:00:00.000Z"
    # A caller's own time gets the same treatment, and times are compared as times: as strings,
    # "10:00:00Z" sorts after "10:00:00.500Z" and "10:00:01Z" after "10:00:01.5Z".
    e = led.append("key.committed", ACTOR, {"n": 2}, ts="2031-01-01T10:00:00Z")
    assert e["ts"] == head["ts"] and e["ts_clamped_from"] == "2031-01-01T10:00:00Z"
    e = led.append("key.committed", ACTOR, {"n": 3}, ts="2031-01-01T10:00:01Z")
    assert "ts_clamped_from" not in e
    e = led.append("key.committed", ACTOR, {"n": 4}, ts="2031-01-01T10:00:01.5Z")
    assert "ts_clamped_from" not in e
    assert verify(led.events()).ok


def test_a_timestamp_that_is_no_time_is_refused_at_append_and_fails_verification(tmp_path):
    from pqch.ledger import LedgerError
    led = start(tmp_path)
    with pytest.raises(LedgerError, match="not a time"):
        led.append("key.committed", ACTOR, {"n": 0}, ts="2026-13-45T99:99:99Z")
    events = list(led.events())
    assert len(events) == 1
    events.append({**events[0], "type": "key.committed", "actor": ACTOR, "id": "01M40W6W873YWJMWPKGMK3YBMZ",
                   "ts": "2026-13-45T99:99:99Z"})
    rewrite(led, events)          # the schema's pattern admits it; a hand-written ledger can carry it
    res = verify(led.events())
    assert not res.ok and "not a time" in res.error and res.at_seq == 1


def test_an_append_that_names_its_head_is_refused_when_the_head_moved(tmp_path):
    from pqch.ledger import HeadMoved
    led = start(tmp_path)
    a = led.append("key.committed", ACTOR, {"n": 0})
    led.append("key.committed", ACTOR, {"n": 1})
    with pytest.raises(HeadMoved):
        led.append("run.closed", RUNNER, {}, expect_head=a["id"])
    assert sum(1 for _ in led.events()) == 3


def test_a_byte_that_is_not_utf8_fails_at_its_event_without_raising(tmp_path):
    led = start(tmp_path)
    led.append("key.committed", ACTOR, {"note": "abcdef"})
    led.append("key.committed", ACTOR, {"n": 2})
    data = led.path.read_bytes()
    led.path.write_bytes(data.replace(b"abcdef", b"abc\xffef"))
    res = verify(led.events())
    assert not res.ok and res.at_seq == 1 and "hash" in res.error


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
