"""The citation rule of Ask the CBOM (rule 1: a model never decides whether its answer is supported)."""

import json
from pathlib import Path

from pqch import ask

EVENTS = [{"id": f"01M0000000000000000000000{c}", "type": "finding.observed", "actor": {"id": "t"}} for c in "ABCD"]
A, B, C, D = (e["id"] for e in EVENTS)
# A service, its two listeners, and an asset on each: the chain the CBOM's dependencies give.
SHOWN = [
    {"ref": "svc:bastion", "kind": "service", "label": "bastion", "text": "", "events": [D], "near": ["listener:a"]},
    {"ref": "listener:a", "kind": "listener", "label": "a", "text": "", "events": [A], "near": ["svc:bastion", "fp:kex-a"]},
    {"ref": "fp:kex-a", "kind": "asset", "label": "DH-1024", "text": "", "events": [C], "near": ["listener:a"]},
    {"ref": "listener:b", "kind": "listener", "label": "b", "text": "", "events": [B], "near": ["svc:other"]},
]


def _reply(**kw):
    return {"answer": "The bastion offers DH-1024.", "components": [], "citations": [], "not_in_passages": False, **kw}


def test_an_answer_that_cites_nothing_fails():
    out = ask.check(_reply(), SHOWN, EVENTS)
    assert out["ok"] is False and out["declined"] is False and "No events cited" in out["verdict"]
    # Naming a component without an event behind it is still nothing to check the answer by.
    assert ask.check(_reply(components=["listener:a"]), SHOWN, EVENTS)["ok"] is False


def test_saying_the_passages_do_not_answer_is_declined_and_not_a_pass():
    out = ask.check(_reply(not_in_passages=True), SHOWN, EVENTS)
    assert out["declined"] is True and out["ok"] is False and "do not answer" in out["verdict"]


def test_a_citation_passes_only_from_a_named_component_or_its_chain():
    # its own passage
    assert ask.check(_reply(components=["listener:a"], citations=[A]), SHOWN, EVENTS)["ok"] is True
    # the service named, the listener's and the asset's events cited: one and two dependencies away
    out = ask.check(_reply(components=["svc:bastion"], citations=[A, C]), SHOWN, EVENTS)
    assert out["ok"] is True and all(c["supports"] for c in out["citations"]) and out["chain"] == "checked"
    # another listener's event for a claim about this one: in the ledger, shown, and no support
    out = ask.check(_reply(components=["listener:a"], citations=[B]), SHOWN, EVENTS)
    c = out["citations"][0]
    assert c["in_ledger"] and c["shown"] and c["supports"] is False and c["ok"] is False and c["from"] == ["listener:b"]
    assert out["ok"] is False and "neither a named component's nor in its chain" in out["verdict"]
    # events cited and no component named: nothing ties them to the answer
    assert ask.check(_reply(citations=[A]), SHOWN, EVENTS)["ok"] is False
    # an event that is not in the ledger, or was not shown, fails as before
    assert ask.check(_reply(components=["listener:a"], citations=["01M0000000000000000000000Z"]), SHOWN, EVENTS)["ok"] is False


def test_an_older_recording_without_chains_is_checked_as_far_as_it_can_be_and_says_so():
    old = [{k: v for k, v in p.items() if k != "near"} for p in SHOWN]
    out = ask.check(_reply(components=["listener:a"], citations=[B]), old, EVENTS)
    assert out["ok"] is True and out["citations"][0]["supports"] is None and out["chain"].startswith("not checked")
    assert ask.check(_reply(), old, EVENTS)["ok"] is False          # the empty answer fails there too


def test_passages_carry_the_components_one_dependency_away(slice_run):
    from pqch.assessor import load_policy, structure
    from pqch.cbom import project

    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    events = list(slice_run.ledger.events())
    bom = project(events)
    ps = ask.passages(bom, events)
    deps = {d["ref"]: set(d.get("dependsOn", [])) for d in bom.get("dependencies", [])}
    by_ref = {p["ref"]: p for p in ps}
    some = next(r for r, kids in deps.items() if kids and r in by_ref)
    assert deps[some] & set(by_ref[some]["near"])
    child = next(iter(deps[some] & set(by_ref)))
    assert some in by_ref[child]["near"]                           # either way


def test_a_failed_question_is_recorded_without_the_engines_address(slice_run, monkeypatch):
    from pqch.assessor import load_policy, structure

    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()

    class Idx:
        def __init__(self, *a, **k):
            pass
    monkeypatch.setattr(ask, "Index", Idx)

    def boom(seam, index, q, events):
        raise RuntimeError("503 from http://10.99.0.7:8014/v1/chat/completions")
    monkeypatch.setattr(ask, "ask", boom)
    rec = ask.record(object(), slice_run, questions=["q?"])
    assert rec["answers"]["q?"]["unavailable"] == "RuntimeError"
    assert "10.99.0.7" not in ask.recording_path(slice_run.var, slice_run.id).read_text()


def test_the_item_set_has_questions_the_cbom_cannot_answer():
    items = [json.loads(x) for x in Path("eval/ask/items.jsonl").read_text().splitlines()]
    un = [i for i in items if i.get("unanswerable")]
    assert len(items) - len(un) == 12 and len(un) >= 3 and all(i["refs"] == [] for i in un)
