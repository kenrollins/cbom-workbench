"""Where a page names a model, it reads the name: from the deployment's inference config for a role's
binding, from the event's actor for recorded work, from eval/role-cards.yaml for a score. Nothing typed in."""

import json
import re
from pathlib import Path

import yaml

from pqch.assessor import load_policy, structure
from pqch.inference import Completion, TierUnavailable
from pqch.pipeline import write_cboms
from pqch.ui import agility, demo

from .test_copy import copy_scope
from .test_ui_gates import KEN, app_with

CARDS = Path("eval/role-cards.yaml")
REPORT = Path("spikes/s3/results/scored/report.json")


def test_no_model_hardware_or_score_is_written_into_the_overview_or_the_stage():
    names = set()
    for card in yaml.safe_load(CARDS.read_text())["roles"].values():
        for m in card.get("measured") or []:
            names.update(w.lower() for w in re.findall(r"[A-Za-z]{4,}", m["label"].split(",")[0]))
    names -= {"super"}                       # an English word; the model names it belongs to are caught by their other words
    assert {"nemotron", "gemma", "lightning"} <= names
    for path in ("src/pqch/ui/agility.py", "src/pqch/ui/static/demo.js"):
        text = Path(path).read_text().lower()
        hit = sorted(n for n in names if re.search(rf"\b{n}\b", text))
        assert not hit, (path, hit)
        assert not re.search(r"\bgb10\b|\bl4s\b|aarch64|\b\d\d of 30\b", text), path
    assert 'complete("fast"' not in Path("src/pqch/ui/demo.py").read_text()      # the narration is a role, bound in config


def _cfg(tmp_path, roles):
    tiers = {"fast": {"base_url": "http://127.0.0.1:1/v1", "api_key_env": "K", "model": "fast", "engine": "vllm",
                      "hardware": "one box (Nemotron 3.5 Lightning 30B-A3B NVFP4)", "reasoning": {"model": "fast"}},
             "deliberate": {"base_url": "http://127.0.0.1:1/v1", "api_key_env": "K", "model": "an-unmeasured-model",
                            "hardware": "one box", "engine": "ollama"}}
    p = tmp_path / "inference.yaml"
    p.write_text(yaml.safe_dump({"schema": "pqch.inference/1", "profile": "t", "tiers": tiers, "roles": roles}))
    return str(p)


def test_a_roles_line_is_its_binding_in_the_config_and_the_score_recorded_for_that_model(tmp_path):
    m = agility.Measurements(CARDS, REPORT)
    b = agility.bindings(_cfg(tmp_path, {"change-plan": {"tier": "fast", "reasoning": True},
                                         "trace-to-cause": {"tier": "deliberate"}}), m)
    plan = b["change-plan"]
    assert (plan["tier"], plan["model"], plan["engine"], plan["reasoning"]) == ("fast", "fast", "vllm", True)
    # The card's own numbers for that model in that role, with what it is measured against and where it is from:
    # this binding is below its floor, and the page says so rather than showing another model's score.
    assert plan["measured"]["text"] == "23 of 30, 3 harmful; floor 24 of 30, 2 harmful allowed: below the floor"
    assert plan["measured"]["label"].startswith("Nemotron 3.5 Lightning") and plan["measured"]["source"]
    # A model no card measured in the role: nothing is shown in a score's place.
    assert b["trace-to-cause"]["measured"] is None and b["trace-to-cause"]["engine"] == "ollama"
    assert "resolve-conflict" not in b                       # an unbound role has no line at all
    assert agility.bindings(None, m) == {} and agility.bindings(str(tmp_path / "absent.yaml"), m) == {}
    # No role cards on the box: the binding is still shown, with no score.
    none = agility.bindings(_cfg(tmp_path, {"change-plan": {"tier": "fast", "reasoning": True}}), agility.Measurements(None, None))
    assert none["change-plan"]["model"] == "fast" and none["change-plan"]["measured"] is None


def test_a_recorded_step_names_the_model_its_event_names(tmp_path):
    m = agility.Measurements(CARDS, REPORT)
    actor = {"kind": "model", "id": "fast:g", "tier": "fast", "model": "gemma-4-31b", "engine": "vllm",
             "hardware": "four GPUs (vLLM, Gemma 4 31B FP8)", "role": "change-plan"}
    step = agility._actor_model("change-plan", actor, m)
    assert step["model"] == "gemma-4-31b" and step["hardware"].startswith("four GPUs") and step["engine"] == "vllm"
    assert step["measured"]["text"].startswith("27 of 30, 0 harmful") and step["measured"]["verdict"] == "reaches the floor"
    assert agility._actor_model("change-plan", {"kind": "rule", "id": "r"}, m) is None
    # An arm that says it did not clear is never shown as reaching its floor, whatever its one number says.
    ask = m.for_model("ask-cbom", "x", "a box (Nemotron 3.5 Super VL 120B-A12B NVFP4)", None)
    assert ask["verdict"] == "below the floor"


def test_the_overview_page_renders_bindings_from_the_config(slice_run, tmp_path, monkeypatch):
    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    write_cboms(slice_run)
    cfg = _cfg(tmp_path, {"change-plan": {"tier": "fast", "reasoning": True}, "trace-to-cause": {"tier": "deliberate"}})
    _, c = app_with(monkeypatch, slice_run.var, PQCH_INFERENCE_CONFIG=cfg)
    html = c.get("/").text
    assert "bound to the <code>fast</code> tier: fast (vllm) on one box (Nemotron 3.5 Lightning 30B-A3B NVFP4), reasoning on" in html
    assert "below the floor" in html and "an-unmeasured-model (ollama)" in html
    assert "no measurement is recorded for this model in this role" in html
    assert "resolve-conflict" not in html and "normalize-name" not in html
    assert "portal, api, records-db, bastion under policy" in html            # read from the policy file
    # With no inference config the page claims no model at all.
    _, c = app_with(monkeypatch, slice_run.var)
    html = c.get("/").text
    assert 'class="aiuse"' not in html and "Gemma" not in html and "Nemotron" not in html


# ───────── the narration is a role, labelled, and checked by a rule ─────────

def _completion(text, finish="stop"):
    return Completion(text=text, parsed=None, usage={"completion_tokens": 20}, model="m-narrate", tier="fast",
                      hardware="one box", latency_ms=321, purpose="demo-narration", finish_reason=finish, engine="vllm")


def test_the_narration_goes_through_its_role_and_is_labelled_with_engine_and_hardware(monkeypatch):
    seen = []
    row = {"rank": 1, "service": "portal", "mission": "benefits", "kex": "classical", "title": "offer the hybrid group"}

    def fake(role, messages, **kw):
        seen.append((role, kw))
        return _completion("The portal, which serves benefits, is ranked first; its next step is to offer the hybrid group.")
    monkeypatch.setattr("pqch.inference.complete_role", fake)
    out = demo.narrate("plan", row, services=["portal", "bastion"])
    assert seen[0][0] == "narrate-plan-row" == demo.ROLE
    assert out["text"].startswith("The portal") and out["check"] == {"ok": True, "why": ""}
    assert (out["model"], out["engine"], out["hardware"], out["tier"], out["ms"]) == ("m-narrate", "vllm", "one box", "fast", 321)

    # A line about another row's service, a line cut short, an empty line: refused, with the reason, and no text.
    for text, finish, why in (("The bastion is ranked first.", "stop", "does not name the row's service (portal)"),
                              ("The portal and the bastion both offer the hybrid group.", "stop", "names another service (bastion)"),
                              ("The portal is ranked", "length", "cut short at the reply cap"),
                              ("", "stop", "no text")):
        monkeypatch.setattr("pqch.inference.complete_role", lambda *a, text=text, finish=finish, **k: _completion(text, finish))
        out = demo.narrate("plan", row, services=["portal", "bastion"])
        assert "text" not in out and why in out["error"] and out["check"]["ok"] is False, text
        assert out["model"] == "m-narrate"                       # the call is still labelled

    # The role unbound in this deployment: no narration, said plainly, and no address in the reason.
    def unbound(*a, **k):
        raise TierUnavailable("role 'narrate-plan-row' is bound to no tier in profile 't'")
    monkeypatch.setattr("pqch.inference.complete_role", unbound)
    assert "bound to no tier" in demo.narrate("plan", row)["error"]

    def broken(*a, **k):
        raise RuntimeError("500 from http://10.99.0.7:8014/v1/chat/completions")
    monkeypatch.setattr("pqch.inference.complete_role", broken)
    assert demo.narrate("plan", row)["error"] == "RuntimeError"


def test_the_narration_role_has_a_card_with_a_floor_and_no_claimed_measurement():
    cards = yaml.safe_load(CARDS.read_text())["roles"]
    card = cards[demo.ROLE]
    # Measured against its floor (the rule check on every line, and a person's read) before it was bound.
    assert card["floor"] and card["measured"] and card["measured"][0]["correct"] == card["floor"]["correct"]
    assert cards["ask-notes"]["floor"] is None and cards["ask-notes"]["measured"] == []
    # No recorded ask arm cleared its floor, and the card does not say one did.
    assert cards["ask-cbom"]["measured"] and all(m.get("clears") is False for m in cards["ask-cbom"]["measured"])
    for path in ("kit/inference.yaml", "config/inference.example.yaml"):
        assert demo.ROLE in yaml.safe_load(Path(path).read_text())["roles"], path


# ───────── a still draws a recorded answer or none ─────────

def test_a_still_of_the_ask_beat_is_a_recorded_answer_checked_again_or_nothing(slice_run, monkeypatch):
    from pqch import ask

    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    write_cboms(slice_run)
    assert demo.still_block(slice_run.var) == {"ask": None}
    real = next(iter(slice_run.ledger.events()))["id"]
    q = ask.EXAMPLES[0]
    shown = [{"ref": "listener/x", "kind": "listener", "label": "x", "score": 0.9, "events": [real], "text": "x"}]
    reply = {"answer": "the bastion", "components": ["listener/x"], "citations": [real, "01M00000000000000000000000"],
             "not_in_passages": False}
    p = ask.recording_path(slice_run.var, slice_run.id)
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"run": slice_run.id, "recorded_at": "2026-11-05T19:30:00Z", "answers": {q: {
        "question": q, "shown": shown, "reply": reply, "check": {"ok": True}, "model": "m", "engine": "vllm",
        "tier": "fast", "hardware": "h", "latency_ms": 1234, "reasoning": False, "completion_tokens": 9}}}))
    a = demo.still_block(slice_run.var)["ask"]
    assert a["question"] == q and a["run"] == slice_run.id and (a["model"], a["engine"], a["hardware"], a["latency_ms"]) == ("m", "vllm", "h", 1234)
    # The recording said every citation passed; the still carries the rule's verdict as of now.
    assert a["check"]["ok"] is False and [c["ok"] for c in a["check"]["citations"]] == [True, False]
    _, c = app_with(monkeypatch, slice_run.var)
    html = c.get("/demo?snap=1").text
    assert '"still"' in html and "1234" in html
    js = Path("src/pqch/ui/static/demo.js").read_text()
    assert "5,111" not in js and "37,663" not in js and "01M6KW2M0ZPQ18E1SZ26G53FRQ" not in js
    assert "no recorded answer for this scan" in js


# ───────── the imports table ─────────

def test_an_import_of_a_copy_is_set_beside_the_scan_of_that_copy_and_shows_its_denominator(tmp_path, monkeypatch):
    from pqch import scope as scope_mod
    from pqch.run import Run

    from .test_ui_gates import _copy_import

    var = tmp_path / "var"
    lab, _own = _copy_import(var)
    scope = copy_scope()
    pair = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="copy", kind="scan-copy")
    pair.close()
    other = {**scope, "id": "01M40W6W873YWJMWPKGMK3YBMP", "copy": {**scope["copy"], "taken": "2026-10-01T00:00:00Z"}}
    Run.start(var, other, runner_scope_hash=scope_mod.scope_hash(other), profile="copy", kind="scan-copy").close()

    ui, c = app_with(monkeypatch, var, PQCH_TRUSTED_PROXIES="testclient")
    assert ui._copy_pair(scope["copy"])["run"] == pair.id                  # the same copy, by what it copies and when
    page = c.get("/imports", headers=KEN).text
    assert f"<code>{pair.id}</code>" in page and lab.id in page

    # The newer import.completed payload, and an older one without its fields, both render.
    from pqch.ui import view
    rows = [{"run": "01NEW", "tool": "t", "version": "1", "documents": [], "assets": {}, "unplaced": 0, "lab": False,
             "score": {"wire": {"scanned": True, "covered": 28, "present": 38, "denominator": 35, "false_positives": 7,
                                "out_of_reach": 0, "flagged_decoys": [], "remediated": 3, "unplanted": 1, "unrecognised": 0}},
             "left_out": {"no_location": 4, "out_of_scope": 0, "client_side": 2, "referenced": 0, "listeners": 1, "repeated": 0},
             "observation": {"observed": "wire", "conditions": [], "window": "2026-11-16"}},
            {"run": "01OLD", "tool": "t", "version": "1", "documents": [], "assets": {}, "unplaced": 0, "lab": False,
             "score": {"wire": {"scanned": True, "covered": 5, "present": 22, "out_of_reach": 1, "flagged_decoys": []}}}]
    monkeypatch.setattr(view, "imports_view", lambda var: [dict(r) for r in rows])
    page = c.get("/imports").text
    assert "28 of 35" in page and "7 false positives" in page and "3 remediated since" in page
    assert "4 with no location" in page and "2 client-side" in page and "1 listeners" in page
    assert "5 of 22" in page and "+1 out of reach" in page
