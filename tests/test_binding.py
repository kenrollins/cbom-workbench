"""F-31: wire and host evidence are joined only when the listener runs the scope's image."""

import pytest

from pqch.assessor import load_policy, structure

from .conftest import binding_for, make_run

POLICY = load_policy("policy/pq-algorithms.yaml")
OTHER = "pqch-agency/portal@sha256:" + "9" * 64


def bindings(run):
    return {(e["payload"]["subject"]["host"], e["payload"]["subject"]["port"]): e["payload"]
            for e in run.ledger.events() if e["payload"].get("rule_id") == "binding/scope/1"}


def test_a_listener_running_the_scopes_image_is_bound_and_joined(slice_run):
    counts = structure(slice_run, POLICY)
    assert counts["unbound"] == 0 and counts["links"] == 4
    assert all(b["classification"]["bound"] for b in bindings(slice_run).values())


@pytest.mark.parametrize("bind,reason", [
    (lambda t: binding_for(t, image=OTHER if t.get("host") == "172.16.106.10" else None), "not the scope's"),
    (lambda t: binding_for(t, stable=t.get("host") != "172.16.106.10"), "changed during the scan"),
    (lambda t: None if t.get("host") == "172.16.106.10" else binding_for(t), "no container"),
])
def test_an_unbound_listener_is_reported_and_never_joined(tmp_path, bind, reason):
    run = make_run(tmp_path, bind)
    counts = structure(run, POLICY)
    b = bindings(run)[("172.16.106.10", 443)]
    assert b["classification"]["bound"] is False and reason in b["basis"]
    assert counts["unbound"] == 1
    events = list(run.ledger.events())
    findings = {e["id"]: e["payload"] for e in events if e["type"] == "finding.observed"}
    links = [e["payload"] for e in events if e["type"] == "link.asserted"]
    assert links and not any(findings[ln["from"]]["subject"]["host"] == "172.16.106.10" for ln in links)
    # And nothing in the portal image is judged unused on the strength of a listener nobody can vouch for.
    judged = [e["payload"] for e in events if e["payload"].get("rule_id") == "in-use/not-served/1"]
    assert not any(findings[j["finding"]]["subject"].get("image") == "pqch-agency/portal" for j in judged)


def test_the_page_says_when_a_listener_is_not_bound(tmp_path, monkeypatch):
    import importlib
    import warnings

    from pqch.pipeline import write_cboms, write_score
    run = make_run(tmp_path, lambda t: binding_for(t, image=OTHER if t.get("host") == "172.16.106.10" else None))
    structure(run, POLICY)
    run.close()
    write_cboms(run)
    write_score(run, __import__("pathlib").Path("eval/answer-keys/mini-agency-m0.yaml"))
    monkeypatch.setenv("PQCH_VAR", str(run.var))
    monkeypatch.delenv("PQCH_SIGNER_SOCKET", raising=False)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from fastapi.testclient import TestClient

        import pqch.ui.app as ui
        importlib.reload(ui)
        html = TestClient(ui.app).get("/walkthrough").text
    assert "did not run the image the scope names" in html and "172.16.106.10:443" in html
    assert "not bound to scope" in html
