"""M8, FR-11: the signer and the runner know who is on the other end of their Unix sockets."""

import os
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request

from pqch.peercred import PeerCredProtocol, caller, require_uid, uid_list


def _app():
    app = FastAPI()

    @app.get("/who")
    def who(request: Request):
        return {"caller": caller(request)}

    @app.get("/guarded")
    def guarded(request: Request):
        return {"caller": require_uid(request, "PQCH_TEST_GUARD_UIDS")}

    return app


@pytest.fixture
def served(tmp_path):
    sock = str(tmp_path / "s.sock")
    server = uvicorn.Server(uvicorn.Config(_app(), uds=sock, http=PeerCredProtocol, log_level="error", lifespan="off"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    for _ in range(200):
        if server.started:
            break
        time.sleep(0.01)
    yield httpx.Client(transport=httpx.HTTPTransport(uds=sock), base_url="http://s", timeout=5)
    server.should_exit = True
    t.join(5)


def test_the_kernel_names_the_caller(served):
    c = served.get("/who").json()["caller"]
    assert c == {"uid": os.getuid(), "pid": os.getpid()}


def test_with_no_list_set_every_caller_is_accepted_as_before(served, monkeypatch):
    monkeypatch.delenv("PQCH_SOCKET_ALLOW_UIDS", raising=False)
    monkeypatch.delenv("PQCH_TEST_GUARD_UIDS", raising=False)
    assert served.get("/guarded").status_code == 200


def test_a_uid_not_on_the_endpoints_list_is_refused(served, monkeypatch):
    monkeypatch.setenv("PQCH_TEST_GUARD_UIDS", str(os.getuid() + 1))
    r = served.get("/guarded")
    assert r.status_code == 403 and f"uid {os.getuid()}" in r.json()["detail"]
    monkeypatch.setenv("PQCH_TEST_GUARD_UIDS", f"0,{os.getuid()}")
    assert served.get("/guarded").status_code == 200


def test_a_uid_not_on_the_socket_list_is_closed_before_a_byte_is_read(served, monkeypatch):
    monkeypatch.setenv("PQCH_SOCKET_ALLOW_UIDS", str(os.getuid() + 1))
    with pytest.raises(httpx.TransportError):
        served.get("/who")
    monkeypatch.setenv("PQCH_SOCKET_ALLOW_UIDS", str(os.getuid()))
    assert served.get("/who").status_code == 200


def test_uid_lists_parse_unset_means_no_restriction_and_empty_means_nobody():
    from pqch.peercred import check_env
    assert uid_list(None) is None
    assert uid_list("  ") == set() and uid_list("") == set()       # set but empty: nobody, not everybody
    assert uid_list("1000, 1001") == {1000, 1001}
    for bad in ("1000;1001", "abc", "-1"):
        with pytest.raises(ValueError, match="not a uid"):
            uid_list(bad)
    os.environ["PQCH_RUNNER_CHANGE_UIDS"] = "abc"
    try:
        with pytest.raises(SystemExit, match="PQCH_RUNNER_CHANGE_UIDS"):
            check_env()
    finally:
        del os.environ["PQCH_RUNNER_CHANGE_UIDS"]


def test_an_empty_or_unreadable_socket_list_admits_nobody(served, monkeypatch):
    for value in ("", "1000;1001"):
        monkeypatch.setenv("PQCH_SOCKET_ALLOW_UIDS", value)
        with pytest.raises(httpx.TransportError):
            served.get("/who")


def test_the_signer_keeps_the_caller_in_its_own_record(slice_run, tmp_path):
    from .test_checkpoints import PySigner

    s = PySigner(tmp_path / "signer", slice_run.var / "runs")
    s.ensure_key()
    seq = len(list(slice_run.ledger.events())) - 1
    s.checkpoint(slice_run.id, seq, caller={"uid": 1000, "pid": 42})
    assert s.record(slice_run.id)[-1]["caller"] == {"uid": 1000, "pid": 42}


def test_the_compose_files_serve_both_sockets_with_the_check():
    for f in ("compose.yaml", "kit/compose.system.yaml"):
        text = open(f).read()
        for svc in ("pqch.runner.service:app", "pqch.signer.service:app"):
            line = text[text.index(svc):text.index("]", text.index(svc))]
            assert "pqch.peercred:PeerCredProtocol" in line, (f, svc)
