"""Who is on the other end of a Unix socket: the kernel's answer (`SO_PEERCRED`), not the caller's.

The signer and the runner are served on Unix sockets. Anyone who can reach a socket can connect,
and a read-only mount does not prevent connecting (FR-11). This module gives uvicorn a protocol
that reads the peer's pid, uid and gid from the kernel when a connection is made, and:

- puts the caller in the request as `client = ("uid:<uid>", <pid>)`, so a service can record who
  asked (`caller(request)`) and refuse an endpoint to a uid not on its list (`require_uid`);
- closes, before a byte is read, a connection from a uid not in `PQCH_SOCKET_ALLOW_UIDS`, when
  that is set.

Every list is opt-in: unset, every caller is accepted as before, and only recorded. A uid list is
only as strong as the uids are distinct: services that run as one user cannot be told apart by it.
The kernel translates the peer's uid and pid into this process's namespaces: with rootful Docker and
no userns remapping the uid is the host's, which is what the lists assume; a pid from another
container's pid namespace comes back as 0 and is then not recorded.

Served as `uvicorn --http pqch.peercred:PeerCredProtocol`; it is the protocol uvicorn's `auto`
choice would pick (httptools when installed, h11 otherwise), with the check added.
"""

from __future__ import annotations

import logging
import os
import socket
import struct

from uvicorn.protocols.http.auto import AutoHTTPProtocol

ALLOW_ENV = "PQCH_SOCKET_ALLOW_UIDS"
_CRED = struct.Struct("3i")


def peer_cred(sock: socket.socket | None) -> tuple[int, int, int] | None:
    """(pid, uid, gid) of a Unix socket's peer, or None when it is not one or the kernel will not say."""
    if sock is None or getattr(sock, "family", None) != socket.AF_UNIX or not hasattr(socket, "SO_PEERCRED"):
        return None
    try:
        return _CRED.unpack(sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, _CRED.size))
    except OSError:
        return None


log = logging.getLogger("pqch.peercred")
_LISTS = (ALLOW_ENV, "PQCH_SIGNER_CHECKPOINT_UIDS", "PQCH_RUNNER_CHANGE_UIDS")


def uid_list(value: str | None) -> set[int] | None:
    """A comma-separated list of uids. None when the variable is unset (no restriction); a set when it
    is set, which may be empty: a list that is present and names nobody admits nobody. Anything that
    is not a uid raises ValueError, and a service checks its lists before it starts (`check_env`)."""
    if value is None:
        return None
    out = set()
    for x in value.replace(" ", "").split(","):
        if not x:
            continue
        if not x.isdigit():
            raise ValueError(f"{x!r} is not a uid; a uid list is comma-separated integers")
        out.add(int(x))
    return out


def check_env() -> None:
    """Every uid list in the environment parses, or the service refuses to start (SystemExit) rather
    than serve with a list it cannot read."""
    for name in _LISTS:
        try:
            uid_list(os.environ.get(name))
        except ValueError as e:
            raise SystemExit(f"{name}: {e}") from e


class PeerCredProtocol(AutoHTTPProtocol):  # type: ignore[misc, valid-type]
    def connection_made(self, transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        cred = peer_cred(transport.get_extra_info("socket"))
        if cred:
            self.client = (f"uid:{cred[1]}", cred[0])
        try:
            allow = uid_list(os.environ.get(ALLOW_ENV))
        except ValueError as e:
            # Fail closed, and say so once per connection in one line, not a traceback.
            log.error("%s cannot be read (%s): connection from %s closed", ALLOW_ENV, e, self.client)
            transport.close()
            return
        if allow is not None and (cred is None or cred[1] not in allow):
            transport.close()


def caller(request) -> dict | None:
    """The kernel's word on who sent a request served by PeerCredProtocol: {"uid", "pid"}."""
    c = getattr(request, "client", None)
    host = getattr(c, "host", None) or ""
    if not host.startswith("uid:"):
        return None
    pid = int(c.port)
    return {"uid": int(host[4:]), **({"pid": pid} if pid else {})}


def require_uid(request, env: str) -> dict | None:
    """Refuse (403) a caller whose uid is not in the list `env` names, when that list is set."""
    from fastapi import HTTPException

    who = caller(request)
    allow = uid_list(os.environ.get(env))
    if allow is not None and (who is None or who["uid"] not in allow):
        raise HTTPException(status_code=403, detail=f"this endpoint is not open to uid {who and who['uid']}")
    return who
