"""The signer's interface, served on a Unix socket.

    GET  /key                   algorithm (PQCH_CHECKPOINT_ALG), key id, public key, OpenSSL version
    POST /checkpoint            {"run", "through_seq"} -> a signed pqch.checkpoint/1, with signing time
    GET  /record/{run}          the checkpoints this signer has signed for a run

Served with `--http pqch.peercred:PeerCredProtocol`, each checkpoint's caller (uid and pid, from the
kernel) goes in the signer's own record; `PQCH_SIGNER_CHECKPOINT_UIDS`, when set, is the only uids
that may ask for one (reads stay open to every connection the socket accepts).
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi import Request as HTTPRequest
from pydantic import BaseModel

from pqch.peercred import check_env, require_uid

from pqch.signer import Signer, SignerError

check_env()                                   # a uid list that cannot be read stops the service here
app = FastAPI(title="pqch-signer", docs_url=None, redoc_url=None, openapi_url=None)
signer = Signer(os.environ.get("PQCH_SIGNER_KEY_DIR", "/var/pqch-signer"),
                os.environ.get("PQCH_RUNS", "/var/pqch/runs"),
                hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"),
                alg=os.environ.get("PQCH_CHECKPOINT_ALG") or "ML-DSA-65")
signer.ensure_key()


class Request(BaseModel):
    run: str
    through_seq: int


@app.get("/key")
def get_key() -> dict:
    return signer.public()


@app.post("/checkpoint")
def post_checkpoint(req: Request, http: HTTPRequest) -> dict:
    who = require_uid(http, "PQCH_SIGNER_CHECKPOINT_UIDS")
    try:
        return signer.checkpoint(req.run, req.through_seq, caller=who)
    except SignerError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e


@app.get("/record/{run}")
def get_record(run: str) -> list[dict]:
    if not run.isalnum():
        raise HTTPException(404)
    return signer.record(run)
