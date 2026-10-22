"""The signer's interface, served on a Unix socket.

    GET  /key                   algorithm, key id, public key, OpenSSL version
    POST /checkpoint            {"run", "through_seq"} -> a signed pqch.checkpoint/1, with signing time
    GET  /record/{run}          the checkpoints this signer has signed for a run
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from pqch.signer import Signer, SignerError

app = FastAPI(title="pqch-signer", docs_url=None, redoc_url=None, openapi_url=None)
signer = Signer(os.environ.get("PQCH_SIGNER_KEY_DIR", "/var/pqch-signer"),
                os.environ.get("PQCH_RUNS", "/var/pqch/runs"),
                hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"))
signer.ensure_key()


class Request(BaseModel):
    run: str
    through_seq: int


@app.get("/key")
def get_key() -> dict:
    return signer.public()


@app.post("/checkpoint")
def post_checkpoint(req: Request) -> dict:
    try:
        return signer.checkpoint(req.run, req.through_seq)
    except SignerError as e:
        raise HTTPException(status_code=409, detail=str(e)) from e


@app.get("/record/{run}")
def get_record(run: str) -> list[dict]:
    if not run.isalnum():
        raise HTTPException(404)
    return signer.record(run)
