"""The runner's HTTP interface, served on a Unix socket.

    GET  /scope     the scope the runner enforces, with its hash
    GET  /profiles  the profile names
    POST /jobs      {"profile", "target", "scope_hash", "params"?} -> a job result, or a refusal
    POST /apply     {"run", "change_id"} -> what was applied, or a refusal (pqch.runner.apply)
    POST /recreate  {"run", "change_id"} -> the service recreated, unchanged, or a refusal
    POST /rehearse  {"run", "change_id"} -> a copy of the service on the twin network with the proposal
    POST /rehearse/end  {"run", "change_id"} -> the copy removed
    GET  /log       every apply and recreate this runner has done
    GET  /jobs      ?ids=a,b — the runner's own record of those jobs
"""

from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from pqch.runner import Refused, Runner
from pqch.runner.apply import Applier

app = FastAPI(title="pqch-runner", docs_url=None, redoc_url=None, openapi_url=None)
runner = Runner(
    os.environ.get("PQCH_SCOPE", "/etc/pqch/scope.json"),
    os.environ.get("PQCH_RAW", "/var/pqch/raw"),
    target_network=os.environ.get("PQCH_TARGET_NETWORK", "pqch-agency-net"),
    log_dir=os.environ.get("PQCH_RUNNER_LOG"),
)


applier = None
if os.environ.get("PQCH_AGENCY_DIR") and os.environ.get("PQCH_SIGNER_SOCKET"):
    from pqch.signer.client import SignerClient

    applier = Applier(runner, runs_dir=os.environ.get("PQCH_RUNS", "/var/pqch/runs"),
                      agency_dir=os.environ["PQCH_AGENCY_DIR"],
                      log_dir=os.environ.get("PQCH_RUNNER_LOG", "/var/pqch-runner"),
                      signer=SignerClient(os.environ["PQCH_SIGNER_SOCKET"]),
                      compose_files=[f for f in os.environ.get("PQCH_AGENCY_COMPOSE_FILES", "").split(":") if f] or None)


class Job(BaseModel):
    profile: str
    target: dict
    scope_hash: str
    params: dict | None = None


class Change(BaseModel):
    run: str
    change_id: str


@app.get("/scope")
def get_scope() -> dict:
    scope, h = runner.scope()
    return {"scope": scope, "scope_hash": h}


@app.get("/profiles")
def get_profiles() -> list[str]:
    return sorted(runner.profiles)


@app.post("/jobs")
def post_job(job: Job) -> dict:
    try:
        return runner.run(job.profile, job.target, job.scope_hash, job.params).to_dict()
    except Refused as r:
        raise HTTPException(status_code=r.code, detail=r.reason) from r


def _applier() -> Applier:
    if applier is None:
        raise HTTPException(status_code=503, detail="this runner is not configured to apply changes")
    return applier


@app.post("/apply")
def post_apply(c: Change) -> dict:
    try:
        return _applier().apply(c.run, c.change_id)
    except Refused as r:
        raise HTTPException(status_code=r.code, detail=r.reason) from r


@app.post("/recreate")
def post_recreate(c: Change) -> dict:
    try:
        return _applier().recreate(c.run, c.change_id)
    except Refused as r:
        raise HTTPException(status_code=r.code, detail=r.reason) from r


@app.post("/rehearse")
def post_rehearse(c: Change) -> dict:
    try:
        return _applier().rehearse(c.run, c.change_id)
    except Refused as r:
        raise HTTPException(status_code=r.code, detail=r.reason) from r


@app.post("/rehearse/end")
def post_rehearse_end(c: Change) -> dict:
    try:
        return _applier().rehearse_end(c.run, c.change_id)
    except Refused as r:
        raise HTTPException(status_code=r.code, detail=r.reason) from r


@app.get("/jobs")
def get_jobs(ids: str = "") -> list[dict]:
    """The runner's own record of the named jobs (comma-separated ids)."""
    wanted = {i for i in ids.split(",") if i.isalnum()}
    return runner.jobs(wanted) if wanted else []


@app.get("/log")
def get_log() -> list[dict]:
    return _applier().log()
