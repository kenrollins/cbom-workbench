"""The harness side of the runner: an HTTP client over the runner's Unix socket."""

from __future__ import annotations

import httpx


class RunnerRefused(Exception):
    def __init__(self, code: int, reason: str):
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason


class RunnerClient:
    def __init__(self, socket_path: str, timeout_s: float = 900):
        self._http = httpx.Client(transport=httpx.HTTPTransport(uds=socket_path),
                                  base_url="http://runner", timeout=timeout_s)

    def scope(self) -> tuple[dict, str]:
        r = self._http.get("/scope")
        r.raise_for_status()
        body = r.json()
        return body["scope"], body["scope_hash"]

    def _post(self, path: str, body: dict) -> dict:
        r = self._http.post(path, json=body)
        if r.status_code in (400, 403, 404, 409, 500, 503):
            try:
                detail = r.json().get("detail", "")
            except ValueError:
                detail = r.text[:200]
            raise RunnerRefused(r.status_code, detail)
        r.raise_for_status()
        return r.json()

    def job(self, profile: str, target: dict, scope_hash: str, params: dict | None = None) -> dict:
        body = {"profile": profile, "target": target, "scope_hash": scope_hash}
        if params:
            body["params"] = params
        return self._post("/jobs", body)

    def apply(self, run_id: str, change_id: str) -> dict:
        return self._post("/apply", {"run": run_id, "change_id": change_id})

    def recreate(self, run_id: str, change_id: str) -> dict:
        return self._post("/recreate", {"run": run_id, "change_id": change_id})

    def rehearse(self, run_id: str, change_id: str) -> dict:
        return self._post("/rehearse", {"run": run_id, "change_id": change_id})

    def rehearse_end(self, run_id: str, change_id: str) -> dict:
        return self._post("/rehearse/end", {"run": run_id, "change_id": change_id})

    def jobs(self, ids) -> list[dict]:
        r = self._http.get("/jobs", params={"ids": ",".join(ids)})
        r.raise_for_status()
        return r.json()

    def log(self) -> list[dict]:
        r = self._http.get("/log")
        r.raise_for_status()
        return r.json()
