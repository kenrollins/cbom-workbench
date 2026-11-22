"""The harness side of the runner: an HTTP client over the runner's Unix socket."""

from __future__ import annotations

import httpx


class RunnerRefused(Exception):
    """A refusal from the runner. `entry` is the runner's own log line when it refused after it had
    touched the estate (an apply it put back, a reset it could not finish), else None."""

    def __init__(self, code: int, reason: str, entry: dict | None = None):
        super().__init__(f"{code}: {reason}")
        self.code = code
        self.reason = reason
        self.entry = entry


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
            entry = None
            try:
                detail = r.json().get("detail", "")
            except (ValueError, AttributeError):
                detail = r.text[:200]
            if isinstance(detail, dict):          # a refusal after the estate was touched: reason and log line
                detail, entry = str(detail.get("reason", "")), detail.get("entry")
            raise RunnerRefused(r.status_code, detail, entry if isinstance(entry, dict) else None)
        r.raise_for_status()
        return r.json()

    def settings(self) -> dict:
        """What this runner enforces before it changes anything, so a caller can compare its own
        settings with the runner's instead of assuming they match."""
        r = self._http.get("/settings")
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

    def reset(self, run_id: str) -> dict:
        return self._post("/reset", {"run": run_id})

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
