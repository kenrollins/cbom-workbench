"""The harness side of the signer: an HTTP client over its Unix socket."""

from __future__ import annotations

import httpx


class SignerRefused(Exception):
    pass


class SignerClient:
    def __init__(self, socket_path: str, timeout_s: float = 60):
        self._http = httpx.Client(transport=httpx.HTTPTransport(uds=socket_path),
                                  base_url="http://signer", timeout=timeout_s)

    def key(self) -> dict:
        r = self._http.get("/key")
        r.raise_for_status()
        return r.json()

    def checkpoint(self, run_id: str, through_seq: int) -> dict:
        r = self._http.post("/checkpoint", json={"run": run_id, "through_seq": through_seq})
        if r.status_code == 409:
            raise SignerRefused(r.json().get("detail", ""))
        r.raise_for_status()
        return r.json()

    def record(self, run_id: str) -> list[dict]:
        r = self._http.get(f"/record/{run_id}")
        r.raise_for_status()
        return r.json()
