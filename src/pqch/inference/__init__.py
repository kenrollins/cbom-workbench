"""The inference seam (spec/interfaces.md, section 4): the only code that knows where a model lives.

Code names a tier — `fast`, `deliberate`, `embed` — or a role. A `pqch.inference/1`
config file maps each tier to an OpenAI-compatible base URL, the name of the
environment variable holding its key, a model id and a hardware label; a tier may
also say how the same engine is reached with reasoning on (another model id, a
longer timeout, extra request fields). The file's `roles` section binds each
named role to a tier and a reasoning setting — that binding is data decided by
measurement (spike S3), never a default in code. The seam knows nothing of
prompts or the ledger.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml
from jsonschema import Draft202012Validator

SCHEMA = "pqch.inference/1"
TIERS = ("fast", "deliberate", "embed")


class TierUnavailable(Exception):
    """An on-demand tier that is not loaded. Raised at once; the caller queues the work."""


class SchemaViolation(Exception):
    """The reply did not satisfy the JSON Schema the caller required."""


@dataclass
class Completion:
    text: str
    parsed: object | None
    usage: dict
    model: str
    tier: str
    hardware: str
    latency_ms: int
    purpose: str
    reasoning: bool = False
    finish_reason: str | None = None
    role: str | None = None
    served_by: str | None = None   # the upstream the endpoint said served this call, when it says
    raw: dict = field(repr=False, default_factory=dict)

    def actor(self) -> dict:
        """The ledger actor for an event this completion contributed to."""
        a = {"kind": "model", "id": f"{self.tier}:{self.model}", "tier": self.tier,
             "model": self.model, "hardware": self.hardware}
        if self.reasoning:
            a["reasoning"] = True
        if self.role:
            a["role"] = self.role
        if self.served_by:
            a["served_by"] = self.served_by
        return a


def load_config(path: str | Path) -> dict:
    cfg = yaml.safe_load(Path(path).read_text())
    if cfg.get("schema") != SCHEMA:
        raise ValueError(f"{path}: expected schema {SCHEMA}, found {cfg.get('schema')!r}")
    for tier, t in cfg.get("tiers", {}).items():
        if tier not in TIERS:
            raise ValueError(f"{path}: unknown tier {tier!r}")
        for k in ("base_url", "api_key_env", "model", "hardware"):
            if k not in t:
                raise ValueError(f"{path}: tier {tier} lacks {k}")
        r = t.get("reasoning")
        if r is not None and (not isinstance(r, dict) or set(r) - {"model", "timeout_s", "request"}):
            raise ValueError(f"{path}: tier {tier}: reasoning takes only model, timeout_s and request")
    for role, b in (cfg.get("roles") or {}).items():
        if not isinstance(b, dict) or b.get("tier") not in cfg.get("tiers", {}):
            raise ValueError(f"{path}: role {role!r} is bound to no configured tier")
        if b["tier"] == "embed" or not isinstance(b.get("reasoning", False), bool):
            raise ValueError(f"{path}: role {role!r}: a role binds a completion tier and a boolean reasoning flag")
    return cfg


class Seam:
    def __init__(self, config: dict, *, transport: httpx.BaseTransport | None = None):
        self.config = config
        self._transport = transport

    def _tier(self, tier: str) -> dict:
        t = self.config.get("tiers", {}).get(tier)
        if t is None:
            raise TierUnavailable(f"tier {tier!r} is not configured in profile {self.config.get('profile')!r}")
        return t

    def _client(self, t: dict, timeout_s: float) -> httpx.Client:
        key = os.environ.get(t["api_key_env"], "")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        return httpx.Client(base_url=t["base_url"].rstrip("/"), headers=headers, timeout=timeout_s,
                            transport=self._transport)

    def _require_loaded(self, t: dict) -> None:
        if t.get("residency", "resident") != "on-demand":
            return
        try:
            with self._client(t, 5) as c:
                ids = {m["id"] for m in c.get("/models").json().get("data", [])}
        except Exception as e:
            raise TierUnavailable(f"{t['model']}: status unknown ({type(e).__name__})") from e
        if t["model"] not in ids:
            raise TierUnavailable(f"{t['model']} is not loaded")

    def for_role(self, role: str) -> tuple[str, bool]:
        """The tier and reasoning setting a role is bound to in the config. A config with no `roles`
        section binds every role to `fast` without reasoning, and says so; a config with one must
        name the role — code never chooses a model for a role."""
        roles = self.config.get("roles")
        if not roles:
            return "fast", False
        if role not in roles:
            raise TierUnavailable(f"role {role!r} is bound to no tier in profile {self.config.get('profile')!r}")
        return roles[role]["tier"], bool(roles[role].get("reasoning", False))

    def complete_role(self, role: str, messages: list[dict], *, schema: dict | None = None,
                      max_tokens: int | None = None, purpose: str) -> Completion:
        tier, reasoning = self.for_role(role)
        c = self.complete(tier, messages, schema=schema, max_tokens=max_tokens, purpose=purpose, reasoning=reasoning)
        c.role = role
        return c

    def complete(self, tier: str, messages: list[dict], *, schema: dict | None = None,
                 max_tokens: int | None = None, purpose: str, reasoning: bool = False) -> Completion:
        t = self._tier(tier)
        if reasoning:
            # The same engine with reasoning on: another model id or lane, a longer timeout, extra
            # request fields — whatever the endpoint needs, from the config, never from here.
            r = t.get("reasoning") or {}
            t = {**t, "model": r.get("model", t["model"]), "timeout_s": r.get("timeout_s", t.get("timeout_s", 60))}
            extra = r.get("request") or {}
        else:
            extra = {}
        self._require_loaded(t)
        body: dict = {**extra, "model": t["model"], "messages": messages, "temperature": 0}
        if max_tokens:
            body["max_tokens"] = max_tokens
        if schema is not None:
            body["response_format"] = {"type": "json_schema",
                                       "json_schema": {"name": purpose.replace("-", "_"), "schema": schema}}
        started = time.monotonic()
        with self._client(t, t.get("timeout_s", 60)) as c:
            r = c.post("/chat/completions", json=body)
        latency_ms = round((time.monotonic() - started) * 1000)
        r.raise_for_status()
        raw = r.json()
        # A gateway can move a lane between machines without the config knowing; when it names
        # the upstream in a response header, that is recorded beside the config's hardware label.
        served_by = r.headers.get(self.config.get("served_by_header", "x-litellm-model-api-base"))
        text = raw["choices"][0]["message"].get("content") or ""
        parsed = None
        if schema is not None:
            try:
                parsed = json.loads(_strip_fences(text))
            except json.JSONDecodeError as e:
                err = SchemaViolation(f"reply is not JSON: {text[:200]!r}")
                err.raw = raw      # so a caller can see why: a cap reached, a refusal
                raise err from e
            errors = list(Draft202012Validator(schema).iter_errors(parsed))
            if errors:
                raise SchemaViolation("; ".join(e.message for e in errors[:3]))
        return Completion(text=text, parsed=parsed, usage=raw.get("usage", {}),
                          model=raw.get("model", t["model"]), tier=tier, hardware=t["hardware"],
                          latency_ms=latency_ms, purpose=purpose, reasoning=reasoning,
                          finish_reason=raw["choices"][0].get("finish_reason"), served_by=served_by, raw=raw)

    def embed(self, tier: str, texts: list[str]) -> list[list[float]]:
        t = self._tier(tier)
        self._require_loaded(t)
        with self._client(t, t.get("timeout_s", 60)) as c:
            r = c.post("/embeddings", json={"model": t["model"], "input": texts})
        r.raise_for_status()
        return [d["embedding"] for d in r.json()["data"]]


def _strip_fences(text: str) -> str:
    s = text.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        s = s.rsplit("```", 1)[0]
    return s.strip()


_default: Seam | None = None


def default() -> Seam:
    global _default
    if _default is None:
        _default = Seam(load_config(os.environ.get("PQCH_INFERENCE_CONFIG", "config/inference.yaml")))
    return _default


def complete(tier: str, messages: list[dict], *, schema: dict | None = None,
             max_tokens: int | None = None, purpose: str, reasoning: bool = False) -> Completion:
    return default().complete(tier, messages, schema=schema, max_tokens=max_tokens, purpose=purpose,
                              reasoning=reasoning)


def complete_role(role: str, messages: list[dict], *, schema: dict | None = None,
                  max_tokens: int | None = None, purpose: str) -> Completion:
    return default().complete_role(role, messages, schema=schema, max_tokens=max_tokens, purpose=purpose)


def embed(tier: str, texts: list[str]) -> list[list[float]]:
    return default().embed(tier, texts)
