"""The inference seam (spec/interfaces.md, section 4): the only code that knows where a model lives.

Code names a tier — `fast`, `deliberate`, `embed` — or a role. A `pqch.inference/1`
config file maps each tier to an OpenAI-compatible base URL, the name of the
environment variable holding its key, a model id and a hardware label; a tier may
also say how the same engine is reached with reasoning on (another model id, a
longer timeout, extra request fields). The file's `roles` section binds each
named role to a tier and a reasoning setting — that binding is data decided by
measurement (spike S3), never a default in code. The seam knows nothing of
prompts or the ledger.

Two checks, both opt-in in the config, so a config without them behaves as before (FR-03, FR-07):

- `tls: {require: true, ca_file: <path>, allow_plain_subnets: [<cidr>, ...]}` — an `https://` base
  URL is verified against `ca_file` (or a tier's own `ca_file`; else the system's trust store), and a
  plain `http://` one is refused unless its host is a loopback address or every address it resolves
  to lies in a subnet the operator listed (the kit's engine bridge, say). Nothing is inferred from
  the routing table: a container with a leg on a VLAN reaches the whole VLAN with no router. Every
  call's actor records which: `tls`, `loopback`, `listed-subnet` (with the subnets) or `plain`.
- `origins: {allowed: [US, ...]}` — each tier names its model's `provenance: {origin, licence,
  weights_sha256}`; a tier whose origin is not on the list is refused when the config is loaded and
  again at the call. The actor records the origin and the weights digest.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
from functools import lru_cache
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

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
    engine: str | None = None      # the tier's declared engine (vLLM, a NIM, ollama), when the config names it
    raw: dict = field(repr=False, default_factory=dict)
    transport: str | None = None   # tls, loopback, listed-subnet or plain
    plain_subnets: tuple[str, ...] = ()   # the subnets listed, when the transport is listed-subnet
    origin: str | None = None
    weights_sha256: str | None = None

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
        if self.engine:
            a["engine"] = self.engine
        for k in ("transport", "origin", "weights_sha256"):
            if getattr(self, k):
                a[k] = getattr(self, k)
        if self.transport == "listed-subnet":
            a["plain_subnets"] = list(self.plain_subnets)
        return a


@lru_cache(maxsize=64)
def transport_of(base_url: str, plain_subnets: tuple[str, ...] = ()) -> str:
    """How a base URL is reached: `tls` (https), `loopback`, `listed-subnet` (every address the host
    resolves to lies in a subnet the operator listed in `tls.allow_plain_subnets`) or `plain`. The seam
    does not guess what a bridge is: a container with a leg on a VLAN reaches the whole VLAN with no
    router, so "directly attached" would admit every host on it. The operator names the subnets."""
    u = urlsplit(base_url)
    if u.scheme == "https":
        return "tls"
    host = u.hostname or ""
    if host == "localhost":
        return "loopback"
    try:
        addrs = {ai[4][0] for ai in socket.getaddrinfo(host, u.port or 80, proto=socket.IPPROTO_TCP)}
    except OSError:
        return "plain"
    ips = [ipaddress.ip_address(a.split("%")[0]) for a in addrs]
    if ips and all(ip.is_loopback for ip in ips):
        return "loopback"
    nets = [ipaddress.ip_network(s, strict=False) for s in plain_subnets]
    if ips and nets and all(any(ip in n for n in nets) for ip in ips):
        return "listed-subnet"
    return "plain"


def plain_subnets(cfg: dict) -> tuple[str, ...]:
    """`tls.allow_plain_subnets` as a tuple of validated CIDR strings; empty when none is listed."""
    subs = (cfg.get("tls") or {}).get("allow_plain_subnets") or []
    return tuple(str(ipaddress.ip_network(s, strict=False)) for s in subs)


def origin_refusal(cfg: dict, tier: str, t: dict) -> str | None:
    """Why a tier's model may not be used under the config's origin allowlist, or None."""
    allowed = (cfg.get("origins") or {}).get("allowed")
    if not allowed:
        return None
    origin = (t.get("provenance") or {}).get("origin")
    if origin is None:
        return f"tier {tier}: model {t.get('model')} declares no origin, and the config allows only {', '.join(allowed)}"
    if origin not in allowed:
        return f"tier {tier}: model {t.get('model')} is of origin {origin}, not one of {', '.join(allowed)}"
    return None


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
        prov = t.get("provenance")
        if prov is not None and (not isinstance(prov, dict) or set(prov) - {"origin", "licence", "weights_sha256", "source"}):
            raise ValueError(f"{path}: tier {tier}: provenance takes only origin, licence, weights_sha256 and source")
        why = origin_refusal(cfg, tier, t)
        if why:
            raise ValueError(f"{path}: {why}")
        r = t.get("reasoning")
        if r is not None and (not isinstance(r, dict) or set(r) - {"model", "timeout_s", "request", "structured"}):
            raise ValueError(f"{path}: tier {tier}: reasoning takes only model, timeout_s, request and structured")
    tls = cfg.get("tls")
    if tls is not None:
        if not isinstance(tls, dict) or set(tls) - {"require", "ca_file", "allow_plain_subnets"}:
            raise ValueError(f"{path}: tls takes only require, ca_file and allow_plain_subnets")
        try:
            plain_subnets(cfg)
        except ValueError as e:
            raise ValueError(f"{path}: tls.allow_plain_subnets: {e}") from e
    for role, b in (cfg.get("roles") or {}).items():
        if not isinstance(b, dict) or b.get("tier") not in cfg.get("tiers", {}):
            raise ValueError(f"{path}: role {role!r} is bound to no configured tier")
        if b["tier"] == "embed" or not isinstance(b.get("reasoning", False), bool):
            raise ValueError(f"{path}: role {role!r}: a role binds a completion tier and a boolean reasoning flag")
    return cfg


def _skeleton(schema: dict):
    """A filled-in instance of a JSON Schema's shape, for a prompt: objects with every property, one example
    element per array, placeholder scalars."""
    ty = schema.get("type")
    if ty == "object":
        return {k: _skeleton(v) for k, v in (schema.get("properties") or {}).items()}
    if ty == "array":
        return [_skeleton(schema.get("items") or {"type": "string"})]
    if ty == "boolean":
        return False
    if ty in ("integer", "number"):
        return 0
    if "enum" in schema:
        return schema["enum"][0]
    return "text"


def _schema_notes(schema: dict) -> str:
    notes = []
    for k, v in (schema.get("properties") or {}).items():
        it = v.get("items") or {}
        if v.get("enum"):
            notes.append(f"{k}: one of {', '.join(map(str, v['enum']))}")
        if it.get("pattern"):
            notes.append(f"{k}: each element a string matching {it['pattern']}; an empty list when there are none")
        if it.get("enum"):
            notes.append(f"{k}: elements from {', '.join(map(str, it['enum']))}")
    return (" Notes: " + "; ".join(notes) + ".") if notes else ""


class Seam:
    def __init__(self, config: dict, *, transport: httpx.BaseTransport | None = None):
        self.config = config
        self._transport = transport

    def _tier(self, tier: str) -> dict:
        t = self.config.get("tiers", {}).get(tier)
        if t is None:
            raise TierUnavailable(f"tier {tier!r} is not configured in profile {self.config.get('profile')!r}")
        return t

    def admit(self, tier: str, t: dict) -> str:
        """The tier's transport, after the config's checks: refused (TierUnavailable) when its origin is
        not allowed, or when TLS is required and the URL is plain HTTP to another network."""
        why = origin_refusal(self.config, tier, t)
        if why:
            raise TierUnavailable(why)
        how = transport_of(t["base_url"], plain_subnets(self.config))
        if (self.config.get("tls") or {}).get("require") and how == "plain":
            raise TierUnavailable(f"tier {tier}: {t['base_url']} is plain HTTP to a host that is neither loopback nor "
                                  f"in a subnet listed in tls.allow_plain_subnets, and the config requires TLS")
        return how

    def _client(self, t: dict, timeout_s: float) -> httpx.Client:
        key = os.environ.get(t["api_key_env"], "")
        headers = {"Authorization": f"Bearer {key}"} if key else {}
        verify = t.get("ca_file") or (self.config.get("tls") or {}).get("ca_file") or True
        if self._transport is not None:
            return httpx.Client(base_url=t["base_url"].rstrip("/"), headers=headers, timeout=timeout_s,
                                transport=self._transport)
        return httpx.Client(base_url=t["base_url"].rstrip("/"), headers=headers, timeout=timeout_s, verify=verify)

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
            t = {**t, "model": r.get("model", t["model"]), "timeout_s": r.get("timeout_s", t.get("timeout_s", 60)),
                 "structured": r.get("structured", t.get("structured", True))}
            extra = r.get("request") or {}
        else:
            # Reasoning off: the tier's own `request` block, for what the endpoint needs to answer plainly
            # (a Nemotron chat template thinks unless told not to: chat_template_kwargs.enable_thinking).
            extra = t.get("request") or {}
        how = self.admit(tier, t)
        self._require_loaded(t)
        body: dict = {**extra, "model": t["model"], "messages": messages, "temperature": 0}
        if max_tokens:
            body["max_tokens"] = max_tokens
        if schema is not None and t.get("structured", True) is not False:
            body["response_format"] = {"type": "json_schema",
                                       "json_schema": {"name": purpose.replace("-", "_"), "schema": schema}}
        elif schema is not None:
            # `structured: false` on the tier: the engine's grammar is not used (on vLLM 0.27 with Lightning and
            # thinking off, xgrammar fails to advance and the call runs to its cap, 2026-11-05); the reply's shape
            # goes in the prompt as a filled-in skeleton (a schema pasted raw came back as the schema itself, 6 of
            # 36 calls, 2026-11-05) and the reply is validated below exactly as before.
            body["messages"] = messages + [{"role": "system", "content": "Reply with one JSON object only, no prose "
                                            "and no code fence, with exactly these keys and value types, every key present: "
                                            + json.dumps(_skeleton(schema)) + _schema_notes(schema)}]
        started = time.monotonic()
        # A reply that fails its schema is asked for once more, with the complaint, when the engine's grammar is
        # not holding the shape (structured: false); the total time of both calls is the call's latency.
        tries = 2 if (schema is not None and t.get("structured", True) is False) else 1
        for attempt in range(tries):
            with self._client(t, t.get("timeout_s", 60)) as c:
                r = c.post("/chat/completions", json=body)
            r.raise_for_status()
            raw = r.json()
            served_by = r.headers.get(self.config.get("served_by_header", "x-litellm-model-api-base"))
            text = raw["choices"][0]["message"].get("content") or ""
            parsed = None
            if schema is None:
                break
            try:
                try:
                    parsed = json.loads(_strip_fences(text))
                except json.JSONDecodeError as e:
                    # Why, on the record: a reply cut at the cap says so, with the tokens it used (lesson 55).
                    fin = raw["choices"][0].get("finish_reason"); used = (raw.get("usage") or {}).get("completion_tokens")
                    why = f" (finish_reason {fin}, {used} completion tokens)" if fin or used else ""
                    err = SchemaViolation(f"reply is not JSON{why}: {text[:200]!r}")
                    err.raw = raw      # so a caller can see why: a cap reached, a refusal
                    raise err from e
                errors = list(Draft202012Validator(schema).iter_errors(parsed))
                if errors:
                    raise SchemaViolation("; ".join(e.message for e in errors[:3]))
                break
            except SchemaViolation as sv:
                if attempt + 1 >= tries:
                    raise
                body = {**body, "messages": body["messages"] + [{"role": "assistant", "content": text[:4000]},
                                                               {"role": "user", "content": f"That reply did not fit: {sv}. Reply again with the JSON object only."}]}
        latency_ms = round((time.monotonic() - started) * 1000)
        return Completion(text=text, parsed=parsed, usage=raw.get("usage", {}),
                          model=raw.get("model", t["model"]), tier=tier, hardware=t["hardware"],
                          latency_ms=latency_ms, purpose=purpose, reasoning=reasoning,
                          finish_reason=raw["choices"][0].get("finish_reason"), served_by=served_by, raw=raw,
                          transport=how, plain_subnets=plain_subnets(self.config), engine=t.get("engine"),
                          origin=(t.get("provenance") or {}).get("origin"),
                          weights_sha256=(t.get("provenance") or {}).get("weights_sha256"))

    def embed(self, tier: str, texts: list[str], *, purpose: str = "passage") -> list[list[float]]:
        """`purpose` is `query` or `passage`. An engine that embeds the two differently names the
        request field that carries it in the tier's `purpose_field` (NVIDIA's retrieval NIMs:
        `input_type`); the tier's `request` block adds any other field the endpoint needs."""
        t = self._tier(tier)
        self.admit(tier, t)
        self._require_loaded(t)
        body = {**(t.get("request") or {}), "model": t["model"], "input": texts}
        if t.get("purpose_field"):
            body[t["purpose_field"]] = purpose
        with self._client(t, t.get("timeout_s", 60)) as c:
            r = c.post("/embeddings", json=body)
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
