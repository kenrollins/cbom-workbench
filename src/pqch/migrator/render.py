"""The policy rendered into each target's TLS configuration (nginx).

The rendered file holds only what the policy decides: the protocol versions
and the key-establishment groups. Everything else stays in the service's own
nginx.conf, which includes this file by exact name, so a missing file stops
nginx instead of leaving it on OpenSSL's defaults.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

SCHEMA = "pqch.crypto-policy/1"
INTENTS = ("none", "enable", "require")
# nginx and OpenSSL spellings of the policy's group names.
NGINX_GROUP = {"secp256r1": "prime256v1", "secp384r1": "secp384r1", "X25519": "X25519",
               "X25519MLKEM768": "X25519MLKEM768"}


def load(path: str | Path) -> dict:
    policy = yaml.safe_load(Path(path).read_text())
    if policy.get("schema") != SCHEMA:
        raise ValueError(f"{path}: expected schema {SCHEMA}")
    for t in policy["targets"]:
        if t["intent"] not in INTENTS:
            raise ValueError(f"{t['service']}: intent must be one of {INTENTS}")
    return policy


def groups(policy: dict, intent: str) -> list[str]:
    ke = policy["key_establishment"]
    return {"none": ke["classical"], "enable": ke["hybrid"] + ke["classical"], "require": ke["hybrid"]}[intent]


def render_tls(policy: dict, intent: str) -> str:
    protocols = "TLSv1.3" if intent == "require" else "TLSv1.2 TLSv1.3"
    curve = ":".join(NGINX_GROUP[g] for g in groups(policy, intent))
    return (f"# Rendered from policy/crypto-policy.yaml, intent {intent}. Do not edit:\n"
            f"# change the policy, and the change is proposed, approved and verified.\n"
            f"ssl_protocols {protocols};\n"
            f"ssl_ecdh_curve {curve};\n")


# A comment holds printable ASCII only: a carriage return or another line separator inside one
# would show an approver a line that the service reads as part of the comment.
_LINE = re.compile(r"^(#[\x20-\x7e]*|ssl_protocols( TLSv1\.[23])+;|ssl_ecdh_curve [A-Za-z0-9_-]+(:[A-Za-z0-9_-]+)*;)?$")


# PostgreSQL: the TLS settings only — the groups, the lowest and highest protocol version, the
# cipher list — each a single-quoted value of a fixed character set. Nothing else is written.
_PG_LINE = re.compile(r"^(#[\x20-\x7e]*|ssl_groups = '[A-Za-z0-9_-]+(:[A-Za-z0-9_-]+)*'"
                      r"|ssl_(min|max)_protocol_version = 'TLSv1\.[23]'|ssl_ciphers = '[A-Za-z0-9:+!@._=-]+')?$")
# OpenSSH: comments and a KexAlgorithms line of OpenSSH algorithm names.
_SSH_LINE = re.compile(r"^(#[\x20-\x7e]*|KexAlgorithms [a-z0-9@._-]+(,[a-z0-9@._-]+)*)?$")
SHAPES = {"nginx": _LINE, "postgresql": _PG_LINE, "openssh": _SSH_LINE}
# Software whose policy file the harness renders by rule; any other is drafted (the change-plan role).
# OpenSSH is rendered: one line, nothing to interpret, and spike S3's change-plan items held no SSH.
RENDERED = {"nginx", "openssh"}
POLICY_FILE = {"nginx": "tls.conf", "postgresql": "tls.conf", "openssh": "kex.conf"}


def render_for(software: str, policy: dict, intent: str) -> str:
    if software == "nginx":
        return render_tls(policy, intent)
    if software == "openssh":
        return render_ssh(policy, intent)
    raise ValueError(f"{software} has no renderer")


def render_ssh(policy: dict, intent: str) -> str:
    sk = policy["ssh_key_exchange"]
    head = (f"# Rendered from policy/crypto-policy.yaml, intent {intent}. Do not edit:\n"
            f"# change the policy, and the change is proposed, approved and verified.\n")
    if intent == "none":
        return head          # no line: the service's own KexAlgorithms holds
    algs = sk["hybrid"] if intent == "require" else sk["hybrid"] + sk["classical"]
    return head + f"KexAlgorithms {','.join(algs)}\n"


def is_rendered_shape(content: str, software: str = "nginx") -> bool:
    """True when every line is one the runner may write for that software: for nginx a comment,
    an ssl_protocols or an ssl_ecdh_curve line; for PostgreSQL a comment or one of its TLS
    settings. The runner writes nothing else into a service's configuration, whatever a
    proposal holds, and nothing for software it has no shape for."""
    shape = SHAPES.get(software)
    return shape is not None and all(shape.fullmatch(line) for line in content.split("\n"))


def base(software: str) -> str:
    """The policy file an estate is built with when nothing is yet set by the policy."""
    if software in RENDERED:
        raise ValueError(f"{software}'s file is rendered from the intent")
    return ("# The central crypto policy's settings for this listener. Empty until a change is proposed,\n"
            "# approved and applied; the settings in the service's own file hold until then.\n")


def check(policy: dict, target: dict, sni: str | None) -> dict:
    """The pqch.verifier/1 check that will count as verified, fixed before anything is applied."""
    intent = target["intent"]
    if target.get("protocol") == "ssh":
        sk = policy["ssh_key_exchange"]
        accept, refuse = (sk["hybrid"], sk["every_other"]) if intent != "none" else (sk["classical"][:1], sk["hybrid"])
        return {"schema": "pqch.verifier/1", "kind": "ssh-kex", "intent": "require" if intent == "none" else intent,
                "policy_intent": intent, "target": {"host": target["address"], "port": target["port"], "protocol": "ssh"},
                "must_accept": accept, "must_refuse": refuse}
    ke = policy["key_establishment"]
    # The refuse list is every group of the other kind, not only the configured ones.
    if intent == "none":
        # Back to classical: classical accepted, every post-quantum group refused.
        accept, refuse, v_intent = ke["classical"][:1], ke.get("every_post_quantum", ke["hybrid"]), "require"
    else:
        accept, refuse, v_intent = ke["hybrid"], ke.get("every_classical", ke["classical"]), intent
    t = {"host": target["address"], "port": target["port"], "protocol": target.get("protocol", "tls")}
    if sni:
        t["sni"] = sni
    out = {"schema": "pqch.verifier/1", "kind": "wire-kex", "intent": v_intent, "policy_intent": intent,
           "target": t, "must_accept": accept, "must_refuse": refuse}
    if intent == "require":
        out["refuse_tls12"] = True
    return out


def diff(old: str, new: str, service: str, software: str = "nginx") -> str:
    """The unified diff an approver reads. The runner recomputes it before applying."""
    import difflib

    path = f"agency/generated/{service}/{POLICY_FILE.get(software, 'tls.conf')}"
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), path, path))


def target_path(agency_dir: Path, service: str, software: str = "nginx") -> Path:
    return agency_dir / "generated" / service / POLICY_FILE.get(software, "tls.conf")
