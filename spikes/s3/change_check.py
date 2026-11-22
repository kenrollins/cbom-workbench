"""Score a change plan the way the product verifies a change: apply the edits to the service's
configuration in the lab, start it, and run the verifier's paired probes and witness. No model.

The decision is `pqch.verifier`'s own: the same expected groups, the same parsers, the same `decide`.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

import lab

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT / "src"))
from pqch import verifier  # noqa: E402

TESTSSL = "ghcr.io/testssl/testssl.sh@sha256:31213829a371e90afc9beae12a715793190aecebe9b64488ea49f72de7ff3c62"
POLICY = yaml.safe_load((ROOT / "policy" / "crypto-policy.yaml").read_text())["key_establishment"]
MEETS = {"enable": ("enabled-not-enforced", "enforced"), "require": ("enforced",)}


def check_for(intent: str) -> dict:
    return {"schema": "pqch.verifier/1", "kind": "wire-kex", "intent": intent, "policy_intent": intent,
            "must_accept": POLICY["hybrid"], "must_refuse": POLICY["every_classical"]}


def apply_edits(files: dict[str, str], edits: list[dict]) -> dict[str, str]:
    """Each edit replaces lines line_start..line_end (1-based, inclusive) of `file` with `replacement`.
    line_end = line_start - 1 inserts before line_start. A file that does not exist is created."""
    out = {p: t.splitlines() for p, t in files.items()}
    for e in sorted(edits, key=lambda e: (e["file"], -int(e["line_start"]))):
        lines = out.setdefault(e["file"], [])
        a, b = int(e["line_start"]), int(e["line_end"])
        if not (1 <= a <= len(lines) + 1 and a - 1 <= b <= len(lines)):
            raise ValueError(f"edit outside {e['file']}: lines {a}-{b} of {len(lines)}")
        lines[a - 1:b] = e["replacement"].splitlines()
    return {p: "\n".join(ls) + "\n" for p, ls in out.items()}


def verify(service: str, intent: str, *, sni: str | None = None) -> dict:
    """The paired probes and the witness against the lab's listener; status by verifier.decide."""
    spec = lab.SERVICES[service]
    check = check_for(intent)
    conn = f"-connect {lab.IP}:{spec['port']}" + (f" -servername {sni}" if sni else "") + \
        (f" -starttls {spec['starttls']}" if spec.get("starttls") else "")
    parsed, raws = {}, {}
    for name, (_profile, params) in verifier.expected_jobs(check).items():
        if name == "witness":
            with tempfile.TemporaryDirectory() as tmp:
                Path(tmp).chmod(0o777)
                target = f"https://{sni}:{spec['port']}" if sni else f"{lab.IP}:{spec['port']}"
                args = ["docker", "run", "--rm", "--network", lab.NET, "-v", f"{tmp}:/out", TESTSSL, "--quiet", "--color", "0",
                        "--warnings", "off", "--nodns", "none", "-f", "--jsonfile", "/out/w.json"]
                if sni:
                    args += ["--ip", lab.IP]
                if spec.get("starttls"):
                    args += ["--starttls", spec["starttls"]]
                subprocess.run([*args, target], capture_output=True, text=True, timeout=600)
                w = Path(tmp) / "w.json"
                raw = w.read_bytes() if w.exists() else b""
            raws[name] = raw.decode(errors="replace")
            parsed[name] = verifier.read_witness(raw, check) if raw else {"result": "error"}
        else:
            cmd = f"openssl s_client {conn} -groups {params['groups']} {params['tls13']} -showcerts </dev/null 2>&1; echo PQCH_EXIT=$?"
            raw = lab.sh("docker", "run", "--rm", "--network", lab.NET, "--entrypoint", "sh", lab.HARNESS, "-c", cmd, check=False)
            raws[name] = raw
            parsed[name] = verifier.parse_probe(raw)
    status, also, disagreement = verifier.decide(check, parsed)
    if disagreement:
        status = "inconclusive"
    return {"status": status, "meets_intent": status in MEETS[intent], "also_accepts": also,
            "probes": {k: {"result": v["result"], "negotiated": v.get("negotiated")} for k, v in parsed.items()},
            "raw_sha256": {k: lab.sha256(v) for k, v in raws.items()}}


def run_plan(service: str, files: dict[str, str], edits: list[dict], intent: str, *, sni: str | None = None) -> dict:
    """Apply, start, verify. A plan after which the service does not start is `service-down`."""
    try:
        new = apply_edits(files, edits)
    except (ValueError, KeyError, TypeError) as e:
        return {"status": "bad-edit", "meets_intent": False, "error": str(e)[:200]}
    try:
        lab.start(service, new)
    except RuntimeError as e:
        return {"status": "service-down", "meets_intent": False, "error": str(e)[-300:]}
    return verify(service, intent, sni=sni)


if __name__ == "__main__":
    print(json.dumps(check_for("require"), indent=1))
