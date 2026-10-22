"""The code layer, thin: candidate call sites by rule, judged by the call-site-read role.

A rule pack (`policy/code-rules/<language>.yaml`) matches lines in a repository checked out at a
pinned commit; each match is a finding of layer `code` with a `call-site` subject, its tool the
rule pack. Nothing in the repository is run, and nothing is sent anywhere but the line and its
context to the inference seam.

Whether a candidate is a live cryptographic use — not a comment, a string, an import, a test
mock or the application's own wrapper — is the call-site-read role's (spike S3's R1: Gemma 4 31B
with reasoning on, 29 of 30 on this repository's lines, floor 27). Three calls per candidate,
the majority taken, recorded as the model's assessment with `in_use`; the CBOM carries it.
"""

from __future__ import annotations

import json
import re
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from importlib import resources
from pathlib import Path

import yaml

from pqch import inference
from pqch.common import hash_object, sha256_hex, utc_now
from pqch.run import Run

ROLE = "call-site-read"
TOOL = "pqch-code-rules"
FAMILIES = ["RSA", "ECDSA", "EC", "Ed25519", "DSA", "DH", "AES", "3DES", "ChaCha20", "SHA-1", "SHA-2", "SHA-3",
            "MD5", "HMAC", "PBKDF2", "scrypt", "bcrypt", "X.509", "unspecified", "none"]
SIX_ROLES = ["key-establishment", "signature", "encryption", "hash", "mac", "other"]
SCHEMA = {"type": "object", "required": ["is_crypto_use", "family", "role", "key_bits"],
          "properties": {"is_crypto_use": {"type": "boolean"}, "family": {"enum": FAMILIES},
                         "role": {"enum": SIX_ROLES}, "key_bits": {"type": ["integer", "null"]}},
          "additionalProperties": False}


def load_rules(path: str | Path) -> dict:
    doc = yaml.safe_load(Path(path).read_text())
    if doc.get("schema") != "pqch.code-rules/1":
        raise ValueError(f"{path}: expected schema pqch.code-rules/1")
    for r in doc["rules"]:
        r["_rx"] = re.compile(r["pattern"])
    return doc


def head_commit(repo_dir: Path) -> str | None:
    """The checkout's commit, read from .git without the git binary: a detached HEAD holds the sha;
    a branch HEAD names a ref, read from its file or from packed-refs."""
    git = Path(repo_dir) / ".git"
    try:
        head = (git / "HEAD").read_text().strip()
    except OSError:
        return None
    if not head.startswith("ref: "):
        return head
    ref = head[5:]
    if (git / ref).is_file():
        return (git / ref).read_text().strip()
    packed = git / "packed-refs"
    if packed.is_file():
        for line in packed.read_text().splitlines():
            if line.endswith(" " + ref):
                return line.split(" ")[0]
    return None


def candidates(repo_dir: Path, rules: dict, context: int = 15) -> list[dict]:
    repo_dir = Path(repo_dir)
    files = sorted(str(p.relative_to(repo_dir)) for base in rules["paths"] for p in (repo_dir / base).rglob("*.rb")
                   if p.is_file())
    out = []
    for rel in (f for f in files if not any(x in f for x in rules.get("exclude", []))):
        lines = (repo_dir / rel).read_text(errors="replace").split("\n")
        for i, text in enumerate(lines, 1):
            hit = next(((r, m) for r in rules["rules"] if (m := r["_rx"].search(text))), None)
            if hit is None:
                continue
            r, m = hit
            lo, hi = max(1, i - context), min(len(lines), i + context)
            out.append({"path": rel, "line": i, "text": text.strip(), "rule": r["id"],
                        "family_hint": r["family"].replace("{1}", m.group(1) if m.groups() else ""),
                        "role_hint": r["role"],
                        "context": "\n".join(f"{n:5d}  {lines[n - 1]}" for n in range(lo, hi + 1))})
    return out


def prompt(repo: str, language: str, c: dict) -> list[dict]:
    system, _, user = resources.files("pqch.scout").joinpath("prompts/call-site-read.md").read_text().partition("\n---\n")
    user = (user.replace("{repo}", repo).replace("{path}", c["path"]).replace("{language}", language)
            .replace("{line}", str(c["line"])).replace("{context}", c["context"]))
    return [{"role": "system", "content": system.strip()}, {"role": "user", "content": user.strip()}]


def scan(var: Path, repo_dir: Path, *, repo: str, commit: str, rules_path: Path, seam: inference.Seam | None = None,
         repeats: int = 3, workers: int = 4, authorized_by: str, signer=None, progress=None) -> tuple[Run, dict]:
    from pqch import scope as scope_mod

    s = seam or inference.default()
    head = head_commit(repo_dir) or ""
    if head != commit:
        raise ValueError(f"{repo_dir} is at {head[:12]}, not the pinned {commit[:12]}")
    rules = load_rules(rules_path)
    scope = {"schema": "pqch.scope/1", "id": sha256_hex(f"{repo}@{commit}".encode())[:26].upper().translate(
                 str.maketrans("ILOU", "1100")),
             "estate": "external", "owned": False, "authorized_by": authorized_by, "endpoints": [], "images": [],
             "sources": [{"repo": repo, "commit": commit}], "reach": {"kind": "local"}}
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="code-rules",
                    runner_id="pqch-code-reader", kind="scan-code")
    started = utc_now()
    t0 = time.monotonic()
    cands = candidates(repo_dir, rules)
    raw = json.dumps([{k: v for k, v in c.items() if k != "context"} for c in cands], indent=1).encode()
    # The reader's output is the harness's own, so it lives with its run: raw scanner output under
    # var/raw is the runner's, which the harness may only read.
    (run.dir / "code-candidates.json").write_bytes(raw)
    raw_ref = f"var/runs/{run.id}/code-candidates.json"
    digest = sha256_hex(raw)
    sc = run.ledger.append("scan.completed", {"kind": "runner", "id": "pqch-code-reader"}, {
        "profile": "code-rules", "target": {"repo": repo, "commit": commit}, "tool": TOOL,
        "version": sha256_hex(Path(rules_path).read_bytes())[:12], "image_digest": "sha256:" + "0" * 64,
        "started_at": started, "ended_at": utc_now(), "duration_ms": round((time.monotonic() - t0) * 1000),
        "hardware": "host", "status": "ok", "exit_code": 0, "raw": raw_ref, "raw_sha256": digest,
        "findings": len(cands)})
    findings = []
    for c in cands:
        subject = {"kind": "call-site", "repo": repo, "commit": commit, "path": c["path"], "line": c["line"]}
        asset = {"type": "algorithm", "role": c["role_hint"], "name": c["family_hint"] or "unspecified",
                 "parameters": {"rule": c["rule"], "line_text": c["text"]}}
        fp = hash_object({"layer": "code", "subject": subject, "type": "algorithm", "role": asset["role"],
                          "name": asset["name"], "identity": None})
        f = run.ledger.append("finding.observed", {"kind": "scanner", "id": TOOL}, {
            "schema": "pqch.finding/1", "id": sc["id"][:20] + f"{len(findings):06d}", "observed_at": started, "layer": "code",
            "source": {"tool": TOOL, "version": sc["payload"]["version"], "image_digest": sc["payload"]["image_digest"],
                       "profile": "code-rules"},
            "subject": subject, "asset": asset,
            "evidence": {"raw": raw_ref, "sha256": digest, "excerpt": c["text"][:200]},
            "fingerprint": fp}, inputs=[sc["id"]])
        findings.append((f, c))

    def judge(item):
        f, c = item
        msgs = prompt(repo, rules["language"], c)
        calls = []
        for _ in range(repeats):
            try:
                r = s.complete_role(ROLE, msgs, schema=SCHEMA, max_tokens=16000, purpose=ROLE)
                calls.append({"reply": r.parsed, "latency_ms": r.latency_ms, "tokens": int(r.usage.get("total_tokens") or 0),
                              "actor": r.actor()})
            except (inference.SchemaViolation, inference.TierUnavailable, OSError) as e:
                calls.append({"reply": None, "error": f"{type(e).__name__}: {e}"[:200]})
        return f, c, calls

    summary = Counter()
    lat = []
    with ThreadPoolExecutor(workers) as pool:
        results = list(pool.map(judge, findings))
    for f, c, calls in results:
        good = [x["reply"] for x in calls if x.get("reply")]
        votes = Counter(json.dumps({k: r[k] for k in ("is_crypto_use", "family", "role")}, sort_keys=True) for r in good)
        majority = json.loads(votes.most_common(1)[0][0]) if votes else None
        actor = next((x["actor"] for x in calls if x.get("actor")), {"kind": "rule", "id": "call-site-read/failed"})
        lat += [x["latency_ms"] for x in calls if x.get("latency_ms")]
        run.ledger.append("assessment.made", actor, {
            "finding": f["id"], "purpose": ROLE, "rule_id": None,
            "classification": ({"in_use": majority["is_crypto_use"], "family": majority["family"], "role": majority["role"]}
                               if majority else {"in_use": None}),
            "agreement": f"{votes.most_common(1)[0][1]} of {len(calls)}" if votes else "0",
            "calls": [{k: v for k, v in x.items() if k != "actor"} for x in calls], "used_by_rules": False,
            "basis": "the call-site-read role's majority of three" if majority else "no usable reply"}, inputs=[f["id"]])
        summary["candidates"] += 1
        summary["uses" if majority and majority["is_crypto_use"] else ("not_uses" if majority else "failed")] += 1
        if progress:
            progress(c, majority)
    run.close(signer)
    out = dict(summary)
    out["latencies_ms"] = sorted(lat)
    return run, out
