"""The code layer, thin: candidate call sites by rule, judged by the call-site-read role.

A rule pack (`policy/code-rules/<language>.yaml`) matches lines in a repository checked out at a
pinned commit; each match is a finding of layer `code` with a `call-site` subject, its tool the
rule pack. Nothing in the repository is run, and nothing is sent anywhere but the line and its
context to the inference seam.

Whether a candidate is a live cryptographic use — not a comment, a string, an import, a test
mock or the application's own wrapper — is the call-site-read role's (spike S3's R1: Gemma 4 31B
with reasoning on, 29 of 30 on this repository's lines, floor 27). Three calls per candidate,
recorded as the model's assessment with `in_use`; the CBOM carries it. `in_use` is set only by a
true majority of the calls made, counted on the one question (is it a live use); the family and
role are then the commonest among the replies that agree. A candidate with no majority, or whose
calls failed (a gateway timeout, an HTTP error, a reply that is not the schema's), is recorded as
not read, with the counts and the reason: the reading is optional, and its failure never ends the
scan or decides anything.

A matched line can hold a literal that is a secret (a hard-coded HMAC key). The line goes on a
signed ledger and into every CBOM, so string literals longer than 16 characters are masked there;
the whole line stays in the run's private candidates file.
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

from pqch import inference, varmode
from pqch.common import hash_object, sha256_hex, utc_now
from pqch.run import Run
from pqch.scout import names

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


# The files a rule pack reads when it names no `globs` of its own, by its language.
DEFAULT_GLOBS = {"ruby": ["*.rb", "*.rake"]}
_LITERAL = re.compile(r"""(["'])((?:\\.|(?!\1).){17,})\1""")


def mask_literals(line: str) -> str:
    """The line with every quoted literal longer than 16 characters replaced by its length: the
    call's shape stays readable and a key written into the source does not travel with it."""
    return _LITERAL.sub(lambda m: f"{m.group(1)}<{len(m.group(2))} characters>{m.group(1)}", line)


def _excluded(rel: str, exclude: list[str]) -> bool:
    """Whether a path is under an excluded directory. An entry names a directory (`spec/`) or a
    path prefix (`lib/generated/`), matched on whole path components: `spec/` does not exclude
    `lib/inspec/`."""
    parts = Path(rel).parts
    for x in exclude:
        want = tuple(Path(x).parts)
        if want and any(parts[i:i + len(want)] == want for i in range(len(parts) - len(want) + 1)):
            return True
    return False


def source_files(repo_dir: Path, rules: dict) -> list[str]:
    """The files the pack's rules are matched against: its globs under its paths, less its
    exclusions. A symbolic link is never read, nor a file under a linked directory: a checkout's
    link can point outside the repository, and its lines would go to the inference seam."""
    repo_dir = Path(repo_dir)
    real = repo_dir.resolve()
    globs = rules.get("globs") or DEFAULT_GLOBS.get(rules.get("language"), ["*.rb"])
    found = set()
    for base in rules["paths"]:
        for glob in globs:
            for p in (repo_dir / base).rglob(glob):
                if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(real):
                    continue
                if p.resolve() != real / p.relative_to(repo_dir):       # reached through a linked directory
                    continue
                found.add(str(p.relative_to(repo_dir)))
    return sorted(f for f in found if not _excluded(f, rules.get("exclude", [])))


def candidates(repo_dir: Path, rules: dict, context: int = 15) -> list[dict]:
    repo_dir = Path(repo_dir)
    out = []
    for rel in source_files(repo_dir, rules):
        lines = (repo_dir / rel).read_text(errors="replace").split("\n")
        for i, text in enumerate(lines, 1):
            hit = next(((r, m) for r in rules["rules"] if (m := r["_rx"].search(text))), None)
            if hit is None:
                continue
            r, m = hit
            lo, hi = max(1, i - context), min(len(lines), i + context)
            hint = r["family"].replace("{1}", (m.group(1) or "") if m.groups() else "")
            out.append({"path": rel, "line": i, "text": text.strip(), "rule": r["id"],
                        # A hash the rule captured as the code spells it (SHA256) takes the name
                        # every other layer gives it (SHA-256), from the alias pack.
                        "family_hint": names.HASHES.get(hint, hint),
                        "role_hint": r["role"],
                        "context": "\n".join(f"{n:5d}  {lines[n - 1]}" for n in range(lo, hi + 1))})
    return out


def prompt(repo: str, language: str, c: dict) -> list[dict]:
    system, _, user = resources.files("pqch.scout").joinpath("prompts/call-site-read.md").read_text().partition("\n---\n")
    user = (user.replace("{repo}", repo).replace("{path}", c["path"]).replace("{language}", language)
            .replace("{line}", str(c["line"])).replace("{context}", c["context"]))
    return [{"role": "system", "content": system.strip()}, {"role": "user", "content": user.strip()}]


def _commonest(values: list[str], otherwise: str) -> str:
    """The value most of the agreeing replies gave; when two tie for it, none of them."""
    ranked = Counter(values).most_common(2)
    if not ranked or (len(ranked) == 2 and ranked[0][1] == ranked[1][1]):
        return otherwise
    return ranked[0][0]


def tally(replies: list[dict], repeats: int, *, role_hint: str = "other") -> dict:
    """The call-site-read role's replies for one candidate, counted. `in_use` is True or False only
    when more than half of the `repeats` calls made say so; the question counted is `is_crypto_use`
    alone, so replies that agree it is a use and differ on the family still agree. The family and
    role are the commonest among the agreeing replies. Anything else is `in_use: None`: not read."""
    uses = sum(1 for r in replies if r.get("is_crypto_use") is True)
    nots = sum(1 for r in replies if r.get("is_crypto_use") is False)
    votes = {"use": uses, "not_a_use": nots, "failed": repeats - uses - nots, "of": repeats}
    need = repeats // 2 + 1
    side = True if uses >= need else False if nots >= need else None
    if side is None:
        return {"classification": {"in_use": None}, "votes": votes, "agreement": f"{max(uses, nots)} of {repeats}",
                "basis": (f"not read: no majority of the call-site-read role's {repeats} calls "
                          f"({uses} a use, {nots} not a use, {votes['failed']} without a usable reply)")}
    agreeing = [r for r in replies if r.get("is_crypto_use") is side]
    return {"classification": {"in_use": side,
                               "family": _commonest([r["family"] for r in agreeing], "unspecified" if side else "none"),
                               "role": _commonest([r["role"] for r in agreeing], role_hint)},
            "votes": votes, "agreement": f"{len(agreeing)} of {repeats}",
            "basis": f"the call-site-read role: {len(agreeing)} of {repeats} calls say it is {'a' if side else 'not a'} live use"}


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
    varmode.private(run.dir / "code-candidates.json")
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
                 "parameters": {"rule": c["rule"], "line_text": mask_literals(c["text"])}}
        fp = hash_object({"layer": "code", "subject": subject, "type": "algorithm", "role": asset["role"],
                          "name": asset["name"], "identity": None})
        f = run.ledger.append("finding.observed", {"kind": "scanner", "id": TOOL}, {
            "schema": "pqch.finding/1", "id": sc["id"][:20] + f"{len(findings):06d}", "observed_at": started, "layer": "code",
            "source": {"tool": TOOL, "version": sc["payload"]["version"], "image_digest": sc["payload"]["image_digest"],
                       "profile": "code-rules"},
            "subject": subject, "asset": asset,
            "evidence": {"raw": raw_ref, "sha256": digest, "excerpt": mask_literals(c["text"])[:200]},
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
            except Exception as e:
                # A schema violation, a tier that is down, a gateway timeout or HTTP error (httpx's
                # are not OSError), a body that is not the shape expected: each is one failed call,
                # recorded with its reason. The reading is optional; nothing here may end the scan.
                calls.append({"reply": None, "error": f"{type(e).__name__}: {e}"[:200]})
        return f, c, calls

    summary = Counter()
    lat = []
    with ThreadPoolExecutor(workers) as pool:
        results = list(pool.map(judge, findings))
    for f, c, calls in results:
        verdict = tally([x["reply"] for x in calls if isinstance(x.get("reply"), dict)], repeats, role_hint=c["role_hint"])
        errors = sorted({x["error"] for x in calls if x.get("error")})
        actor = next((x["actor"] for x in calls if x.get("actor")), {"kind": "rule", "id": "call-site-read/failed"})
        lat += [x["latency_ms"] for x in calls if x.get("latency_ms")]
        basis = verdict["basis"] + (f"; {len(errors)} kind{'s' if len(errors) != 1 else ''} of failure: {errors[0]}" if errors else "")
        run.ledger.append("assessment.made", actor, {
            "finding": f["id"], "purpose": ROLE, "rule_id": None,
            "classification": verdict["classification"], "agreement": verdict["agreement"],
            "votes": verdict["votes"],
            "calls": [{k: v for k, v in x.items() if k != "actor"} for x in calls], "used_by_rules": False,
            "basis": basis[:400]}, inputs=[f["id"]])
        in_use = verdict["classification"]["in_use"]
        summary["candidates"] += 1
        summary["uses" if in_use else ("not_uses" if in_use is False else "failed")] += 1
        if progress:
            progress(c, None if in_use is None else {"is_crypto_use": in_use, "family": verdict["classification"]["family"],
                                                     "role": verdict["classification"]["role"]})
    run.close(signer)
    out = dict(summary)
    out["latencies_ms"] = sorted(lat)
    return run, out
