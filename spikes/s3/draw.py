"""Spike S3: draw candidate items from the pinned sources. No model is called here or anywhere in labeling.

    uv run python spikes/s3/draw.py r1        # call sites from the three pinned repositories
    uv run python spikes/s3/draw.py r2        # tool spellings the name table does not hold

Candidates are written to spikes/s3/candidates/<role>.jsonl in a seeded order. Items are taken
from the top of that order under the quota stated in spikes/s3/labels/README.md; nothing is
composed and nothing is picked by eye.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SEED = "pqch-s3-2026-10-05"

# R1. Two pattern classes per language. `crypto`: the API names the BRIEF's counts were taken
# with. `lookalike`: words that read like cryptography and usually are not. Both classes hit
# comments and strings as well as code, which is where the hard third comes from.
R1 = {
    "identity-idp": {"glob": "*.rb", "crypto": r"OpenSSL::|JWT\.|JWE::|JWK|Digest::|HMAC|\.sign\(|\.verify\(|\.encrypt\(|\.decrypt\(|Cipher",
                     "lookalike": r"\b(signature|fingerprint|checksum|digest|secret_key|signed|cipher)\b"},
    "dpc-app": {"glob": "*.java", "crypto": r"bouncycastle|java\.security|javax\.crypto|KeyPairGenerator|Signature\.getInstance|MessageDigest|KeyFactory|Cipher\.getInstance|Mac\.getInstance|JWSAlgorithm|SecretKey",
                "lookalike": r"\b(signature|fingerprint|checksum|digest|token|certificate|signed|verify)\b"},
    "bluebutton-web-server": {"glob": "*.py", "crypto": r"hashlib|hmac|cryptography|jwt\.|Crypto\.|pbkdf2|\.encrypt\(|\.decrypt\(|sha256|sha1|md5",
                              "lookalike": r"\b(signature|fingerprint|checksum|digest|token|secret|signed|hash)\b"},
}
IMPORT = re.compile(r"\s*(import |from \S+ import |require |require_relative |package )")
PER_FILE = 2           # at most two candidates from one file
PER_REPO = 60          # candidates kept per repository, 2 of 3 from `crypto`
CONTEXT = 30           # lines shown before and after the flagged line


def sh(*args: str, cwd: Path) -> str:
    return subprocess.run(args, cwd=cwd, capture_output=True, text=True).stdout


def grep(repo: Path, pattern: str, glob: str) -> list[tuple[str, int, str]]:
    out = sh("git", "grep", "-n", "-I", "-E", "-i", pattern, "--", glob, cwd=repo)
    hits = []
    for line in out.splitlines():
        path, n, text = line.split(":", 2)
        # Not call sites: minified and generated lines, and import or require statements. (The
        # first draw kept imports and one line per file; Java then yielded three call sites in
        # sixty candidates. Changed before any item was labeled.)
        if len(text) <= 300 and not IMPORT.match(text):
            hits.append((path, int(n), text))
    return hits


def draw_r1() -> None:
    pins = {r["name"]: r for r in yaml.safe_load((ROOT / "eval/pins.yaml").read_text())["repositories"]}
    out = []
    for name, spec in R1.items():
        repo = ROOT / "targets" / name
        head = sh("git", "rev-parse", "HEAD", cwd=repo).strip()
        if head != pins[name]["commit"]:
            raise SystemExit(f"{name} is at {head}, not the pinned {pins[name]['commit']}")
        crypto = grep(repo, spec["crypto"], spec["glob"])
        seen = {(p, n) for p, n, _ in crypto}
        look = [h for h in grep(repo, spec["lookalike"], spec["glob"]) if (h[0], h[1]) not in seen]
        rng = random.Random(f"{SEED}/r1/{name}")
        rng.shuffle(crypto)
        rng.shuffle(look)
        # A cap per file: forty call sites from one file would be one item forty times.
        picked, files = [], {}
        for pool, cls, want in ((crypto, "crypto", PER_REPO * 2 // 3), (look, "lookalike", PER_REPO // 3)):
            got = 0
            for path, n, text in pool:
                if files.get(path, 0) >= PER_FILE or got >= want:
                    continue
                files[path] = files.get(path, 0) + 1
                got += 1
                picked.append((cls, path, n, text))
        rng.shuffle(picked)
        for cls, path, n, text in picked:
            lines = (repo / path).read_text(errors="replace").splitlines()
            lo, hi = max(1, n - CONTEXT), min(len(lines), n + CONTEXT - 1)
            out.append({"repo": pins[name]["repo"], "commit": head, "language": pins[name]["language"].split()[0],
                        "path": path, "line": n, "text": text.strip(), "pattern_class": cls,
                        "pool": {"crypto": len(crypto), "lookalike": len(look)},
                        "context_start": lo,
                        "context": "\n".join(f"{i:>5}  {lines[i - 1]}" for i in range(lo, hi + 1))})
    write("r1", out)


# R2. Spellings in saved tool output that the scout's name table does not map.
def draw_r2() -> None:
    sys.path.insert(0, str(ROOT / "src"))
    from pqch.scout import names

    known = set(names.TLS_GROUPS) | set(names.SSH_KEX) | set(names.SSH_HOSTKEY) | set(names.HASHES) | \
        set(names.SSH_HOSTKEY_CURVE) | {"RSA", "DSA", "ECDSA", "Ed25519", "Ed448"}
    found: dict[tuple[str, str, str], str] = {}

    def add(tool: str, field: str, spelling: str, where: str) -> None:
        spelling = spelling.strip()
        if spelling and spelling not in known and len(spelling) <= 80:
            found.setdefault((tool, field, spelling), where)

    files = sorted((ROOT / "var/raw").glob("*")) + sorted((ROOT / "spikes/s2/results").rglob("*.*")) + \
        sorted((ROOT / "tests/fixtures").glob("*"))
    for f in files:
        rel = str(f.relative_to(ROOT))
        try:
            text = f.read_text()
        except (UnicodeDecodeError, IsADirectoryError):
            continue
        if f.suffix == ".json":
            try:
                doc = json.loads(text)
            except ValueError:
                continue
            if isinstance(doc, list) and doc and isinstance(doc[0], dict) and "finding" in doc[0]:      # testssl.sh
                for e in doc:
                    eid, val = e.get("id", ""), str(e.get("finding", ""))
                    if eid in ("FS_KEMs", "FS_ECDHE_curves", "FS_ciphers", "FS_TLS13_sig_algs", "FS_TLS12_sig_algs"):
                        for tok in val.split():
                            add("testssl.sh", eid, tok, rel)
                    elif eid in ("DH_groups", "cert_signatureAlgorithm", "cert_keySize"):
                        add("testssl.sh", eid, val, rel)
                    elif eid.startswith("cipher-") and val.split():
                        add("testssl.sh", "cipher suite", val.split()[-1], rel)
            elif isinstance(doc, dict) and "kex" in doc:                                               # ssh-audit
                for field in ("kex", "key", "enc", "mac"):
                    for a in doc.get(field, []):
                        add("ssh-audit", field, a.get("algorithm", ""), rel)
            elif isinstance(doc, dict) and "components" in doc:                                        # cbomkit-theia
                for c in doc.get("components") or []:
                    if c.get("type") == "cryptographic-asset":
                        add("cbomkit-theia", "component name", c.get("name", ""), rel)
                        oid = c.get("cryptoProperties", {}).get("oid")
                        if oid:
                            add("cbomkit-theia", "oid", oid, rel)
        elif f.suffix == ".txt":                                                                        # openssl s_client
            for m in re.finditer(r"(?:Peer|Server) Temp Key: ([^\n]+)|Signature Algorithm: (\S+)|Public Key Algorithm: (\S+)"
                                 r"|Peer signature type: (\S+)|Peer signing digest: (\S+)|Negotiated TLS1\.3 group: (\S+)"
                                 r"|Cipher is (\S+)", text):
                field = ["Temp Key", "Signature Algorithm", "Public Key Algorithm", "Peer signature type",
                         "Peer signing digest", "Negotiated TLS1.3 group", "Cipher"][next(i for i, g in enumerate(m.groups()) if g)]
                add("openssl s_client", field, next(g for g in m.groups() if g), rel)
    rows = [{"tool": t, "field": fld, "spelling": sp, "seen_in": where} for (t, fld, sp), where in sorted(found.items())]
    random.Random(f"{SEED}/r2").shuffle(rows)
    write("r2", rows)


def write(role: str, rows: list[dict]) -> None:
    p = HERE / "candidates" / f"{role}.jsonl"
    p.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows))
    print(f"{role}: {len(rows)} candidates -> {p.relative_to(ROOT)}  sha256 {hashlib.sha256(p.read_bytes()).hexdigest()[:16]}")


if __name__ == "__main__":
    {"r1": draw_r1, "r2": draw_r2}[sys.argv[1]]()
