#!/usr/bin/env python
"""A dated snapshot of NIST's Cryptographic Module Validation Program (CMVP) for the libraries
the estate runs, with what each active certificate's approved algorithms include.

The assessor's validated-module blocker reads this file, never the network: the snapshot is
data, dated, with the SHA-256 of every page it was read from, so a reader can see what was
true on the day and the bundle carries it. Run it to refresh; commit the result.

    uv run python tools/cmvp_snapshot.py [--out policy/snapshots/cmvp-YYYY-MM-DD.json]

Only active certificates, from the CMVP's own search. A certificate page lists approved
algorithms by name with their CAVP numbers; this records which post-quantum ones appear.
It does not record the validated software version: the page does not state it, the
Security Policy does, and that PDF is not read here.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

BASE = "https://csrc.nist.gov/projects/cryptographic-module-validation-program"
UA = "Mozilla/5.0 (X11; Linux x86_64) cbom-workbench cmvp_snapshot (research; one request a second)"
# What the estate links: OpenSSL (nginx, PostgreSQL, OpenSSH 10, Erlang/OTP's crypto), the
# Java runtime's providers, and the two names searched in case a module is filed under them.
SEARCHES = [("ModuleName", "OpenSSL"), ("Vendor", "OpenSSL"), ("ModuleName", "Java"),
            ("ModuleName", "Erlang"), ("ModuleName", "OpenSSH")]
PQ = ("ML-KEM", "ML-DSA", "SLH-DSA")


def fetch(url: str) -> tuple[str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
    time.sleep(1)
    return data.decode("utf-8", "replace"), hashlib.sha256(data).hexdigest()


def text(h: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", h))).strip()


def field(t: str, name: str, stop: str) -> str | None:
    m = re.search(re.escape(name) + r"\s+(.*?)\s+" + re.escape(stop), t)
    return m.group(1).strip() if m else None


def search(kind: str, term: str) -> tuple[list[dict], dict]:
    q = urllib.parse.urlencode({"SearchMode": "Advanced", kind: term, "CertificateStatus": "Active",
                                "ValidationYear": "0"})
    url = f"{BASE}/validated-modules/search?{q}"
    h, digest = fetch(url)
    rows = []
    for r in re.findall(r"<tr[^>]*>(.*?)</tr>", h, re.S):
        cells = [text(c) for c in re.findall(r"<td[^>]*>(.*?)</td>", r, re.S)]
        if len(cells) >= 6 and cells[0].isdigit():
            rows.append({"certificate": int(cells[0]), "vendor": cells[1], "module": cells[2],
                         "type": cells[3], "validated": cells[4], "status": cells[5]})
    m = re.search(r"(\d+) certificates? match(?:es)? the search criteria", text(h))
    stated = int(m.group(1)) if m else (0 if "No records" in h or not rows else None)
    if stated is not None and stated != len(rows):
        raise SystemExit(f"{kind}={term}: the page says {stated} match and lists {len(rows)}; results are paged")
    return rows, {"url": url, "sha256": digest, "rows": len(rows), "stated_matches": stated}


def certificate(n: int) -> dict:
    url = f"{BASE}/certificate/{n}"
    h, digest = fetch(url)
    t = text(h)
    algs = t[t.find("Approved Algorithms"):t.find("Vendor ")] if "Approved Algorithms" in t else ""
    return {
        "certificate": n, "url": url, "sha256": digest,
        "standard": field(t, "Standard", "Status"), "sunset": field(t, "Sunset Date", "Overall Level"),
        "level": field(t, "Overall Level", "Caveat"),
        "approved_pq": sorted({a for a in PQ if a in algs}),
        "approved_ml_kem": "ML-KEM" in algs, "approved_ml_dsa": "ML-DSA" in algs,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    taken = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = {"schema": "pqch.cmvp-snapshot/1", "taken_at": taken, "source": BASE,
           "scope": "active certificates matching the searches below; approved algorithms read from each certificate page",
           "searches": [], "certificates": {}}
    seen = {}
    for kind, term in SEARCHES:
        rows, meta = search(kind, term)
        out["searches"].append({"field": kind, "term": term, **meta,
                                "certificates": [r["certificate"] for r in rows]})
        for r in rows:
            seen.setdefault(r["certificate"], r)
    for n, r in sorted(seen.items()):
        out["certificates"][str(n)] = {**r, **certificate(n)}
        print(n, r["vendor"][:30], r["module"][:50], out["certificates"][str(n)]["approved_pq"], flush=True)
    path = Path(a.out or f"policy/snapshots/cmvp-{taken[:10]}.json")
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"{path}: {len(seen)} certificates")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
