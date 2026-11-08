"""The workbench's own SBOM (FR-05): Syft over a harness image, pinned by digest and run with no network,
then each minimum element counted, and optionally Grype over the result.

    uv run python tools/sbom.py pqch/harness:m8 --out release/ [--grype]

Writes <out>/sbom.cdx.json (CycloneDX, Syft's own) and <out>/sbom-summary.json: the image, the tools by
digest, the component count by kind, and for each minimum element the share of components or the
document field that carries it. Grype fetches its vulnerability database, so it is the one step that
needs a network; its counts go in the summary with the database's build date.

The element list is CISA's *Minimum Elements for a Software Bill of Materials* as the 2025 draft lists
them and summaries of the 2026 version describe them; it was not read first-hand here. Check it against
the published document before citing a coverage figure as compliance.
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
from pathlib import Path

SYFT = "anchore/syft@sha256:f94e5d9fce1f2278491a8e3a63bd5f6ddb81fdfdbb8bf7a1637565c1d5344357"    # v1.33.0
GRYPE = "anchore/grype@sha256:dcf0168c9b275c6dbcbff5ceeecfac29a6ccf138a87f0adc9ce5bd69fe6146f3"   # v0.100.0

# Per document: SBOM author, tool name, timestamp, generation context. Per component: the rest.
DOC_ELEMENTS = ("sbom_author", "tool_name", "timestamp", "generation_context")
COMPONENT_ELEMENTS = ("software_producer", "component_name", "component_version", "software_identifiers",
                      "component_hash", "license", "dependency_relationship")


def coverage(doc: dict) -> dict:
    """For each minimum element: True/False for a document element, the share of library and
    application components carrying it for a component element (files and the OS entry excluded)."""
    md = doc.get("metadata") or {}
    tools = md.get("tools") or {}
    tool_names = [t.get("name") for t in (tools.get("components") or [])] if isinstance(tools, dict) else \
        [t.get("name") for t in tools]
    out = {"sbom_author": bool(md.get("authors") or md.get("manufacturer") or md.get("supplier")),
           "tool_name": bool([t for t in tool_names if t]),
           "timestamp": bool(md.get("timestamp")),
           "generation_context": bool(md.get("lifecycles"))}
    comps = [c for c in doc.get("components") or [] if c.get("type") in ("library", "application", "framework")]
    depends = {d["ref"] for d in doc.get("dependencies") or [] if d.get("dependsOn")} | \
        {r for d in doc.get("dependencies") or [] for r in d.get("dependsOn") or []}
    has = {
        "software_producer": lambda c: bool(c.get("supplier") or c.get("publisher") or c.get("author") or c.get("authors")),
        "component_name": lambda c: bool(c.get("name")),
        "component_version": lambda c: bool(c.get("version")),
        "software_identifiers": lambda c: bool(c.get("purl") or c.get("cpe") or c.get("swid")),
        "component_hash": lambda c: bool(c.get("hashes")),
        "license": lambda c: bool(c.get("licenses")),
        "dependency_relationship": lambda c: c.get("bom-ref") in depends,
    }
    n = len(comps)
    for k in COMPONENT_ELEMENTS:
        out[k] = round(sum(1 for c in comps if has[k](c)) / n, 3) if n else None
    out["components"] = n
    return out


def run_syft(image: str) -> dict:
    r = subprocess.run(["docker", "run", "--rm", "--network", "none", "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
                        SYFT, f"docker:{image}", "-o", "cyclonedx-json"], capture_output=True, text=True, timeout=1200)
    if r.returncode != 0:
        raise SystemExit(f"syft failed: {r.stderr[-800:]}")
    return json.loads(r.stdout)


def run_grype(sbom: Path, db_dir: Path) -> dict:
    db_dir.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(["docker", "run", "--rm", "-v", f"{sbom.parent.resolve()}:/w:ro", "-v", f"{db_dir.resolve()}:/db",
                        "-e", "GRYPE_DB_CACHE_DIR=/db", GRYPE, f"sbom:/w/{sbom.name}", "-o", "json"],
                       capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise SystemExit(f"grype failed: {r.stderr[-800:]}")
    d = json.loads(r.stdout)
    sev = collections.Counter(m["vulnerability"]["severity"] for m in d["matches"])
    fixable = collections.Counter(m["artifact"]["type"] for m in d["matches"]
                                  if m["vulnerability"]["severity"] in ("High", "Critical")
                                  and (m["vulnerability"].get("fix") or {}).get("state") == "fixed")
    return {"matches": len(d["matches"]), "by_severity": dict(sev), "high_or_critical_with_a_fix_by_kind": dict(fixable),
            "db_built": ((d.get("descriptor") or {}).get("db") or {}).get("status", {}).get("built")}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("image")
    ap.add_argument("--out", default="release")
    ap.add_argument("--grype", action="store_true")
    ap.add_argument("--author", default="cbom-workbench release build")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    doc = run_syft(a.image)
    # What Syft cannot know: who the SBOM is by, and at what point it was made (an image already built).
    md = doc.setdefault("metadata", {})
    md.setdefault("authors", [{"name": a.author}])
    md.setdefault("lifecycles", [{"phase": "post-build"}])
    sbom = out / "sbom.cdx.json"
    sbom.write_text(json.dumps(doc, indent=1) + "\n")
    image_id = subprocess.run(["docker", "image", "inspect", a.image, "--format", "{{.Id}}"],
                              capture_output=True, text=True).stdout.strip()
    kinds = collections.Counter(next((p["value"] for p in c.get("properties") or [] if p["name"] == "syft:package:type"),
                                     c.get("type")) for c in doc.get("components") or [])
    summary = {"image": a.image, "image_id": image_id, "syft": SYFT, "components_by_kind": dict(kinds),
               "minimum_elements": coverage(doc)}
    if a.grype:
        summary["grype"] = {"image": GRYPE, **run_grype(sbom, out / ".grype-db")}
    (out / "sbom-summary.json").write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
