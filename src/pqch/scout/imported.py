"""Bring your own scanner: any tool's CycloneDX CBOM, imported as evidence and scored.

A commercial or open-source discovery tool that exports a CycloneDX 1.6 or 1.7 CBOM can be brought to
the workbench without integrating it. Each cryptographic asset becomes a finding on a ledger of its
own (a run of kind `import`), labelled with the tool that made it and the hash of the document it came
from, and placed where the workbench can check it:

- an occurrence `host:port` that the scope lists is a listener (wire);
- an absolute path, with `--image` naming the scanned image, is a file in that image (host);
- `path` with a line number, with `--repo` and `--commit`, is a call site in a pinned repository (code).

Names are normalized by the same functions the workbench's own readers use, so an imported CBOM is
scored against the answer key on the same terms as ours. An entry with no location the workbench can
place stays out of the findings and is listed by name in the import record: a CBOM entry nobody can
find again cannot be verified or scored.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

from pqch import schemas
from pqch import scope as scope_mod
from pqch.common import sha256_hex, utc_now
from pqch.run import Run
from pqch.scout import names
from pqch.scout.normalize import _PRIMITIVE_ROLE, _Collector, fingerprint

HOSTPORT = re.compile(r"^\[?([A-Za-z0-9.:-]+?)\]?:(\d{1,5})$")
ACTOR = {"kind": "scanner", "id": "pqch-import"}


def _tool(bom: dict) -> tuple[str, str]:
    """The tool that made the document, as its metadata names it (1.4 list or 1.5+ components)."""
    t = (bom.get("metadata") or {}).get("tools") or {}
    items = t.get("components", []) if isinstance(t, dict) else t
    first = items[0] if items else {}
    return first.get("name") or "unnamed tool", first.get("version") or "unstated"


def _asset(comp: dict, refs: dict) -> tuple[str, str, str, dict] | None:
    """(type, role, name, parameters) by the workbench's conventions, or None if not an asset."""
    if comp.get("type") != "cryptographic-asset":
        return None
    cp = comp.get("cryptoProperties") or {}
    kind = cp.get("assetType")
    name = comp.get("name") or "unknown"
    if kind == "algorithm":
        prim = (cp.get("algorithmProperties") or {}).get("primitive", "")
        return "algorithm", _PRIMITIVE_ROLE.get(prim, "other"), names.algorithm_name(name), {"primitive": prim} if prim else {}
    if kind == "certificate":
        props = cp.get("certificateProperties") or {}
        pub = refs.get(props.get("subjectPublicKeyRef"), {})
        params = {k: v for k, v in {"subject": props.get("subjectName"), "issuer": props.get("issuerName"),
                                    "not_after": props.get("notValidAfter")}.items() if v}
        return "certificate", "signature", names.key_family(pub.get("name", name)), params
    if kind == "related-crypto-material":
        rcm = cp.get("relatedCryptoMaterialProperties") or {}
        params = {"kind": [rcm.get("type", "unknown")]}
        if rcm.get("size"):
            params["key_bits"] = rcm["size"]
        return "related-crypto-material", "other", names.key_family(name), params
    if kind == "protocol":
        return "protocol", "other", name, {}
    return None


def place(loc: str, occ: dict, *, scope: dict, image: str | None, image_digest: str | None,
          repo: str | None, commit: str | None) -> tuple[str, dict] | None:
    """(layer, subject) for one occurrence, or None when the workbench cannot find it again."""
    m = HOSTPORT.match(loc)
    if m:
        host, port = m.group(1), int(m.group(2))
        ep = next((e for e in scope["endpoints"] if e["host"] == host and e["port"] == port), None)
        if ep:
            return "wire", {"kind": "endpoint", "host": host, "port": port, "protocol": ep["protocol"],
                            **({"sni": ep["sni"]} if ep.get("sni") else {})}
        return None
    line = occ.get("line")
    if repo and commit and line and not loc.startswith("/"):
        return "code", {"kind": "call-site", "repo": repo, "commit": commit, "path": loc, "line": int(line)}
    if loc.startswith("/") and image and image_digest:
        return "host", {"kind": "file", "image": image, "path": loc}
    return None


def run_import(var: Path, docs: list[tuple[Path, str | None]], scope: dict, *, repo: str | None = None,
               commit: str | None = None, key_path: Path | None = None, tool: str | None = None,
               signer=None) -> tuple[Run, dict]:
    """Import one or more CBOMs from one tool into a run of their own; each document may name the image
    it describes (`(path, image)`), as a tool that scans images one at a time writes one per image."""
    schemas.validate(scope)
    loaded = []
    for path, image in docs:
        raw = Path(path).read_bytes()
        bom = json.loads(raw)
        if bom.get("bomFormat") != "CycloneDX":
            raise ValueError(f"{path}: not a CycloneDX document")
        loaded.append((Path(path), image, raw, bom))
    name, version = _tool(loaded[0][3])
    name = tool or name
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile=f"import:{name}",
                    kind="import", runner_id="pqch-import")
    if key_path:
        run.commit_key(key_path, author="workbench")
    unplaced: list[str] = []
    seen = Counter()
    documents, findings = [], []
    for n, (path, image, raw, bom) in enumerate(loaded):
        digest = "sha256:" + sha256_hex(raw)
        stored = run.dir / f"imported-{n}.cdx.json"
        stored.write_bytes(raw)
        documents.append({"name": path.name, "image": image, "path": str(stored.relative_to(var)), "sha256": digest,
                          "spec_version": bom.get("specVersion")})
        image_digest = None
        if image:
            pinned = next((i for i in scope.get("images", []) if i.split("@")[0] == image), None)
            image_digest = pinned.split("@", 1)[1] if pinned and "@" in pinned else None
        job = {"tool": name, "version": _tool(bom)[1], "image_digest": digest, "profile": f"import:{name}",
               "ended_at": utc_now(), "raw": str(stored.relative_to(var)), "raw_sha256": digest.split(":", 1)[1]}
        collectors: dict[str, _Collector] = {}
        refs = {c.get("bom-ref"): c for c in bom.get("components", []) if c.get("bom-ref")}
        for comp in bom.get("components", []):
            a = _asset(comp, refs)
            if not a:
                continue
            seen[comp["cryptoProperties"]["assetType"]] += 1
            placed = False
            for occ in (comp.get("evidence") or {}).get("occurrences") or []:
                p = place(str(occ.get("location", "")), occ, scope=scope, image=image, image_digest=image_digest,
                          repo=repo, commit=commit)
                if not p:
                    continue
                layer, subject = p
                c = collectors.setdefault(layer, _Collector(job, layer, subject_digest=image_digest if layer == "host" else None))
                params = dict(a[3])
                if layer == "code":
                    params["line_text"] = occ.get("additionalContext", "")
                c.add(subject, a[0], a[1], a[2], params, f"{comp.get('name')} at {occ.get('location')}"
                      + (f":{occ['line']}" if occ.get("line") else ""))
                placed = True
            if not placed:
                unplaced.append(f"{a[0]} {comp.get('name')}")
        for layer, c in collectors.items():
            for f in c.findings():
                f["fingerprint"] = fingerprint(layer, f["subject"], f["asset"])
                schemas.validate(f)
                findings.append(f)
    for f in findings:
        run.ledger.append("finding.observed", ACTOR, f)
    summary = {"tool": name, "version": version, "documents": documents, "assets": dict(seen), "findings": len(findings),
               "by_layer": dict(Counter(f["layer"] for f in findings)), "unplaced": len(unplaced),
               "unplaced_names": unplaced[:200]}
    if key_path:
        import yaml

        from pqch.cbom import project
        from pqch.score import score_bom
        score = score_bom(project(list(run.ledger.events())), yaml.safe_load(key_path.read_bytes()))
        summary["score"] = {k: {x: v[x] for x in ("present", "covered", "out_of_reach", "decoys", "false_positives",
                                                  "missed", "flagged_decoys", "scanned")}
                            for k, v in score["layers"].items()}
    run.ledger.append("import.completed", ACTOR, summary)
    run.close(signer)
    return run, summary
