"""`verifier/class/1`: which verifier, if any, can confirm a change to each class of finding.

ADR-0001, decision 5: a finding class with no verifier is recorded as such and
counted in the receipts. The classes and their verifier kinds are data
(`policy/verifiers.yaml`); the rule records one `assessment.made` per class
present in the run, naming every finding of the class in `inputs`, and the CBOM
projection carries the kind on each component as `pqch:verifiable-by`.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from pqch.run import Run

SCHEMA = "pqch.verifiers/1"
KINDS = ("wire-kex", "cert-parse", "compat-run", "none")


def load_verifiers(path: str | Path) -> dict:
    doc = yaml.safe_load(Path(path).read_text())
    if doc.get("schema") != SCHEMA:
        raise ValueError(f"{path}: expected schema {SCHEMA}, found {doc.get('schema')!r}")
    for row in doc.get("classes", []):
        if row.get("verifier") not in KINDS or "layer" not in row:
            raise ValueError(f"{path}: a class row needs a layer and a verifier in {KINDS}")
    return doc


def class_of(finding: dict) -> tuple[str, str, str]:
    return finding["layer"], finding["asset"]["type"], finding["asset"]["role"]


def kind_for(doc: dict, cls: tuple[str, str, str]) -> dict | None:
    layer, type_, role = cls
    for row in doc.get("classes", []):
        if row["layer"] == layer and row.get("type", type_) == type_ and row.get("role", role) == role:
            return row
    return None


def classes(run: Run, doc: dict) -> dict:
    events = list(run.ledger.events())
    by_class: dict[tuple[str, str, str], list[str]] = {}
    for e in events:
        if e["type"] == "finding.observed":
            by_class.setdefault(class_of(e["payload"]), []).append(e["id"])
    counts = {"classes": 0, "without_verifier": 0, "findings_without_verifier": 0}
    for cls, ids in sorted(by_class.items()):
        row = kind_for(doc, cls) or {"verifier": "none", "why": "no row in the verifier table names this class"}
        layer, type_, role = cls
        run.ledger.append("assessment.made", {"kind": "rule", "id": "verifier/class/1"}, {
            "subject": {"kind": "finding-class", "layer": layer, "type": type_, "role": role},
            "rule_id": "verifier/class/1",
            "classification": {"verifiable_by": row["verifier"], "findings": len(ids)},
            "basis": row.get("why", ""),
        }, inputs=ids)
        counts["classes"] += 1
        if row["verifier"] == "none":
            counts["without_verifier"] += 1
            counts["findings_without_verifier"] += len(ids)
    return counts
