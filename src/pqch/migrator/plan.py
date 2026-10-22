"""A change drafted by a model, for a listener whose software has no renderer.

The `change-plan` role (spike S3's R6, measured against a floor) drafts the edit. Its context is
the CBOM: the listener's entries from the latest scan — what it negotiates, serves and accepts —
the investigator's trace of its key exchange where there is one, and the service's build files
with line numbers. The prompt is S3's, verbatim (`prompts/change-plan.md`), with one paragraph
added: only the policy include file may be edited, the service reads it last, and the runner
writes into it only these lines.

Three calls are made and all three are recorded. A reply is usable when it edits only the include
file and the result has the software's shape; the first usable one becomes the proposal, with
the model as its actor. Nothing more is trusted: the proposal is rehearsed on a copy of the
service in the twin, applied only on approval, and the verifier decides whether it landed.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from pqch import inference
from pqch.common import sha256_hex
from pqch.investigator import Workspace
from pqch.migrator import render
from pqch.run import Run

ROLE = "change-plan"
PURPOSE = "change-plan"
SCHEMA = {
    "type": "object", "required": ["blocked", "edits"],
    "properties": {"blocked": {"enum": ["none", "supplier", "protocol"]},
                   "edits": {"type": "array", "items": {
                       "type": "object", "required": ["file", "line_start", "line_end", "replacement"],
                       "properties": {"file": {"type": "string"}, "line_start": {"type": "integer"},
                                      "line_end": {"type": "integer"}, "replacement": {"type": "string"}},
                       "additionalProperties": False}}},
    "additionalProperties": False,
}
SHAPE_HELP = {
    "postgresql": ("comment lines starting with #, and only these settings, one per line: "
                   "ssl_groups = '<group>[:<group>...]', ssl_min_protocol_version = 'TLSv1.2' or 'TLSv1.3', "
                   "ssl_max_protocol_version = 'TLSv1.2' or 'TLSv1.3', ssl_ciphers = '<OpenSSL cipher list>'"),
}


def prompt_text() -> str:
    return resources.files(__package__).joinpath("prompts/change-plan.md").read_text()


def messages(service: str, intent: str, findings: list[dict], ws: Workspace, editable: str, software: str) -> list[dict]:
    system, _, user = prompt_text().partition("\n---\n")
    system = system.strip() + (
        f"\n\nIn this estate the change is made in one file only: {editable}. The service reads it last, so a "
        f"setting there replaces the same setting anywhere above it. Edit no other file. The runner writes into "
        f"that file nothing but {SHAPE_HELP[software]}; a reply with any other line is refused.")
    files = "\n\n".join(f"--- {rel}\n{ws.read(rel, 1, 400)}" for rel in ws.files)
    user = (user.replace("{service}", service).replace("{intent}", intent)
            .replace("{findings}", json.dumps(findings, indent=1, ensure_ascii=False)).replace("{files}", files))
    return [{"role": "system", "content": system}, {"role": "user", "content": user.strip()}]


def apply_edits(text: str, edits: list[dict]) -> str:
    """Line replacements, applied from the bottom up so earlier line numbers stay valid."""
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]
    for e in sorted(edits, key=lambda e: -e["line_start"]):
        start, end = e["line_start"], e["line_end"]
        if start < 1 or end < start - 1 or end > len(lines):
            raise ValueError(f"lines {start}-{end} are outside a file of {len(lines)} lines")
        repl = e["replacement"].split("\n")
        if repl and repl[-1] == "":
            repl = repl[:-1]
        lines[start - 1:end] = repl
    return "\n".join(lines) + "\n"


def context(scan_events: list[dict], host: str, port: int) -> tuple[list[dict], list[str]]:
    """The listener's entries from the scan: what was seen there, as the CBOM carries it."""
    out, ids = [], []
    for e in scan_events:
        f = e["payload"] if e["type"] == "finding.observed" else None
        if f and f["layer"] == "wire" and f["subject"].get("host") == host and f["subject"].get("port") == port:
            out.append({"layer": f["layer"], "subject": f["subject"],
                        "asset": {k: f["asset"][k] for k in ("type", "role", "name")} | {"parameters": f["asset"].get("parameters", {})},
                        "evidence": f["evidence"]["excerpt"]})
            ids.append(e["id"])
    return out, ids


def draft(run: Run, *, scan_run: Run, target: dict, intent: str, agency_dir: Path, inputs: list[str],
          seam: inference.Seam | None = None, trace: dict | None = None, repeats: int = 3) -> dict:
    """Draft the change and record it: a `change.proposed` from the model when a reply is usable,
    otherwise an `assessment.made` saying why there is no proposal. Returns the event."""
    s = seam or inference.default()
    software = target["software"]
    ws = Workspace(Path(agency_dir), target["service"])
    editable = next((rel for rel in ws.files
                     if rel.endswith(f"generated/{target['service']}/{render.POLICY_FILE[software]}")), None)
    if editable is None:
        raise ValueError(f"{target['service']} has no policy file to edit")
    old = ws.files[editable].read_text()
    findings, finding_ids = context(list(scan_run.ledger.events()), target["address"], target["port"])
    msgs = messages(target["service"], intent, findings, ws, editable, software)
    if trace:
        msgs[1]["content"] += ("\n\nThe investigator traced the key exchange on this listener to: "
                               + json.dumps({k: trace["payload"][k] for k in ("answer", "line_text")}))
    calls, chosen = [], None
    for _ in range(repeats):
        try:
            c = s.complete_role(ROLE, msgs, schema=SCHEMA, max_tokens=20000, purpose=PURPOSE)
        except inference.SchemaViolation as e:
            calls.append({"usable": False, "why": f"schema: {e}"[:200]})
            continue
        rec = {"reply": c.parsed, "latency_ms": c.latency_ms, "tokens": int(c.usage.get("total_tokens") or 0),
               "finish_reason": c.finish_reason, "actor": c.actor()}
        why = None
        if c.parsed["blocked"] != "none":
            why = f"the model says blocked: {c.parsed['blocked']}"
        elif any(e["file"] != editable for e in c.parsed["edits"]):
            why = "edits a file other than " + editable
        else:
            try:
                new = apply_edits(old, c.parsed["edits"])
                if not render.is_rendered_shape(new, software):
                    why = f"the result holds a line the runner does not write for {software}"
                elif new == old:
                    why = "the edits change nothing"
                else:
                    rec["new_content"] = new
            except ValueError as e:
                why = str(e)
        rec["usable"], rec["why"] = why is None, why
        calls.append(rec)
        if chosen is None and why is None:
            chosen = rec
    summary = [{k: v for k, v in r.items() if k in ("usable", "why", "latency_ms", "tokens", "finish_reason", "reply")}
               for r in calls]
    drafted = {"role": ROLE, "prompt_sha256": sha256_hex(json.dumps(msgs).encode()),
               "context": {"scan_run": scan_run.id, "findings": finding_ids, "trace": trace and trace["id"],
                           "files": [{"path": rel, "sha256": sha256_hex(p.read_bytes())} for rel, p in ws.files.items()]},
               "calls": summary}
    if chosen is None:
        actor = next((r["actor"] for r in calls if "actor" in r), {"kind": "rule", "id": "change-plan/failed"})
        return run.ledger.append("assessment.made", actor, {
            "subject": {"kind": "change", "service": target["service"], "intent": intent}, "purpose": PURPOSE,
            "rule_id": None, "classification": {"proposal": None}, "basis": "; ".join(r.get("why") or "" for r in calls),
            "drafted": drafted, "used_by_rules": False}, inputs=inputs)
    new = chosen["new_content"]
    return {"actor": chosen["actor"], "drafted": drafted, "new": new, "old": old, "editable": editable}
