"""Ask the CBOM: a question answered from the CBOM, citing ledger events, every citation checked.

Two parts, scored apart (eval/ask/README.md): retrieval over one passage per component, by the
`embed` tier; and the answer, a typed reply from the `ask-cbom` role made only from the passages
it was shown. A rule then checks each citation against the ledger and the shown passages. The
ledger is not written: a question is not an event of the estate.
"""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

from pqch import varmode
from pqch.cbom import anatomy

PROMPT = (Path(__file__).parent / "prompts" / "ask-cbom.md").read_text()
TOP_K = 8
SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "components": {"type": "array", "items": {"type": "string"}},
        # One ledger event id (a ULID) per citation, held by the schema: a reply that packed three ids
        # into one string failed every citation at the rule on 2026-11-04 (Lightning, demo GB10).
        "citations": {"type": "array", "items": {"type": "string", "pattern": "^[0-9A-HJKMNP-TV-Z]{26}$"}},
        "not_in_passages": {"type": "boolean"},
    },
    "required": ["answer", "components", "citations", "not_in_passages"],
    "additionalProperties": False,
}
ROLE = "ask-cbom"
# Questions the page offers, from eval/ask/items.jsonl, whose answers the key knows.
EXAMPLES = ["Which SSH listener still offers the 1024-bit Diffie-Hellman group?",
            "Which listeners already negotiate a hybrid post-quantum key exchange?",
            "Does any service present an ML-DSA certificate, and which?",
            "Which listeners are still limited to TLS 1.2?",
            "What signs the certificate on the message queue's TLS listener?",
            "Is there a listener on port 8443 that presents an RSA certificate, and which service is it?"]


def passages(bom: dict, events: list[dict]) -> list[dict]:
    """One passage per component: what the CBOM says about it, in words a question would use, with
    the ledger events behind it. Built from the same anatomy the CBOM page shows."""
    out = []
    names = {c["bom-ref"]: anatomy.label_of(c) for c in bom.get("components", [])}
    for c in bom.get("components", []):
        a = anatomy.component(bom, events, c["bom-ref"])
        if a is None:
            continue
        facts, ev = [], set()
        for row in a["rows"]:
            v = row["value"]
            if isinstance(v, (dict, list)):
                v = json.dumps(v, ensure_ascii=False)
            if v in (None, "", "[]", "{}"):
                continue
            facts.append(f"{row['field']}: {v}")
            ev.update(x["event"] for x in row["evidence"])
        ev.update(i for i in (anatomy._props(c).get("pqch:evidence") or "").split(",") if i)
        rel = [f"depends on {names.get(d['ref'], d['ref'])} ({d['ref']})" for d in a["depends_on"]]
        rel += [f"depended on by {names.get(d['ref'], d['ref'])} ({d['ref']})" for d in a["depended_by"]]
        ev.update(d["link"]["event"] for d in a["depends_on"] + a["depended_by"] if d.get("link"))
        text = f"{a['kind']} {a['label']} (bom-ref {a['ref']}). " + "; ".join(facts)[:3000]
        if rel:
            text += ". " + "; ".join(rel)
        out.append({"ref": a["ref"], "kind": a["kind"], "label": a["label"], "text": text, "events": sorted(ev)})
    return out


def _cos(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return dot / (na * nb) if na and nb else 0.0


class Index:
    """The passages and their embeddings for one CBOM, cached beside the run: embedding 250
    passages is seconds on the box but not free, and the CBOM does not change between questions."""

    def __init__(self, seam, run_dir: Path, bom: dict, events: list[dict]):
        self.seam = seam
        self.path = Path(run_dir) / "ask-index.json"
        self.passages = passages(bom, events)
        self.by_ref = {p["ref"]: p for p in self.passages}
        self.parents: dict[str, list[str]] = {}
        for d in bom.get("dependencies", []):
            for child in d["dependsOn"]:
                self.parents.setdefault(child, []).append(d["ref"])
        key = hashlib.sha256(json.dumps([p["text"] for p in self.passages]).encode(), usedforsecurity=False).hexdigest()
        tier = seam.config["tiers"].get("embed") or {}
        self.model = tier.get("model", "")
        self.hardware = tier.get("hardware", "")
        self.vectors: list[list[float]] | None = None
        if self.path.exists():
            cached = json.loads(self.path.read_text())
            if cached.get("key") == key and cached.get("model") == self.model:
                self.vectors = cached["vectors"]
        if self.vectors is None:
            self.vectors = []
            for i in range(0, len(self.passages), 32):
                self.vectors += seam.embed("embed", [p["text"] for p in self.passages[i:i + 32]], purpose="passage")
            self.path.write_text(json.dumps({"key": key, "model": self.model, "vectors": self.vectors}))
            varmode.private(self.path)

    def retrieve(self, question: str, k: int = TOP_K) -> list[dict]:
        """The k passages nearest the question, then the chain each sits in: an asset brings its
        listener, a listener its service (two hops up the CBOM's dependencies), so a question about
        a service is answered from the assets that make it what it is. A rule, not a model."""
        q = self.seam.embed("embed", [question], purpose="query")[0]
        scored = sorted(((_cos(q, v), i) for i, v in enumerate(self.vectors)), reverse=True)[:k]
        out = [{**self.passages[i], "score": round(s, 4)} for s, i in scored]
        have = {p["ref"] for p in out}
        for p in list(out):
            for parent in self.parents.get(p["ref"], []):
                for ref in (parent, *self.parents.get(parent, [])):
                    if ref not in have and ref in self.by_ref:
                        have.add(ref)
                        out.append({**self.by_ref[ref], "score": 0.0, "via": p["ref"]})
        return out


def _messages(question: str, shown: list[dict]) -> list[dict]:
    lines = []
    for n, p in enumerate(shown, 1):
        lines.append(f"[{n}] {p['text']}\n    events: {', '.join(p['events']) or 'none'}")
    return [{"role": "system", "content": PROMPT},
            {"role": "user", "content": f"Question: {question}\n\nPassages:\n" + "\n".join(lines)}]


def check(reply: dict, shown: list[dict], events: list[dict]) -> dict:
    """The rule: a citation passes when the event exists in the ledger and belongs to a passage the
    model was shown; a component passes when it was shown. Nothing here asks a model."""
    by_id = {e["id"]: e for e in events}
    shown_refs = {p["ref"] for p in shown}
    # The model names components as it was shown them: a bom-ref, sometimes written "bom-ref: X"
    # or as the passage's number "[n]". Both spellings are read; nothing else is guessed.
    def norm(r: str) -> str:
        r = r.strip().lstrip("/").strip()
        for pre in ("bom-ref:", "bom-ref", "ref:"):
            if r.lower().startswith(pre):
                r = r[len(pre):].strip(" :")
        if r.startswith("[") and r.endswith("]") and r[1:-1].isdigit() and 0 < int(r[1:-1]) <= len(shown):
            r = shown[int(r[1:-1]) - 1]["ref"]
        return r
    # A citation that is a shown component's hash (with or without its `fp:`) names a component,
    # not an event: it moves to the components list rather than failing as an unknown event.
    hashes = {p["ref"].removeprefix("fp:"): p["ref"] for p in shown}
    comps_named = [norm(r) for r in reply.get("components", [])]
    cites_kept = []
    for c in reply.get("citations", []):
        c = c.strip()
        if norm(c).removeprefix("fp:") in hashes:          # a component's hash, or any shown bom-ref,
            comps_named.append(hashes[norm(c).removeprefix("fp:")])   # given as a citation
        elif norm(c) in shown_refs:
            comps_named.append(norm(c))
        else:
            cites_kept.append(c)
    reply = {**reply, "components": list(dict.fromkeys(comps_named)), "citations": cites_kept}
    shown_events = {e for p in shown for e in p["events"]}
    cites = []
    for c in reply.get("citations", []):
        e = by_id.get(c)
        cites.append({"event": c, "in_ledger": e is not None, "shown": c in shown_events,
                      "ok": e is not None and c in shown_events,
                      "type": e["type"] if e else None, "actor": (e or {}).get("actor", {}).get("id"),
                      "at": (e or {}).get("at") or (e or {}).get("time")})
    comps = [{"ref": r, "ok": r in shown_refs} for r in reply.get("components", [])]
    return {"citations": cites, "components": comps,
            "ok": all(c["ok"] for c in cites) and all(c["ok"] for c in comps)}


def ask(seam, index: Index, question: str, events: list[dict]) -> dict:
    """Retrieve, answer through the role, check. The result carries the shown passages, the typed
    reply, each citation's verdict, and the model call's provenance."""
    shown = index.retrieve(question)
    # A reply cap on a thinking tier is a thinking budget (lesson 55). On Lightning with thinking on a GB10
    # (2026-11-04): at 4000 three of six example questions came back cut short, at 8000 three, at 16000 two
    # (one empty after 120 s, one cut mid-answer); 20000 is the largest envelope any role measured (change
    # plans, p90 19,352). The page shows each call's finish reason and completion tokens, so the next
    # cut-off is measured, not guessed.
    # Thinking off answers in a few hundred tokens; a cap of 1,200 ends a runaway in about ten seconds on this class of
    # engine instead of two hundred. Thinking on keeps the 20,000 envelope above.
    cap = 20000 if seam.for_role(ROLE)[1] else 1200
    c = seam.complete_role(ROLE, _messages(question, shown), schema=SCHEMA, max_tokens=cap, purpose="ask-cbom")
    reply = c.parsed if isinstance(c.parsed, dict) else {"answer": c.text, "components": [], "citations": [],
                                                           "not_in_passages": True}
    return {"question": question, "shown": shown, "reply": reply, "check": check(reply, shown, events),
            "model": c.model, "tier": c.tier, "hardware": c.hardware, "latency_ms": c.latency_ms,
            "reasoning": c.reasoning, "finish_reason": c.finish_reason,
            "completion_tokens": (c.usage or {}).get("completion_tokens"),
            "embed_model": index.model, "embed_hardware": index.hardware}


# Recorded answers. A static copy of the workbench (the public demo) has no model to call, so the page there
# shows the example questions answered once, by a real call, and says when and by what. The recording lives
# beside the run it answers (var/ask/<run>.json); the citation check is run again when the page renders, so
# "checked" on the static page is the rule's verdict against the ledger it is published with.
def recording_path(var: Path, run_id: str) -> Path:
    return Path(var) / "ask" / f"{run_id}.json"


def load_recording(var: Path, run_id: str) -> dict | None:
    p = recording_path(var, run_id)
    try:
        rec = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return rec if rec.get("run") == run_id else None


def record(seam, run, questions: list[str] | None = None) -> dict:
    """Answer each example question against one scan run and write the answers beside it."""
    from datetime import datetime, timezone

    from pqch.cbom import project

    events = list(run.ledger.events())
    index = Index(seam, run.dir, project(events), events)
    answers = {}
    for q in questions or EXAMPLES:
        try:
            answers[q] = ask(seam, index, q, events)
        except Exception as e:  # an engine down, a timeout: recorded as not answered, never as an answer
            answers[q] = {"question": q, "unavailable": f"{type(e).__name__}: {e}"[:300]}
    rec = {"run": run.id, "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "answers": answers}
    p = recording_path(run.var, run.id)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(rec, indent=1))
    varmode.private(p)
    return rec
