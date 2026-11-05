"""Ask the field notes: a question about the project's own journal — its notes, lessons and how-it-works
pages — answered from the built site's sections, citing passages by number, every citation checked.

The same shape as Ask the CBOM (pqch.ask), on different material: the site's search index
(`site/search/search_index.json`, one entry per page section, written by mkdocs) is the corpus; the
`embed` tier retrieves the sections nearest the question; the `deliberate` tier answers from the
passages it was shown and nothing else; a rule then checks that every passage it cites was shown.
Nothing is written to a ledger: a question about the notes is not an event of any estate.
"""
from __future__ import annotations

import hashlib
import html
import json
import math
import re
from pathlib import Path

TOP_K = 8
ROLE = "ask-notes"   # bound to a tier in the inference config, like every role; code never chooses
SCHEMA = {
    "type": "object",
    "properties": {
        "answer": {"type": "string"},
        "citations": {"type": "array", "items": {"type": "integer", "minimum": 1}},
        "not_in_passages": {"type": "boolean"},
    },
    "required": ["answer", "citations", "not_in_passages"],
}
SYSTEM = (
    "You answer questions about the cbom-workbench project from its field notes: the journal's notes, lessons, "
    "how-it-works pages and sources. You are shown numbered passages from those pages. Answer only from the "
    "passages; cite each fact by passage number in `citations`; if the passages do not answer the question, say so "
    "in `answer` and set `not_in_passages` true. Write plainly, at most 120 words, no preamble. "
    "Reply as JSON: {\"answer\": string, \"citations\": [passage numbers], \"not_in_passages\": boolean}."
)

_TAG = re.compile(r"<[^>]+>")


def passages(site: Path) -> list[dict]:
    """One passage per site section with text, from mkdocs' search index; the page title carried along."""
    data = json.loads((site / "search" / "search_index.json").read_text())
    out, page_title = [], {}
    for d in data.get("docs", []):
        loc = d.get("location") or ""
        page = loc.split("#")[0]
        if "#" not in loc:
            page_title[page] = d.get("title") or page
    for d in data.get("docs", []):
        loc = d.get("location") or ""
        text = html.unescape(_TAG.sub(" ", d.get("text") or ""))
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) < 40:
            continue
        page = loc.split("#")[0]
        out.append({"n": len(out) + 1, "location": loc, "page": page_title.get(page, page or "home"),
                    "title": d.get("title") or "", "text": text[:1400]})
    return out


def _cos(a: list[float], b: list[float]) -> float:
    num = sum(x * y for x, y in zip(a, b))
    da, db = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return num / (da * db) if da and db else 0.0


class Index:
    """The site's passages and their embeddings, cached in the run store: the site changes only when
    it is rebuilt, and the cache is keyed by its text."""

    def __init__(self, seam, site: Path, var: Path):
        self.seam = seam
        self.passages = passages(site)
        self.path = Path(var) / "runs" / "notes-ask-index.json"
        key = hashlib.sha256(json.dumps([p["text"] for p in self.passages]).encode()).hexdigest()
        tier = seam.config["tiers"].get("embed") or {}
        self.model, self.hardware = tier.get("model", ""), tier.get("hardware", "")
        self.key = key
        self.vectors = None
        if self.path.exists():
            try:
                cached = json.loads(self.path.read_text())
                if cached.get("key") == key and cached.get("model") == self.model:
                    self.vectors = cached["vectors"]
            except Exception:
                self.vectors = None
        if self.vectors is None:
            self.vectors = []
            for i in range(0, len(self.passages), 32):
                self.vectors += seam.embed("embed", [f"{p['page']} — {p['title']}. {p['text']}" for p in self.passages[i:i + 32]], purpose="passage")
            self.path.write_text(json.dumps({"key": key, "model": self.model, "vectors": self.vectors}))

    def retrieve(self, question: str, k: int = TOP_K) -> list[dict]:
        q = self.seam.embed("embed", [question], purpose="query")[0]
        scored = sorted(((_cos(q, v), p) for v, p in zip(self.vectors, self.passages)), key=lambda x: -x[0])
        shown, seen = [], set()
        for s, p in scored:
            if p["location"] in seen:
                continue
            seen.add(p["location"])
            shown.append({**p, "score": round(s, 4)})
            if len(shown) >= k:
                break
        for i, p in enumerate(shown, 1):
            p["shown_as"] = i
        return shown


def _messages(question: str, shown: list[dict]) -> list[dict]:
    body = "\n\n".join(f"[{p['shown_as']}] {p['page']} — {p['title']}\n{p['text']}" for p in shown)
    return [{"role": "system", "content": SYSTEM},
            {"role": "user", "content": f"Passages:\n\n{body}\n\nQuestion: {question}"}]


def check(reply: dict, shown: list[dict]) -> dict:
    valid = {p["shown_as"] for p in shown}
    cites = [c for c in (reply.get("citations") or []) if isinstance(c, int)]
    rows = [{"n": c, "shown": c in valid, "passage": next((p for p in shown if p["shown_as"] == c), None)} for c in cites]
    ok = bool(rows) and all(r["shown"] for r in rows) and not reply.get("not_in_passages")
    return {"rows": rows, "ok": ok, "declined": bool(reply.get("not_in_passages")),
            "verdict": "Every citation is a passage the model was shown." if ok else
                       ("The model says the passages do not answer this." if reply.get("not_in_passages") else
                        "A citation names a passage the model was not shown: treat the answer as unsupported." if rows else "No passages cited.")}


def ask(seam, index: Index, question: str) -> dict:
    shown = index.retrieve(question)
    c = seam.complete_role(ROLE, _messages(question, shown), schema=SCHEMA, max_tokens=20000, purpose="ask-notes")
    reply = c.parsed if isinstance(c.parsed, dict) else {"answer": (c.text or "").strip(), "citations": [], "not_in_passages": True}
    return {"question": question, "shown": shown, "reply": reply, "check": check(reply, shown),
            "model": c.model, "tier": c.tier, "hardware": c.hardware, "latency_ms": c.latency_ms, "reasoning": c.reasoning,
            "finish_reason": c.finish_reason, "completion_tokens": (c.usage or {}).get("completion_tokens"),
            "embed_model": index.model, "embed_hardware": index.hardware, "corpus": len(index.passages)}
