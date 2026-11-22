"""The investigator: a model traces a wire finding to the configuration line that causes it.

Spike S3's role R5 (`trace-to-cause`) measured this as the one role that needs
the large model; the spike's call handed the model every file at once. This is
the loop M1 builds around that call: the model works over the service's
configuration directory with three typed tools — list, read a range of lines,
grep — under a step budget and a token budget, and ends with an answer: the
file and line range that set the behaviour, or `cause: default` when no live
line does. No shell: each tool is a fixed function over the files the scope's
estate was built from, and the model's text never reaches a command line. The
grep's pattern is the model's, and Python's matcher has no time limit of its own,
so the search runs in a child process that is ended at a deadline (the pattern
goes to it on standard input, as data). A trace has a wall-clock budget beside its
step and token budgets, and a call that gets no reply ends it as `no-answer`, on
the record, with the run still closed and signed.

What it records is a claim, labelled as the model's: the `trace.completed`
event carries the engine, its settings (tier, reasoning, the model id the
endpoint reported and the upstream that served it), every step with its
latency and token usage, the budgets and what was used, the measured total
time, and the answer, with `answer_lines_seen`: whether every line the answer
names was in a result the model was shown (a rule's check of "name a line only
after you have read it"). The answer settles nothing by itself. When the answer key
names the cause of the finding (`trace: {path, contains}`), the event also says
whether the model's line agrees with the key — a check against a written
answer, not a verification on the wire. A trace never changes an assessment,
a link or a verdict.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

from pqch import inference, schemas
from pqch import scope as scope_mod
from pqch.common import sha256_hex
from pqch.run import Run

ROLE = "trace-to-cause"
PURPOSE = "trace-to-cause"
EVENT = "trace.completed"
MAX_READ_LINES = 120
MAX_GREP_HITS = 40
MAX_RESULT_CHARS = 12000
GREP_TIMEOUT_S = 5          # a pattern that has not finished by then is ended and reported to the model
TIME_BUDGET_S = 1800        # one trace's wall clock, beside its step and token budgets
# The grep, as the child process runs it: the pattern and the files arrive as JSON on standard input.
_GREP_CHILD = """
import json, re, sys
job = json.load(sys.stdin)
try:
    rx = re.compile(job["pattern"], re.I)
except re.error as err:
    json.dump({"error": "bad pattern: %s" % err}, sys.stdout); sys.exit(0)
hits = []
for rel, path in job["files"]:
    with open(path, errors="replace") as f:
        for i, line in enumerate(f.read().splitlines(), 1):
            if rx.search(line):
                hits.append([rel, i, line.strip()])
                if len(hits) >= job["max_hits"]:
                    json.dump({"hits": hits, "stopped": True}, sys.stdout); sys.exit(0)
json.dump({"hits": hits}, sys.stdout)
"""
# The reply cap per step. On an engine with reasoning on, its thinking tokens count against this;
# spike S3 ran the single-call trace at 16,000, and a 4,000 cap returned an empty reply once.
MAX_REPLY_TOKENS = 16000
TEXT_SUFFIXES = {".conf", ".config", ".xml", ".sh", ".yaml", ".yml", ".json", ".ini", ".cfg", ".txt",
                 ".properties", ".disabled", ".env", ".toml", ""}
TEXT_NAMES = {"Dockerfile", "sshd_config", "ssh_config", "pg_hba.conf", "postgresql.conf", "nginx.conf"}

SCHEMA = {
    "type": "object",
    "required": ["action"],
    "properties": {
        "action": {"enum": ["read", "grep", "answer"]},
        "path": {"type": "string"},
        "start": {"type": "integer", "minimum": 1},
        "end": {"type": "integer", "minimum": 1},
        "pattern": {"type": "string", "maxLength": 200},
        "file": {"type": ["string", "null"]},
        "line_start": {"type": ["integer", "null"]},
        "line_end": {"type": ["integer", "null"]},
        "cause": {"enum": ["default", None]},
        "note": {"type": "string", "maxLength": 400},
    },
    "additionalProperties": False,
}

SYSTEM = """You trace one wire finding about a service to the configuration line that causes it. You work over the service's build directory with three tools and must end with an answer.

Tools, one per reply, as JSON only:
- {"action": "read", "path": "<file>", "start": <line>, "end": <line>}  — numbered lines of one file (at most 120 per call; omit start and end for the first 120).
- {"action": "grep", "pattern": "<regex>"}  — matching lines across every file, as file:line: text.
- {"action": "answer", "file": "<file>", "line_start": <n>, "line_end": <n>}  — the one directive that sets the behaviour in the finding; or {"action": "answer", "cause": "default", "file": null, "line_start": null, "line_end": null} when no live line sets it and the software's default does.
You may add a short "note" to any reply.

Rules.
- A commented-out line sets nothing. A file that is not loaded sets nothing. A file included by another file is loaded; a Dockerfile shows which files reach the image and where.
- When a setting appears more than once, name the occurrence that takes effect, by the software's own precedence.
- A line that only removes or restricts other values does not cause a value that the default supplies.
- Name a line only after you have read it. Do not guess.
- You have a budget of steps and tokens; it is stated below and in every tool result. Answer before it runs out."""


def files_for(agency_dir: Path, service: str) -> list[Path]:
    """The text files a service was built from: its build context and its rendered policy directory."""
    out = []
    for base in (agency_dir / service, agency_dir / "generated" / service):
        if not base.is_dir():
            continue
        root = base.resolve()
        for p in sorted(base.rglob("*")):
            # A link is read only when it stays inside the service's own directory: one that points out of it
            # would hand the model a file the service was not built from.
            if p.is_symlink() and not p.resolve().is_relative_to(root):
                continue
            if p.is_file() and (p.suffix in TEXT_SUFFIXES or p.name in TEXT_NAMES) and p.stat().st_size <= 200_000:
                out.append(p)
    return out


class Workspace:
    """The three tools over a fixed set of files. Paths are shown and taken relative to the agency dir."""

    def __init__(self, agency_dir: Path, service: str):
        self.agency_dir = Path(agency_dir)
        self.service = service
        self.files = {str(p.relative_to(self.agency_dir.parent)) if self.agency_dir.name == "agency"
                      else str(p.relative_to(self.agency_dir)): p for p in files_for(self.agency_dir, service)}
        # Every line a tool result has shown, by file: what "read before you name it" is checked against.
        self.seen: dict[str, set[int]] = {}

    def listing(self) -> str:
        rows = []
        for rel, p in self.files.items():
            text = p.read_text(errors="replace")
            rows.append(f"{rel}  ({len(text.splitlines())} lines)")
        return "\n".join(rows) if rows else "(no files)"

    def manifest(self) -> list[dict]:
        return [{"path": rel, "sha256": sha256_hex(p.read_bytes())} for rel, p in self.files.items()]

    def read(self, path: str, start: int | None, end: int | None) -> str:
        p = self.files.get(path)
        if p is None:
            return f"error: no such file {path!r}; the files are:\n" + self.listing()
        lines = p.read_text(errors="replace").splitlines()
        s = max(1, start or 1)
        e = min(len(lines), end or (s + MAX_READ_LINES - 1), s + MAX_READ_LINES - 1)
        if s > len(lines):
            return f"error: {path} has {len(lines)} lines"
        self.seen.setdefault(path, set()).update(range(s, e + 1))
        return "\n".join(f"{i:4d}  {lines[i - 1]}" for i in range(s, e + 1)) + \
            (f"\n(… {len(lines) - e} more lines)" if e < len(lines) else "")

    def grep(self, pattern: str, *, timeout_s: float = GREP_TIMEOUT_S) -> str:
        """The model's pattern over every file, in a child process ended at `timeout_s`: `(a+)+$` against one
        long line would otherwise hold the trace, and whatever called it, for good."""
        job = json.dumps({"pattern": pattern, "files": [[rel, str(p)] for rel, p in self.files.items()],
                          "max_hits": MAX_GREP_HITS})
        try:
            r = subprocess.run([sys.executable, "-I", "-c", _GREP_CHILD], input=job, capture_output=True, text=True,
                               timeout=timeout_s)
            out = json.loads(r.stdout)
        except subprocess.TimeoutExpired:
            return (f"error: the pattern did not finish in {timeout_s:g} s and was stopped; "
                    "use a simpler pattern (no repeated group inside a repeated group)")
        except (OSError, ValueError):
            return "error: the search could not be run"
        if "error" in out:
            return f"error: {out['error']}"
        for rel, i, _ in out["hits"]:
            self.seen.setdefault(rel, set()).add(i)
        hits = [f"{rel}:{i}: {text}" for rel, i, text in out["hits"]]
        if out.get("stopped"):
            return "\n".join(hits) + f"\n(stopped at {MAX_GREP_HITS} hits)"
        return "\n".join(hits) if hits else "(no match)"

    def lines_seen(self, path: str, start: int, end: int) -> bool:
        """Whether every line of a range was in a read or grep result."""
        return 1 <= start <= end and set(range(start, end + 1)) <= self.seen.get(path, set())

    def line_text(self, path: str, start: int, end: int) -> str | None:
        p = self.files.get(path)
        if p is None:
            return None
        lines = p.read_text(errors="replace").splitlines()
        if not (1 <= start <= end <= len(lines)):
            return None
        return "\n".join(lines[start - 1:end])


def key_check(key: dict | None, finding: dict, answer: dict | None, line_text: str | None) -> dict | None:
    """Whether the model's line agrees with the answer key's `trace` for the item this finding matches.
    None when the key names no cause for it. A check against a written answer, not a verification."""
    if key is None or answer is None:
        return None
    from pqch.score import matches

    comp = {"layer": finding["layer"], "subject": finding["subject"], "type": finding["asset"]["type"],
            "role": finding["asset"]["role"], "name": finding["asset"]["name"],
            "parameters": finding["asset"].get("parameters", {})}
    item = next((i for i in key.get("items", []) if i.get("trace") and matches(i, comp)), None)
    if item is None:
        return None
    want = item["trace"]
    if want.get("cause") == "default":
        agrees = answer.get("cause") == "default"
        return {"item": item["id"], "agrees": agrees, "key": want,
                "why": "" if agrees else "the key says no live line sets it; the model named a line"}
    if answer.get("cause") == "default":
        return {"item": item["id"], "agrees": False, "key": want, "why": "the key names a line; the model said default"}
    agrees = answer.get("file") == want["path"] and bool(line_text) and want["contains"] in line_text
    return {"item": item["id"], "agrees": agrees, "key": want,
            "why": "" if agrees else ("another file than the key names" if answer.get("file") != want["path"]
                                      else f"the lines do not contain {want['contains']!r}")}


def trace(run: Run, scan_run: Run, finding_event: dict, *, agency_dir: Path, seam: inference.Seam | None = None,
          step_budget: int = 8, token_budget: int = 60000, key: dict | None = None,
          time_budget_s: float = TIME_BUDGET_S) -> dict:
    """Trace one wire finding to its cause and record the `trace.completed` event on `run`. A call that
    gets no reply (the engine down, a timeout, the role unbound) is the trace's last step and its outcome
    is `no-answer`: recorded, never raised, so the run it is in is still closed."""
    s = seam or inference.default()
    f = finding_event["payload"]
    scope = next(iter(scan_run.ledger.events()))["payload"]["scope"]
    ep = scope_mod.endpoint(scope, f["subject"]["host"], f["subject"]["port"]) or {}
    service = ep.get("service")
    if not service:
        raise ValueError(f"the scope names no service for {f['subject']['host']}:{f['subject']['port']}")
    ws = Workspace(Path(agency_dir), service)
    finding_text = json.dumps({"subject": f["subject"], "asset": f["asset"], "evidence": f["evidence"]["excerpt"],
                               "tool": f"{f['source']['tool']} {f['source']['version']}"}, indent=1)
    budget_line = lambda used_steps, used_tokens: (  # noqa: E731
        f"[budget: {step_budget - used_steps} of {step_budget} steps left, "
        f"{max(0, token_budget - used_tokens)} of {token_budget} tokens left]")
    messages = [{"role": "system", "content": SYSTEM},
                {"role": "user", "content": f"Service: {service}\n\nFinding:\n{finding_text}\n\nFiles:\n{ws.listing()}\n\n"
                                            + budget_line(0, 0)}]
    steps, used_tokens, outcome, answer, last = [], 0, "budget-exhausted", None, None
    started = time.monotonic()
    for n in range(step_budget):
        if time.monotonic() - started > time_budget_s:
            steps.append({"n": n + 1, "action": "invalid", "error": f"the trace's time budget of {round(time_budget_s)} s ran out"})
            outcome = "budget-exhausted"
            break
        try:
            c = s.complete_role(ROLE, messages, schema=SCHEMA, max_tokens=MAX_REPLY_TOKENS, purpose=PURPOSE)
        except inference.TierUnavailable as e:
            # No reply at all. The seam's own words only: an HTTP error's text carries the gateway's URL.
            steps.append({"n": n + 1, "action": "invalid", "error": inference.failure_text(e)})
            outcome = "no-answer"
            break
        except inference.SchemaViolation as e:
            # The reply cap counts the engine's reasoning tokens too: a step that thinks long can
            # return no content at all. Record what the endpoint said about why.
            raw = getattr(e, "raw", None) or {}
            choice = (raw.get("choices") or [{}])[0]
            usage = raw.get("usage") or {}
            steps.append({"n": n + 1, "action": "invalid", "error": str(e)[:300],
                          "finish_reason": choice.get("finish_reason"),
                          "tokens": usage.get("total_tokens"), "completion_tokens": usage.get("completion_tokens")})
            used_tokens += int(usage.get("total_tokens") or 0)
            outcome = "schema-failure"
            break
        last = c
        used_tokens += int(c.usage.get("total_tokens") or 0)
        step = {"n": n + 1, "action": c.parsed["action"], "latency_ms": c.latency_ms,
                "tokens": int(c.usage.get("total_tokens") or 0), "finish_reason": c.finish_reason}
        if c.parsed.get("note"):
            step["note"] = c.parsed["note"][:400]
        messages.append({"role": "assistant", "content": c.text})
        if c.parsed["action"] == "answer":
            answer = {k: c.parsed.get(k) for k in ("file", "line_start", "line_end", "cause")}
            steps.append({**step, "answer": answer})
            outcome = "answered"
            break
        if c.parsed["action"] == "read":
            step.update(path=c.parsed.get("path"), start=c.parsed.get("start"), end=c.parsed.get("end"))
            result = ws.read(c.parsed.get("path", ""), c.parsed.get("start"), c.parsed.get("end"))
        else:
            step.update(pattern=c.parsed.get("pattern", ""))
            result = ws.grep(c.parsed.get("pattern", ""))
        result = result[:MAX_RESULT_CHARS]
        step["result_chars"] = len(result)
        steps.append(step)
        if used_tokens >= token_budget:
            outcome = "budget-exhausted"
            break
        messages.append({"role": "user", "content": result + "\n\n" + budget_line(n + 1, used_tokens)})
    total_ms = round((time.monotonic() - started) * 1000)
    line_text, lines_seen = None, None
    if answer and answer.get("file") and answer.get("line_start") and answer.get("line_end"):
        line_text = ws.line_text(answer["file"], answer["line_start"], answer["line_end"])
        # By rule, not by the model's word: were the lines it names in a result it was shown?
        lines_seen = ws.lines_seen(answer["file"], answer["line_start"], answer["line_end"])
    actor = last.actor() if last else {"kind": "model", "id": "none", "tier": "none", "model": "none", "hardware": "none"}
    payload = {
        "finding": {"run": scan_run.id, "event": finding_event["id"], "fingerprint": f["fingerprint"],
                    "subject": f["subject"], "asset": f["asset"]},
        "service": service, "files": ws.manifest(),
        "budget": {"steps": step_budget, "tokens": token_budget}, "time_budget_s": round(time_budget_s),
        "used": {"steps": len(steps), "tokens": used_tokens},
        "settings": {"role": ROLE, "tier": actor.get("tier"), "reasoning": bool(actor.get("reasoning")),
                     "model": actor.get("model"), "served_by": actor.get("served_by"), "hardware": actor.get("hardware"),
                     "engine": actor.get("engine")},
        "steps": steps, "answer": answer, "line_text": line_text, "answer_lines_seen": lines_seen,
        "outcome": outcome, "latency_ms": total_ms,
        "key_check": key_check(key, f, answer, line_text),
        "claim": "the model's; settles nothing by itself",
    }
    return run.ledger.append(EVENT, actor, payload)


def pick_findings(scan_events: list[dict], *, one_per_listener: bool = True, finding_ids: list[str] | None = None,
                  only_fingerprints: set[str] | None = None) -> list[dict]:
    """Which wire findings to trace: named ones, or one key-establishment finding per bound listener,
    the classical one first where the listener has both."""
    findings = [e for e in scan_events if e["type"] == "finding.observed" and e["payload"]["layer"] == "wire"
                and e["payload"]["subject"]["kind"] == "endpoint"]
    if finding_ids:
        return [e for e in findings if e["id"] in set(finding_ids)]
    bound = {(e["payload"]["subject"]["host"], e["payload"]["subject"]["port"]) for e in scan_events
             if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "binding/scope/1"
             and e["payload"]["classification"]["bound"]}
    pq = set()
    for e in scan_events:
        if e["type"] == "assessment.made" and e["payload"].get("rule_id") == "posture/kex-auth/1":
            pq.update(e["payload"]["classification"].get("kex_pq", []))
    out, seen = [], set()
    for e in sorted(findings, key=lambda e: (e["payload"]["subject"]["host"], e["payload"]["subject"]["port"],
                                              e["payload"]["asset"]["name"] in pq, e["payload"]["asset"]["name"])):
        f = e["payload"]
        k = (f["subject"]["host"], f["subject"]["port"])
        if f["asset"]["role"] != "key-establishment" or k not in bound or (one_per_listener and k in seen):
            continue
        if only_fingerprints is not None and f["fingerprint"] not in only_fingerprints:
            continue
        seen.add(k)
        out.append(e)
    return out


def investigate(var: Path, scan_run: Run, *, agency_dir: Path, signer=None, seam: inference.Seam | None = None,
                finding_ids: list[str] | None = None, step_budget: int = 8, token_budget: int = 60000,
                key_path: Path | None = None, progress=None,
                only_fingerprints: set[str] | None = None) -> tuple[Run, list[dict]]:
    """A run of kind `investigate` over one scan run: one trace per chosen finding, then closed. The run
    is closed whatever a trace does; once one trace gets no reply the rest are not started (an engine that
    is down is not asked again for every finding)."""
    import yaml

    scan_events = list(scan_run.ledger.events())
    scope = scan_events[0]["payload"]["scope"]
    schemas.validate(scope)
    key = yaml.safe_load(Path(key_path).read_text()) if key_path and Path(key_path).is_file() else None
    events = []
    run = None
    picked = pick_findings(scan_events, finding_ids=finding_ids, only_fingerprints=only_fingerprints)
    if not picked:
        return None, []
    run = Run.start(var, scope, runner_scope_hash=scope_mod.scope_hash(scope), profile="trace-to-cause",
                    kind="investigate", runner_id="pqch-investigator")
    try:
        for fe in picked:
            ev = trace(run, scan_run, fe, agency_dir=agency_dir, seam=seam, step_budget=step_budget,
                       token_budget=token_budget, key=key)
            events.append(ev)
            if progress:
                progress(ev)
            if ev["payload"]["outcome"] == "no-answer":
                break
    finally:
        run.close(signer)
    return run, events
