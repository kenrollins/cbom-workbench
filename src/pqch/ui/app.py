"""The one page: the spreadsheet, the scan button, the CBOM with its evidence, the score.

Server-rendered; the stylesheet and script are vendored in `static/`. The
service holds no Docker socket: a scan is a sequence of jobs sent to the runner
over its Unix socket.
"""

from __future__ import annotations

import os
import threading
import traceback
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from pqch.run import Run
from pqch.ui.view import capture_view, change_view, estate_graph, receipts_view, run_view

# The spreadsheet the opening starts from: hand-kept rows, two of them for systems the estate does not have, and none for four services it does.
# `service` names the estate service a row is really about, so the estate map can show which rows have evidence.
SHEET = [
    {"system": "Benefits portal", "says": "HTTPS, \"SSL cert renewed\"", "owner": "Web team", "service": "portal"},
    {"system": "Partner API", "says": "TLS, \"ECC?\"", "owner": "Integration", "service": "api"},
    {"system": "Records SFTP drop", "says": "SSH", "owner": "Records office", "service": "sftp-legacy"},
    {"system": "Admin jump host", "says": "SSH keys", "owner": "Operations", "service": "bastion"},
    {"system": "Mail relay", "says": "STARTTLS", "owner": "Operations", "service": None},
    {"system": "Site-to-site VPN", "says": "IPsec, \"AES\"", "owner": "Network", "service": None},
]

# The clock the work runs against: the dated federal requirements, each cited in BRIEF.md's facts table.
# `key` marks the date that shapes the design: the minimum elements of a CBOM are not published yet.
CLOCK = [
    {"date": "2026-06-22", "label": "EO 14412 signed", "source": "Executive Order 14412"},
    {"date": "2026-10-22", "label": "agency PQC migration plans due", "source": "OMB M-26-15 §1, 120 days"},
    {"date": "2027-01-01", "label": "new NSS acquisitions CNSA 2.0", "source": "NSA CNSA 2.0 FAQ, through secondary summaries; the primary was not read"},
    {"date": "2027-03-19", "label": "CBOM minimum elements published by CISA and NIST", "source": "EO 14412, 270 days", "key": True},
    {"date": "2030-01-02", "label": "TLS 1.3 everywhere", "source": "OMB M-26-15 §4"},
    {"date": "2030-12-31", "label": "PQ key establishment, prioritized systems", "source": "EO 14412; M-26-15 phase 3"},
    {"date": "2031-12-31", "label": "PQ signatures, prioritized systems", "source": "EO 14412; M-26-15 phase 4"},
    {"date": "2035-12-31", "label": "full migration", "source": "OMB M-26-15 phase 5"},
]

HERE = Path(__file__).parent
VAR = Path(os.environ.get("PQCH_VAR", "var"))
KEY = Path(os.environ.get("PQCH_KEY", "agency/answer-key.yaml"))
SOCKET = os.environ.get("PQCH_RUNNER_SOCKET", "/run/pqch/runner.sock")
POLICY = Path(os.environ.get("PQCH_CRYPTO_POLICY", "policy/crypto-policy.yaml"))
AGENCY = Path(os.environ.get("PQCH_AGENCY_DIR", "agency"))
HARDWARE = os.environ.get("PQCH_HARDWARE", "unlabelled")
PROJECTIONS = Path(os.environ.get("PQCH_PROJECTIONS", "policy/projections"))
DOWNLOADS = {"ledger.jsonl", "workbench.cdx.json", "baseline-cbomkit.cdx.json",
             "baseline-scanners.cdx.json", "score.json"}

app = FastAPI(title="cbom-workbench", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
# The built journal site (mkdocs build), when a deployment mounts it: served behind the same door
# as the page, at /site/. Nothing in the application depends on it being there.
SITE = Path(os.environ.get("PQCH_SITE_DIR", "/app/site"))


class _Revalidated(StaticFiles):
    """Static files the browser must check again on every visit (the ETag makes that cheap). Without
    a Cache-Control, Firefox keeps a page a tenth of its age, so a site rebuilt under a page days old
    is not seen for hours: the header changed on the demo and stayed old in the notes (2026-11-05)."""

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


if SITE.is_dir():
    app.mount("/site", _Revalidated(directory=SITE, html=True), name="site")
# A preview of the public, static demo (tools/build_public.py --base /preview/), when a deployment
# mounts one: reviewed behind the same door before anything is published.
PREVIEW = Path(os.environ.get("PQCH_PREVIEW_DIR", "/app/preview"))
if PREVIEW.is_dir():
    app.mount("/preview", _Revalidated(directory=PREVIEW, html=True), name="preview")
templates = Jinja2Templates(directory=HERE / "templates")
# Under "Demo" in the header: "live" when this app serves the pages; a static copy sets another word.
templates.env.filters["first_up"] = lambda s: s[:1].upper() + s[1:] if s else s
# The estate's service count, from its own description, and the ledger's signature algorithm, from the signer:
# the pages name both in prose and never carry the number or the name typed by hand.
from pqch.signer import ALG as _SIG_ALG  # noqa: E402

templates.env.globals["sig_alg"] = _SIG_ALG


def _estate_services() -> int | None:
    try:
        import yaml

        return len(yaml.safe_load((AGENCY / "about.yaml").read_text())["services"])
    except Exception:
        return None


templates.env.globals["estate_services"] = _estate_services()
templates.env.filters["words"] = lambda n: ["no", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven", "twelve"][n] if isinstance(n, int) and 0 <= n <= 12 else str(n if n is not None else "?")
templates.env.globals["demo_mode"] = os.environ.get("PQCH_DEMO_MODE", "live")


def _journal_span() -> str:
    """The first and latest journal entry's dates, as tools/build_site.py wrote them into the built
    site; a static build passes them in PQCH_JOURNAL_SPAN instead; blank where neither is there."""
    if os.environ.get("PQCH_JOURNAL_SPAN"):
        return os.environ["PQCH_JOURNAL_SPAN"].strip()
    try:
        return (Path(os.environ.get("PQCH_SITE_DIR", "site")) / "journal-span.txt").read_text().strip()
    except OSError:
        return ""


templates.env.globals["journal_span"] = _journal_span()
# Public: the mini-agency only, read-only. No lab page, link or data; no scan, propose or approve.
# Set for the static build published on GitHub Pages (tools/build_public.py).
PUBLIC = os.environ.get("PQCH_PUBLIC") == "1"
templates.env.globals["public"] = PUBLIC
# "The lab" is a tab only where there is one: a capture or an external scan in the run store. On a box
# with neither (the demo box, 2026-11-04) the tab is absent. Hosts has no tab of its own: the estate
# switcher on the CBOM, plan and overview pages reaches it (2026-11-09).
templates.env.globals["lab_shown"] = lambda: bool(Run.latest(VAR, "capture") or Run.latest(VAR, "scan-external"))
# The lab portal's address(es), allowed to read the VLAN-level summary (/lab/estate.json) and
# nothing else of the lab. Empty means only a signed-on viewer through the front door may.
ESTATE_READERS = {a.strip() for a in os.environ.get("PQCH_ESTATE_READERS", "").split(",") if a.strip()}
LAB_KINDS = ("capture", "scan-external", "scan-system")


def lab_viewer(request: Request) -> bool:
    """The lab's pages and files answer only to a signed-on viewer arriving through the front door:
    not public, a trusted-proxy peer, and the sign-on header set. Anything else is 404, the same as
    public mode — the lab is not acknowledged to a peer on the DMZ network that typed the address."""
    return not PUBLIC and identity(request) is not None


def _lab_or_404(request: Request) -> None:
    if not lab_viewer(request):
        raise HTTPException(404)


def _lab_run(run_id: str) -> bool:
    """True for a run that is the lab's — or one whose kind cannot be read, which is not shown either:
    a run directory with a damaged or missing ledger fails closed, not open."""
    if not run_id.isalnum() or not (VAR / "runs" / run_id).is_dir():
        return False
    return _run_kind(run_id) in (*LAB_KINDS, None)


def _refuse_lab_run(request: Request, run_id: str | None) -> None:
    if run_id is not None and _lab_run(run_id) and not lab_viewer(request):
        raise HTTPException(404)


def _run_kind(run_id: str) -> str | None:
    """A run's kind from its first event alone, or None when there is no such run."""
    led = VAR / "runs" / run_id / "ledger.jsonl"
    if not run_id.isalnum() or not led.is_file():
        return None
    try:
        import json as _json

        with led.open(encoding="utf-8") as f:
            return (_json.loads(f.readline() or "{}").get("payload") or {}).get("kind", "scan")
    except (OSError, ValueError):
        return None


@app.on_event("startup")
def _warm() -> None:
    """Build the lab's views once in the background at start, so the first visitor to the lab does not
    wait for the capture's ledger to be read. A failure only means the first visit builds them."""
    def go():
        try:
            cr, sr = Run.latest(VAR, "capture"), Run.latest(VAR, "scan-external")
            cr = cr if cr and cr.ledger.exists() else None
            sr = sr if sr and sr.ledger.exists() else None
            if cr:
                _capture_cached(cr)
            _house_cached(cr, sr)
        except Exception:
            traceback.print_exc()
    threading.Thread(target=go, daemon=True).start()


class ScanState:
    def __init__(self):
        self.lock = threading.Lock()
        self.running = False
        self.lines: list[dict] = []
        self.error: str | None = None
        self.run_id: str | None = None

    def snapshot(self) -> dict:
        with self.lock:
            return {"running": self.running, "lines": list(self.lines), "error": self.error,
                    "run": self.run_id}


state = ScanState()


def _scan_thread(host: str) -> None:
    from pqch.pipeline import run_once
    from pqch.runner.client import RunnerClient

    def progress(line: dict) -> None:
        with state.lock:
            state.lines.append(line)

    try:
        run, _ = run_once(VAR, RunnerClient(SOCKET), KEY, host=host, progress=progress)
        with state.lock:
            state.run_id = run.id
    except Exception as e:
        with state.lock:
            state.error = f"{type(e).__name__}: {e}"
        traceback.print_exc()
    finally:
        with state.lock:
            state.running = False


@app.get("/")
def overview(request: Request, estate: str = "mini-agency"):
    """The first page: NIST's crypto-agility plan (CSWP 39-upd1, Fig. 3), each part filled with what
    this workbench does there for one estate, read from the ledgers."""
    from pqch.ui import agility

    if estate not in ("mini-agency", "lab") or (estate == "lab" and not lab_viewer(request)):
        raise HTTPException(404)
    if estate == "lab":
        cr, sr = Run.latest(VAR, "capture"), Run.latest(VAR, "scan-external")
        cr, sr = (cr if cr and cr.ledger.exists() else None), (sr if sr and sr.ledger.exists() else None)
        a = agility.build("lab", VAR, _capture_cached(cr) if cr else None, run_view(sr) if sr else None,
                          _house_cached(cr, sr))
    else:
        a = agility.build("mini-agency", VAR)
    return templates.TemplateResponse(request, "overview.html", {"a": a, "hardware": HARDWARE})


@app.get("/about")
def about(request: Request):
    """What the project is and is not, and the disclaimer: the field notes' About in the demo's theme."""
    return templates.TemplateResponse(request, "about.html", {})


@app.get("/agency")
def agency(request: Request):
    """The test agency at a glance: what the mini-agency is, its services and what was planted in each."""
    from pqch.ui import estate

    return templates.TemplateResponse(request, "agency.html", {"e": estate.build(AGENCY, KEY)})


@app.get("/hosts")
def hosts_page(request: Request):
    """Servers scanned as estates: each one's latest system scan, its parts, and links to its CBOM and plan."""
    from pqch.systems import hosts

    _lab_or_404(request)
    lab = Run.latest(VAR, "scan-external")
    return templates.TemplateResponse(request, "hosts.html", {"hosts": hosts(VAR),
                                                              "lab_run": lab.id if lab and lab.ledger.exists() else None})


@app.get("/plan")
def plan_page(request: Request, estate: str = "mini-agency", assume: str = "", run: str | None = None):
    """The plan the CBOM makes possible: what depends on what, what comes first, in what order."""
    from pqch import planning

    if estate not in ("mini-agency", "lab", "system") or (estate in ("lab", "system") and not lab_viewer(request)):
        raise HTTPException(404)
    # What-if: steps taken as done, named in the address; nothing is written anywhere.
    assumed = frozenset(a for a in assume.split(",") if a)
    if estate == "system":
        if run is not None and (not run.isalnum() or _run_kind(run) != "scan-system"):
            raise HTTPException(404)
        sr = Run(VAR, run) if run else Run.latest(VAR, "scan-system")
        from pqch import attest

        plan = planning.system_build(sr, assume=assumed,
                                     pack_path=Path(os.environ.get("PQCH_PACKS", "policy/packs")) / "m-26-15.yaml",
                                     cnsa_path=Path(os.environ.get("PQCH_PACKS", "policy/packs")) / "cnsa-2.0.yaml",
                                     attestation=attest.for_system(VAR, list(sr.ledger.events()))) \
            if sr and sr.ledger.exists() else None
        return templates.TemplateResponse(request, "plan.html", {"plan": plan, "estate": "system", "sheet": None, "sheet_rows": [],
                                                                 "system_run": sr.id if plan else None})
    if estate == "lab":
        cr, sr = Run.latest(VAR, "capture"), Run.latest(VAR, "scan-external")
        cr, sr = (cr if cr and cr.ledger.exists() else None), (sr if sr and sr.ledger.exists() else None)
        plan = planning.lab_build(_capture_cached(cr) if cr else None, _house_cached(cr, sr), assume=assumed)
        return templates.TemplateResponse(request, "plan.html", {"plan": plan, "estate": "lab", "sheet": None, "sheet_rows": []})
    r = Run.latest(VAR, "scan")
    plan = planning.build(VAR, r, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots")),
                          assume=assumed) if r and r.ledger.exists() else None
    sheet = {"rows": len(SHEET), "ghosts": sum(1 for x in SHEET if not x["service"])}
    return templates.TemplateResponse(request, "plan.html", {"plan": plan, "estate": "mini-agency", "sheet": sheet, "sheet_rows": SHEET})


@app.get("/estate/cbom.json")
def estate_cbom(request: Request, runs: str = ""):
    """One CBOM over the named runs (M9's estate projection), computed now; lab runs only to a lab viewer."""
    from fastapi.responses import JSONResponse

    from pqch.cbom import project_estate

    ids = [x for x in runs.split(",") if x]
    if not ids or len(ids) > 32 or not all(x.isalnum() for x in ids):
        raise HTTPException(404)
    for x in ids:
        _refuse_lab_run(request, x)
        if not Run(VAR, x).ledger.exists():
            raise HTTPException(404)
    try:
        bom = project_estate([Run(VAR, x) for x in ids])
    except ValueError:
        raise HTTPException(409) from None
    return JSONResponse(bom)


@app.get("/imports")
def imports(request: Request):
    """Bring your own scanner: every imported CBOM, placed and scored beside the workbench's own."""
    from pqch.ui.view import imports_view

    r = Run.latest(VAR, "scan")
    own = run_view(r) if r and r.ledger.exists() else {}
    score = (own.get("score") or {}).get("columns") or {}
    combined = _combined(r, imports_view(VAR)) if r and r.ledger.exists() else None
    return templates.TemplateResponse(request, "imports.html", {"imports": imports_view(VAR), "own": score, "own_run": own.get("run"),
                                                                "combined": combined})


def _combined(scan: Run, imports: list[dict]) -> dict | None:
    """The scan and every import of the same estate projected as one document (M9): the entries, how
    many carry more than one claim, how many dissent, and the score of the combined document against
    the key the scan committed, where it has one."""
    from pqch.cbom import anatomy, project_estate
    from pqch.ledger import verify
    from pqch.score import score_bom
    from pqch.watch import _estate_key

    events = list(scan.ledger.events())
    if not verify(events).ok:
        return None
    mine = _estate_key(events[0]["payload"]["scope"])
    runs = [scan]
    for i in imports:
        if i.get("broken"):
            continue
        ir = Run(VAR, i["run"])
        first = next(ir.ledger.events(), None)
        if first and _estate_key(first["payload"]["scope"]) == mine:
            runs.append(ir)
    if len(runs) < 2:
        return None
    try:
        bom = project_estate(runs)
    except ValueError:
        return None
    d = anatomy.document(bom)
    key_ev = next((e for e in events if e["type"] == "key.committed"), None)
    key_path = Path(key_ev["payload"]["path"]) if key_ev and Path(key_ev["payload"].get("path", "")).is_file() else None
    sc = None
    if key_path:
        import yaml

        sc = score_bom(bom, yaml.safe_load(key_path.read_text()))
    return {"runs": [p["run"] for p in d["runs"]], "components": d["components"], "claims": d["claims"],
            "score": sc and {k: {x: v[x] for x in ("present", "covered", "out_of_reach", "false_positives", "scanned")}
                             for k, v in sc["layers"].items()}}


@app.get("/packages")
def packages(request: Request, run: str | None = None):
    """Change packages for what no configuration change can do: one per item blocked on its supplier."""
    from pqch.ui.view import packages_view

    if run is not None and not run.isalnum():
        raise HTTPException(404)
    _refuse_lab_run(request, run)
    r = Run(VAR, run) if run else Run.latest(VAR, "package")
    return templates.TemplateResponse(request, "packages.html", {"p": packages_view(r)})


@app.get("/resolve")
def resolve(request: Request, change: str | None = None, busy: str | None = None):
    """Resolution: carrying out a step of the plan — propose, rehearse, matrix, approve, apply, verify."""
    if change is not None and not change.isalnum():
        raise HTTPException(404)
    _refuse_lab_run(request, change)
    from pqch.pipeline import signer_from_env

    cr = Run(VAR, change) if change else Run.latest(VAR, "change")
    cview = change_view(cr, signer_from_env(), _runner_log(), _runner_jobs) if cr and cr.ledger.exists() else {}
    return templates.TemplateResponse(request, "resolve.html", {"c": cview, "change": change_state.snapshot(),
                                                                "who": identity(request), "hardware": HARDWARE,
                                                                "separation": SEPARATION, "approver_group": APPROVER_GROUP,
                                                                "busy": bool(busy)})


@app.get("/walkthrough")
def index(request: Request, run: str | None = None, change: str | None = None):
    if (run is not None and not run.isalnum()) or (change is not None and not change.isalnum()):
        raise HTTPException(404)
    _refuse_lab_run(request, run)
    _refuse_lab_run(request, change)
    from pqch.pipeline import signer_from_env

    signer = signer_from_env()
    r = Run(VAR, run) if run else (Run.latest(VAR, "scan") or Run.latest(VAR))
    # The walkthrough reads a scan of the mini-agency; asked for a run of any other kind (a change, a code
    # scan, a capture), it shows the latest scan instead of failing on the other kind's events.
    if r and r.ledger.exists() and next(r.ledger.events())["payload"].get("kind", "scan") != "scan":
        r = Run.latest(VAR, "scan")
    view = run_view(r, signer) if r and r.ledger.exists() else {}
    from pqch import planning

    plan = planning.build(VAR, r) if view and not view.get("broken") and next(r.ledger.events())["payload"].get("kind", "scan") == "scan" else None
    return templates.TemplateResponse(request, "index.html", {
        "plan": plan,
        "v": view, "hardware": HARDWARE, "scan": state.snapshot(), "change": change_state.snapshot(),
        "sheet": SHEET, "clock": CLOCK, "graph": estate_graph(view, SHEET) if view and not view.get("broken") else None,
        "receipts": receipts_view(VAR, view) if view and not view.get("broken") else None,
        "who": identity(request),
    })


def _scan_run(run: str | None) -> Run | None:
    r = Run(VAR, run) if run else Run.latest(VAR, "scan")
    return r if r and r.ledger.exists() else None


@app.get("/cbom")
def cbom_page(request: Request, run: str | None = None, ref: str | None = None):
    """The CBOM itself: the document, one entry field by field, and a second projection rebuilt live."""
    from pqch.cbom import anatomy, project, tables
    from pqch.ledger import verify

    if run is not None and not run.isalnum():
        raise HTTPException(404)
    r = _scan_run(run)
    if r and next(r.ledger.events())["payload"].get("kind") in LAB_KINDS and not lab_viewer(request):
        raise HTTPException(404)
    code = Run.latest(VAR, "scan-code")
    lab = Run.latest(VAR, "scan-external") if lab_viewer(request) else None
    estate = Run.latest(VAR, "scan")
    ctx = {"d": None}
    if r:
        events = list(r.ledger.events())
        if verify(events).ok:
            bom = project(events)
            ref = ref if ref and any(c["bom-ref"] == ref for c in bom["components"]) else anatomy.default_ref(bom)
            from pqch.ui.view import traces_by_fingerprint
            from pqch.watch import previous

            prev = previous(r)
            delta = None
            if prev:
                pe = list(prev.ledger.events())
                if verify(pe).ok:
                    delta = {"run": prev.id, **anatomy.diff(project(pe), bom)}
            ctx = {"run": r.id, "d": anatomy.document(bom), "entries": anatomy.entries(bom),
                   "c": anatomy.component(bom, events, ref),
                   "work": anatomy.model_work(bom, ref, traces_by_fingerprint(VAR), {
                       e["payload"]["service"]: {f["path"]: f["sha256"] for f in e["payload"]["files"]}
                       for e in events if e["type"] == "config.observed"}),
                   "p": tables.rebuild(events, tables.load(PROJECTIONS / "agency-inventory.yaml")),
                   "delta": delta,
                   "kind": events[0]["payload"].get("kind", "scan"),
                   "graph": _chain(r, events[0]["payload"].get("kind", "scan")),
                   "code_run": code.id if code and code.ledger.exists() and code.id != r.id else None,
                   "estate_run": (Run.latest(VAR, "scan").id if events[0]["payload"].get("kind") == "scan-code"
                                  and Run.latest(VAR, "scan") else None)}
    system = Run.latest(VAR, "scan-system") if lab_viewer(request) else None
    if ctx.get("kind") == "scan-system":
        from pqch import attest

        ctx["attested"] = attest.for_system(VAR, events)
    if ctx.get("d"):
        from pqch.assessor import gaps

        ctx["gaps"] = gaps.queue(VAR, events)
    ctx["switch"] = {"estate": estate.id if estate and estate.ledger.exists() else None,
                     "lab": lab.id if lab and lab.ledger.exists() else None,
                     "system": system.id if system and system.ledger.exists() else None, "on": r.id if r else None,
                     "on_host": bool(r) and _run_kind(r.id) == "scan-system"}
    return templates.TemplateResponse(request, "cbom.html", ctx)


def _chain(r: Run, kind: str) -> dict | None:
    """The chain view for a CBOM: the estate's for a scan of the mini-agency, the house's for the lab."""
    from pqch.ui.view import house_graph

    if kind == "scan":
        view = run_view(r)
        return estate_graph(view, SHEET) if view and not view.get("broken") else None
    if kind == "scan-external":
        cr = Run.latest(VAR, "capture")
        return house_graph(_house_cached(cr if cr and cr.ledger.exists() else None, r))
    return None


@app.get("/ask")
def ask_page(request: Request, q: str | None = None, run: str | None = None):
    """Ask the CBOM: a question answered from the CBOM's components, citing ledger events, every
    citation checked by a rule against the ledger (eval/ask/README.md)."""
    from pqch import ask as askmod
    from pqch.cbom import project
    from pqch.inference import Seam, TierUnavailable, load_config
    from pqch.ledger import verify

    if run is not None and not run.isalnum():
        raise HTTPException(404)
    _refuse_lab_run(request, run)
    r = _scan_run(run)
    ctx: dict = {"q": (q or "").strip()[:500], "run": r.id if r else None, "result": None, "unavailable": None,
                 "examples": askmod.EXAMPLES}
    if not r:
        return templates.TemplateResponse(request, "ask.html", ctx)
    if os.environ.get("PQCH_DEMO_MODE") == "snapshot":
        # A static copy has no model: the examples answered once by a real call, the check run again here.
        rec = askmod.load_recording(VAR, r.id)
        ctx["recorded"] = rec["recorded_at"] if rec else None
        if not rec:
            ctx["unavailable"] = "this copy has no model to call; questions are answered in the running workbench"
            return templates.TemplateResponse(request, "ask.html", ctx)
        ctx["examples"] = [q for q in askmod.EXAMPLES if q in rec["answers"]]
        first = next((a for a in rec["answers"].values() if "model" in a), None)
        if first:
            ctx["bound"] = {"tier": first["tier"], "reasoning": first["reasoning"], "model": first["model"],
                            "embed": first["embed_model"]}
        if ctx["q"]:
            a = rec["answers"].get(ctx["q"])
            if not a:
                ctx["unavailable"] = "only the example questions are answered in this copy; any question is answered in the running workbench"
            elif "unavailable" in a:
                ctx["unavailable"] = a["unavailable"]
            else:
                ctx["result"] = {**a, "check": askmod.check(a["reply"], a["shown"], list(r.ledger.events()))}
        return templates.TemplateResponse(request, "ask.html", ctx)
    try:
        seam = Seam(load_config(os.environ["PQCH_INFERENCE_CONFIG"]))
        tier, reasoning = seam.for_role(askmod.ROLE)
        ctx["bound"] = {"tier": tier, "reasoning": reasoning, "model": seam.config["tiers"][tier].get("model"),
                        "embed": seam.config["tiers"].get("embed", {}).get("model")}
        if "embed" not in seam.config["tiers"]:
            raise TierUnavailable("no `embed` tier in this profile")
    except (TierUnavailable, KeyError, OSError) as e:
        ctx["unavailable"] = str(e)
        return templates.TemplateResponse(request, "ask.html", ctx)
    if ctx["q"]:
        events = list(r.ledger.events())
        if not verify(events).ok:
            ctx["unavailable"] = "the run's ledger does not verify"
            return templates.TemplateResponse(request, "ask.html", ctx)
        try:
            index = askmod.Index(seam, r.dir, project(events), events)
            ctx["result"] = askmod.ask(seam, index, ctx["q"], events)
        except Exception as e:  # an engine down, a timeout: shown as such, never as an answer
            ctx["unavailable"] = f"{type(e).__name__}: {e}"[:300]
    return templates.TemplateResponse(request, "ask.html", ctx)


@app.get("/runs/{run_id}/register.{fmt}")
def register_file(request: Request, run_id: str, fmt: str):
    """The plan as a register, computed now from the run and the change runs since: CSV or JSON."""
    from fastapi.responses import JSONResponse, PlainTextResponse

    from pqch import planning

    if not run_id.isalnum() or fmt not in ("csv", "json"):
        raise HTTPException(404)
    _refuse_lab_run(request, run_id)
    r = Run(VAR, run_id)
    if not r.ledger.exists():
        raise HTTPException(404)
    kind = _run_kind(run_id)
    if kind == "scan-system":
        if not lab_viewer(request):
            raise HTTPException(404)
        plan = planning.system_build(r)
    else:
        plan = planning.build(VAR, r, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots")))
    if not plan:
        raise HTTPException(404)
    reg = planning.register(plan, list(r.ledger.events()))
    if fmt == "json":
        return JSONResponse(reg)
    return PlainTextResponse(planning.register_csv(reg), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{run_id}-register.csv"'})


@app.get("/runs/{run_id}/projection/{name}.csv")
def projection_csv(request: Request, run_id: str, name: str):
    from fastapi.responses import PlainTextResponse

    from pqch.cbom import tables

    if not run_id.isalnum() or not name.replace("-", "").isalnum():
        raise HTTPException(404)
    _refuse_lab_run(request, run_id)
    path = PROJECTIONS / f"{name}.yaml"
    r = Run(VAR, run_id)
    if not path.is_file() or not r.ledger.exists():
        raise HTTPException(404)
    result = tables.rebuild(list(r.ledger.events()), tables.load(path))
    return PlainTextResponse(tables.to_csv(result), media_type="text/csv",
                             headers={"Content-Disposition": f'attachment; filename="{run_id}-{name}.csv"'})


@app.get("/lab")
def lab(request: Request, run: str | None = None):
    """The owner's lab as passive capture shows it: the latest capture run, drawn."""
    _lab_or_404(request)
    if run is not None and (not run.isalnum() or _run_kind(run) != "capture"):
        raise HTTPException(404)
    r = Run(VAR, run) if run else Run.latest(VAR, "capture")
    view = _capture_cached(r) if r and r.ledger.exists() else {}
    # The latest targeted scan of the same estate, if one has run: certificates and what each accepts.
    sr = Run.latest(VAR, "scan-external")
    scan = run_view(sr, signer_from_env_safe()) if sr and sr.ledger.exists() else {}
    house = _house_cached(r if r and r.ledger.exists() else None, sr if sr and sr.ledger.exists() else None)
    from pqch.ui.view import house_graph

    return templates.TemplateResponse(request, "lab.html", {"lab": view, "scan": scan, "house": house, "house_graph": house_graph(house),
                                                            "hardware": HARDWARE,
                                                            "clock": CLOCK})


@app.get("/lab/house.cdx.json")
def lab_house_cbom(request: Request):
    """The house as one CycloneDX document: the capture's inside entries and the targeted scan's, merged."""
    _lab_or_404(request)
    cr, sr = Run.latest(VAR, "capture"), Run.latest(VAR, "scan-external")
    h = _house_cached(cr if cr and cr.ledger.exists() else None, sr if sr and sr.ledger.exists() else None)
    if not h:
        raise HTTPException(404)
    return JSONResponse(h["doc"], headers={"Content-Disposition": "attachment; filename=house.cdx.json"})


@app.get("/lab/estate.json")
def lab_estate(request: Request):
    """The lab at VLAN level for the lab portal's front page: shares, postures and counts by VLAN name,
    never an address. Read by the portal's address (PQCH_ESTATE_READERS) or a signed-on viewer."""
    peer = request.client.host if request.client else None
    if PUBLIC or not (peer in ESTATE_READERS or lab_viewer(request)):
        raise HTTPException(404)
    from pqch.ui import lab_summary

    cr, sr = Run.latest(VAR, "capture"), Run.latest(VAR, "scan-external")
    out = lab_summary.build(VAR, cr if cr and cr.ledger.exists() else None, sr if sr and sr.ledger.exists() else None)
    if not out:
        raise HTTPException(404)
    return JSONResponse(out, headers={"Cache-Control": "max-age=300"})


_house_cache: dict[tuple, dict | None] = {}


def _house_cached(cr: Run | None, sr: Run | None) -> dict | None:
    """The house's merged CBOM, rebuilt only when either ledger changes. Neither ledger that fails to
    verify contributes: the capture through its view's check, the scan through its own CBOM file."""
    import json as _json

    from pqch.cbom import house
    from pqch.ledger import verify

    def stamp(r):
        if not r:
            return None
        st = r.ledger.path.stat()
        return (r.id, st.st_size, st.st_mtime_ns)
    key = (stamp(cr), stamp(sr))
    if key in _house_cache:
        return _house_cache[key]
    cap = list(cr.ledger.events()) if cr else None
    if cap and not verify(cap).ok:
        cap = None
    bom = None
    if sr and (sr.dir / "workbench.cdx.json").exists() and verify(list(sr.ledger.events())).ok:
        bom = _json.loads((sr.dir / "workbench.cdx.json").read_text())
    h = house.build(cap, bom)
    _house_cache.clear()
    _house_cache[key] = h
    return h


def signer_from_env_safe():
    from pqch.pipeline import signer_from_env

    return signer_from_env()


_capture_cache: dict[str, tuple[tuple[int, int], dict]] = {}


def _capture_cached(r: Run) -> dict:
    """The capture view, rebuilt only when the run's ledger changes (a closed run never does)."""
    st = r.ledger.path.stat()
    key = (st.st_size, st.st_mtime_ns)
    hit = _capture_cache.get(r.id)
    if hit and hit[0] == key:
        return hit[1]
    view = capture_view(r)
    _capture_cache.clear()
    _capture_cache[r.id] = (key, view)
    return view


# The header the front door sets with the signed-on user, and how an approval says it was signed on.
IDENTITY_HEADER = os.environ.get("PQCH_IDENTITY_HEADER", "X-Forwarded-User")
SIGN_ON = os.environ.get("PQCH_SIGN_ON", "the front door's single sign-on")
# The kit: the operator at the box's console, when no front door signs anyone on (see identity()).
OPERATOR = os.environ.get("PQCH_OPERATOR", "").strip() or None
# The addresses the front door connects from. The sign-on header is believed only on a
# connection from one of them; from anywhere else it is a string anyone can type. Empty,
# the default, means the page cannot approve at all and approvals come from the command line.
TRUSTED_PROXIES = {a.strip() for a in os.environ.get("PQCH_TRUSTED_PROXIES", "").split(",") if a.strip()}
# ADR-0008: the front door's groups header, read on the same connection as the sign-on; the group an
# approver must be in (empty: anyone signed on may approve, as before); and separation of duties, under
# which an approval is one request and the apply another, and the runner refuses self-approval.
GROUPS_HEADER = os.environ.get("PQCH_GROUPS_HEADER", "X-Forwarded-Groups")
APPROVER_GROUP = os.environ.get("PQCH_APPROVER_GROUP", "").strip() or None
SEPARATION = os.environ.get("PQCH_SEPARATION_OF_DUTIES") == "1"
MARKING = os.environ.get("PQCH_MARKING", "").strip() or None
templates.env.globals["marking"] = MARKING
change_state = ScanState()


def identity(request: Request) -> str | None:
    """Who is acting: the name the front door's header carries, on a connection from the front door.
    On one box with no front door (the kit), the page is published on the box's loopback only, and
    the person at its console is the operator named in PQCH_OPERATOR: the connection must still come
    from the one trusted peer (the bridge gateway, which is the box itself), and the approval event
    records that it was the console, not a sign-on, that vouched for the name."""
    peer = request.client.host if request.client else None
    if peer not in TRUSTED_PROXIES:
        return None
    return request.headers.get(IDENTITY_HEADER) or OPERATOR or None


def same_origin(request: Request) -> None:
    """Refuse a form posted from another site with the user's sign-on riding along."""
    origin = request.headers.get("origin")
    if origin and origin.split("://", 1)[-1] != request.headers.get("host"):
        raise HTTPException(403, "cross-site request")


def _runner_log() -> list[dict] | None:
    from pqch.runner.client import RunnerClient

    try:
        return RunnerClient(SOCKET, timeout_s=5).log()
    except Exception:
        return None


def _runner_jobs(ids) -> list[dict] | None:
    from pqch.runner.client import RunnerClient

    try:
        return RunnerClient(SOCKET, timeout_s=10).jobs(ids)
    except Exception:
        return None


def _who(request: Request) -> str:
    same_origin(request)
    who = identity(request)
    if not who:
        raise HTTPException(403, "an approval needs the front door's sign-on, on a connection from the front door")
    return who


def groups_of(request: Request) -> list[str]:
    """The groups the front door says the signed-on person is in, on a connection from the front door."""
    peer = request.client.host if request.client else None
    if peer not in TRUSTED_PROXIES:
        return []
    return sorted({g.strip() for g in (request.headers.get(GROUPS_HEADER) or "").replace(";", ",").split(",") if g.strip()})


def _approver(request: Request) -> tuple[str, list[str]]:
    """Who approves and the groups it rests on; refused when the deployment names an approver group the
    person is not in (ADR-0008)."""
    who = _who(request)
    groups = groups_of(request)
    if APPROVER_GROUP and APPROVER_GROUP not in groups:
        raise HTTPException(403, f"approving needs the {APPROVER_GROUP} group; the front door lists {', '.join(groups) or 'none'} for {who}")
    return who, groups


def _change_thread(fn) -> None:
    try:
        fn()
    except Exception as e:
        with change_state.lock:
            change_state.error = f"{type(e).__name__}: {e}"
        traceback.print_exc()
    finally:
        with change_state.lock:
            change_state.running = False


class _ChangeInProgress(Exception):
    """A second click while a proposal or an approval is being carried out: refused, and the person is
    sent back to the page that shows the work in progress, not to a JSON 409 (demo GB10, 2026-11-04)."""


@app.exception_handler(_ChangeInProgress)
def _change_in_progress(request: Request, exc: _ChangeInProgress):
    return RedirectResponse("/resolve?busy=1", status_code=303)


def _start_change(fn) -> None:
    with change_state.lock:
        if change_state.running:
            raise _ChangeInProgress()
        change_state.running, change_state.error = True, None
    threading.Thread(target=_change_thread, args=(fn,), daemon=True).start()


@app.post("/changes/propose")
def propose_change(request: Request):
    from pqch.migrator import propose
    from pqch.runner.client import RunnerClient

    who = _who(request)
    from pqch.pipeline import signer_from_env

    _start_change(lambda: propose(VAR, RunnerClient(SOCKET), POLICY, AGENCY, by=who,
                                  authenticated_by=SIGN_ON,
                                  signer=signer_from_env()))
    return RedirectResponse("/resolve", status_code=303)


@app.post("/changes/{run_id}/{change_id}/rehearse")
def rehearse_change(request: Request, run_id: str, change_id: str):
    from pqch.migrator import rehearse
    from pqch.pipeline import signer_from_env
    from pqch.runner.client import RunnerClient

    if not run_id.isalnum() or not change_id.isalnum():
        raise HTTPException(404)
    _who(request)
    run = Run(VAR, run_id)
    _start_change(lambda: rehearse(run, RunnerClient(SOCKET), signer_from_env(), change_id, hardware=HARDWARE))
    return RedirectResponse("/resolve", status_code=303)


@app.post("/changes/{run_id}/{change_id}/approve")
def approve_change(request: Request, run_id: str, change_id: str):
    from pqch.migrator import approve, execute
    from pqch.pipeline import signer_from_env
    from pqch.runner.client import RunnerClient

    if not run_id.isalnum() or not change_id.isalnum():
        raise HTTPException(404)
    who, groups = _approver(request)
    run = Run(VAR, run_id)

    def go():
        signer = signer_from_env()
        approve(run, change_id, by=who, signer=signer, authenticated_by=SIGN_ON,
                role="approver" if (APPROVER_GROUP or SEPARATION) else None, groups=groups or None)
        if not SEPARATION:
            execute(run, RunnerClient(SOCKET), signer, change_id)
    _start_change(go)
    return RedirectResponse("/resolve", status_code=303)


@app.post("/changes/{run_id}/{change_id}/apply")
def apply_change(request: Request, run_id: str, change_id: str):
    """Under separation of duties the apply is its own request, after the approval is on the ledger under a
    signed checkpoint; the runner reads that ledger itself and refuses what it does not find (ADR-0008)."""
    from pqch.migrator import execute
    from pqch.pipeline import signer_from_env
    from pqch.runner.client import RunnerClient

    if not run_id.isalnum() or not change_id.isalnum():
        raise HTTPException(404)
    _who(request)
    run = Run(VAR, run_id)
    _start_change(lambda: execute(run, RunnerClient(SOCKET), signer_from_env(), change_id))
    return RedirectResponse("/resolve", status_code=303)


@app.post("/estate/reset")
def estate_reset(request: Request):
    """Put the mini-agency back to its starting state, as the signed-on person asked; then scan."""
    if PUBLIC:
        raise HTTPException(404)
    from pqch.migrator.reset import reset_estate
    from pqch.pipeline import signer_from_env
    from pqch.runner.client import RunnerClient

    who = _who(request)
    _start_change(lambda: reset_estate(VAR, RunnerClient(SOCKET), signer_from_env(), by=who, authenticated_by=SIGN_ON))
    return RedirectResponse("/resolve", status_code=303)


@app.post("/scan")
def scan(request: Request, host: str = "replay"):
    # Started from the page itself, never from another site; where there is a front door, by a viewer signed on
    # through it; never in the public snapshot.
    if PUBLIC:
        raise HTTPException(404)
    same_origin(request)
    if TRUSTED_PROXIES and not identity(request):
        raise HTTPException(403, "a scan needs the front door's sign-on, on a connection from the front door")
    if host not in ("replay", "live"):
        raise HTTPException(400, "host must be replay or live")
    with state.lock:
        if state.running:
            return RedirectResponse("/walkthrough", status_code=303)
        state.running, state.lines, state.error, state.run_id = True, [], None, None
    threading.Thread(target=_scan_thread, args=(host,), daemon=True).start()
    return RedirectResponse("/walkthrough", status_code=303)


@app.get("/api/scan")
def scan_status():
    return JSONResponse(state.snapshot())


@app.get("/runs/{run_id}/{name}")
def download(request: Request, run_id: str, name: str):
    if name not in DOWNLOADS or not run_id.isalnum():
        raise HTTPException(404)
    _refuse_lab_run(request, run_id)
    path = VAR / "runs" / run_id / name
    if not path.is_file():
        raise HTTPException(404)
    return FileResponse(path, media_type="application/json", filename=f"{run_id}-{name}")


@app.get("/healthz")
def healthz():
    # The files a scan or a proposal reads. A bind mount whose directory was replaced on the
    # host (a branch switch does it) leaves the service up and these gone.
    missing = [str(p) for p in (KEY, POLICY, Path(os.environ.get("PQCH_POLICY", "policy/pq-algorithms.yaml")),
                                Path(os.environ.get("PQCH_CONTEXT", "agency/context.yaml")),
                                Path(os.environ.get("PQCH_VERIFIERS", "policy/verifiers.yaml")))
               if not p.is_file()]
    if missing:
        return JSONResponse({"ok": False, "missing": missing}, status_code=503)
    return {"ok": True}


# ───────────── The demo stage: one page, the story in beats, every number live ─────────────
# kit/README.md, "Demo day": eight minutes is one page, not eight. The data is the same run store,
# CBOM projection, plan and ledgers the other pages show, served as one document the page animates.
from pqch.ui import demo as _demo  # noqa: E402


@app.get("/api/demo/slow")
def demo_slow(s: float = 5):
    """A pixel that arrives late: the stage's wait hook, so a headless browser's screenshot lands after the live animations."""
    import time as _time
    from fastapi.responses import Response as _Response
    _time.sleep(max(0.0, min(20.0, s)))
    return _Response(content=b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;", media_type="image/gif")


@app.get("/demo")
def demo_page(request: Request, snap: str | None = None, inline_data: str | None = None, wait: float | None = None):
    inline, static_hw = None, None
    if PUBLIC:
        # the static copy: the document inlined, the test agency only, what the stage would fetch carried inside
        import json as _json
        doc = _demo.payload(VAR, SHEET, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots")),
                            hardware="unlabelled", inference_config=None, this_host=None, static=True)
        static_hw = doc.get("hardware")
        inline = _json.dumps(doc).replace("</", "<\\/")
        snap = inline_data = None
    elif snap or inline_data:  # a still of one beat (snap: the document inlined, animations skipped) or the live stage with the document inlined
        import json as _json
        inline = _json.dumps(_demo.payload(VAR, SHEET, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots")),
                                           hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"), inference_config=os.environ.get("PQCH_INFERENCE_CONFIG"),
                                           this_host=os.environ.get("PQCH_THIS_HOST") or None))
    r = Run.latest(VAR, "scan")
    try:
        from pqch import planning
        plan = planning.build(VAR, r, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots"))) if r and r.ledger.exists() else None
    except Exception:
        plan = None
    # the stage's own files, versioned by content so a browser never keeps a rebuilt script under the same name
    import hashlib as _h
    # A cache-busting version, not security: under a FIPS provider md5 raises unless it says so.
    v = _h.md5(b"".join((HERE / "static" / n).read_bytes() for n in ("demo.js", "demo.css", "plan.js")),
               usedforsecurity=False).hexdigest()[:10]
    return templates.TemplateResponse(request, "demo.html", {
        "inline": inline, "snap": bool(snap), "wait": wait, "plan": plan, "v": v,
        "outcome": os.environ.get("PQCH_MISSION_OUTCOME",
                                  "We need to know what cryptography every system depends on, and what to change first, "
                                  "so that the agency meets the post-quantum deadlines — measured by every planted weakness found, "
                                  "and every change proved on the wire."),
        "hardware": static_hw or os.environ.get("PQCH_HARDWARE", "unlabelled"), "operator": os.environ.get("PQCH_OPERATOR", "the operator"),
        "static": PUBLIC})


@app.get("/api/demo")
def demo_api(request: Request):
    if PUBLIC:
        raise HTTPException(404)
    return JSONResponse(_demo.payload(VAR, SHEET, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots")),
                                      hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"),
                                      inference_config=os.environ.get("PQCH_INFERENCE_CONFIG"),
                                      this_host=os.environ.get("PQCH_THIS_HOST") or None))


@app.get("/api/demo/entry")
def demo_entry(ref: str = ""):
    """One component of the latest scan's CBOM, as the file holds it, with its dependency row: the stage shows the
    entry beside the figure for whatever is under the pointer."""
    if PUBLIC:
        raise HTTPException(404)
    import json as _json
    scan = Run.latest(VAR, "scan")
    path = scan.dir / "workbench.cdx.json" if scan else None
    if not path or not path.is_file():
        raise HTTPException(404, "no CBOM yet")
    doc = _json.loads(path.read_text())
    comp = next((c for c in doc.get("components", []) if c.get("bom-ref") == ref), None)
    if comp is None:
        raise HTTPException(404, "no such entry")
    deps = next((d.get("dependsOn", []) for d in doc.get("dependencies", []) if d.get("ref") == ref), [])
    return JSONResponse({"component": comp, "depends_on": deps, "run": scan.id,
                         "bom": {"format": doc.get("bomFormat"), "spec": doc.get("specVersion"), "serial": doc.get("serialNumber"),
                                 "components": len(doc.get("components", []))}})


@app.post("/api/demo/narrate")
async def demo_narrate(request: Request):
    if PUBLIC:
        raise HTTPException(404)
    same_origin(request)
    body = await request.json()
    return JSONResponse(_demo.narrate(str(body.get("kind") or "plan"), body.get("row") or {}))


# ───────────── Ask the field notes: the journal answered by the box's model, citations checked ─────────────
_NOTES_INDEX: dict = {}


@app.get("/notes/ask")
def notes_ask(request: Request, q: str = ""):
    if PUBLIC:
        raise HTTPException(404)
    from pqch import notes_ask as nmod
    from pqch.inference import Seam, TierUnavailable, load_config
    tries = ["How does the runner read a server's files, and as which user?", "What does the verifier check before a change counts as enforced?",
             "Why is a role moved to a model only by measurement?", "What is the event substrate, and what is projected from it?",
             "How is a recording replayed on another box?", "What did spike S3 measure on the GB10?"]
    ctx = {"q": q.strip()[:400], "result": None, "unavailable": None, "tries": tries, "corpus": "—", "embed_model": "the embed tier", "model": "the deliberate tier"}
    try:
        seam = Seam(load_config(os.environ["PQCH_INFERENCE_CONFIG"]))
        notes_tier = seam.for_role(nmod.ROLE)[0]
        if "embed" not in seam.config["tiers"] or notes_tier not in seam.config["tiers"]:
            raise TierUnavailable("this profile has no embed or deliberate tier")
        ctx["embed_model"] = seam.config["tiers"]["embed"].get("model")
        ctx["model"] = seam.config["tiers"][notes_tier].get("model")
        idx_path = SITE / "search" / "search_index.json"
        if not idx_path.exists():
            raise TierUnavailable("the field notes site is not built on this box")
        stamp = idx_path.stat().st_mtime
        if _NOTES_INDEX.get("stamp") != stamp:
            _NOTES_INDEX.update({"stamp": stamp, "index": nmod.Index(seam, SITE, VAR)})
        index = _NOTES_INDEX["index"]
        ctx["corpus"] = len(index.passages)
        if ctx["q"]:
            ctx["result"] = nmod.ask(seam, index, ctx["q"])
    except (TierUnavailable, KeyError) as e:
        ctx["unavailable"] = str(e)
    except Exception as e:  # the page says what went wrong rather than a 500 on stage
        ctx["unavailable"] = f"{type(e).__name__}: {str(e)[:200]}"
    return templates.TemplateResponse(request, "notes_ask.html", ctx)
