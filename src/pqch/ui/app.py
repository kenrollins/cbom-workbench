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
if SITE.is_dir():
    app.mount("/site", StaticFiles(directory=SITE, html=True), name="site")
# A preview of the public, static demo (tools/build_public.py --base /preview/), when a deployment
# mounts one: reviewed behind the same door before anything is published.
PREVIEW = Path(os.environ.get("PQCH_PREVIEW_DIR", "/app/preview"))
if PREVIEW.is_dir():
    app.mount("/preview", StaticFiles(directory=PREVIEW, html=True), name="preview")
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
# Public: the mini-agency only, read-only. No lab page, link or data; no scan, propose or approve.
# Set for the static build published on GitHub Pages (tools/build_public.py).
PUBLIC = os.environ.get("PQCH_PUBLIC") == "1"
templates.env.globals["public"] = PUBLIC
# The lab portal's address(es), allowed to read the VLAN-level summary (/lab/estate.json) and
# nothing else of the lab. Empty means only a signed-on viewer through the front door may.
ESTATE_READERS = {a.strip() for a in os.environ.get("PQCH_ESTATE_READERS", "").split(",") if a.strip()}
LAB_KINDS = ("capture", "scan-external")


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


@app.get("/agency")
def agency(request: Request):
    """The test agency at a glance: what the mini-agency is, its services and what was planted in each."""
    from pqch.ui import estate

    return templates.TemplateResponse(request, "agency.html", {"e": estate.build(AGENCY, KEY)})


@app.get("/plan")
def plan_page(request: Request, estate: str = "mini-agency", assume: str = ""):
    """The plan the CBOM makes possible: what depends on what, what comes first, in what order."""
    from pqch import planning

    if estate not in ("mini-agency", "lab") or (estate == "lab" and not lab_viewer(request)):
        raise HTTPException(404)
    # What-if: steps taken as done, named in the address; nothing is written anywhere.
    assumed = frozenset(a for a in assume.split(",") if a)
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


@app.get("/imports")
def imports(request: Request):
    """Bring your own scanner: every imported CBOM, placed and scored beside the workbench's own."""
    from pqch.ui.view import imports_view

    r = Run.latest(VAR, "scan")
    own = run_view(r) if r and r.ledger.exists() else {}
    score = (own.get("score") or {}).get("columns") or {}
    return templates.TemplateResponse(request, "imports.html", {"imports": imports_view(VAR), "own": score, "own_run": own.get("run")})


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
def resolve(request: Request, change: str | None = None):
    """Resolution: carrying out a step of the plan — propose, rehearse, matrix, approve, apply, verify."""
    if change is not None and not change.isalnum():
        raise HTTPException(404)
    _refuse_lab_run(request, change)
    from pqch.pipeline import signer_from_env

    cr = Run(VAR, change) if change else Run.latest(VAR, "change")
    cview = change_view(cr, signer_from_env(), _runner_log(), _runner_jobs) if cr and cr.ledger.exists() else {}
    return templates.TemplateResponse(request, "resolve.html", {"c": cview, "change": change_state.snapshot(),
                                                                "who": identity(request), "hardware": HARDWARE})


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
    ctx["switch"] = {"estate": estate.id if estate and estate.ledger.exists() else None,
                     "lab": lab.id if lab and lab.ledger.exists() else None, "on": r.id if r else None}
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
# The addresses the front door connects from. The sign-on header is believed only on a
# connection from one of them; from anywhere else it is a string anyone can type. Empty,
# the default, means the page cannot approve at all and approvals come from the command line.
TRUSTED_PROXIES = {a.strip() for a in os.environ.get("PQCH_TRUSTED_PROXIES", "").split(",") if a.strip()}
change_state = ScanState()


def identity(request: Request) -> str | None:
    peer = request.client.host if request.client else None
    if peer not in TRUSTED_PROXIES:
        return None
    return request.headers.get(IDENTITY_HEADER) or None


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


def _start_change(fn) -> None:
    with change_state.lock:
        if change_state.running:
            raise HTTPException(409, "a change is in progress")
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
    who = _who(request)
    run = Run(VAR, run_id)

    def go():
        signer = signer_from_env()
        approve(run, change_id, by=who, signer=signer,
                authenticated_by=SIGN_ON)
        execute(run, RunnerClient(SOCKET), signer, change_id)
    _start_change(go)
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
