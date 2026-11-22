"""The one page: the spreadsheet, the scan button, the CBOM with its evidence, the score.

Server-rendered; the stylesheet and script are vendored in `static/`. The
service holds no Docker socket: a scan is a sequence of jobs sent to the runner
over its Unix socket.
"""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
import traceback
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, RedirectResponse
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
    {"date": "2027-01-01", "label": "new NSS acquisitions CNSA 2.0", "source": "NSA CNSA 2.0 FAQ Ver. 2.2, Timeframe, read first-hand 2026-11-09"},
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


# ───────── Who is asking ─────────
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
# Public: the mini-agency only, read-only. No lab page, link or data; no scan, propose or approve.
# Set for the static build published on GitHub Pages (tools/build_public.py).
PUBLIC = os.environ.get("PQCH_PUBLIC") == "1"


def _hostname(host: str | None) -> str:
    """The name in a Host or Origin value, without its port: `[::1]:8080` is `::1`."""
    h = (host or "").strip().lower()
    if h.startswith("["):
        return h[1:].split("]", 1)[0]
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


# The names this page is served under (PQCH_ALLOWED_HOSTS, comma-separated, without ports). A request
# whose Host is any other name is refused before any route runs. This is what stops DNS rebinding: a
# hostile page whose own name is re-pointed at this address is same-origin to the browser, so comparing
# Origin with Host proves nothing (both are the attacker's name); only a list written by the deployment
# can tell. In console mode (PQCH_OPERATOR) nothing but the network path vouches for the operator, so the
# list defaults to the loopback names the kit publishes on; behind a front door the deployment names the
# door (unset there, the sign-on's cookie is the door's own name's and the check is the door's to make).
ALLOWED_HOSTS = {_hostname(a) for a in os.environ.get("PQCH_ALLOWED_HOSTS", "").split(",") if a.strip()} \
    or ({"127.0.0.1", "localhost", "::1"} if OPERATOR else set())


def _identity_of(peer: str | None, header) -> str | None:
    """Who is acting, from the connection's peer and a header lookup. Two modes, never mixed:

    - **Console** (PQCH_OPERATOR set; the kit): the page is published on the box's loopback only and the
      person at its console is the operator named in the setting. The connection must still come from the
      one trusted peer (the bridge gateway, which is the box itself). No header is read: nothing on that
      path sets or strips one, so a header there is a string any local process can type, and an approval
      recorded as "the box's console" must carry the name the console was given.
    - **Front door**: the name the door's header carries, on a connection from the door's address."""
    if peer not in TRUSTED_PROXIES:
        return None
    if OPERATOR:
        return OPERATOR
    return header(IDENTITY_HEADER) or None


class _AllowedHosts:
    """Refuse a request whose Host is not one of the deployment's names (ALLOWED_HOSTS), on every route."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and ALLOWED_HOSTS:
            host = next((v.decode("latin-1") for k, v in scope.get("headers") or [] if k == b"host"), "")
            if _hostname(host) not in ALLOWED_HOSTS:
                await PlainTextResponse("this page is not served under that host name", status_code=400)(scope, receive, send)
                return
        await self.inner(scope, receive, send)


class _SignedOn:
    """Files that answer only to a signed-on viewer, as the lab's pages do (lab_viewer): anything else is
    404. The built journal carries lab-only entries and the whole private journal's search index, and a
    peer on the application's own network can reach the app without passing the front door, so "behind
    the same door" has to be checked here, per connection, not assumed from the proxy."""

    def __init__(self, inner):
        self.inner = inner

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
            peer = (scope.get("client") or (None,))[0]
            if PUBLIC or _identity_of(peer, lambda name: headers.get(name.lower())) is None:
                await PlainTextResponse("Not Found", status_code=404)(scope, receive, send)
                return
        await self.inner(scope, receive, send)


@asynccontextmanager
async def _lifespan(_app):
    _warm()
    yield


app = FastAPI(title="cbom-workbench", docs_url=None, redoc_url=None, openapi_url=None, lifespan=_lifespan)
app.add_middleware(_AllowedHosts)
app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
# The built journal site (mkdocs build), when a deployment mounts it, at /site/: for a signed-on viewer
# only (_SignedOn). Nothing in the application depends on it being there.
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
    app.mount("/site", _SignedOn(_Revalidated(directory=SITE, html=True)), name="site")
# A preview of the public, static demo (tools/build_public.py --base /preview/), when a deployment
# mounts one: reviewed by a signed-on viewer before anything is published, so it is not public yet.
PREVIEW = Path(os.environ.get("PQCH_PREVIEW_DIR", "/app/preview"))
if PREVIEW.is_dir():
    app.mount("/preview", _SignedOn(_Revalidated(directory=PREVIEW, html=True)), name="preview")
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
templates.env.globals["public"] = PUBLIC
# "The lab" is a tab only where there is one (a capture or an external scan in the run store; on a box
# with neither, the demo box of 2026-11-04, the tab is absent) and only for a viewer the lab's pages
# answer: to anyone else the link would acknowledge a lab its own page then denies. Hosts has no tab of
# its own: the estate switcher on the CBOM, plan and overview pages reaches it (2026-11-09).
templates.env.globals["lab_shown"] = lambda request=None: bool(
    request is not None and lab_viewer(request) and (Run.latest(VAR, "capture") or Run.latest(VAR, "scan-external")))
# The lab portal's address(es), allowed to read the VLAN-level summary (/lab/estate.json) and
# nothing else of the lab. Empty means only a signed-on viewer through the front door may.
ESTATE_READERS = {a.strip() for a in os.environ.get("PQCH_ESTATE_READERS", "").split(",") if a.strip()}
LAB_KINDS = ("capture", "scan-external", "scan-system", "scan-copy")
# The one kind of run over an estate the owner did not build that is public: a federal repository read
# at a pinned commit. Every other run under an external scope is the lab's.
PUBLIC_EXTERNAL_KINDS = ("scan-code",)


def is_lab(first: dict | None) -> bool:
    """Whether a run is the lab's, from its first event: by its kind, or by its scope. A run of any kind
    whose scope is a copy placed on a lab network (`copy`), or is an estate the workbench did not build
    (`estate: external`) and is not a public code scan, carries lab addresses whatever it is called: an
    import of another tool's CBOM of the range copy is of kind `import` (2026-11-16). No first event that
    can be read is the lab's too: it fails closed."""
    if not isinstance(first, dict) or not isinstance(first.get("payload"), dict):
        return True
    p = first["payload"]
    kind = p.get("kind", "scan")
    scope = p.get("scope") if isinstance(p.get("scope"), dict) else {}
    return (kind in LAB_KINDS or bool(scope.get("copy"))
            or (scope.get("estate") == "external" and kind not in PUBLIC_EXTERNAL_KINDS))


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
    return is_lab(_first_event(run_id))


def _refuse_lab_run(request: Request, run_id: str | None) -> None:
    if run_id is not None and _lab_run(run_id) and not lab_viewer(request):
        raise HTTPException(404)


def _first_event(run_id: str) -> dict | None:
    """A run's first event, read alone; None when there is no such run or its first line is not an event."""
    led = VAR / "runs" / run_id / "ledger.jsonl"
    if not run_id.isalnum() or not led.is_file():
        return None
    try:
        with led.open(encoding="utf-8") as f:
            first = json.loads(f.readline() or "null")
        return first if isinstance(first, dict) and isinstance(first.get("payload"), dict) else None
    except (OSError, ValueError):
        return None


def _run_kind(run_id: str) -> str | None:
    """A run's kind from its first event alone, or None when there is no such run."""
    first = _first_event(run_id)
    return first["payload"].get("kind", "scan") if first else None


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
        a = agility.build("mini-agency", VAR, inference_config=os.environ.get("PQCH_INFERENCE_CONFIG"),
                          role_cards=Path(os.environ.get("PQCH_ROLE_CARDS", "eval/role-cards.yaml")),
                          s3_report=Path(os.environ.get("PQCH_S3_REPORT", "spikes/s3/results/scored/report.json")),
                          policy_path=POLICY)
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

    # An import under a lab scope (a document of the range copy, say) is the lab's: listed only to a lab
    # viewer, and never part of the combined document anyone else is shown.
    lab_ok = lab_viewer(request)
    rows = [i for i in imports_view(VAR) if lab_ok or not i.get("lab")]
    r = Run.latest(VAR, "scan")
    own = run_view(r) if r and r.ledger.exists() else {}
    score = (own.get("score") or {}).get("columns") or {}
    for i in rows:
        # A document of a copy is read beside the workbench's own scan of that copy, not beside the
        # estate's latest scan: the copy was taken at another time and may hold other things.
        if i.get("copy") and not i.get("broken"):
            i["pair"] = _copy_pair(i["copy"])
    combined = _combined(r, [i for i in rows if not i.get("lab")]) if r and r.ledger.exists() else None
    return templates.TemplateResponse(request, "imports.html", {"imports": rows, "own": score, "own_run": own.get("run"),
                                                                "combined": combined})


def _copy_pair(copy: dict) -> dict | None:
    """The latest scan-copy run of the same copy (what it copies, and when it was taken), with its score."""
    from pqch.ui.view import runs_of_kind

    for r in reversed(runs_of_kind(VAR, "scan-copy")):
        first = _first_event(r.id)
        c = ((first or {}).get("payload", {}).get("scope") or {}).get("copy") or {}
        if c.get("of") == copy.get("of") and c.get("taken") == copy.get("taken"):
            view = run_view(r)
            layers = (((view.get("score") or {}).get("columns") or {}).get("workbench") or {}).get("layers")
            return {"run": r.id, "layers": layers} if layers and not view.get("broken") else {"run": r.id, "layers": None}
    return None


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
    who = identity(request)
    # Under separation the one who asked for a change is not offered its approve button (and is refused if
    # they post anyway); with no approver group named, nobody is.
    own = set()
    if SEPARATION and who and cview and not cview.get("broken"):
        ev = list(cr.ledger.events())
        own = {ch["change_id"] for ch in cview.get("changes") or [] if who in requesters_of(ev, ch["change_id"])}
    return templates.TemplateResponse(request, "resolve.html", {"c": cview, "change": change_state.snapshot(),
                                                                "who": who, "hardware": HARDWARE, "own_requests": own,
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
    # (The kind is read from the first line alone: a ledger with no line, or one that is not an event,
    # is not a scan either, and is not a reason to fail.)
    if r and r.ledger.exists() and _run_kind(r.id) != "scan":
        r = Run.latest(VAR, "scan")
    view = run_view(r, signer) if r and r.ledger.exists() and _run_kind(r.id) == "scan" else {}
    from pqch import planning

    plan = planning.build(VAR, r) if view and not view.get("broken") else None
    return templates.TemplateResponse(request, "index.html", {
        "plan": plan,
        "v": view, "hardware": HARDWARE, "scan": state.snapshot(), "change": change_state.snapshot(),
        "sheet": SHEET, "clock": CLOCK, "graph": estate_graph(view, SHEET) if view and not view.get("broken") else None,
        "receipts": receipts_view(VAR, view) if view and not view.get("broken") else None,
        "who": identity(request),
        # The upstream that served a model call is an address on the deployment's own network: named only
        # to a viewer the lab's pages answer.
        "lab_ok": lab_viewer(request),
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
    _refuse_lab_run(request, run)
    r = _scan_run(run)
    if r and _first_event(r.id) is None:        # an empty or unreadable ledger: no such CBOM
        raise HTTPException(404)
    if r:
        _refuse_lab_run(request, r.id)          # the latest scan too, whatever it turns out to be
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
def ask_page(request: Request, q: str | None = None, run: str | None = None, recorded: int = 0):
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
    if r:
        _refuse_lab_run(request, r.id)
    live = os.environ.get("PQCH_DEMO_MODE") != "snapshot"
    # A question is a model call and an embedding index: where there is a front door, only for a viewer
    # signed on through it, as a scan is. (A static copy calls nothing and answers from its recording.)
    if live and (q or "").strip() and TRUSTED_PROXIES and not identity(request):
        raise HTTPException(403, "asking needs the front door's sign-on, on a connection from the front door")
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
    if recorded and ctx["q"]:
        # The stage asks for the answer recorded for this scan, when there is one: a real call made
        # once, kept as it came back and labelled with when, its citations checked again here. A
        # question with no recording falls through to a call now.
        rec = askmod.load_recording(VAR, r.id)
        a = (rec or {}).get("answers", {}).get(ctx["q"])
        if a and "unavailable" not in a:
            events = list(r.ledger.events())
            if verify(events).ok:
                ctx["recorded"] = rec["recorded_at"]
                ctx["bound"] = {"tier": a.get("tier"), "reasoning": a.get("reasoning"), "model": a.get("model"), "embed": a.get("embed_model")}
                ctx["result"] = {**a, "check": askmod.check(a["reply"], a["shown"], events)}
                return templates.TemplateResponse(request, "ask.html", ctx)
    try:
        seam = Seam(load_config(os.environ["PQCH_INFERENCE_CONFIG"]))
        tier, reasoning = seam.for_role(askmod.ROLE)
        ctx["bound"] = {"tier": tier, "reasoning": reasoning and "reasoning" in seam.config["tiers"][tier],
                        "model": seam.config["tiers"][tier].get("model"),
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
            from pqch.inference import failure_text

            ctx["unavailable"] = failure_text(e)     # never the exception's own text: it can carry the gateway's address
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
    from pqch.ledger import verify

    events = list(r.ledger.events())
    if not verify(events).ok:
        # The pages show nothing from a ledger that does not verify; a file to download says nothing of where
        # it came from once it is saved, so none is made.
        raise HTTPException(409, "the run's ledger does not verify; no projection is made from it")
    result = tables.rebuild(events, tables.load(path))
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
    verify contributes. The scan's part is projected here from its verified events: the CBOM file beside
    the ledger is an export, written once when the run closed by whatever projector ran then, and nothing
    ties it to the events (the lab's had 171 components where today's projection of the same ledger has
    188, 2026-11-20). The CBOM is a projection of the ledger; so is every page."""
    from pqch.cbom import house, project
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
    if sr:
        scan_events = list(sr.ledger.events())
        if verify(scan_events).ok:
            bom = project(scan_events)
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


MARKING = os.environ.get("PQCH_MARKING", "").strip() or None
templates.env.globals["marking"] = MARKING
change_state = ScanState()


def identity(request: Request) -> str | None:
    """Who is acting (`_identity_of`): the console's operator in console mode, else the name the front
    door's header carries; in both, only on a connection from a trusted peer."""
    return _identity_of(request.client.host if request.client else None, request.headers.get)


# One JSON line per request for a collector (FR-12), when PQCH_ACCESS_LOG names a file: who, what, the
# answer and how long, with a download of a ledger, a CBOM, a register or a plan marked as one. The
# ledger is already JSON lines; this is the half it does not hold, who read what.
ACCESS_LOG = os.environ.get("PQCH_ACCESS_LOG", "").strip() or None
_DOWNLOAD = (".json", ".jsonl", ".csv", ".pub", ".sig", ".tar", ".zip")


def access_record(request: Request, status: int, ms: float) -> dict:
    path = request.url.path
    return {"schema": "pqch.access/1", "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "who": identity(request), "peer": request.client.host if request.client else None,
            "method": request.method, "path": path, "query": request.url.query or None, "status": status,
            "ms": round(ms, 1), "download": path.endswith(_DOWNLOAD) and not path.startswith("/static/"),
            "marking": MARKING}


if ACCESS_LOG:
    @app.middleware("http")
    async def _access_log(request: Request, call_next):
        t0 = time.monotonic()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            try:
                with open(ACCESS_LOG, "a") as fh:
                    fh.write(json.dumps(access_record(request, status, (time.monotonic() - t0) * 1000)) + "\n")
            except OSError:
                pass        # a full or missing log volume must not take the pages down


def same_origin(request: Request) -> None:
    """Refuse a form posted from another site with the user's sign-on riding along. The browser's own
    statement is believed where it makes one (Sec-Fetch-Site); an Origin must name the host the request
    was sent to; and where the deployment lists its names (ALLOWED_HOSTS), that host must be one of them,
    which the Host check on every request has already required: Origin equal to Host proves nothing on
    its own, because a page whose name was re-pointed at this address sends its own name in both."""
    site = request.headers.get("sec-fetch-site")
    if site and site not in ("same-origin", "none"):
        raise HTTPException(403, "cross-site request")
    origin = request.headers.get("origin")
    if origin:
        named = origin.split("://", 1)[-1]
        if named != request.headers.get("host") or (ALLOWED_HOSTS and _hostname(named) not in ALLOWED_HOSTS):
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
    """The groups the front door says the signed-on person is in, on a connection from the front door.
    In console mode there is no front door and so no groups: the header is not read."""
    peer = request.client.host if request.client else None
    if peer not in TRUSTED_PROXIES or OPERATOR:
        return []
    return sorted({g.strip() for g in (request.headers.get(GROUPS_HEADER) or "").replace(";", ",").split(",") if g.strip()})


def _approver(request: Request) -> tuple[str, list[str]]:
    """Who approves and the groups it rests on; refused when the deployment names an approver group the
    person is not in (ADR-0008), and refused under separation of duties when it names none: the runner
    then requires `role: approver` on the approval, and with no group there is nothing that grants one."""
    who = _who(request)
    groups = groups_of(request)
    if APPROVER_GROUP and APPROVER_GROUP not in groups:
        raise HTTPException(403, f"approving needs the {APPROVER_GROUP} group; the front door lists {', '.join(groups) or 'none'} for {who}")
    if SEPARATION and not APPROVER_GROUP:
        raise HTTPException(403, "separation of duties is on and this deployment names no approver group "
                                 "(PQCH_APPROVER_GROUP), so the page cannot say who holds the approver role; "
                                 "set the group, or approve from the command line in its labelled single-operator mode")
    return who, groups


def requesters_of(events: list[dict], change_id: str) -> set[str]:
    """Who asked for a change, as the runner reads it (runner/apply.py, ADR-0008): whoever recorded the
    policy, and whoever proposed the change as a person. A rule's proposal has no requester."""
    out = {e["payload"].get("by") for e in events if e["type"] == "policy.changed"}
    out |= {e["actor"]["id"] for e in events if e["type"] == "change.proposed"
            and e["payload"].get("change_id") == change_id and e["actor"]["kind"] == "human"}
    out.discard(None)
    return out


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
    if not run.ledger.exists():
        raise HTTPException(404)
    # Refused here, before anything is written. The runner reads the first approval on the ledger and no
    # other, so an approval it will refuse is not a harmless one: it dead-ends the change.
    try:
        events = list(run.ledger.events())
    except ValueError:
        raise HTTPException(409, "the change run's ledger cannot be read") from None
    if not any(e["type"] == "change.proposed" and e["payload"].get("change_id") == change_id for e in events):
        raise HTTPException(404)
    if any(e["type"] in ("approval.granted", "approval.denied") and e["payload"].get("change_id") == change_id for e in events):
        raise HTTPException(409, f"change {change_id} already has an approval or a denial on the ledger; one decision a change")
    if SEPARATION and who in requesters_of(events, change_id):
        raise HTTPException(403, f"{who} asked for this change; under separation of duties another person approves it")

    def go():
        signer = signer_from_env()
        # The role is written only where something granted it: the approver group, matched above.
        approve(run, change_id, by=who, signer=signer, authenticated_by=SIGN_ON,
                role="approver" if APPROVER_GROUP else None, groups=groups or None)
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
    """Put the mini-agency back to its starting state, as the signed-on person asked; then scan. A reset
    undoes every approved change, so where the deployment names who may approve one (an approver group,
    or separation of duties) the same person is who may reset."""
    if PUBLIC:
        raise HTTPException(404)
    from pqch.migrator.reset import reset_estate
    from pqch.pipeline import signer_from_env
    from pqch.runner.client import RunnerClient

    who = _approver(request)[0] if (APPROVER_GROUP or SEPARATION) else _who(request)
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


def script_json(doc) -> str:
    """A document as JSON that is safe inside a <script> block, in every mode: `<`, `>` and `&` leave as
    \\u escapes (no `</script>`, no `<!--`), and the two line separators JSON allows raw and JavaScript
    once did not. The document carries scanned text (certificate subjects, firmware strings, diffs)."""
    return (json.dumps(doc).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
            .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029"))


def _model_gate(request: Request) -> None:
    """Where there is a front door, a route that calls a model or holds the service answers only a viewer
    signed on through it (the rule `/scan` uses)."""
    if TRUSTED_PROXIES and not identity(request):
        raise HTTPException(403, "this needs the front door's sign-on, on a connection from the front door")


@app.get("/api/demo/slow")
async def demo_slow(request: Request, s: float = 5):
    """A pixel that arrives late: the stage's wait hook, so a headless browser's screenshot lands after the live
    animations. It waits on the event loop, not in a worker thread (forty of these would hold every page), and
    only for a signed-on viewer where there is a front door; a static copy has no stills to take."""
    if PUBLIC:
        raise HTTPException(404)
    _model_gate(request)
    from fastapi.responses import Response as _Response
    await asyncio.sleep(max(0.0, min(20.0, s)))
    return _Response(content=b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;", media_type="image/gif")


@app.get("/demo")
def demo_page(request: Request, snap: str | None = None, inline_data: str | None = None, wait: float | None = None):
    inline, static_hw = None, None
    if PUBLIC:
        # the static copy: the document inlined, the test agency only, what the stage would fetch carried inside
        doc = _demo.payload(VAR, SHEET, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots")),
                            hardware="unlabelled", inference_config=None, this_host=None, static=True)
        static_hw = doc.get("hardware")
        inline = script_json(doc)
        snap = inline_data = None
    elif snap or inline_data:  # a still of one beat (snap: the document inlined, animations skipped) or the live stage with the document inlined
        doc = _demo.payload(VAR, SHEET, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots")),
                            hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"), inference_config=os.environ.get("PQCH_INFERENCE_CONFIG"),
                            this_host=os.environ.get("PQCH_THIS_HOST") or None, lab=lab_viewer(request),
                            signer=signer_from_env_safe())
        if snap:
            doc["still"] = _demo.still_block(VAR)      # what a still draws in place of a live call: a recorded answer
        inline = script_json(doc)
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
                                  "so that the agency meets the post-quantum deadlines. The approach: evidence onto a signed record, "
                                  "rules to judge it, a person to approve, a re-scan to prove."),
        "hardware": static_hw or os.environ.get("PQCH_HARDWARE", "unlabelled"), "operator": os.environ.get("PQCH_OPERATOR", "the operator"),
        "static": PUBLIC})


@app.get("/api/demo")
def demo_api(request: Request):
    if PUBLIC:
        raise HTTPException(404)
    # The servers scanned as estates and the engine's address are the lab's: in the document only for a
    # viewer the lab's pages answer. Anyone else gets the test agency's stage, as the static copy does.
    return JSONResponse(_demo.payload(VAR, SHEET, snapshots_dir=Path(os.environ.get("PQCH_SNAPSHOTS", "policy/snapshots")),
                                      hardware=os.environ.get("PQCH_HARDWARE", "unlabelled"),
                                      inference_config=os.environ.get("PQCH_INFERENCE_CONFIG"),
                                      this_host=os.environ.get("PQCH_THIS_HOST") or None, lab=lab_viewer(request),
                                      signer=signer_from_env_safe()))


@app.get("/api/demo/entry")
def demo_entry(ref: str = ""):
    """One component of the latest scan's CBOM, as projected from its verified ledger, with its dependency row:
    the stage shows the entry beside the figure for whatever is under the pointer."""
    if PUBLIC:
        raise HTTPException(404)
    scan = Run.latest(VAR, "scan")
    doc = _demo.projected(scan) if scan and scan.ledger.exists() else None
    if doc is None:
        raise HTTPException(404, "no CBOM yet")
    comp = next((c for c in doc.get("components", []) if c.get("bom-ref") == ref), None)
    if comp is None:
        raise HTTPException(404, "no such entry")
    deps = next((d.get("dependsOn", []) for d in doc.get("dependencies", []) if d.get("ref") == ref), [])
    return JSONResponse({"component": comp, "depends_on": deps, "run": scan.id,
                         "bom": {"format": doc.get("bomFormat"), "spec": doc.get("specVersion"), "serial": doc.get("serialNumber"),
                                 "components": len(doc.get("components", []))}})


@app.post("/api/demo/narrate")
def demo_narrate(request: Request, body: dict = Body(...)):  # noqa: B008 — FastAPI's own idiom
    """One narration line for a plan row. A plain function, so the model call it makes runs in a worker
    thread and not on the event loop (where it stalled every page for the length of the call); the body
    must be a JSON object (anything else is a 422, not a 500)."""
    if PUBLIC:
        raise HTTPException(404)
    same_origin(request)
    _model_gate(request)
    row = body.get("row")
    return JSONResponse(_demo.narrate(str(body.get("kind") or "plan"), row if isinstance(row, dict) else {}))


# ───────────── Ask the field notes: the journal answered by the box's model, citations checked ─────────────
_NOTES_INDEX: dict = {}


@app.get("/notes/ask")
def notes_ask(request: Request, q: str = ""):
    # The journal's text, answered by a model: for a signed-on viewer only, as the journal site itself is.
    _lab_or_404(request)
    from pqch import notes_ask as nmod
    from pqch.inference import Seam, TierUnavailable, failure_text, load_config
    tries = ["How does the runner read a server's files, and as which user?", "What does the verifier check before a change counts as enforced?",
             "Why is a role moved to a model only by measurement?", "What is the event substrate, and what is projected from it?",
             "How is a recording replayed on another box?", "What did spike S3 measure on the GB10?"]
    ctx = {"q": q.strip()[:400], "result": None, "unavailable": None, "tries": tries, "corpus": "—", "embed_model": "the embed tier", "model": "the tier the ask-notes role is bound to"}
    try:
        seam = Seam(load_config(os.environ["PQCH_INFERENCE_CONFIG"]))
        notes_tier = seam.for_role(nmod.ROLE)[0]
        if "embed" not in seam.config["tiers"] or notes_tier not in seam.config["tiers"]:
            raise TierUnavailable("this profile has no embed tier, or none for the ask-notes role")
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
        ctx["unavailable"] = failure_text(e)      # never the exception's own text: it can carry the gateway's address
    return templates.TemplateResponse(request, "notes_ask.html", ctx)
