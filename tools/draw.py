"""Draw the journal's sketches, and marks on screenshots, as hand-drawn SVG (the fieldnotes book).

    uv run --with fonttools --with brotli python tools/draw.py

Every drawing is defined here, from the numbers in the entry it illustrates, and written as
committed SVG: no script runs in the reader's browser, and the same seed draws the same wobble
every time. Two pens, a pencil and a stamp: ballpoint for what is written, stamp red for
what must jump, pencil for what is there but does not count. Handwriting is Caveat, subset
to the characters each file uses and embedded in it, because an SVG shown as an image cannot load
the page's fonts.

Sketches (docs/journal/img/sketches/) belong to the journal and are copied into the site by
tools/build_site.py; an entry shows one as `<figure class="sketch" markdown>` with a full alt text
(the picture's claim) and a one-line figcaption (docs/journal/STYLE.md, Drawings). Each sketch is a
function below named `sketch_<entry>_<slug>`, called from main(); add one, run the tool, look at the SVG. Marks (site_src/img/marks/) are transparent overlays the size of the
screenshot they annotate; the screenshot itself is never edited.
"""

from __future__ import annotations

import base64
import io
import math
import random
from pathlib import Path

from fontTools import subset
from fontTools.ttLib import TTFont

ROOT = Path(__file__).resolve().parent.parent
FONT = ROOT / "site_src" / "stylesheets" / "fonts" / "caveat-latin-wght-normal.woff2"
SKETCHES = ROOT / "docs" / "journal" / "img" / "sketches"
MARKS = ROOT / "site_src" / "img" / "marks"

# The materials: the inks fieldnotes.css names, and a graphite pencil.
INK = "#211a14"
BALLPOINT = "#1f3a8a"
STAMP = "#c8401f"
STAMP_LIGHT = "#f2876a"   # the stamp, written straight onto a dark screen
PENCIL = "#5d6166"   # graphite: what is there but does not count
PAPER = "#f7f2e8"
KRAFT = "#d9c39c"

_font = TTFont(FONT)
_cmap = _font.getBestCmap()
_hmtx = _font["hmtx"]
_upm = _font["head"].unitsPerEm


def measure(text: str, size: float) -> float:
    """Advance width of `text` in Caveat at `size`, plus a little for the drawn weight (600)."""
    units = sum(_hmtx[_cmap.get(ord(c), _cmap[ord("?")])][0] for c in text)
    return units * size / _upm * 1.04


def _font_face(chars: set[str]) -> str:
    opts = subset.Options()
    opts.flavor = "woff2"
    opts.layout_features = ["*"]
    sub = subset.Subsetter(opts)
    sub.populate(text="".join(sorted(chars | {" "})))
    font = TTFont(FONT, recalcTimestamp=False)   # else the head table carries the time of the run
    sub.subset(font)
    buf = io.BytesIO()
    font.save(buf)
    data = base64.b64encode(buf.getvalue()).decode()
    return f'@font-face{{font-family:"Caveat";font-weight:400 700;src:url(data:font/woff2;base64,{data}) format("woff2");}}'


def _smooth(pts: list[tuple[float, float]]) -> str:
    """Catmull-Rom through the points, as cubic Béziers: a line that bends like a hand's."""
    d = [f"M{pts[0][0]:.1f},{pts[0][1]:.1f}"]
    for i in range(len(pts) - 1):
        p0 = pts[i - 1] if i > 0 else pts[i]
        p1, p2 = pts[i], pts[i + 1]
        p3 = pts[i + 2] if i + 2 < len(pts) else p2
        c1 = (p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6)
        d.append(f"C{c1[0]:.1f},{c1[1]:.1f} {c2[0]:.1f},{c2[1]:.1f} {p2[0]:.1f},{p2[1]:.1f}")
    return " ".join(d)


class Page:
    """One drawing. `u` scales strokes and lettering, so a mark on a 3000-px screenshot reads like
    one on a 1600-px one."""

    def __init__(self, w: float, h: float, seed: int, u: float = 1.0, title: str = ""):
        self.w, self.h, self.u = w, h, u
        self.r = random.Random(seed)
        self.title = title
        self.parts: list[str] = []
        self.chars: set[str] = set()

    def j(self, amt: float) -> float:
        return self.r.uniform(-amt, amt) * self.u

    # ---- strokes ---------------------------------------------------------------------------
    def line(self, x1, y1, x2, y2, color=BALLPOINT, width=2.2, dash=False, opacity=1.0):
        length = math.hypot(x2 - x1, y2 - y1) or 1
        nx, ny = -(y2 - y1) / length, (x2 - x1) / length
        bow = self.r.uniform(-1, 1) * min(length * 0.012, 6 * self.u)
        pts = [(x1 + self.j(1.5), y1 + self.j(1.5))]
        for t in (0.33, 0.66):
            pts.append((x1 + (x2 - x1) * t + nx * bow, y1 + (y2 - y1) * t + ny * bow))
        pts.append((x2 + self.j(1.5), y2 + self.j(1.5)))
        self._path(_smooth(pts), color, width, dash, opacity)

    def curve(self, pts, color=BALLPOINT, width=2.2, dash=False, opacity=1.0):
        self._path(_smooth([(x + self.j(1), y + self.j(1)) for x, y in pts]), color, width, dash, opacity)

    def arrow(self, pts, color=BALLPOINT, width=2.2, head=13):
        self.curve(pts, color, width)
        (ax, ay), (bx, by) = pts[-2], pts[-1]
        ang = math.atan2(by - ay, bx - ax)
        for side in (-1, 1):
            a = ang + math.pi + side * math.radians(26)
            hl = head * self.u
            self.line(bx, by, bx + math.cos(a) * hl, by + math.sin(a) * hl, color, width)

    def ring(self, cx, cy, rx, ry, color=STAMP, width=2.8):
        """A loop drawn round something: it overshoots its start and does not quite close."""
        start = self.r.uniform(0, 2 * math.pi)
        n = 14
        pts = []
        for i in range(n + 1):
            t = start + (2 * math.pi + 0.55) * i / n
            grow = 1 + 0.07 * i / n
            pts.append((cx + math.cos(t) * rx * grow + self.j(1.2), cy + math.sin(t) * ry * grow + self.j(1.2)))
        self._path(_smooth(pts), color, width, False, 1.0)

    def box(self, x, y, w, h, color=BALLPOINT, width=2.2, fill=None, over=4, dash=False):
        o = over * self.u
        if fill:
            self.parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" fill="{fill}"/>')
        self.line(x - o, y, x + w + o * 0.5, y, color, width, dash)
        self.line(x + w, y - o * 0.5, x + w, y + h + o, color, width, dash)
        self.line(x + w + o * 0.5, y + h, x - o * 0.5, y + h, color, width, dash)
        self.line(x, y + h + o * 0.5, x, y - o, color, width, dash)

    def stamp(self, cx, cy, s, size=64, color=STAMP):
        """A rubber-stamped count: the number in a ruled box, inked once, not quite square."""
        w = measure(s, size) + 34 * self.u
        h = size * 1.05
        self.box(cx - w / 2, cy - h / 2, w, h, color, 3.2, over=2)
        self.text(cx, cy + size * 0.3, s, size, color, "middle", 700)

    def cross(self, x, y, size=16, color=STAMP, width=3.0):
        s = size * self.u
        self.line(x, y, x + s, y + s, color, width)
        self.line(x + s, y, x, y + s, color, width)

    def tick(self, x, y, size=16, color=STAMP, width=3.0):
        s = size * self.u
        self.curve([(x, y), (x + s * 0.35, y + s * 0.45), (x + s, y - s * 0.6)], color, width)

    def _path(self, d, color, width, dash, opacity):
        extra = f' stroke-dasharray="{6 * self.u:.1f} {7 * self.u:.1f}"' if dash else ""
        if opacity < 1:
            extra += f' opacity="{opacity}"'
        self.parts.append(
            f'<path d="{d}" fill="none" stroke="{color}" stroke-width="{width * self.u:.2f}" '
            f'stroke-linecap="round" stroke-linejoin="round"{extra}/>')

    # ---- writing ---------------------------------------------------------------------------
    def text(self, x, y, s, size=24, color=BALLPOINT, anchor="start", weight=600, opacity=1.0):
        self.chars |= set(s)
        esc = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        op = f' opacity="{opacity}"' if opacity < 1 else ""
        self.parts.append(
            f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size * self.u:.1f}" fill="{color}" '
            f'font-weight="{weight}" text-anchor="{anchor}"{op}>{esc}</text>')

    def slip(self, x, y, lines, size=24, color=BALLPOINT, pad=14, tape=True):
        """A torn-off slip of the book's paper, taped over the screen, with a note written on it.
        Returns its box (x, y, w, h) so an arrow can leave from its edge."""
        s, p = size * self.u, pad * self.u
        lh = s * 1.12
        w = max(measure(t, s) for t in lines) + 2 * p
        h = lh * len(lines) + p * 1.3
        c = [(x + self.j(2), y + self.j(2)), (x + w + self.j(2), y + self.j(2)),
             (x + w + self.j(2), y + h + self.j(2)), (x + self.j(2), y + h + self.j(2))]
        pts = " ".join(f"{a:.1f},{b:.1f}" for a, b in c)
        self.parts.append(f'<polygon points="{pts}" fill="{PAPER}" filter="url(#lift)"/>')
        if tape:
            tw, th = 70 * self.u, 20 * self.u
            tx = x + w * self.r.uniform(0.3, 0.6) - tw / 2
            self.parts.append(
                f'<rect x="{tx:.1f}" y="{y - th / 2:.1f}" width="{tw:.1f}" height="{th:.1f}" '
                f'fill="{KRAFT}" opacity=".75"/>')
        for i, t in enumerate(lines):
            self.text(x + p, y + p * 0.55 + lh * (i + 0.8), t, size, color)
        return x, y, w, h

    # ---- output ----------------------------------------------------------------------------
    def svg(self) -> str:
        style = _font_face(self.chars) + 'text{font-family:"Caveat","Segoe Script",cursive;}'
        title = f"<title>{self.title}</title>" if self.title else ""
        lift = (f'<filter id="lift" x="-10%" y="-10%" width="130%" height="140%">'
                f'<feDropShadow dx="0" dy="{2 * self.u:.1f}" stdDeviation="{3 * self.u:.1f}" '
                f'flood-color="#000" flood-opacity=".35"/></filter>')
        return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {self.w} {self.h}" '
                f'width="{self.w}" height="{self.h}">{title}<defs><style>{style}</style>{lift}</defs>'
                + "".join(self.parts) + "</svg>\n")

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.svg(), encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")


# ==== sketches ===================================================================================


# Each sketch is one function: the entry's numbers in as named constants, an SVG out, named
# sketch_<entry>_<slug> and written to docs/journal/img/sketches/<entry>-<slug>.svg. The survey that
# chose them and the record of each one are docs/journal/img/sketches/PLAN.md and PROGRESS.md. Before
# committing one, render it and look: tools/render_sketch.py <svg> <png> 1200.


def sketch_12_ledger_chain() -> None:
    """Note 12, the worked example: a change run of 15 events and 5 checkpoints, chained by hash,
    with the CBOM projected from the chain and never edited."""
    EVENTS = ["scope", "policy change", "proposal", "approval", "checkpoint", "apply", "verdict",
              "checkpoint", "recreate", "verdict", "checkpoint", "a further check", "checkpoint",
              "closing checkpoint", "close"]          # 15 events, in the entry's order
    N_EVENTS, N_CHECKPOINTS = 15, 5                  # note 12, worked example
    SIGNATURE = "ML-DSA-65"                          # note 12, "Signed checkpoints"
    assert len(EVENTS) == N_EVENTS and sum("checkpoint" in e for e in EVENTS) == N_CHECKPOINTS

    p = Page(1000, 660, seed=12, title="The ledger is the record; the CBOM is rebuilt from it")
    p.text(500, 50, "Append an event. Never edit one. Rebuild the rest.", 36, INK, "middle")

    # The chain, top to bottom: one box per event, one line through them all.
    x0, y0, step = 170, 104, 34
    p.text(x0 - 10, 88, "the ledger: one file, one line per event", 20, PENCIL)
    p.line(x0 + 12, y0 - 4, x0 + 12, y0 + step * (N_EVENTS - 1) + 4, BALLPOINT, 2.4)
    for i, name in enumerate(EVENTS):
        y = y0 + i * step
        is_cp = "checkpoint" in name
        p.box(x0, y - 11, 24, 22, BALLPOINT, 2.0, fill=PAPER, over=2)
        p.text(x0 + 12, y + 7, str(i + 1), 17, INK, "middle")
        p.text(x0 + 44, y + 8, name, 23, BALLPOINT if not is_cp else INK)
        if is_cp:
            w = measure(name, 23)
            p.tick(x0 + 52 + w, y - 2, 13, BALLPOINT, 2.4)
            p.text(x0 + 72 + w, y + 8, "signed", 18, PENCIL)
    # One `prev` arrow, drawn once: each event carries the hash of the one before.
    p.arrow([(x0 - 14, y0 + step * 1.0), (x0 - 30, y0 + step * 0.5), (x0 - 14, y0 + 3)], BALLPOINT, 1.8, 9)
    p.text(x0 - 36, y0 + step * 2.4, "prev:", 18, PENCIL, "end")
    p.text(x0 - 36, y0 + step * 3.0, "the hash", 18, PENCIL, "end")
    p.text(x0 - 36, y0 + step * 3.6, "of the one", 18, PENCIL, "end")
    p.text(x0 - 36, y0 + step * 4.2, "before", 18, PENCIL, "end")

    # The count, and the signer.
    p.text(x0 - 10, y0 + step * N_EVENTS + 10, f"{N_EVENTS} events, {N_CHECKPOINTS} checkpoints: one change run", 20, PENCIL)
    p.text(430, 118, "a checkpoint is signed", 21, PENCIL)
    p.text(430, 144, f"with {SIGNATURE} by a separate", 21, PENCIL)
    p.text(430, 170, "signer that keeps its own list", 21, PENCIL)
    p.text(430, 196, "of what it signed", 21, PENCIL)

    # The projection: the CBOM, rebuilt from the chain.
    cx, cy, cw, ch = 640, 300, 300, 200
    p.arrow([(420, 390), (500, 395), (600, 382), (cx - 12, 378)], BALLPOINT, 2.4)
    p.text(490, 372, "projected", 22, BALLPOINT)
    p.box(cx, cy, cw, ch, INK, 2.2, fill=PAPER)
    p.text(cx + cw / 2, cy + 46, "CBOM", 34, INK, "middle")
    p.text(cx + 18, cy + 90, "a pure function of the events:", 20, BALLPOINT)
    p.text(cx + 18, cy + 116, "no clock, no randomness,", 20, BALLPOINT)
    p.text(cx + 18, cy + 142, "the same events give", 20, BALLPOINT)
    p.text(cx + 18, cy + 168, "the same bytes", 20, BALLPOINT)
    p.text(cx, cy + ch + 30, "so are the scores and every screen:", 19, PENCIL)
    p.text(cx, cy + ch + 54, "delete them, rebuild them", 19, PENCIL)

    # The one thing nobody does: the pencil hand that would edit the CBOM, crossed out.
    p.arrow([(930, 200), (880, 240), (cx + cw - 50, cy - 6)], PENCIL, 1.8)
    p.text(760, 196, "an edit", 20, PENCIL)
    p.cross(868, 214, 30, STAMP, 3.4)
    p.text(884, 262, "never", 24, STAMP)
    p.save(SKETCHES / "12-ledger-chain.svg")


def sketch_08_paired_verdict() -> None:
    """Note 08: a change is verified when a client offering only the new group connects and a client
    offering only the old ones is refused; accepted both times is enabled, not enforced. The status
    table and the probe timings are the entry's."""
    NEW = "X25519MLKEM768"                       # the hybrid group, note 08
    PROBE_S, WITNESS_S = "about 1 s", "21 to 31 s"   # note 08, claims (measured 2026-10-03, xr7620)
    ROWS = [("enforced", "accepted", "refused", "the policy is met"),
            ("enabled-not-enforced", "accepted", "accepted", "old clients still get classical keys"),
            ("not-landed", "refused", "either", "the change did not take"),
            ("inconclusive", "—", "—", "a probe failed; never guessed")]   # note 08, the status table

    p = Page(1000, 680, seed=8, title="Two probes: the new one must connect, the old one must be refused")
    p.text(500, 50, "One client that can only do the new. One that can only do the old.", 34, INK, "middle")

    # The listener, in the middle.
    lx, ly, lw, lh = 390, 130, 220, 110
    p.box(lx, ly, lw, lh, INK, 2.2, fill=PAPER)
    p.text(lx + lw / 2, ly + 44, "the listener", 28, INK, "middle")
    p.text(lx + lw / 2, ly + 74, "after the change", 21, PENCIL, "middle")
    p.text(lx + lw / 2, ly + 96, "on the container it was applied to", 16, PENCIL, "middle")

    # Probe 1, from the left: offers only the new group.
    p.box(40, 140, 250, 92, BALLPOINT, 2.0)
    p.text(58, 172, "client 1 offers only", 22, BALLPOINT)
    p.text(58, 202, NEW, 24, INK)
    p.arrow([(292, 186), (340, 184), (lx - 6, 186)], BALLPOINT, 2.2)
    p.text(316, 172, "?", 22, PENCIL, "middle")
    p.tick(300, 262, 18, BALLPOINT, 3.0)
    p.text(326, 272, "must connect", 23, BALLPOINT)

    # Probe 2, from the right: offers only the old groups, every one of them.
    p.box(710, 140, 250, 92, BALLPOINT, 2.0)
    p.text(728, 172, "client 2 offers only", 22, BALLPOINT)
    p.text(728, 202, "the old groups, every one", 22, INK)
    p.arrow([(708, 186), (660, 184), (lx + lw + 6, 186)], BALLPOINT, 2.2)
    p.text(684, 172, "?", 22, PENCIL, "middle")
    p.cross(624, 250, 18, BALLPOINT, 3.0)
    p.text(652, 272, "must be refused", 23, BALLPOINT)

    # The status table: what the pair says.
    ty = 330
    cols = (70, 400, 560, 720)
    p.text(cols[1], ty, "client 1", 20, PENCIL)
    p.text(cols[2], ty, "client 2", 20, PENCIL)
    p.text(cols[3], ty, "meaning", 20, PENCIL)
    p.line(60, ty + 10, 950, ty + 10, PENCIL, 1.2, opacity=0.6)
    for i, (status, a, b, why) in enumerate(ROWS):
        y = ty + 46 + i * 62
        p.text(cols[0], y, status, 25, INK)
        p.text(cols[1], y, a, 23, BALLPOINT)
        p.text(cols[2], y, b, 23, BALLPOINT)
        p.text(cols[3], y, why, 19, PENCIL)
    # The point: accepted twice is not a pass.
    ry = ty + 46 + 1 * 62
    p.ring(cols[2] + measure("accepted", 23) / 2, ry - 8, measure("accepted", 23) / 2 + 18, 22)
    p.text(cols[2] + measure("accepted", 23) / 2 + 2, ry + 34, "enabled is not enforced", 21, STAMP, "middle")

    # Cost, in pencil.
    p.text(60, 628, f"each probe {PROBE_S}; a second witness of another kind enumerates every group, {WITNESS_S},", 19, PENCIL)
    p.text(60, 652, "and the pair runs again after the service is recreated", 19, PENCIL)
    p.save(SKETCHES / "08-paired-verdict.svg")


def sketch_20_four_clocks() -> None:
    """Note 20, the answer and the concept: a server's cryptography sits in four places, each with
    its own owner and clock, and a scan of the listeners alone sees the first. Nothing from the
    note's lab block is drawn."""
    PLACES = [  # (place, who changes it, what the runner reads there), from note 20's answer and jobs table
        ("its listeners", "changed by its software",
         ["key exchange", "host keys", "certificates", "protocol versions"]),
        ("its own files", "changed by its administrators",
         ["certificates", "public and private keys", "keystores", "unreadable files, listed"]),
        ("its firmware's trust databases", "changed by firmware updates",
         ["PK, KEK, db and dbx", "with keys and dates", "Secure Boot on or off", "the TPM's banks"]),
        ("its management controller", "changed by the controller's", "firmware and its settings"),
    ]
    PLACES[3] = ("its management controller", "changed by the controller's firmware and settings",
                 ["its own TLS and SSH", "SNMP, FIPS mode", "identity certificates", "firmware inventory"])
    N_JOBS = 10   # note 20: "The runner reads; nothing is installed. Ten jobs"

    p = Page(1000, 620, seed=20, title="Four places, four owners, four clocks")
    p.text(500, 50, "Four places, four owners, four clocks. One record.", 36, INK, "middle")

    colw, gap, x0, top = 218, 18, 40, 100
    for i, (place, who, reads) in enumerate(PLACES):
        x = x0 + i * (colw + gap)
        cx = x + colw / 2
        # A clock face, with its hands set differently in each column.
        p.ring(cx, top + 30, 22, 22, BALLPOINT, 2.0)
        ang = [-90, 30, 150, 250][i]
        p.line(cx, top + 30, cx + 13 * math.cos(math.radians(ang)), top + 30 + 13 * math.sin(math.radians(ang)), BALLPOINT, 2.0)
        p.line(cx, top + 30, cx + 8 * math.cos(math.radians(ang + 100)), top + 30 + 8 * math.sin(math.radians(ang + 100)), BALLPOINT, 2.0)
        # The place and its owner.
        p.box(x, top + 72, colw, 284, BALLPOINT, 2.0)
        lines = [place] if measure(place, 24) < colw - 24 else place.replace("its firmware's trust databases", "its firmware's\ntrust databases").replace("its management controller", "its management\ncontroller").split("\n")
        for k, t in enumerate(lines):
            p.text(cx, top + 104 + k * 28, t, 24, INK, "middle")
        wy = top + 104 + 28 * len(lines) + 2
        wl = [who] if measure(who, 18) < colw - 20 else [who[:who.index(" firmware")], who[who.index(" firmware") + 1:]]
        for k, t in enumerate(wl):
            p.text(cx, wy + k * 22, t, 18, PENCIL, "middle")
        p.line(x + 24, wy + 22 * len(wl) + 4, x + colw - 24, wy + 22 * len(wl) + 4, PENCIL, 1.2, opacity=0.6)
        ry = wy + 22 * len(wl) + 34
        p.text(x + 16, ry - 8, "the runner reads:", 17, PENCIL)
        for k, t in enumerate(reads):
            p.text(x + 16, ry + 20 + k * 26, t, 20, BALLPOINT)

    # The point: a scan of the listeners alone sees the first place and no other.
    p.ring(x0 + colw / 2, top + 214, colw / 2 + 6, 154, STAMP, 2.8)
    p.text(x0 + colw / 2 + 8, top + 396, "a scan of the listeners sees this one", 22, STAMP)
    p.text(x0 + colw / 2 + 8, top + 422, "and nothing below the operating system", 22, STAMP)

    # The record: one runner, ten jobs, one ledger.
    bx = x0 + 2 * (colw + gap) + 40
    p.text(bx, top + 396, f"one runner, {N_JOBS} read-only jobs, nothing installed,", 20, PENCIL)
    p.text(bx, top + 422, "into one signed ledger; the CBOM carries the server", 20, PENCIL)
    p.text(bx, top + 448, "as a device and its firmware as components", 20, PENCIL)
    p.save(SKETCHES / "20-four-clocks.svg")


def sketch_17_lanes_and_waves() -> None:
    """Note 17: the plan as lanes (one per service) over waves, with the four shared dependencies
    that set the order. The step counts and the spreadsheet's row count are the entry's; the boxes
    are the steps the entry's worked example names, not all 26."""
    STEPS, WAITING, DEPENDENCIES, ENTRIES = 26, 15, 4, 34   # note 17, claims (computed 2026-10-22)
    SHEET_ROWS, SHEET_EMPTY, SHEET_MISSING = 6, 2, 4          # the agency's spreadsheet, same claim
    LANES = ["message queue", "case-management app", "internal CA", "records database", "portal",
             "partner API", "post-quantum gateway", "SFTP drop", "jump host"]

    p = Page(1000, 760, seed=17, title="The plan's order comes from what the services share")
    p.text(500, 48, "The order comes from what they share. A list of systems has no lines.", 33, INK, "middle")

    lx, top, rh = 40, 96, 62
    cols = {"now": 236, "kex": 486, "sig": 736}
    cw = 228
    p.text(cols["now"] + cw / 2, top, "now: depends on nothing", 21, PENCIL, "middle")
    p.text(cols["kex"] + cw / 2, top, "key establishment", 21, PENCIL, "middle")
    p.text(cols["sig"] + cw / 2, top, "signatures", 21, PENCIL, "middle")
    p.line(lx, top + 12, 970, top + 12, PENCIL, 1.2, opacity=0.6)

    def lane_y(i):
        return top + 30 + i * rh

    for i, name in enumerate(LANES):
        p.text(lx, lane_y(i) + 32, name, 22, INK if name != "internal CA" else PENCIL)
        if i:
            p.line(lx, lane_y(i) - 2, 970, lane_y(i) - 2, PENCIL, 0.8, opacity=0.35)

    boxes = {}

    def step(key, lane, col, lines, done=False, color=BALLPOINT):
        x, y = cols[col], lane_y(lane) + 6
        h = rh - 14
        p.box(x, y, cw, h, color, 1.9)
        for k, t in enumerate(lines):
            p.text(x + 10, y + 22 + k * 21, t, 18 if len(lines) > 1 else 20, color)
        if done:
            p.tick(x + cw - 30, y + 10, 16, BALLPOINT, 2.6)
        boxes[key] = (x, y, cw, h)
        return boxes[key]

    def link(a, b, color=BALLPOINT):
        ax, ay, aw, ah = boxes[a]
        bx, by, bw, bh = boxes[b]
        if abs(ax - bx) < 1:   # same column: vertical
            if by > ay:
                p.arrow([(ax + aw / 2, ay + ah), (bx + bw / 2, by)], color, 1.8, 9)
            else:
                p.arrow([(ax + aw / 2, ay), (bx + bw / 2, by + bh)], color, 1.8, 9)
        else:
            p.arrow([(ax + aw, ay + ah / 2), (ax + aw + 24, ay + ah / 2 + (by - ay) * 0.3), (bx - 4, by + bh / 2)], color, 1.8, 9)

    # The certificate authority: two replacements first, then the root, then three certificates.
    step("q-replace", 0, "now", ["replace its software:", "no post-quantum signature"])
    step("a-replace", 1, "now", ["replace its software:", "no post-quantum signature"])
    step("ca-root", 2, "sig", ["an ML-DSA root,", "distributed everywhere"])
    step("q-reissue", 0, "sig", ["reissue its certificate"])
    step("a-reissue", 1, "sig", ["reissue its certificate"])
    step("r-reissue", 3, "sig", ["reissue its certificate"])
    link("q-replace", "ca-root")
    link("a-replace", "ca-root")
    cx_, cy_, cw_, ch_ = boxes["ca-root"]
    qx_, qy_, qw_, qh_ = boxes["q-reissue"]
    p.arrow([(cx_ + cw_ + 2, cy_ + ch_ / 2 - 6), (cx_ + cw_ + 18, cy_ - 30), (qx_ + qw_ + 18, qy_ + qh_ + 20), (qx_ + qw_ + 2, qy_ + qh_ / 2)], BALLPOINT, 1.8, 9)
    link("ca-root", "a-reissue")
    link("ca-root", "r-reissue")
    # The records database's require change: done.
    step("r-require", 3, "kex", ["require the hybrid group"], done=True)
    p.text(cols["kex"] + cw - 44, lane_y(3) + 50, "done", 16, PENCIL, "end")
    # One library build: two already negotiate the hybrid group; for the portal it is a setting.
    step("p-setting", 4, "kex", ["the hybrid group:", "a setting, not an upgrade"])
    p.text(cols["now"] + 8, lane_y(4) + 24, "one OpenSSL build on portal,", 17, PENCIL)
    p.text(cols["now"] + 8, lane_y(4) + 44, "API and gateway; two of them", 17, PENCIL)
    p.text(cols["now"] + 8, lane_y(5) + 24, "already negotiate", 17, PENCIL)
    p.text(cols["now"] + 8, lane_y(5) + 44, "X25519MLKEM768", 17, PENCIL)
    p.curve([(cols["now"] + cw + 6, lane_y(4) + 14), (cols["now"] + cw + 14, lane_y(4) + 30),
             (cols["now"] + cw + 14, lane_y(6) + 30), (cols["now"] + cw + 6, lane_y(6) + 46)], PENCIL, 1.6)
    p.text(cols["kex"] + 8, lane_y(6) + 36, "already hybrid: proves the build", 17, PENCIL)
    # One key on two ports, and a partner CA that sets the pace.
    step("api-reissue", 5, "sig", ["one key on 443 and 8443:", "one step for both"])
    p.arrow([(975, lane_y(5) - 30), (cols["sig"] + cw + 10, lane_y(5) + 10)], PENCIL, 1.6, 9)
    p.text(974, lane_y(5) - 38, "the partners' CA sets the pace", 16, PENCIL, "end")
    # The SFTP drop: an upgrade the estate already holds, then the hybrid key exchange.
    step("s-upgrade", 7, "now", ["upgrade OpenSSH 6.6 to 10.0,", "which the jump host runs"])
    step("s-kex", 7, "kex", ["the hybrid key exchange"])
    link("s-upgrade", "s-kex")
    p.text(cols["now"] + 8, lane_y(8) + 36, "OpenSSH 10.0 lists the hybrid already", 17, PENCIL)

    # The point: the authority is in no row of the list.
    bx, by, bw, bh = boxes["ca-root"]
    p.ring(bx + bw / 2, by + bh / 2, bw / 2 + 10, bh / 2 + 10)
    p.text(lx, lane_y(2) + 52, "no row in the list holds it", 19, STAMP)

    # The counts.
    yb = lane_y(len(LANES)) + 16
    p.stamp(110, yb + 30, str(STEPS), 44, BALLPOINT)
    p.text(170, yb + 24, "steps over", 20, PENCIL)
    p.text(170, yb + 48, f"{ENTRIES} CBOM entries", 20, PENCIL)
    p.stamp(360, yb + 30, str(WAITING), 44, BALLPOINT)
    p.text(416, yb + 24, "wait on", 20, PENCIL)
    p.text(416, yb + 48, "another step", 20, PENCIL)
    p.stamp(590, yb + 30, str(DEPENDENCIES), 44, BALLPOINT)
    p.text(632, yb + 24, "shared", 20, PENCIL)
    p.text(632, yb + 48, "dependencies", 20, PENCIL)
    p.text(780, yb + 24, f"the spreadsheet: {SHEET_ROWS} rows,", 20, PENCIL)
    p.text(780, yb + 48, f"{SHEET_EMPTY} empty, {SHEET_MISSING} of 8 services missing", 20, PENCIL)
    p.save(SKETCHES / "17-lanes-and-waves.svg")


def sketch_03_the_clock() -> None:
    """Note 03, the dates table: EO 14412 and OMB M-26-15 on one line, with the inventory required
    in the discovery phase before the minimum elements of a CBOM are published on 2027-03-19."""
    def t(year, month=1, day=1):   # a date as a fraction of a year
        return year + (month - 1) / 12 + (day - 1) / 365
    EVENTS = [  # (date, label, source), note 03's dates table
        (t(2026, 6, 22), ["EO 14412", "signed"], "2026-06-22"),
        (t(2026, 10, 22), ["each agency's", "migration plan due"], "2026-10-22"),
        (t(2027, 3, 19), ["CISA and NIST publish the", "minimum elements of a CBOM"], "2027-03-19"),
        (t(2030, 1, 2), ["TLS 1.3", "supported"], "2030-01-02"),
        (t(2030, 12, 31), ["key establishment post-quantum", "on prioritized systems"], "2030-12-31"),
        (t(2031, 12, 31), ["signatures", "post-quantum"], "2031-12-31"),
        (t(2035), ["full migration of", "remaining systems"], "2035"),
    ]
    PHASES = [  # (start, end, label), M-26-15 §3.D as the table carries them
        (t(2026), t(2028), "Phase 1: strategy, planning and discovery: the inventory is built"),
        (t(2027), t(2029), "Phase 2: pilots, prioritized systems"),
        (t(2028), t(2031), "Phase 3: prioritized key establishment"),
        (t(2031), t(2032), "Phase 4: signatures"),
    ]
    X0, X1, Y = 80, 940, 300
    scale = (X1 - X0) / (t(2036) - t(2026))

    def x(d):
        return X0 + (d - t(2026)) * scale

    p = Page(1000, 600, seed=3, title="The inventory is required before anyone has said what it must contain")
    p.text(500, 48, "The inventory is due before its contents are defined.", 36, INK, "middle")

    # The line and its years.
    p.line(X0 - 10, Y, X1 + 10, Y, INK, 2.4)
    for yr in range(2026, 2036):
        xx = x(t(yr))
        p.line(xx, Y - 6, xx, Y + 6, INK, 1.6)
        p.text(xx + 4, Y + 28, str(yr), 18, PENCIL)
    # The events, above the line, at three heights so the labels do not collide.
    heights = [40, 172, 104, 70, 140, 70, 140]
    for (d, lines, when), h in zip(EVENTS, heights):
        xx = x(d)
        red = when == "2027-03-19"
        col = STAMP if red else BALLPOINT
        p.line(xx, Y - 2, xx, Y - h + 26, col, 1.6, dash=not red)
        anchor = "end" if when == "2026-06-22" or d >= t(2034) else "start"
        tx = xx + 6 if anchor == "start" else xx - 6
        p.text(tx, Y - h - 28, when, 17, PENCIL, anchor)
        for k, s in enumerate(lines):
            p.text(tx, Y - h + k * 22, s, 19, col, anchor)
    # The phases, below the line, as bars.
    for i, (a, b, label) in enumerate(PHASES):
        yy = Y + 60 + i * 44
        p.line(x(a), yy, x(b), yy, BALLPOINT, 5.0, opacity=0.5)
        p.line(x(a), yy - 7, x(a), yy + 7, BALLPOINT, 1.6)
        p.line(x(b), yy - 7, x(b), yy + 7, BALLPOINT, 1.6)
        p.text(x(b) + 10, yy + 7, label, 18, PENCIL)
    # The point: the minimum elements land after the discovery phase has begun.
    mx = x(t(2027, 3, 19))
    p.ring(mx + 96, Y - 104 + 8, 120, 28)
    p.text(X0 + 20, Y + 60 + 4 * 44 + 10, "the minimum elements arrive inside the discovery phase: an inventory built to one shape", 19, PENCIL)
    p.text(X0 + 20, Y + 60 + 4 * 44 + 34, "may be measured against another, so this project keeps the record and projects the CBOM", 19, PENCIL)
    p.save(SKETCHES / "03-the-clock.svg")


def sketch_06_the_chain() -> None:
    """Note 06, the worked example: the portal's X25519 entry and the six links above it, three
    discovered by rule from named ledger events and three supplied by the owner, labelled, and never
    counted as coverage."""
    LINKS = [  # bottom to top: (link, status, what it rests on), from the worked example's table
        ("listener TLS 172.16.106.10:443", "discovered", ["scan.completed: testssl.sh 3.2.4,", "raw output by hash"]),
        ("certificate RSA (2048)", "discovered", ["link/public-key/1: the same public key", "in /etc/nginx/tls/portal.crt"]),
        ("service portal", "discovered", ["link/service/1: the scope names portal;", "binding/scope/1: its container ran the", "scope's image for the whole scan"]),
        ("mission function: benefits enrollment", "supplied", ["link.asserted by the operator;", "agency/context.yaml, sha256 recorded"]),
        ("data lifetime: 10 years", "supplied", ["the same"]),
        ("high-value asset: no", "supplied", ["the same"]),
    ]
    FINDING = "X25519 key exchange, seen on the wire"   # the entry: the portal's X25519 key-exchange entry

    p = Page(1000, 630, seed=6, title="A finding becomes a chain: three links found, three told")
    p.text(500, 48, "Three links the evidence found. Three a person said.", 36, INK, "middle")

    bx, bw, bh, step = 390, 300, 44, 72
    y_bottom = 590
    # The observation at the bottom.
    p.box(bx, y_bottom - bh, bw, bh, INK, 2.2, fill=PAPER)
    p.text(bx + bw / 2, y_bottom - 15, FINDING, 20, INK, "middle")
    p.text(bx - 14, y_bottom - 15, "the finding", 20, PENCIL, "end")
    # The links, rising.
    for i, (link, status, rests) in enumerate(LINKS):
        y = y_bottom - 2 * bh - 28 - i * step   # the box's top
        supplied = status == "supplied"
        p.arrow([(bx + bw / 2, y + bh + 26), (bx + bw / 2, y + bh + 4)], BALLPOINT if not supplied else PENCIL, 1.8, 9)
        p.box(bx, y, bw, bh, BALLPOINT, 2.0, dash=supplied)
        p.text(bx + bw / 2, y + 29, link, 21, BALLPOINT, "middle")
        for k, t in enumerate(rests):
            p.text(bx + bw + 16, y + 18 + k * 20, t, 16, PENCIL)
        p.text(bx - 14, y + 29, status, 20, INK if not supplied else PENCIL, "end")
    # Braces: what the rule asserted from the ledger, and what the owner typed in.
    top_sup = y_bottom - 2 * bh - 28 - 5 * step
    top_disc = y_bottom - 2 * bh - 28 - 2 * step
    p.curve([(bx - 128, top_disc + 2), (bx - 140, top_disc + 10), (bx - 140, top_disc + 1.5 * step - 10),
             (bx - 150, top_disc + 1.5 * step), (bx - 140, top_disc + 1.5 * step + 10), (bx - 140, top_disc + 3 * step - 24), (bx - 128, top_disc + 3 * step - 16)], BALLPOINT, 1.8)
    p.text(bx - 160, top_disc + 1.5 * step - 8, "a rule asserted each,", 18, BALLPOINT, "end")
    p.text(bx - 160, top_disc + 1.5 * step + 14, "naming its ledger events", 18, BALLPOINT, "end")
    p.curve([(bx - 128, top_sup + 2), (bx - 140, top_sup + 10), (bx - 140, top_sup + 1.5 * step - 10),
             (bx - 150, top_sup + 1.5 * step), (bx - 140, top_sup + 1.5 * step + 10), (bx - 140, top_sup + 3 * step - 24), (bx - 128, top_sup + 3 * step - 16)], STAMP, 2.4)
    p.text(bx - 160, top_sup + 1.5 * step - 20, "typed in by the owner,", 19, STAMP, "end")
    p.text(bx - 160, top_sup + 1.5 * step + 2, "labelled supplied,", 19, STAMP, "end")
    p.text(bx - 160, top_sup + 1.5 * step + 24, "never counted as coverage", 19, STAMP, "end")
    p.save(SKETCHES / "06-the-chain.svg")


def sketch_07_two_queues() -> None:
    """Note 07, the worked example: each service's key establishment and signatures placed in the
    memo's queues with their dates, and the items blocked on a supplier. The counts are the entry's
    claims (measured 2026-10-20, scan run 01M5DFXYNNG08S8ADTDF48WYFE)."""
    OPEN, MET, BLOCKED = 14, 2, 7                    # fourteen open, two met, seven blocked on a supplier
    KEX_DUE, SIG_DUE, REST_DUE = "2030-12-31", "2031", "2035"
    ROWS = [  # (service, prioritized by, key establishment, signatures, supplier blocker), the worked-example table
        ("records-db", "impact, HVA, lifetime", ("kex", "hybrid offered, classical accepted"), ("sig", ""), None),
        ("sftp-legacy", "impact, HVA, lifetime", ("kex", "DH-1024 and six more"), ("sig", "DSA, ECDSA, Ed25519, RSA"), ("both", "OpenSSH 6.6: replace")),
        ("pq-gateway", "impact, HVA, lifetime", ("met", "X25519MLKEM768 only"), ("met", "ML-DSA-65 only"), None),
        ("queue", "lifetime (7 years)", ("kex", "TLS 1.2 only, so TLS 1.3 by 2030 too"), ("sig", ""), ("both", "Erlang/OTP 27: no ML-KEM group")),
        ("legacy-app", "lifetime", ("kex", "TLS 1.2 only"), ("sig", ""), ("both", "Java 8: neither")),
        ("portal", "lifetime", ("kex", ""), ("sig", ""), None),
        ("api", "lifetime", ("kex", ""), ("sig", ""), None),
        ("bastion", "none: sensitive one year", ("rest", ""), ("rest", ""), ("sig", "OpenSSH 10: no PQ host key")),
    ]
    assert sum(k == "kex" for _, _, (k, _), _, _ in ROWS) == 6 and sum(k == "sig" for _, _, _, (k, _), _ in ROWS) == 6
    assert sum((b or ("", ""))[0] == "both" for *_, b in ROWS) * 2 + sum((b or ("", ""))[0] == "sig" for *_, b in ROWS) == BLOCKED

    p = Page(1000, 680, seed=7, title="Two queues, one per function; half the open items are blocked on a supplier")
    p.text(500, 48, "Every system waits in two queues. Half the waiting cannot start.", 35, INK, "middle")

    cx = {"svc": 40, "pri": 170, "kex": 320, "sig": 560, "rest": 800}
    cw = 225
    top, rh = 96, 54
    p.text(cx["pri"], top, "prioritized by", 17, PENCIL)
    p.text(cx["kex"] + cw / 2, top, f"key establishment, by {KEX_DUE}", 19, INK, "middle")
    p.text(cx["sig"] + cw / 2, top, f"signatures, in {SIG_DUE}", 19, INK, "middle")
    p.text(cx["rest"] + 76, top, f"remaining, by {REST_DUE}", 19, INK, "middle")
    p.line(40, top + 10, 960, top + 10, PENCIL, 1.2, opacity=0.6)

    for i, (svc, pri, kex, sig, blk) in enumerate(ROWS):
        y = top + 24 + i * rh
        p.text(cx["svc"], y + 30, svc, 21, INK)
        p.text(cx["pri"], y + 30, pri, 15, PENCIL)
        if kex[0] == "rest":   # the 2035 queue, both functions, in the last column
            p.text(cx["rest"], y + 16, "key establishment: open", 14, BALLPOINT)
            p.text(cx["rest"], y + 33, "signatures: open, supplier:", 14, PENCIL)
            p.text(cx["rest"], y + 49, blk[1], 13, PENCIL)
            continue
        for fn, (state, note) in (("kex", kex), ("sig", sig)):
            blocked = blk is not None and blk[0] in ("both", fn)
            if state == "met":
                p.tick(cx[fn] + 12, y + 20, 16, BALLPOINT, 2.6)
                p.text(cx[fn] + 40, y + 30, "met: " + note, 17, BALLPOINT)
                continue
            col = PENCIL if blocked else BALLPOINT
            p.box(cx[fn], y + 4, cw, rh - 12, col, 1.8, dash=blocked)
            p.text(cx[fn] + 8, y + 22, "open" + (": " + note if note else ""), 14, col)
            if blocked:
                p.text(cx[fn] + 8, y + 38, "supplier: " + blk[1], 13, PENCIL)

    # The counts.
    yb = top + 24 + len(ROWS) * rh + 24
    p.text(40, yb + 16, f"{OPEN} items open, {MET} met", 22, BALLPOINT)
    p.stamp(430, yb + 10, f"{BLOCKED} of {OPEN}", 40)
    p.text(520, yb + 4, "blocked on a supplier whose software lists", 20, STAMP)
    p.text(520, yb + 28, "no post-quantum algorithm: replacement, started now", 20, STAMP)
    p.save(SKETCHES / "07-two-queues.svg")


def sketch_05_two_sides() -> None:
    """Note 05, the concept and the mechanism table: a session is post-quantum only if the client
    offers a hybrid group and the server chooses it; passive capture sees both sides of real
    handshakes, a targeted scan sees everything one listener accepts, and in TLS 1.3 only the scan
    sees the certificate. No number from the note's lab block is drawn."""
    RFC = "RFC 8446 §4.4.2"   # the Certificate message is encrypted in TLS 1.3

    p = Page(1000, 640, seed=5, title="Post-quantum is decided twice: offered by the client, chosen by the server")
    p.text(500, 48, "Decided twice: the client has to offer it, the server has to choose it.", 33, INK, "middle")

    # The two parties and the handshake between them.
    p.box(60, 110, 220, 120, INK, 2.2, fill=PAPER)
    p.text(170, 150, "a client", 28, INK, "middle")
    p.text(170, 182, "offers its groups,", 20, BALLPOINT, "middle")
    p.text(170, 206, "in order of preference", 20, BALLPOINT, "middle")
    p.box(720, 110, 220, 120, INK, 2.2, fill=PAPER)
    p.text(830, 150, "a server", 28, INK, "middle")
    p.text(830, 182, "chooses one", 20, BALLPOINT, "middle")
    p.text(830, 206, "of the groups offered", 20, BALLPOINT, "middle")
    p.arrow([(286, 150), (500, 146), (712, 150)], BALLPOINT, 2.2)
    p.text(500, 136, "offered: a list of groups, versions, signature algorithms", 18, BALLPOINT, "middle")
    p.arrow([(712, 192), (500, 196), (288, 192)], BALLPOINT, 2.2)
    p.text(500, 216, "chosen: one group, one version", 18, BALLPOINT, "middle")
    p.line(288, 236, 712, 236, PENCIL, 2.0, dash=True)
    p.text(500, 258, f"the certificate: encrypted in TLS 1.3 ({RFC}), so it never shows on the wire", 17, PENCIL, "middle")
    p.text(500, 300, "an inventory that sees only one side cannot say which side is the obstacle", 22, STAMP, "middle")

    # The two ways to look, and what each one sees.
    def column(x, head, sub, sees, misses):
        p.text(x, 352, head, 24, INK)
        p.text(x, 376, sub, 17, PENCIL)
        p.text(x, 410, "sees", 19, BALLPOINT)
        for k, t in enumerate(sees):
            p.text(x + 50, 410 + k * 23, t, 18, BALLPOINT)
        y = 410 + len(sees) * 23 + 14
        p.text(x, y, "misses", 19, PENCIL)
        for k, t in enumerate(misses):
            p.text(x + 66, y + k * 23, t, 18, PENCIL)

    column(60, "passive capture at a mirror", "Zeek on a copy of every frame; nothing is sent",
           ["both sides of every real handshake,", "across the whole estate at once,", "clients and servers nobody listed"],
           ["what a server would accept", "but was never offered", "any TLS 1.3 certificate", "frames the mirror dropped"])
    column(540, "a targeted scan of one listener", "testssl.sh, ssh-audit and the paired probes: it asks",
           ["every group, suite and version", "the listener accepts, its certificate", "and key, what it still accepts after a change"],
           ["any client", "which accepted options are ever used", "listeners outside the scope"])
    p.save(SKETCHES / "05-two-sides.svg")


def sketch_00_five_rungs() -> None:
    """Note 00, the concept: the maturity ladder, each rung a question the organization can now
    answer, with the top rung measured as the time from a policy change to a verified result."""
    RUNGS = [  # bottom to top: (rung, what the organization has, the question it can answer), note 00's table
        ("Opaque", "a hand-kept spreadsheet", "none reliably"),
        ("Enumerated", "scanner output", "where is quantum-vulnerable cryptography?"),
        ("Structured", "a CBOM with dependencies", "what depends on it?"),
        ("Managed", "owners, priorities, approvals", "what first, what is blocked, what changed?"),
        ("Agile", "change as routine", "if policy changes, how fast can we respond, and did it land?"),
    ]
    p = Page(1000, 630, seed=0, title="Five rungs: each one a question the organization can now answer")
    p.text(500, 48, "Each rung is a question the organization can now answer.", 36, INK, "middle")

    lx, rx, y_bottom, y_top = 250, 370, 580, 150
    p.line(lx, y_bottom, lx, y_top, INK, 3.0)
    p.line(rx, y_bottom, rx, y_top, INK, 3.0)
    step = (y_bottom - y_top - 60) / (len(RUNGS) - 1)
    for i, (rung, has, asks) in enumerate(RUNGS):
        y = y_bottom - 30 - i * step
        p.line(lx - 4, y, rx + 4, y, INK, 3.0)
        p.text(lx - 24, y + 8, rung, 26, INK, "end")
        p.text(rx + 26, y - 6, "has: " + has, 20, BALLPOINT)
        p.text(rx + 26, y + 18, "can answer: " + asks, 19, PENCIL if i == 0 else BALLPOINT)
    # The top rung is a measurement.
    y = y_bottom - 30 - 4 * step
    cx = lx - 24 - measure("Agile", 26) / 2
    p.ring(cx, y, measure("Agile", 26) / 2 + 20, 24)
    for k, t in enumerate(["measured: the time from", "a policy change", "to a verified result"]):
        p.text(cx + 40, y - 86 + k * 22, t, 19, STAMP, "end")
    p.save(SKETCHES / "00-five-rungs.svg")


def sketch_15_what_the_harness_adds() -> None:
    """Note 15 on the eight-service estate: the scanners alone and the workbench, by layer. The
    wire is the scanners'; the harness's delta is the image layer, the decoys and the postures
    (measured 2026-10-19, run 01M5AS1BSKH8SQN8XN6NCFE1E5, xr7620)."""
    WIRE_KEYED, WIRE_OUT_OF_REACH, WIRE_SCANNERS, WIRE_WORKBENCH = 40, 2, 38, 38
    IMG_KEYED, IMG_DECOYS, IMG_SCANNERS, IMG_WORKBENCH = 20, 2, 14, 20
    DECOYS_SCANNERS, DECOYS_WORKBENCH = 2, 0
    POSTURE_KEYED, POSTURE_WORKBENCH = 9, 9
    READER_S, THEIA_S = "1.0 to 7.6 s", "75 to 136 s"      # per image, same run

    p = Page(1000, 630, seed=15, title="The wire is the scanners'; the harness adds the images, the decoys and the postures")
    p.text(500, 48, "Same wire. The delta is in the images and the structure.", 36, INK, "middle")

    ax, bx, bar = 200, 580, 240
    p.text(ax, 100, "the three scanners alone", 22, INK)
    p.text(bx, 100, "the workbench", 22, INK)
    p.text(ax, 122, "testssl.sh, ssh-audit, cbomkit-theia", 16, PENCIL)
    p.text(bx, 122, "the same findings, its own file reader, and rules", 16, PENCIL)

    def row(y, label, keyed, a, b, note_a, note_b, a_color=PENCIL):
        p.text(40, y + 8, label, 24, INK)
        p.text(40, y + 32, f"keyed: {keyed}", 17, PENCIL)
        for x, n, col in ((ax, a, a_color), (bx, b, BALLPOINT)):
            p.box(x, y - 12, bar, 26, PENCIL, 1.4)
            if n is not None:
                p.line(x + 2, y + 1, x + 2 + bar * n / keyed, y + 1, col, 16, opacity=0.55)
                p.text(x + bar + 14, y + 9, f"{n} of {keyed}", 22, col if col != PENCIL else INK)
            else:
                p.text(x + 12, y + 9, "not stated", 20, PENCIL)
        p.text(ax, y + 44, note_a, 16, PENCIL)
        p.text(bx, y + 44, note_b, 16, PENCIL)

    row(170, "wire", WIRE_KEYED, WIRE_SCANNERS, WIRE_WORKBENCH,
        f"no false positive; {WIRE_OUT_OF_REACH} keyed out of reach", "the same 38: nothing added on the wire", a_color=BALLPOINT)
    row(290, "images", IMG_KEYED, IMG_SCANNERS, IMG_WORKBENCH,
        f"both of the {IMG_DECOYS} decoys flagged", f"neither decoy flagged")
    row(440, "posture", POSTURE_KEYED, None, POSTURE_WORKBENCH,
        "no scanner states one", "a rule over both layers, per listener")

    # The point: the image layer, closed by the harness's own reader and the rules.
    cx = bx + bar + 14 + measure(f"{IMG_WORKBENCH} of {IMG_KEYED}", 22) / 2
    p.ring(cx, 290 + 2, measure(f"{IMG_WORKBENCH} of {IMG_KEYED}", 22) / 2 + 16, 22)
    for k, t in enumerate(["its own file reader: an ML-DSA certificate and key,", "a keystore, DSA and Ed25519 host keys; and the rules"]):
        p.text(bx, 290 + 68 + k * 19, t, 16, STAMP)
    p.text(40, 560, f"cost per image: the harness's reader {READER_S}; cbomkit-theia {THEIA_S}, nearly all of it in its secrets plugin", 18, PENCIL)
    p.text(40, 586, "a TLS listener 27 to 46 s, an SSH listener 2 to 3 s (four-service slice, 2026-10-03)", 18, PENCIL)
    p.save(SKETCHES / "15-what-the-harness-adds.svg")


def sketch_12_what_the_signer_catches() -> None:
    """Note 12, the worked example's tamper table: six tamperings of a copy of a change run's
    ledger, checked by the hash chain alone and against the signer's key and record. Three pass the
    chain alone; the signer catches five; the sixth, a replaced public-key file beside the ledger,
    passes from the files alone (measured 2026-10-03, M0A review F-45 to F-48)."""
    CASES = [  # (tamper, chain only, with the signer's key and record, the signer's reason)
        ("edit one event", "fails", "fails", ""),
        ("remove an event from the middle", "fails", "fails", ""),
        ("remove the last events", "passes", "fails", "a checkpoint through event 6 was signed; events removed"),
        ("change a verdict, recompute every hash", "passes", "fails", "the checkpoint's hash no longer matches"),
        ("the same, then re-sign every checkpoint with a new key", "passes", "fails", "signed with another key"),
        ("the same, and replace the public-key file beside the ledger;", "—", "passes", "verified from the files alone"),
    ]
    SIGN_MS, VERIFY_MS, CHECKPOINT_MS = "0.88 ms", "0.16 ms", "5 to 11 ms"   # note 12, cost on the xr7620

    p = Page(1000, 600, seed=1212, title="What the hash chain lets through and what the signer catches")
    p.text(500, 48, "Hashes prove consistency. The signer's record proves nothing was cut.", 33, INK, "middle")

    c1, c2, c3 = 40, 520, 690
    top = 100
    p.text(c1, top, "a tampered copy of the ledger", 18, PENCIL)
    p.text(c2 + 30, top - 22, "checked by", 16, PENCIL, "middle")
    p.text(c2 + 30, top, "the hashes alone", 18, PENCIL, "middle")
    p.text(c3 + 30, top - 22, "checked against the signer's", 16, PENCIL, "middle")
    p.text(c3 + 30, top, "key and record", 18, PENCIL, "middle")
    p.line(c1, top + 12, 960, top + 12, PENCIL, 1.2, opacity=0.6)
    rh = 62
    for i, (tamper, chain, signer, why) in enumerate(CASES):
        y = top + 44 + i * rh
        p.text(c1, y, tamper, 21, INK)
        if i == 5:
            p.text(c1, y + 22, "verify from the files alone", 21, INK)
        for x, verdict in ((c2, chain), (c3, signer)):
            if verdict == "fails":
                p.tick(x + 18, y - 8, 16, BALLPOINT, 2.6)
                p.text(x + 46, y, "fails: caught", 18, BALLPOINT)
            elif verdict == "passes":
                p.text(x + 10, y, "passes", 22, INK, weight=700)
            else:
                p.text(x + 24, y, "—", 22, PENCIL)
        if why and i < 5:
            p.text(c3 + 10, y + 20, why, 14, PENCIL)
    # The point: a key kept beside what it verifies is not an independent check.
    y = top + 44 + 5 * rh
    p.ring(c3 + 10 + measure("passes", 22) / 2, y - 8, measure("passes", 22) / 2 + 16, 20)
    p.text(c3 + 10 + measure("passes", 22) / 2 + 70, y + 24, "a public key stored next to", 17, STAMP, "middle")
    p.text(c3 + 10 + measure("passes", 22) / 2 + 70, y + 44, "what it verifies is not a check", 17, STAMP, "middle")
    p.text(c1, 560, f"cost: {SIGN_MS} to sign, {VERIFY_MS} to verify, {CHECKPOINT_MS} per checkpoint; signing is not what limits how often to checkpoint", 17, PENCIL)
    p.text(c1, 584, "so: record the signer's key id and the latest checkpoint's hash somewhere the writer cannot reach", 17, PENCIL)
    p.save(SKETCHES / "12-what-the-signer-catches.svg")


def sketch_13_six_roles() -> None:
    """Note 13, the roles table: six roles, a floor each written before the run, and where each
    landed by measurement: three on a 31B model on four L4s, one on the 120B, two back to rules.
    Whether a change worked is the verifier's, never a model's."""
    ROLES = [  # (role, floor (harmful allowed), landed, measured, detail), note 13's roles table
        ("call-site read", "27 (1)", "31b", "29 of 30, 13.6 s", "reasoning on"),
        ("normalization", "28 (0)", "rule", "28, none harmful", "a name table; the live lane as fallback"),
        ("classification", "28 (0)", "31b", "30 of 30, 1.1 s", "no reasoning"),
        ("conflict resolution", "24 of 29 (2)", "rule", "26 with 2 harmful", "rules decide; a model may explain beside"),
        ("trace to cause", "24 (3)", "120b", "28 of 30, 36 to 44 s", "27 of 30 at 12.7 s on the live lane"),
        ("change plan", "24 (2)", "31b", "27 of 30, 3.5 s", "none harmful; the 120B: 24 at 95 s"),
    ]
    ITEMS, ARMS = 216, 15   # note 13: 216 labeled items, fifteen arms

    p = Page(1000, 640, seed=13, title="Six roles, a floor each, placed by measurement")
    p.text(500, 48, "Each role went to the cheapest arm that cleared its floor, or back to a rule.", 32, INK, "middle")

    cols = {"31b": 330, "120b": 560, "rule": 770}
    cw = {"31b": 210, "120b": 200, "rule": 190}
    heads = {"31b": ("a 31B model", "Gemma 4 on four L4s"), "120b": ("the 120B", "Nemotron on the lab GB10"), "rule": ("a rule", "no model decides")}
    top = 96
    for k, (h1, h2) in heads.items():
        p.text(cols[k] + cw[k] / 2, top, h1, 22, INK, "middle")
        p.text(cols[k] + cw[k] / 2, top + 20, h2, 15, PENCIL, "middle")
    p.text(40, top, "role", 18, PENCIL)
    p.text(40, top + 20, "floor, harmful allowed", 15, PENCIL)
    p.line(40, top + 30, 960, top + 30, PENCIL, 1.2, opacity=0.6)
    rh = 60
    for i, (role, floor, landed, measured, detail) in enumerate(ROLES):
        y = top + 60 + i * rh
        p.text(40, y, role, 22, INK)
        p.text(40, y + 20, "floor " + floor, 15, PENCIL)
        x = cols[landed]
        p.box(x, y - 22, cw[landed], 46, BALLPOINT, 1.8)
        p.text(x + 10, y - 2, measured, 18, BALLPOINT)
        p.text(x + 10, y + 16, detail, 13, PENCIL)
    # The seventh question is nobody's but the verifier's.
    y = top + 60 + 6 * rh + 10
    p.line(40, y - 32, 960, y - 32, PENCIL, 1.2, opacity=0.6)
    p.text(40, y, "did the change work?", 22, INK)
    p.text(cols["rule"] + 10, y, "the verifier: a pair of probes", 18, STAMP)
    p.ring(cols["rule"] + cw["rule"] / 2, y - 8, cw["rule"] / 2 + 6, 24)
    p.text(cols["31b"] + 10, y, "never a model", 18, INK)
    p.text(40, 596, f"{ITEMS} labeled items, {ARMS} arms, three calls per item with the majority taken; a floor written before any run", 17, PENCIL)
    p.save(SKETCHES / "13-six-roles.svg")


def sketch_13_reasoning_setting() -> None:
    """Note 13: the same Nemotron 3.5 Super VL weights traced 9, 26 and 21 of 30 findings with
    thinking off, at medium effort and with full thinking, against a floor of 24; the two 120B
    models at the same setting differed by two (measured 2026-10-16, spike S3 role R5, lab GB10)."""
    ARMS = [("thinking off", 9, ""), ("medium effort", 26, ""), ("full thinking", 21, "8 of 90 calls hit the 900 s timeout")]
    FLOOR, HARMFUL_ALLOWED, ITEMS = 24, 3, 30
    INCUMBENT = 28   # the 120B it replaced, on each of two runs nine days apart

    p = Page(1000, 560, seed=1313, title="The reasoning setting moved the result more than the change of model")
    p.text(500, 48, "Same weights, three settings. The setting moved it more than the model did.", 32, INK, "middle")

    base, scale, bw = 420, 10, 110
    xs = [200, 400, 600]
    p.line(120, base, 900, base, INK, 2.0)
    fy = base - FLOOR * scale
    p.line(120, fy, 900, fy, PENCIL, 1.6, dash=True)
    p.text(126, fy - 8, f"the floor: {FLOOR} of {ITEMS}, {HARMFUL_ALLOWED} harmful allowed", 17, PENCIL)
    for (label, n, note), x in zip(ARMS, xs):
        h = n * scale
        p.box(x, base - h, bw, h, BALLPOINT, 2.0, fill=None)
        p.text(x + bw / 2, base - h - 12, str(n), 28, INK, "middle")
        p.text(x + bw / 2, base + 28, label, 20, INK, "middle")
        if note:
            p.text(x + bw / 2, base + 50, note, 14, PENCIL, "middle")
    # The old 120B, same slot, full thinking: the model change is two items.
    x = 820
    h = INCUMBENT * scale
    p.box(x, base - h, bw, h, PENCIL, 1.8, dash=True)
    p.text(x + bw / 2, base - h - 12, str(INCUMBENT), 28, PENCIL, "middle")
    p.text(x + bw / 2, base + 28, "the 120B before it,", 18, PENCIL, "middle")
    p.text(x + bw / 2, base + 50, "full thinking, two runs", 14, PENCIL, "middle")
    p.text(500, 86, "Nemotron 3.5 Super VL 120B-A12B, tracing a wire finding to its configuration line, 30 items", 17, PENCIL, "middle")
    # The point.
    p.text(xs[0] + bw / 2, base - 9 * scale - 50, "a switch: 9 to 26", 22, STAMP, "middle")
    p.arrow([(xs[0] + bw + 6, base - 9 * scale - 20), (xs[1] - 6, base - 26 * scale + 16)], STAMP, 2.4)
    p.text(x + bw / 2, base + 72, "a change of model: 28 to 26", 16, PENCIL, "middle")
    p.save(SKETCHES / "13-reasoning-setting.svg")


def sketch_16_thirteen_steps() -> None:
    """Note 16: one weakness, records-db's classical key exchange, followed from finding to fixed in
    thirteen steps, two by a model and three recording a person's decision, every step reading
    from or writing to the CBOM (read 2026-10-23 from the deployment's ledgers)."""
    STEPS = [  # (lines, actor), in the order the entry tells them
        (["a scan finds X25519, DH-2048", "and RSA key transport"], "scanner"),
        (["rules link the listener", "to its service"], "rule"),
        (["the owner's facts: 75-year", "lifetime, high-value asset"], "person"),
        (["M-26-15 rules: the 2030", "queue, prioritized"], "rule"),
        (["the policy: require"], "person"),
        (["a model traces the finding", "to its cause"], "model"),
        (["a second model drafts", "the edit"], "model"),
        (["rehearsed on a copy"], "runner"),
        (["tried against each", "kind of client"], "probe"),
        (["a person approves"], "person"),
        (["the runner applies"], "runner"),
        (["probes prove it", "on the wire, twice"], "probe"),
        (["the next scan: the", "classical groups gone"], "scanner"),
    ]
    N, BY_MODEL, BY_PERSON = 13, 2, 3
    assert len(STEPS) == N and sum(a == "model" for _, a in STEPS) == BY_MODEL and sum(a == "person" for _, a in STEPS) == BY_PERSON

    p = Page(1000, 720, seed=16, title="Thirteen steps from finding to fixed, around the CBOM")
    p.text(500, 48, "Thirteen steps round one record. Two by a model. None of them decides.", 32, INK, "middle")

    cx, cy, rx, ry = 500, 380, 250, 200
    # The loop.
    pts = [(cx + rx * math.cos(math.radians(a)), cy + ry * math.sin(math.radians(a))) for a in range(-90, 271, 10)]
    p.curve(pts, PENCIL, 1.6, dash=True)
    for i, (lines, actor) in enumerate(STEPS):
        ang = -90 + 360 * i / N
        x, y = cx + rx * math.cos(math.radians(ang)), cy + ry * math.sin(math.radians(ang))
        col = INK if actor in ("model", "person") else BALLPOINT
        p.ring(x, y, 13, 13, col, 1.8)
        p.text(x, y + 6, str(i + 1), 16, col, "middle")
        ca, sa = math.cos(math.radians(ang)), math.sin(math.radians(ang))
        lx, ly = x + ca * 26, y + sa * 26
        anchor = "middle" if abs(ca) < 0.3 else ("start" if ca > 0 else "end")
        ly += 6 if abs(sa) < 0.3 else (sa * 10)
        if anchor == "middle":
            ly += 14 if sa > 0 else -8 - 16 * (len(lines) - 1)
        for k, t in enumerate(lines):
            p.text(lx, ly + k * 18 - (0 if anchor == "middle" else 9 * (len(lines) - 1)), t, 15, col, anchor)
        if actor in ("model", "person"):
            tag_y = ly + len(lines) * 18 - (0 if anchor == "middle" else 9 * (len(lines) - 1))
            p.text(lx, tag_y, actor, 13, PENCIL, anchor)
    # The arrow of time, once.
    a0, a1 = -90 + 360 * 12 / N + 8, -90 + 360 * 13 / N - 8
    p.arrow([(cx + rx * math.cos(math.radians(a)), cy + ry * math.sin(math.radians(a))) for a in (a0, (a0 + a1) / 2, a1)], PENCIL, 1.6, 9)
    # The CBOM at the centre: the point.
    p.box(cx - 70, cy - 36, 140, 72, INK, 2.2, fill=PAPER)
    p.text(cx, cy + 10, "the CBOM", 28, INK, "middle")
    p.ring(cx, cy, 92, 54)
    p.text(cx, cy + 86, "every step reads from it", 18, STAMP, "middle")
    p.text(cx, cy + 108, "or writes to it", 18, STAMP, "middle")
    p.text(40, 698, f"{N} steps: {BY_MODEL} by a model, {BY_PERSON} recording a person's decision, the rest by scanners, rules, the runner and probes", 17, PENCIL)
    p.save(SKETCHES / "16-thirteen-steps.svg")


def sketch_08_the_fourth_probe() -> None:
    """Note 08: a PostgreSQL 18 listener set to the hybrid group alone refused a TLS 1.3 client
    offering every classical group and still completed TLS 1.2 handshakes with DHE-RSA and with RSA
    key transport; with the minimum protocol also TLS 1.3, all four probes held (measured
    2026-10-21, copies of the records database on the twin network)."""
    LEFT = "ssl_groups = 'X25519MLKEM768'"
    RIGHT = "+ ssl_min_protocol_version = 'TLSv1.3'"
    PROBES = [  # (probe, what it offers, result with the groups alone, result with the minimum protocol too)
        ("positive", "TLS 1.3, only X25519MLKEM768", None, "accepted"),
        ("negative", "TLS 1.3, every classical group", "refused", "refused"),
        ("witness", "enumerates every group", None, "only X25519MLKEM768"),
        ("legacy", "TLS 1.2, the client's default suites", "completed: DHE-RSA, and again with RSA key transport", "refused"),
    ]
    p = Page(1000, 600, seed=88, title="The fourth probe: TLS 1.2 establishes keys with no group at all")
    p.text(500, 48, "Three probes say enforced. The fourth says TLS 1.2 still gets in.", 34, INK, "middle")

    c0, c1, c2 = 40, 380, 700
    top = 110
    p.text(c1, top - 6, "the groups alone", 22, INK)
    p.text(c1, top + 16, LEFT, 16, PENCIL)
    p.text(c2, top - 6, "and the minimum protocol", 22, INK)
    p.text(c2, top + 16, RIGHT, 16, PENCIL)
    p.line(c0, top + 30, 960, top + 30, PENCIL, 1.2, opacity=0.6)
    rh = 78
    for i, (probe, offers, a, b) in enumerate(PROBES):
        y = top + 70 + i * rh
        p.text(c0, y, probe, 24, INK)
        p.text(c0, y + 22, offers, 16, PENCIL)
        for x, r in ((c1, a), (c2, b)):
            if r is None:
                p.text(x + 8, y, "—", 22, PENCIL)
            elif r.startswith("completed"):
                p.cross(x + 4, y - 16, 16, INK, 2.6)
                p.text(x + 32, y, "completed: DHE-RSA, and again", 19, INK)
                p.text(x + 32, y + 22, "with RSA key transport", 19, INK)
            else:
                p.tick(x + 4, y - 10, 16, BALLPOINT, 2.6)
                p.text(x + 32, y, r, 19, BALLPOINT)
    # The point: the classical-only TLS 1.3 refusal says nothing about TLS 1.2.
    y = top + 70 + 3 * rh
    p.ring(c1 + 140, y + 4, 170, 36)
    p.text(c1, y + 62, "a TLS 1.3 server sharing no group refuses outright, with no", 16, STAMP)
    p.text(c1, y + 82, "fallback: the negative probe says nothing about TLS 1.2", 16, STAMP)
    p.text(c2 + 32, y + 24, "enforced: all four held", 17, PENCIL)
    p.text(c0, 574, "TLS 1.2 carries no hybrid group: any TLS 1.2 handshake that completes is classical key establishment (lesson 36)", 16, PENCIL)
    p.save(SKETCHES / "08-the-fourth-probe.svg")


def sketch_01_one_entry_two_namespaces() -> None:
    """Note 01, the worked example: the records database's served certificate as the CBOM carries
    it, 10 fields the standard defines beside 13 the project adds, every one traced to the ledger
    event it came from (measured 2026-10-21, scan run 01M5DG85J78FF3FVG3GDH26SWZ)."""
    STANDARD = [  # CycloneDX 1.6 fields on the entry, with their values shortened as the entry shortens them
        ("type", "cryptographic-asset"), ("bom-ref", "fp:03f50533afef3d47…"), ("name", "RSA"),
        ("assetType", "certificate"), ("certificateFormat", "X.509"),
        ("subjectName", "CN=records-db.agency.test"), ("issuerName", "CN=Mini Agency Internal CA"),
        ("notValidBefore", "2026-10-19"), ("notValidAfter", "2029-01-21"),
        ("evidence.occurrences", "172.16.106.30:5432"),
    ]
    PROJECT = [  # the pqch: properties on the same entry
        ("pqch:layer", "wire"), ("pqch:subject", "endpoint 172.16.106.30:5432, postgres"),
        ("pqch:asset-type", "certificate"), ("pqch:role", "signature"), ("pqch:name", "RSA"),
        ("pqch:parameters", "key_bits 2048, ecdsa-with-SHA384, spki…"),
        ("pqch:fingerprint", "03f50533afef3d47…"), ("pqch:evidence", "01M5DGB4PY85H2ANQA75X4H3PK"),
        ("pqch:tools", "testssl.sh"), ("pqch:in-use", "true"), ("pqch:verifiable-by", "cert-parse"),
        ("pqch:family", "rsa-sig"), ("pqch:quantum-vulnerable", "true"),
    ]
    N_STANDARD, N_PROJECT = 10, 13
    COMPONENTS = "254 components: 47 on the wire, 182 in images, 9 listeners, 8 services, 8 images"
    assert len(STANDARD) == N_STANDARD and len(PROJECT) == N_PROJECT

    p = Page(1000, 660, seed=101, title="One entry, two namespaces: what it is and where, and what it rests on")
    p.text(500, 48, "The standard says what it is and where. The extension says what it rests on.", 31, INK, "middle")

    p.box(40, 84, 920, 526, INK, 2.0, fill=PAPER)
    p.text(60, 114, "one entry: the certificate the records database serves after PostgreSQL's TLS upgrade", 19, PENCIL)
    lx, rx, top, rh = 60, 520, 150, 31
    p.text(lx, top, f"{N_STANDARD} fields CycloneDX 1.6 defines", 22, INK)
    p.text(rx, top, f"{N_PROJECT} the project adds, under pqch:", 22, INK)
    p.line(lx, top + 10, lx + 400, top + 10, PENCIL, 1.0, opacity=0.6)
    p.line(rx, top + 10, rx + 420, top + 10, PENCIL, 1.0, opacity=0.6)
    for i, (k, v) in enumerate(STANDARD):
        y = top + 38 + i * rh
        p.text(lx, y, k, 17, BALLPOINT)
        p.text(lx + 190, y, v, 16, INK)
    for i, (k, v) in enumerate(PROJECT):
        y = top + 38 + i * rh
        p.text(rx, y, k, 17, BALLPOINT)
        p.text(rx + 190, y, v, 16, INK)
    # The point: every field is traced to the ledger event it came from.
    y = top + 38 + 7 * rh
    p.ring(rx + 190 + measure("01M5DGB4PY85H2ANQA75X4H3PK", 16) / 2, y - 6, measure("01M5DGB4PY85H2ANQA75X4H3PK", 16) / 2 + 14, 17)
    p.text(lx, top + 38 + 10 * rh + 10, "the ledger event the entry rests on:", 18, STAMP)
    p.text(lx, top + 38 + 10 * rh + 32, "the tool's raw output, by path and SHA-256;", 18, STAMP)
    p.text(lx, top + 38 + 10 * rh + 54, "no field is here without one", 18, STAMP)
    ring_r = rx + 190 + measure("01M5DGB4PY85H2ANQA75X4H3PK", 16) + 16
    p.arrow([(lx + 300, top + 38 + 10 * rh + 20), (430, top + 38 + 12.6 * rh), (935, top + 38 + 12.8 * rh), (948, y + 40), (ring_r + 4, y - 4)], STAMP, 2.0, 9)
    p.text(500, 640, COMPONENTS, 17, PENCIL, "middle")
    p.save(SKETCHES / "01-one-entry-two-namespaces.svg")


def sketch_19_ask_and_check() -> None:
    """Note 19, the mechanism: a question is embedded, the eight nearest passages and their chains
    are handed to a model, the typed reply names components and cites events, and a rule checks
    every citation against the ledger and the shown passages (measured 2026-11-04, lab GB10)."""
    NEAREST, HOPS = 8, 2
    FLOORS = ("11", "10", "12")   # of 12: retrieval recall@8, the expected phrase, every citation passes
    NANO = ("11", "7", "10", "22 s")
    SUPERVL = ("10", "11", "9", "34 s")

    p = Page(1000, 600, seed=19, title="A question is answered from passages and every citation is checked by code")
    p.text(500, 48, "The model answers from passages. Code checks every citation. Never the model.", 31, INK, "middle")

    y = 150
    boxes = [
        (40, 150, ["a question", "in plain words,", "embedded"]),
        (230, 230, [f"the {NEAREST} nearest passages", "by cosine, one per", f"component, + {HOPS} hops up:", "its listener, its service"]),
        (500, 170, ["the model", "role ask-cbom, one call", "through the seam"]),
        (710, 250, ["a typed reply:", "answer, components,", "citations (event ids),", "not_in_passages"]),
    ]
    for x, w, lines in boxes:
        p.box(x, y - 60, w, 112, BALLPOINT, 2.0)
        for k, t in enumerate(lines):
            p.text(x + w / 2, y - 30 + k * 22, t, 19 if k == 0 else 15, INK if k == 0 else BALLPOINT, "middle")
    p.arrow([(192, y - 4), (228, y - 4)], BALLPOINT, 2.0, 9)
    p.arrow([(462, y - 4), (498, y - 4)], BALLPOINT, 2.0, 9)
    p.arrow([(672, y - 4), (708, y - 4)], BALLPOINT, 2.0, 9)
    p.text(345, y + 70, "each passage carries the ledger event ids behind its fields", 15, PENCIL, "middle")

    # The check: a rule, with the ledger on one side and the shown passages on the other.
    cy = 330
    p.box(560, cy - 40, 400, 120, INK, 2.2, fill=PAPER)
    p.text(760, cy - 10, "the check, a rule", 22, INK, "middle")
    p.text(760, cy + 16, "each cited event: in the ledger, and among the shown passages", 15, BALLPOINT, "middle")
    p.text(760, cy + 38, "each named component: among the shown", 15, BALLPOINT, "middle")
    p.text(760, cy + 60, "anything else fails, and the page says the answer is unsupported", 15, BALLPOINT, "middle")
    p.arrow([(835, y + 54), (835, cy - 44)], BALLPOINT, 2.0, 9)
    p.box(300, cy - 30, 200, 100, PENCIL, 1.8, dash=True)
    p.text(400, cy + 6, "the ledger", 22, PENCIL, "middle")
    p.text(400, cy + 30, "every fact has an event;", 14, PENCIL, "middle")
    p.text(400, cy + 48, "a citation can be looked up", 14, PENCIL, "middle")
    p.arrow([(504, cy + 20), (556, cy + 20)], PENCIL, 1.8, 9)
    p.ring(760, cy - 16, 110, 20)
    p.text(760, cy + 112, "the model never decides whether it cited well", 20, STAMP, "middle")

    # The floors, and the two arms measured.
    fy = 492
    p.text(40, fy, "of 12 questions, three repeats", 16, PENCIL)
    p.text(40, fy + 24, f"floors, written first:  retrieval {FLOORS[0]}  ·  the expected phrase {FLOORS[1]}  ·  every citation passes {FLOORS[2]}", 17, BALLPOINT)
    p.text(40, fy + 48, f"Nano 9B NIM: {NANO[0]} · {NANO[1]} · {NANO[2]}, median {NANO[3]}      Super VL 120B at medium effort, with the chain rule: {SUPERVL[0]} · {SUPERVL[1]} · {SUPERVL[2]}, median {SUPERVL[3]}", 17, PENCIL)
    p.text(40, fy + 72, "neither arm clears all three on 2026-11-04; the role is bound to the deliberate tier as the best measured arm, below floor", 16, PENCIL)
    p.save(SKETCHES / "19-ask-and-check.svg")


def sketch_12_bracketed_event() -> None:
    """Note 12, time from someone other than the writer: a signature after an event bounds its end,
    the chain after a signature bounds its start, so the policy event and the approval get a
    checkpoint on both sides; a change read 55.6 s on the writer's clock and no more than 55.6 s on
    the signer's (measured 2026-10-05, change run 01M46RCKJZA12PD1REM722YF4F)."""
    WRITER_S, SIGNER_S = "55.6 s", "no more than 55.6 s"
    TOLERANCE = "two seconds"
    p = Page(1000, 560, seed=1213, title="An event is bracketed by a signature before it and one after it")
    p.text(500, 48, "A signature after says it existed by then. One before says it did not exist yet.", 30, INK, "middle")

    y = 230
    p.line(60, y, 940, y, INK, 2.4)
    p.text(940, y - 14, "the chain, in order", 15, PENCIL, "end")
    items = [  # (x, label, kind)
        (130, ["checkpoint", "signed, the signer's time"], "cp"),
        (300, ["policy change", "the writer's stamp"], "ev"),
        (470, ["checkpoint", "signed"], "cp"),
        (600, ["proposal, approval,", "apply, verdict"], "ev"),
        (820, ["checkpoint", "signed, the signer's time"], "cp"),
    ]
    for x, lines, kind in items:
        if kind == "cp":
            p.box(x - 14, y - 14, 28, 28, BALLPOINT, 2.2, fill=PAPER)
            p.tick(x - 8, y - 2, 12, BALLPOINT, 2.4)
        else:
            p.ring(x, y, 12, 12, INK, 2.0)
        for k, t in enumerate(lines):
            p.text(x, y + 62 + k * 20, t, 17 if k == 0 else 14, INK if k == 0 else PENCIL, "middle")
    # Why both sides.
    p.text(470, y - 128, "a signature over it: it existed by then,", 16, BALLPOINT, "middle")
    p.text(470, y - 108, "an upper bound on its end", 16, BALLPOINT, "middle")
    p.arrow([(470, y - 96), (472, y - 60), (470, y - 24)], BALLPOINT, 1.8, 9)
    p.text(130, y - 128, "the event is hashed onto this signature,", 16, BALLPOINT, "middle")
    p.text(130, y - 108, "so it was written after it: a lower bound", 16, BALLPOINT, "middle")
    p.arrow([(130, y - 96), (132, y - 60), (130, y - 24)], BALLPOINT, 1.8, 9)
    p.ring(300, y + 4, 210, 40)
    p.text(300, y + 118, "a checkpoint on each side of the two events a person causes", 19, STAMP, "middle")
    # The two readings of one interval.
    by = 400
    p.line(300, by, 600, by, BALLPOINT, 2.0)
    p.line(300, by - 8, 300, by + 8, BALLPOINT, 2.0)
    p.line(600, by - 8, 600, by + 8, BALLPOINT, 2.0)
    p.text(450, by - 12, f"the writer's clock: {WRITER_S}", 18, BALLPOINT, "middle")
    p.line(130, by + 44, 820, by + 44, PENCIL, 2.0)
    p.line(130, by + 36, 130, by + 52, PENCIL, 2.0)
    p.line(820, by + 36, 820, by + 52, PENCIL, 2.0)
    p.text(475, by + 72, f"the signer's clock, last signature before to first signature over the verdict: {SIGNER_S}", 17, PENCIL, "middle")
    p.text(60, 530, f"the writer's stamps must sit within {TOLERANCE} of the signatures around them; before a run's first checkpoint nothing bounded a stamp from below,", 14, PENCIL)
    p.text(60, 548, "and a policy event stamped one hour in the past was signed", 14, PENCIL)
    p.save(SKETCHES / "12-bracketed-event.svg")


def sketch_00_time_to_change() -> None:
    """Note 00, the Agile paragraph of the worked example: one policy change on the portal,
    applied and verified in 63.4 s from the policy event and 62.9 s from approval, two verdicts
    included, nearly all of it the enumerating witness at 21 to 31 s per verdict (measured
    2026-10-03, M0 slice, xr7620; change run 01M422Y6WP5TNB65NPFFEWNAK4)."""
    FROM_POLICY_S, FROM_APPROVAL_S = 63.4, 62.9
    WITH_PERSON = ("69.4 s", "65.6 s")
    WITNESS_S, PROBE_S = "21 to 31 s", "about one second"
    SIGNER_BOUND = "55.6 s"   # a later change, the signer's reading as an upper bound

    p = Page(1000, 480, seed=900, title="About a minute from approval to proof, nearly all of it the witness")
    p.text(500, 48, "About a minute from approval to proof. Nearly all of it is the witness.", 32, INK, "middle")

    x0, y, scale = 80, 200, 13.0
    x1 = x0 + FROM_POLICY_S * scale
    xa = x0 + (FROM_POLICY_S - FROM_APPROVAL_S) * scale
    p.line(x0, y, x1, y, BALLPOINT, 14, opacity=0.35)
    p.line(x0, y, x1, y, INK, 1.6)
    for x, label, where in ((x0, "the policy event", "under"), (xa, "approval", "over"), (x1, "the last verdict", "under")):
        p.line(x, y - 16, x, y + 16, INK, 2.0)
        p.text(x, y + 42 if where == "under" else y - 28, label, 19, INK, "middle" if x != x1 else "end")
    p.text(x0 + (x1 - x0) / 2, y - 60, f"{FROM_POLICY_S} s from the policy event, {FROM_APPROVAL_S} s from approval", 21, BALLPOINT, "middle")
    p.text(x0 + (x1 - x0) / 2, y + 80, "two verdicts: the paired probes, the enumerating witness, the service recreated, both again", 16, PENCIL, "middle")
    # The point.
    p.text(x0 + (x1 - x0) / 2, y + 130, f"the witness: {WITNESS_S} per verdict; each paired probe {PROBE_S}", 21, STAMP, "middle")
    p.text(x0 + (x1 - x0) / 2, y + 156, "the price of not trusting a sample", 17, PENCIL, "middle")
    p.text(60, 420, f"with a person approving through the page: {WITH_PERSON[0]} and {WITH_PERSON[1]}; a later change read {SIGNER_BOUND} on the ledger's clock", 16, PENCIL)
    p.text(60, 444, f"and no more than {SIGNER_BOUND} on the signing service's; a starting figure for one listener on one estate, not a benchmark", 16, PENCIL)
    p.save(SKETCHES / "00-time-to-change.svg")


def sketch_05_code_candidates() -> None:
    """Note 05: in 18F/identity-idp at its pinned commit a twelve-pattern Ruby rule pack matched 85
    candidate lines; the call-site-read role judged 79 live cryptographic uses and 6 not, a
    documentation comment and five exception handlers, agreeing within its three calls on 75
    (measured 2026-10-21, scan-code run 01M5FJH69143N17Q6PCF782P8R)."""
    PATTERNS, CANDIDATES, LIVE, NOT_LIVE, AGREED = 12, 85, 79, 6, 75
    NOT_LIVE_KINDS = ["a documentation comment", "five exception handlers that name a class and call nothing"]
    assert LIVE + NOT_LIVE == CANDIDATES

    p = Page(1000, 400, seed=55, title="A code rule's match is a candidate, not a use")
    p.text(500, 48, "A rule finds candidates. Which ones are uses is a reading.", 36, INK, "middle")

    sq, step, per_row, x0, y0 = 22, 30, 17, 60, 110
    p.text(x0, y0 - 18, f"{CANDIDATES} lines a {PATTERNS}-pattern Ruby rule pack matched under app/, lib/ and config/", 19, PENCIL)
    for i in range(CANDIDATES):
        r, c = divmod(i, per_row)
        x, y = x0 + c * step, y0 + r * step
        live = i < LIVE
        p.box(x, y, sq, sq, BALLPOINT if live else PENCIL, 1.8, over=2, dash=not live)
        if live:
            p.tick(x + 4, y + 12, 14, BALLPOINT, 2.4)
        else:
            p.cross(x + 5, y + 5, 12, PENCIL, 2.2)
    # The six that are not uses.
    r, c = divmod(LIVE, per_row)
    cx = x0 + c * step + (NOT_LIVE * step) / 2 - 4
    cy = y0 + r * step + sq / 2
    p.ring(cx, cy, NOT_LIVE * step / 2 + 10, 22)
    p.text(cx + NOT_LIVE * step / 2 + 24, cy + 7, f"{NOT_LIVE} not uses: {NOT_LIVE_KINDS[0]},", 18, STAMP)
    p.text(cx + NOT_LIVE * step / 2 + 24, cy + 29, NOT_LIVE_KINDS[1], 18, STAMP)
    p.text(x0 + per_row * step + 30, y0 + 24, f"{LIVE} live uses", 24, BALLPOINT)
    p.text(x0 + per_row * step + 30, y0 + 50, "read by a model in context:", 16, PENCIL)
    p.text(x0 + per_row * step + 30, y0 + 70, "the call-site-read role, reasoning on,", 16, PENCIL)
    p.text(x0 + per_row * step + 30, y0 + 90, "three calls each, the majority taken", 16, PENCIL)
    p.text(x0, 330, f"its three calls agreed on {AGREED} of the {CANDIDATES} and split two to one on the other {CANDIDATES - AGREED}; the judgement is each entry's pqch:in-use, labelled the model's", 17, PENCIL)
    p.text(x0, 356, "what a rule cannot decide: whether a line that names a library is a call, a comment, or a handler for an error", 17, PENCIL)
    p.save(SKETCHES / "05-code-candidates.svg")


def sketch_27_three_kinds_of_key_exchange() -> None:
    """Lesson 27: a TLS 1.2 listener establishes keys three ways, and a probe that offers one kind
    says nothing about the other two; PostgreSQL 18 with ssl_groups X25519MLKEM768:X25519 and no
    ssl_dh_params_file completed handshakes on a 2048-bit finite-field group and on RSA key
    transport (measured 2026-10-19, mini-agency records-db, xr7620)."""
    KINDS = [  # (kind, what the server contributes, where configured, what a group list shows, the probe)
        ("a named group", ["a key share in a group", "both sides name"], "ssl_groups, ssl_ecdh_curve", "the group", "-groups X25519MLKEM768"),
        ("finite-field DHE", ["parameters the server", "supplies itself"], "ssl_dh_params_file, or nothing", "nothing", "-tls1_2 -cipher kDHE"),
        ("RSA key transport", ["its RSA certificate's key;", "the client encrypts to it"], "the cipher list, by default", "nothing", "-tls1_2 -cipher kRSA"),
    ]
    p = Page(1000, 560, seed=27, title="Three ways to establish a key; a probe per kind")
    p.text(500, 48, "Three ways to agree a key. A probe that offers one says nothing about the other two.", 29, INK, "middle")

    colw, gap, x0, top = 290, 25, 40, 90
    for i, (kind, contributes, where, shows, probe) in enumerate(KINDS):
        x = x0 + i * (colw + gap)
        p.box(x, top, colw, 330, BALLPOINT, 2.0)
        p.text(x + colw / 2, top + 34, kind, 25, INK, "middle")
        p.text(x + 14, top + 68, "the server contributes", 15, PENCIL)
        for k, t in enumerate(contributes):
            p.text(x + 14, top + 90 + k * 21, t, 18, BALLPOINT)
        p.text(x + 14, top + 146, "configured by", 15, PENCIL)
        p.text(x + 14, top + 168, where, 18, BALLPOINT)
        p.text(x + 14, top + 206, "a list of groups shows", 15, PENCIL)
        p.text(x + 14, top + 230, shows, 20, INK if shows == "nothing" else BALLPOINT)
        p.text(x + 14, top + 270, "the probe, on its own", 15, PENCIL)
        p.text(x + 14, top + 294, probe, 18, BALLPOINT)
    # The point: two of the three are invisible to a probe that offers groups.
    x1 = x0 + (colw + gap)
    p.ring((x1 + 14 + x1 + colw + gap + 14 + measure("nothing", 20)) / 2, top + 224, (colw + gap + measure("nothing", 20)) / 2 + 14, 22)
    p.text(x1 + colw + gap / 2, top + 268 - 14 + 110, "invisible to a probe that offers groups: a TLS 1.2 listener", 18, STAMP, "middle")
    p.text(x1 + colw + gap / 2, top + 268 - 14 + 132, "can say no to every group and still agree a key both ways", 18, STAMP, "middle")
    p.text(40, 500, "PostgreSQL 18 with ssl_groups = 'X25519MLKEM768:X25519' and no ssl_dh_params_file refused secp256r1 and still completed", 15, PENCIL)
    p.text(40, 522, "a handshake on a 2048-bit finite-field group it supplied itself (RFC 3526 group 14) and another on RSA key transport", 15, PENCIL)
    p.text(40, 544, "or one full cipher-suite enumeration (testssl.sh -E), which reports the DHE suites and the size of the group behind them", 15, PENCIL)
    p.save(SKETCHES / "27-three-kinds-of-key-exchange.svg")


def sketch_20_three_precedence_rules() -> None:
    """Lesson 20: the same setting given twice is resolved three ways: OpenSSH takes the first
    value it reads, PostgreSQL the last, nginx the innermost block (measured 2026-10-05, spike S3
    lab)."""
    FILES = [  # (software, file, lines, which line wins (index), the rule)
        ("OpenSSH", "sshd_config", ["KexAlgorithms  a", "…", "KexAlgorithms  b"], 0, "the first value read"),
        ("PostgreSQL", "postgresql.conf", ["ssl_groups = 'a'", "…", "ssl_groups = 'b'"], 2, "the last value read"),
        ("nginx", "nginx.conf", ["http {", "  ssl_ecdh_curve a;", "  server {", "    ssl_ecdh_curve b;", "  }", "}"], 3, "the innermost block"),
    ]
    p = Page(1000, 500, seed=20, title="The same two lines, three winners")
    p.text(500, 48, "The same setting twice. Which one wins is the software's rule, not a convention.", 29, INK, "middle")

    colw, gap, x0, top = 290, 25, 40, 90
    for i, (sw, fname, lines, wins, rule) in enumerate(FILES):
        x = x0 + i * (colw + gap)
        p.text(x, top, sw, 26, INK)
        p.text(x + colw, top, fname, 15, PENCIL, "end")
        p.box(x, top + 14, colw, 190, PENCIL, 1.4)
        for k, t in enumerate(lines):
            y = top + 44 + k * 26
            p.text(x + 16, y, t, 18, BALLPOINT if k == wins else PENCIL)
            if k == wins:
                w = measure(t, 18)
                p.ring(x + 16 + w / 2, y - 6, w / 2 + 12, 16, BALLPOINT, 2.0)
        p.text(x + colw / 2, top + 236, "wins: " + rule, 20, INK, "middle")
    p.text(500, 372, "one rule carried to all three names the wrong line with confidence;", 20, STAMP, "middle")
    p.text(500, 396, "a change made to that line applies cleanly and alters nothing", 20, STAMP, "middle")
    p.text(40, 450, "includes follow the same rule: OpenSSH reads a drop-in where the Include stands (at the top it beats the main file, at the bottom it loses);", 14, PENCIL)
    p.text(40, 470, "PostgreSQL likewise, the other way round; nginx inlines the file where the include stands, and a file its pattern does not match is not read at all", 14, PENCIL)
    p.save(SKETCHES / "20-three-precedence-rules.svg")


def sketch_29_an_upgrade_port_is_silent() -> None:
    """Lesson 29: a scanner that speaks TLS from the first byte to a PostgreSQL port gets nothing
    back and reports nothing; through the SSLRequest upgrade the same listener yields the hybrid
    group, X25519, a 2048-bit DHE group, RSA key transport and its certificate in 91 s (measured
    2026-10-19, 172.16.106.30:5432, xr7620)."""
    UPGRADE_S = "91 s"
    FOUND = ["X25519MLKEM768", "X25519", "a 2048-bit DHE group", "RSA key transport", "its certificate"]
    p = Page(1000, 520, seed=29, title="A plain TLS scan of an upgrade port is silent, not negative")
    p.text(500, 48, "Silent is not negative. The port speaks its own protocol first.", 34, INK, "middle")

    # The listener.
    lx, ly = 420, 100
    p.box(lx, ly, 160, 300, INK, 2.2, fill=PAPER)
    p.text(lx + 80, ly + 40, "port 5432", 24, INK, "middle")
    p.text(lx + 80, ly + 66, "PostgreSQL", 18, PENCIL, "middle")
    p.text(lx + 80, ly + 90, "TLS only after", 15, PENCIL, "middle")
    p.text(lx + 80, ly + 110, "an SSLRequest", 15, PENCIL, "middle")
    # Scanner one: TLS from the first byte.
    p.text(60, 150, "the plain TLS profile", 22, INK)
    p.text(60, 174, "sends a ClientHello first", 17, BALLPOINT)
    p.arrow([(300, 166), (360, 166), (lx - 6, 170)], BALLPOINT, 2.0)
    p.arrow([(lx - 6, 206), (360, 208), (300, 206)], PENCIL, 1.8)
    p.text(60, 212, "answered in the wrong language,", 17, PENCIL)
    p.text(60, 234, "or the connection closed", 17, PENCIL)
    p.text(60, 272, "no TLS seen, nothing reported:", 19, INK)
    p.text(60, 296, "the same as a port with no cryptography", 19, INK)
    p.ring(214, 282, 172, 34)
    p.text(60, 340, "silent, not negative", 22, STAMP)
    # Scanner two: the upgrade first.
    p.text(620, 150, "the postgres profile", 22, INK)
    p.text(620, 174, "sends the SSLRequest, then TLS", 17, BALLPOINT)
    p.arrow([(lx + 166, 166), (600, 166)], BALLPOINT, 2.0)
    p.text(620, 212, "found:", 17, PENCIL)
    for k, t in enumerate(FOUND):
        p.text(640, 236 + k * 22, t, 18, BALLPOINT)
    p.text(620, 360, f"in {UPGRADE_S}: every handshake repeats the upgrade", 15, PENCIL)
    p.text(60, 450, "so: name each listener's protocol in the scope (postgres, smtp, imap, ldap), bind it to a profile that speaks the upgrade,", 15, PENCIL)
    p.text(60, 472, "let the plain profile refuse it, and show a protocol no profile claims as unscanned, never as clean", 15, PENCIL)
    p.save(SKETCHES / "29-an-upgrade-port-is-silent.svg")


def sketch_63_a_static_copy_shows_a_recorded_call() -> None:
    """Lesson 63: a page whose answer comes from a model, copied to a static site, shows a call made once
    and kept, labelled with the model, the hardware and the date, and runs the rule's check again when the
    page is built. Measured 2026-11-05: six example questions, Nemotron 3.5 Super VL through the lab
    gateway, 37 to 91 s a call, every citation passing."""
    N, LO, HI = 6, "37", "91"
    p = Page(1000, 500, seed=63, title="A static copy shows a recorded call and checks it again")
    p.text(500, 48, "Record the model once. Run the rule every time.", 34, INK, "middle")
    # Left: the live workbench.
    p.box(30, 100, 310, 230, INK, 2.2, fill=PAPER)
    p.text(185, 136, "the running workbench", 21, INK, "middle")
    p.text(185, 166, "question, retrieve, model call,", 15, PENCIL, "middle")
    p.text(185, 188, "rule checks each citation", 16, PENCIL, "middle")
    p.text(185, 238, f"pqch ask record:", 18, BALLPOINT, "middle")
    p.text(185, 262, f"{N} examples, {LO} to {HI} s each", 16, BALLPOINT, "middle")
    p.text(185, 300, "answers kept beside the run", 16, PENCIL, "middle")
    p.arrow([(346, 220), (390, 220), (420, 220)], BALLPOINT, 2.0)
    # Middle: the recording.
    p.box(425, 150, 170, 140, INK, 2.0, fill=PAPER)
    p.text(510, 186, "the recording", 19, INK, "middle")
    p.text(510, 214, "reply as returned", 15, PENCIL, "middle")
    p.text(510, 236, "model, hardware,", 15, PENCIL, "middle")
    p.text(510, 256, "date, tokens", 15, PENCIL, "middle")
    p.arrow([(601, 220), (630, 220), (652, 220)], BALLPOINT, 2.0)
    # Right: the static page.
    p.box(655, 100, 320, 230, INK, 2.2, fill=PAPER)
    p.text(815, 136, "the static page", 21, INK, "middle")
    p.text(815, 166, "no model; the box is disabled", 15, PENCIL, "middle")
    p.text(815, 196, "\"recorded 2026-11-05\"", 17, BALLPOINT, "middle")
    p.text(815, 238, "the rule runs again at build,", 16, STAMP, "middle")
    p.text(815, 262, "against the published ledger", 16, STAMP, "middle")
    p.ring(815, 250, 150, 36)
    p.text(815, 300, "a stored verdict is never shown", 15, PENCIL, "middle")
    p.text(60, 400, "so: a copy without the model is still honest. It says the answer is a recording and when it was made,", 14, PENCIL)
    p.text(60, 422, "it offers only the questions that were recorded, and the verdict a reader sees is computed where they read it", 14, PENCIL)
    p.save(SKETCHES / "63-a-static-copy-shows-a-recorded-call.svg")


def sketch_arch_five_layers() -> None:
    """The architecture page: five layers of the approach, hardware-neutral, and the ledger standing
    beside every one of them. The same layers as the stage's beat 2 (src/pqch/ui/static/demo.js,
    arch()), each box checked against the code on 2026-11-10: the packs are policy/packs/*.yaml, the
    compatibility rule is compatibility/entry/1, the gap queue is assessor/gaps.py, the roles and
    tiers are config/inference.example.yaml. Hardware is named once, as where a copy was recorded."""
    LAYERS = [
        ("L5", "what comes out", "projections, and the people's part", [
            ("the CBOM", "CycloneDX 1.6"), ("register and plan", "steps in order, facts beside"),
            ("changes", "approved, probed twice"), ("Ask the CBOM", "citations checked"),
            ("gap queue", "what was not reached, named")]),
        ("L4", "judgement", "rules over the evidence", [
            ("policy packs", "data; quotes checked"), ("rules", "status per entry"),
            ("claims and grades", "wire over file over statement"), ("supplier statements", "never merged"),
            ("the owner's facts", "supplied, never computed"), ("verifier", "paired probes; no model")]),
        ("L3", "the harness", "one job each", [
            ("app", "the only door; the one writer"), ("runner", "holds the Docker socket"),
            ("signer", "no network"), ("system runner", "reads a host whole"), ("the seam", "tiers set in config"),
            ("scanners", "containers, by digest")]),
        ("L2", "models, by role", "measured against a floor first", [
            ("fast tier", "narrate, name, propose"), ("deliberate tier", "trace, reconcile, answer"),
            ("embed tier", "retrieval for Ask"), ("never", "a finding, a verdict, an approval")]),
        ("L1", "where it runs", "any host with Docker", [
            ("images by digest", "an offline bundle; nothing fetched"), ("one host named", "on every event, as recorded"),
            ("one option", "an isolated scanner on a desktop GPU box")]),
    ]
    LEDGER = [("hash-chained events", "every finding, judgement, approval, verdict"),
              ("signed checkpoints", "ML-DSA-65, key id on each page"),
              ("projections", "rebuilt from events, never edited"),
              ("replayable", "a recording replays on any host")]

    W, H = 1500, 1040
    p = Page(W, H, seed=33, title="Five layers of the approach, and the ledger beside every one")
    p.text(40, 56, "Five layers, and the ledger beside every one.", 38, INK)
    p.text(40, 88, "Whatever a layer does is an event on the ledger first; the CBOM, the register, the plan and the pages are rebuilt from it.", 21, PENCIL)

    top, band_h, gap = 122, 158, 14
    left, label_w, right_edge = 40, 190, 1150
    lx, lw = 1215, 250
    for k, (code, name, sub, items) in enumerate(LAYERS):
        y = top + k * (band_h + gap)
        p.box(left, y, right_edge - left, band_h, PENCIL, 1.5)
        p.text(left + 16, y + 40, code, 30, BALLPOINT)
        p.text(left + 62, y + 40, name, 28, INK)
        for i, t in enumerate(_wrap(sub, 18)):
            p.text(left + 16, y + 72 + i * 23, t, 19, PENCIL)
        x0, x1 = left + label_w, right_edge - 14
        n = len(items)
        cw = (x1 - x0 - (n - 1) * 12) / n
        for i, (title, note) in enumerate(items):
            bx = x0 + i * (cw + 12)
            p.box(bx, y + 22, cw, band_h - 44, BALLPOINT, 1.8)
            ts = 22 if measure(title, 22) < cw - 20 else 19
            for j, t in enumerate(_wrap(title, int((cw - 20) / (ts * 0.42)))):
                p.text(bx + cw / 2, y + 58 + j * 24, t, ts, BALLPOINT, "middle")
            for j, t in enumerate(_wrap(note, int((cw - 14) / 8.6))):
                p.text(bx + cw / 2, y + 100 + j * 22, t, 19, PENCIL, "middle")
        # every layer writes to the ledger before anything is shown
        p.arrow([(right_edge + 4, y + band_h / 2), (lx - 30, y + band_h / 2 + p.j(6)), (lx - 4, y + band_h / 2)], INK, 1.8, 11)

    ly, lh = top, len(LAYERS) * (band_h + gap) - gap
    p.box(lx, ly, lw, lh, INK, 2.6)
    p.text(lx + lw / 2, ly + 46, "the ledger", 32, INK, "middle")
    p.text(lx + lw / 2, ly + 74, "one signed JSONL per run", 19, PENCIL, "middle")
    p.text(lx + lw / 2, ly + 95, "the record, not a log", 19, PENCIL, "middle")
    step = (lh - 140) / len(LEDGER)
    for i, (title, note) in enumerate(LEDGER):
        y = ly + 150 + i * step
        p.text(lx + lw / 2, y, title, 24, BALLPOINT, "middle")
        for j, t in enumerate(_wrap(note, 24)):
            p.text(lx + lw / 2, y + 40 + j * 22, t, 19, PENCIL, "middle")
        if i < len(LEDGER) - 1:
            p.line(lx + lw / 2, y + 86, lx + lw / 2, y + step - 32, PENCIL, 1.4, dash=True)
    # the point: the record comes before every projection
    y0 = ly + 150
    p.ring(lx + lw / 2, y0 - 8, measure("hash-chained events", 24) / 2 + 16, 21)
    p.text(40, H - 20, "the same layers on an x86_64 server with its models behind one seam, and once on a desktop GPU box with the network cut", 20, PENCIL)
    p.save(SKETCHES / "arch-five-layers.svg")


def sketch_21_foundation_and_shell() -> None:
    """Note 21: the federal readiness review of 2026-11-06 at f3f2621. The foundation holds; the
    thirteen findings are in the shell around it, three of them blocking (federal-review/01-findings.md)."""
    FOUNDATION = [  # what holds, the review's closing table
        "a hash-chained ledger, ML-DSA checkpoints",
        "the CBOM rebuilt from it",
        "scans bounded by a scope file",
        "images by digest, an offline bundle",
        "rules first; models by measurement",
        "verified by probes, never a model",
    ]
    SHELL = [  # (severity, finding) in the review's order
        ("P0", "who may act: one owner, no roles"),
        ("P0", "its own crypto in no validated module"),
        ("P0", "plain HTTP to the page and the models"),
        ("P1", "containers at Docker's defaults"),
        ("P1", "no SBOM or signature of itself"),
        ("P1", "a model's fact unlabelled in the CBOM"),
        ("P1", "AI use undocumented; origin unchecked"),
        ("P1", "the inventory handled as plain files"),
        ("P1", "WCAG gaps, no conformance report"),
        ("P1", "IR 8547 final not in the packs"),
        ("P2", "sockets open to any caller"),
        ("P2", "no log export; reads unrecorded"),
        ("P2", "authorization a free-text name"),
    ]
    p = Page(1000, 640, seed=21, title="The foundation holds; the thirteen findings are in the shell around it")
    p.text(500, 48, "Nothing underneath fails. What blocks is around it.", 36, INK, "middle")

    fx, fy, fw, fh = 40, 110, 400, 470
    p.box(fx, fy, fw, fh, INK, 2.6)
    p.text(fx + fw / 2, fy + 44, "the foundation", 30, INK, "middle")
    p.text(fx + fw / 2, fy + 70, "what an assessor looks for", 18, PENCIL, "middle")
    for i, t in enumerate(FOUNDATION):
        y = fy + 124 + i * 54
        p.tick(fx + 34, y - 6, 14, BALLPOINT, 2.4)
        p.text(fx + 58, y, t, 21, BALLPOINT)

    sx = 520
    p.text(sx, fy + 20, f"the shell: {len(SHELL)} findings", 26, INK)
    for i, (sev, t) in enumerate(SHELL):
        y = fy + 80 + i * 31 + (0 if sev == "P0" else 20)   # room under the ring
        p.text(sx, y, sev, 20, INK if sev == "P0" else PENCIL, weight=700)
        p.text(sx + 44, y, t, 20, BALLPOINT if sev == "P0" else PENCIL)
    # The point: the three that block are all outside the foundation.
    n0 = sum(1 for s, _ in SHELL if s == "P0")
    p.ring(sx + 180, fy + 80 + (n0 - 1) * 31 / 2 - 7, 235, 64)
    p.text(40, 616, "read 2026-11-06 at f3f2621; P0 blocks an authorization as it stands, P1 an assessor opens at once", 18, PENCIL)
    p.save(SKETCHES / "21-foundation-and-shell.svg")


def sketch_65_two_writers_three_readers() -> None:
    """Lesson 65: before a private mode, the readers. Two writers (the kit's system runner as root, writing
    var/raw and agency/generated/) and three readers at three uids (the app as 1000, the public builder as the
    host user, the estate's services as their own). The red ring is on the raw-output file: 0600 under root
    closes it to the uid-1000 reader. Read from kit/compose.system.yaml and compose.yaml, 2026-11-06/08."""
    p = Page(1000, 520, seed=65, title="Two writers, three readers: find every reader before a private mode")
    p.text(500, 46, "Before a private mode, list every reader and its uid.", 32, INK, "middle")
    # The writer, left.
    p.box(30, 120, 250, 150, INK, 2.2, fill=PAPER)
    p.text(155, 156, "system runner", 21, INK, "middle")
    p.text(155, 184, "uid 0 (root)", 18, BALLPOINT, "middle")
    p.text(155, 212, "reads host keys only", 14, PENCIL, "middle")
    p.text(155, 232, "root can read; writes two places", 14, PENCIL, "middle")
    # Two files in the middle.
    p.box(400, 90, 200, 90, INK, 2.0, fill=PAPER)
    p.text(500, 122, "var/raw/<job>", 18, INK, "middle")
    p.text(500, 150, "owner root, 0600 if private", 14, BALLPOINT, "middle")
    p.box(400, 300, 200, 90, INK, 2.0, fill=PAPER)
    p.text(500, 332, "agency/generated/", 18, INK, "middle")
    p.text(500, 360, "the estate's own config", 14, PENCIL, "middle")
    p.arrow([(284, 170), (340, 150), (396, 135)], BALLPOINT, 2.0)
    p.arrow([(284, 230), (340, 300), (396, 340)], BALLPOINT, 2.0)
    # Three readers, right.
    p.box(720, 60, 250, 80, INK, 2.0, fill=PAPER)
    p.text(845, 90, "app", 19, INK, "middle")
    p.text(845, 116, "uid 1000: cannot open 0600 of root", 13, BALLPOINT, "middle")
    p.box(720, 170, 250, 80, INK, 2.0, fill=PAPER)
    p.text(845, 200, "tools/build_public.py", 18, INK, "middle")
    p.text(845, 226, "the host user, outside the containers", 13, PENCIL, "middle")
    p.box(720, 310, 250, 80, INK, 2.0, fill=PAPER)
    p.text(845, 340, "the estate's services", 18, INK, "middle")
    p.text(845, 366, "their own uids: a umask would close this", 13, PENCIL, "middle")
    p.arrow([(604, 125), (660, 110), (716, 100)], BALLPOINT, 2.0)
    p.arrow([(604, 145), (660, 180), (716, 205)], BALLPOINT, 2.0)
    p.arrow([(604, 345), (660, 348), (716, 350)], BALLPOINT, 2.0)
    p.ring(500, 135, 118, 52)
    p.text(60, 450, "so: the private mode is a setting (PQCH_VAR_PRIVATE=1), turned on where every writer and reader is one uid;", 14, PENCIL)
    p.text(60, 472, "a process-wide umask is not used, because the second file is read by other uids by design", 14, PENCIL)
    p.save(SKETCHES / "65-two-writers-three-readers.svg")


def sketch_22_four_statuses() -> None:
    """Note 22: the four statuses an entry can land in under a policy pack, with the slice's counts under
    M-26-15 (47 entries: 2, 39, 1, 5; in use 2, 34, 1, 4), and the CNSA 2.0 answers from the FAQ read first-hand."""
    p = Page(1000, 560, seed=22, title="Four statuses for one entry")
    p.text(500, 44, "Every entry lands in one of four boxes under the pack that governs it", 30, INK, "middle")
    cols = [(30, "compatible", ["the family is one the pack", "calls resistant, or the name", "is one it lists for the function"], "2", "2 in use", BALLPOINT),
            (270, "not compatible", ["the table or footnote 13", "makes it vulnerable, or the pack", "names another algorithm"], "39", "34 in use", STAMP),
            (510, "unknown", ["the entry names no algorithm", "a table places, or the pack", "does not place the name"], "1", "1 in use", BALLPOINT),
            (750, "outside the pack", ["a hash, a symmetric algorithm", "or a protocol version the pack", "says nothing about"], "5", "4 in use", PENCIL)]
    for x, title, lines, n, sub, color in cols:
        p.box(x, 100, 220, 230, INK, 2.2, fill=PAPER)
        p.text(x + 110, 136, title, 23, color, "middle")
        for k, ln in enumerate(lines):
            p.text(x + 110, 172 + 22 * k, ln, 14.5, PENCIL, "middle")
        p.text(x + 110, 282, n, 44, color, "middle")
        p.text(x + 110, 312, sub, 15, PENCIL, "middle")
    p.text(500, 372, "the slice's 47 entries under OMB M-26-15, measured 2026-11-09; unknown is a count, never a pass", 16, BALLPOINT, "middle")
    # The second pack: the same entry, another answer, and the stamp.
    p.text(60, 430, "under CNSA 2.0 the same X25519MLKEM768 is not compatible (ML-KEM-1024 only) and SHA-256 is too (SHA-384, SHA-512);", 15, PENCIL)
    p.text(60, 452, "SecP384r1MLKEM1024 is unknown: a hybrid is compliant only where NSA identified one, and none is for TLS", 15, PENCIL)
    p.text(60, 490, "CNSA 2.0 FAQ Ver. 2.2 (October 2026), read first-hand 2026-11-09, every quote checked against its text; no status is provisional", 14, BALLPOINT)
    p.save(SKETCHES / "22-four-statuses.svg")


def sketch_23_observed_and_reported() -> None:
    """Note 23: observed (what the server showed) and reported (what the supplier states), joined by model
    and firmware version; the example's four outcomes, one each; the right column never crosses over."""
    p = Page(1000, 600, seed=23, title="Observed and reported, joined by model and version")
    p.text(500, 44, "What the server showed, what the supplier states, and the join between them", 29, INK, "middle")
    p.box(40, 90, 360, 290, INK, 2.2, fill=PAPER)
    p.text(220, 126, "observed", 24, BALLPOINT, "middle")
    p.text(220, 150, "the readers, on this server", 14, PENCIL, "middle")
    for k, ln in enumerate(["firmware names and versions (Redfish)", "Secure Boot databases: PK, KEK, db, dbx",
                            "the TPM's banks", "the controller's TLS, SSH, settings", "the listeners, asked directly",
                            "the host's own key files"]):
        p.text(64, 190 + 28 * k, ln, 16, INK)
    p.box(600, 90, 360, 290, PENCIL, 2.2, fill=PAPER, dash=True)
    p.text(780, 126, "reported", 24, STAMP, "middle")
    p.text(780, 150, "the supplier, about the model", 14, PENCIL, "middle")
    for k, ln in enumerate(["what signs each firmware image", "the modules inside, and their CMVP numbers",
                            "the post-quantum roadmap: algorithms,", "version, date or none",
                            "one word: update, replace,", "end-of-life, no-statement"]):
        p.text(624, 190 + 28 * k, ln, 16, INK)
    # The join.
    p.arrow([(400, 235), (600, 235)], BALLPOINT, 2.4)
    p.arrow([(600, 255), (400, 255)], BALLPOINT, 2.4)
    p.text(500, 220, "joined by", 14, PENCIL, "middle")
    p.text(500, 290, "model + firmware version", 17, BALLPOINT, "middle")
    p.cross(500, 330, 14, STAMP, 3.0)
    p.text(500, 362, "never crosses: reported stays reported", 14, STAMP, "middle")
    # The four outcomes.
    p.text(60, 430, "the example's four outcomes, one firmware each:", 16, PENCIL)
    outs = [("same version", "1", BALLPOINT), ("another version", "1", STAMP), ("named, not reported", "1", PENCIL),
            ("reported, not named", "1", PENCIL)]
    for k, (label, n, color) in enumerate(outs):
        x = 70 + 230 * k
        p.box(x, 455, 200, 90, INK, 2.0, fill=PAPER)
        p.text(x + 100, 490, n, 34, color, "middle")
        p.text(x + 100, 528, label, 15, PENCIL, "middle")
    p.text(500, 580, "shown side by side, every disagreement visible; the server's CBOM holds the left column only", 15, BALLPOINT, "middle")
    p.save(SKETCHES / "23-observed-and-reported.svg")


def sketch_68_two_claims_one_entry() -> None:
    """Lesson 68: two claims on one entry; the better-graded claim in force, the other kept as dissent; the
    list of both and the silent overwrite crossed out; a person's resolution as a stamp over the rule."""
    p = Page(1000, 600, seed=68, title="Two claims, one entry")
    p.text(500, 44, "Two sources, one entry: keep both claims, put one in force, show the dissent", 28, INK, "middle")
    # The entry.
    p.box(370, 110, 260, 130, INK, 2.4, fill=PAPER)
    p.text(500, 140, "one entry", 20, INK, "middle")
    p.text(500, 166, "certificate on 172.16.106.10:443", 13, PENCIL, "middle")
    p.text(500, 200, "not_after: 2029-01-05", 18, BALLPOINT, "middle")
    p.text(500, 224, "in force by precedence/1", 12, PENCIL, "middle")
    # The claims.
    p.slip(40, 120, ["claim · observed-wire", "testssl.sh, event 01M…", "not_after 2029-01-05"], 15, BALLPOINT)
    p.slip(720, 120, ["claim · reported", "other-scanner's CBOM", "not_after 2027-01-01"], 15, STAMP)
    p.arrow([(290, 170), (370, 170)], BALLPOINT, 2.6)
    p.line(720, 170, 630, 170, PENCIL, 1.8, dash=True)
    p.text(675, 160, "kept", 12, PENCIL, "middle")
    # The dissent slip.
    p.slip(380, 262, ["dissent · not_after", "2029-01-05  observed-wire  testssl.sh", "2027-01-01  reported  other-scanner"], 14, INK)
    # The two wrong answers.
    p.text(60, 390, "not this:", 16, PENCIL)
    p.box(60, 405, 300, 70, PENCIL, 2.0, fill=PAPER, dash=True)
    p.text(210, 433, 'not_after: ["2027-01-01", "2029-01-05"]', 15, PENCIL, "middle")
    p.text(210, 458, "a list of both: the type changed, nothing said", 12, PENCIL, "middle")
    p.line(80, 415, 340, 465, STAMP, 2.6, opacity=0.6)
    p.box(640, 405, 300, 70, PENCIL, 2.0, fill=PAPER, dash=True)
    p.text(790, 433, "not_after: 2027-01-01", 15, PENCIL, "middle")
    p.text(790, 458, "the last import wins: the scan's value lost", 12, PENCIL, "middle")
    p.line(660, 415, 920, 465, STAMP, 2.6, opacity=0.6)
    # The person's resolution.
    p.stamp(500, 520, "RESOLVED", 30)
    p.text(500, 560, "a person's claim.resolved event sets the field over the rule; resolution.revoked lifts it", 13, STAMP, "middle")
    p.save(SKETCHES / "68-two-claims-one-entry.svg")


def sketch_24_register_three_sources() -> None:
    """Note 24: the register's columns by where they come from (owner in ballpoint, rules in ink, plan in
    pencil), the three buckets above it, and the stamp: nothing estimated here."""
    p = Page(1000, 600, seed=24, title="The register, by source")
    p.text(500, 44, "The hand-off: one row per step, every column from the owner, the rules or the plan", 27, INK, "middle")
    # The buckets.
    for k, (label, sub) in enumerate((("identity, PKI, signing", "the CA's root, the reissues, the retire"),
                                      ("infrastructure, data protection", "offer, then require, the hybrid; TLS 1.3"),
                                      ("applications, mission", "replace the appliance that cannot"))):
        x = 60 + 300 * k
        p.box(x, 80, 270, 78, INK, 2.0, fill=PAPER)
        p.text(x + 135, 110, label, 17, INK, "middle")
        p.text(x + 135, 138, sub, 13, PENCIL, "middle")
    p.text(500, 182, "policy/buckets.yaml, version 1: by the step's id, then its kind; an unplaced step is counted, never hidden", 13, PENCIL, "middle")
    # The table.
    p.box(60, 210, 880, 250, INK, 2.2, fill=PAPER)
    cols = [("from the owner", BALLPOINT, ["system", "interface", "mission thread", "owner", "classification",
                                              "impact, lifetime", "vendor path", "cost + basis"]),
            ("from the rules", INK, ["priority, criteria", "deadline", "what set it", "sensitive through", "blocked on supplier", "compatibility"]),
            ("from the plan", PENCIL, ["step, title, why", "bucket", "wave", "state", "waits for", "entries by fingerprint"])]
    for k, (head, color, items) in enumerate(cols):
        x = 90 + 290 * k
        p.text(x, 244, head, 19, color)
        p.line(x, 252, x + 240, 252, color, 1.6)
        for i, it in enumerate(items):
            p.text(x, 280 + 22 * i, it, 14.5, color)
    p.line(350, 225, 350, 445, PENCIL, 1.2, dash=True)
    p.line(640, 225, 640, 445, PENCIL, 1.2, dash=True)
    p.text(500, 492, "the slice: one service costed (40,000 USD, planted, its basis in the row), three not; the sum says so", 14, PENCIL, "middle")
    p.stamp(500, 545, "NOTHING ESTIMATED HERE", 26)
    p.save(SKETCHES / "24-register-three-sources.svg")


def sketch_25_gaps_as_a_queue() -> None:
    """Note 25: gaps as slips under each asset class rather than a percentage; one slip enlarged and
    filled by evidence a person brought; the id holds across scans."""
    p = Page(1000, 620, seed=25, title="Gaps as a queue")
    p.text(500, 44, "What no tool could see: a slip per gap under its asset class, not a percentage", 27, INK, "middle")
    # The slice's three classes with a count (tests/test_gaps.py), and the synthetic server's firmware class
    # once the supplier's statement is in; a class with nothing to count is not drawn.
    classes = [("listeners", "4 of 4", 0), ("entries", "46 of 47", 1), ("services", "4 of 4", 0), ("firmware*", "2 of 3", 1)]
    for k, (name, n, gaps) in enumerate(classes):
        x = 90 + 220 * k
        p.box(x, 80, 140, 70, INK, 2.0, fill=PAPER)
        p.text(x + 70, 106, name, 16, INK, "middle")
        p.text(x + 70, 134, n, 15, BALLPOINT, "middle")
        for g in range(gaps):
            p.box(x + 18 + 6 * g, 160 + 10 * g, 100, 26, STAMP if g == 0 else PENCIL, 1.4, fill=PAPER)
        if gaps:
            p.text(x + 70, 178 + 10 * (gaps - 1), f"{gaps} gap{'s' if gaps != 1 else ''}", 12, STAMP, "middle")
    # One slip enlarged.
    p.slip(70, 270, ["gap 4261f0a3…  · key file not opened · key files", "pqch-agency/legacy:/etc/ssl/private/app.key",
                     "the reader could not open it (PermissionError);", "its algorithm and size are not known",
                     "fills: a privileged read-only read, or the owner's", "statement of the key's algorithm and size"], 15, INK)
    # The evidence and the fill.
    p.slip(640, 280, ["evidence", "run 01M…  event 01M…", "the owner's statement:", "RSA-3072, from the CA's records"], 15, BALLPOINT)
    p.arrow([(640, 330), (470, 330)], BALLPOINT, 2.4)
    p.stamp(300, 455, "FILLED", 34)
    p.text(300, 492, "by ken, 2026-11-09, citing the run and event; the basis in words", 13, STAMP, "middle")
    p.text(500, 560, "the id is the hash of kind and subject: the next scan's same gap is already filled; coverage moves only by evidence", 14, PENCIL, "middle")
    p.text(500, 590, "the slice's listeners, entries and services; *the synthetic server's firmware once the supplier's statement is in (3 gaps before)", 13, PENCIL, "middle")
    p.save(SKETCHES / "25-gaps-as-a-queue.svg")


def sketch_70_judgements_fold_onto_entries() -> None:
    """Lesson 70: the compatibility rule's 227 judgements (189 not compatible) fold onto the document's 221
    entries (183 not compatible); the plan page read the first, the CBOM page the second."""
    p = Page(1000, 520, seed=70, title="Judgements fold onto entries")
    p.text(500, 44, "A rule judges each observation; the document holds each asset once", 30, INK, "middle")
    p.box(60, 100, 340, 250, INK, 2.2, fill=PAPER)
    p.text(230, 136, "the rule's judgements", 22, BALLPOINT, "middle")
    p.text(230, 160, "one per observation, on the ledger", 14.5, PENCIL, "middle")
    p.text(230, 236, "227", 60, BALLPOINT, "middle")
    p.text(230, 286, "189 not compatible", 22, STAMP, "middle")
    p.text(230, 326, "the plan page counted these", 14.5, PENCIL, "middle")
    p.box(600, 100, 340, 250, INK, 2.2, fill=PAPER)
    p.text(770, 136, "the document's entries", 22, BALLPOINT, "middle")
    p.text(770, 160, "one per asset, in the CBOM", 14.5, PENCIL, "middle")
    p.text(770, 236, "221", 60, BALLPOINT, "middle")
    p.text(770, 286, "183 not compatible", 22, STAMP, "middle")
    p.text(770, 326, "the CBOM page counted these", 14.5, PENCIL, "middle")
    p.line(410, 225, 588, 225, INK, 2.4)
    p.line(588, 225, 572, 215, INK, 2.4)
    p.line(588, 225, 572, 235, INK, 2.4)
    p.text(500, 205, "fold", 20, INK, "middle")
    p.text(500, 252, "same asset, one entry", 14, PENCIL, "middle")
    p.text(500, 272, "6 judgements join", 14, PENCIL, "middle")
    p.text(500, 290, "an entry already there", 14, PENCIL, "middle")
    p.text(500, 410, "one label, two numbers: both true, and a reader who sees both trusts neither", 17, BALLPOINT, "middle")
    p.text(500, 446, "so: every page reads the figure from the document, through one function, and a test holds them equal", 15, PENCIL, "middle")
    p.text(500, 484, "the mini-agency's scan of 2026-11-09", 13, PENCIL, "middle")
    p.save(SKETCHES / "70-judgements-fold-onto-entries.svg")


def sketch_69_summaries_against_the_primary() -> None:
    """Lesson 69: the CNSA 2.0 timeline as two secondary summaries gave it (five equipment categories, dates
    2025 to 2033) beside what the primary FAQ Ver. 2.2 gives (three dates for all of NSS)."""
    p = Page(1000, 560, seed=69, title="The summaries against the primary")
    p.text(500, 44, "A pack written from summaries carries a table the primary had already replaced", 28, INK, "middle")
    p.box(40, 90, 430, 400, INK, 2.2, fill=PAPER)
    p.text(255, 124, "two secondary summaries (2022, undated)", 18, PENCIL, "middle")
    rows = [("software and firmware signing", "exclusive by 2030"), ("browsers, servers, cloud", "prefer 2025, exclusive 2033"),
            ("networking equipment", "exclusive by 2030"), ("operating systems", "prefer 2027, exclusive 2033"),
            ("niche equipment", "prefer 2030, exclusive 2033")]
    for k, (a, b) in enumerate(rows):
        y = 170 + 46 * k
        p.text(70, y, a, 15, PENCIL)
        p.text(70, y + 20, b, 14, PENCIL)
    p.line(40, 90, 470, 490, STAMP, 2.0)
    p.text(255, 460, "verified: false, no deadline applied", 14, STAMP, "middle")
    p.box(530, 90, 430, 400, INK, 2.2, fill=PAPER)
    p.text(745, 124, "the FAQ, Ver. 2.2, October 2026, read 2026-11-09", 18, BALLPOINT, "middle")
    for k, (a, b) in enumerate([("2027-01-01", "required in all new acquisitions for NSS"),
                                ("2030-12-31", "what cannot support CNSA 2.0 phased out"),
                                ("2031-12-31", "CNSA 2.0 algorithms mandated for use")]):
        y = 190 + 80 * k
        p.text(560, y, a, 26, BALLPOINT)
        p.text(560, y + 28, b, 14.5, INK)
    p.text(745, 460, "one clock for all of NSS; every quote checked by the loader", 14, BALLPOINT, "middle")
    p.text(500, 530, "so: a pack from secondaries is marked unverified and sets no date; the primary is read before any date is applied", 15, PENCIL, "middle")
    p.save(SKETCHES / "69-summaries-against-the-primary.svg")


def sketch_67_recording_record_notes() -> None:
    """Lesson 67: what a public copy of a running system may be made of. Three boxes with the cost of a new
    feature in each; the facsimile crossed out with its cost. Counts from the lesson: 11 pages rendered
    before, 4 after; 17 public branches before, none on the dropped pages after."""
    p = Page(1000, 520, seed=67, title="Publish a recording, a record and notes, not a facsimile")
    p.text(500, 46, "What a public copy of a running system is made of", 32, INK, "middle")
    boxes = [(30, "a recording", ["the stage: eight beats", "from one run, dated,", "the hardware named"], "a new feature: one beat"),
             (270, "the record", ["the run's documents:", "ledger, CBOM, score,", "each with its hash"], "a new feature: one row"),
             (510, "notes", ["the explanation, and", "the screens as captured", "(7 screenshots, 1440 px)"], "a new feature: a picture")]
    for x, title, lines, cost in boxes:
        p.box(x, 110, 210, 200, INK, 2.2, fill=PAPER)
        p.text(x + 105, 146, title, 22, INK, "middle")
        for k, ln in enumerate(lines):
            p.text(x + 105, 180 + 24 * k, ln, 15, PENCIL, "middle")
        p.text(x + 105, 284, cost, 15, BALLPOINT, "middle")
    # The facsimile, crossed out.
    x = 760
    p.box(x, 110, 210, 200, PENCIL, 2.0, fill=PAPER, dash=True)
    p.text(x + 105, 146, "a facsimile", 22, PENCIL, "middle")
    for k, ln in enumerate(["the app's pages, static,", "11 of them, 12 branches", "to disable what is dead"]):
        p.text(x + 105, 180 + 24 * k, ln, 15, PENCIL, "middle")
    p.text(x + 105, 284, "a new feature: a page", 15, PENCIL, "middle")
    p.line(x + 20, 125, x + 190, 295, STAMP, 3.0, opacity=0.55)
    p.line(x + 190, 125, x + 20, 295, STAMP, 3.0, opacity=0.55)
    p.text(60, 380, "the first three cost a beat, a row or a picture per feature; the fourth costs a fixture, a template branch,", 15, PENCIL)
    p.text(60, 402, "a dead-button note and a leak check per page, and it is the one the reader who checks learns to distrust", 15, PENCIL)
    p.text(60, 450, "after the rule: 4 pages rendered (the stage, the CBOM viewer, the recorded answers, About), none with a dead control", 15, BALLPOINT)
    p.save(SKETCHES / "67-recording-record-notes.svg")


def sketch_74_size_the_drawing_from_the_screen() -> None:
    """Lesson 74: the opening's drawing at 1813×883. Left, capped by a constant (100vh − 440, at most 780):
    443 px of drawing, 250 px empty under it, eight services 10 px apart. Right, sized from the screen
    (the room under the heading, less the sentence and the bar, at least 560): 600 px, the sheet takes its
    rows' height and the chain and the plan share the rest, eight services 15 px apart."""
    p = Page(1000, 560, seed=74, title="Size the drawing from the screen")
    p.text(500, 42, "The same screen, 883 px tall, twice", 28, INK, "middle")
    # a screen: heading, drawing, sentence, bar; heights to scale (0.5 px per px)
    def screen(x, w, draw_h, bands, empty, note_color):
        y0 = 80
        p.box(x, y0, w, 441, INK, 2.2, fill=PAPER)
        p.text(x + w / 2, y0 + 30, "heading", 15, PENCIL, "middle")
        p.line(x + 6, y0 + 56, x + w - 6, y0 + 56, PENCIL, 1.4, dash=True)
        top = y0 + 60
        for k, (frac, label, gap) in enumerate(bands):
            h = draw_h * frac / 2
            p.box(x + 14, top, w - 28, h, BALLPOINT, 1.8)
            p.text(x + 24, top + h / 2 + 5, label, 13.5, BALLPOINT)
            top += h + gap
        if empty:   # the unused room; the sentence sits under it, against the bar, and is not labelled twice
            p.text(x + w / 2, top + empty / 4 + 6, "empty", 16, PENCIL, "middle")
        else:
            p.text(x + w / 2, top + 20, "the sentence", 14, PENCIL, "middle")
        p.line(x + 6, y0 + 441 - 28, x + w - 6, y0 + 441 - 28, PENCIL, 1.4, dash=True)
        p.text(x + w / 2, y0 + 441 - 9, "the beat bar", 13, PENCIL, "middle")
    screen(60, 380, 443, [(0.29, "the sheet, 129 px", 4), (0.31, "the chain: 8 services, 10 px apart", 4), (0.36, "the plan: 8 lanes, 14 px each", 0)], 250, PENCIL)
    p.text(250, 60, "capped: 100vh - 440, at most 780", 16, PENCIL, "middle")
    p.ring(250, 410, 150, 42, STAMP, 2.6)
    p.text(250, 476, "250 px unused while the labels collide", 16, STAMP, "middle")
    screen(560, 380, 600, [(0.30, "the sheet: its rows' height, 180 px", 8), (0.315, "the chain: 8 services, 15 px apart", 8), (0.355, "the plan: 8 lanes, 19 px each", 0)], 0, PENCIL)
    p.text(750, 60, "measured: the room under the heading, less 160", 16, PENCIL, "middle")
    p.text(500, 548, "the stage's opening beat, headless Chromium at 1813 x 883, 2026-11-13", 13, PENCIL, "middle")
    p.save(SKETCHES / "74-size-the-drawing-from-the-screen.svg")


def _wrap(s: str, n: int) -> list[str]:
    """Words into lines of at most about n characters."""
    out, cur = [], ""
    for w in s.split():
        if cur and len(cur) + 1 + len(w) > n:
            out.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    return out + ([cur] if cur else [])


def main() -> None:
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("sketch_") and callable(v)]:
        fn()


if __name__ == "__main__":
    main()
