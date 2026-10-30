"""The lab estate at VLAN level, for the lab portal: counts, shares and postures by VLAN name.

Nothing in it names a host: no address, no SNI, no certificate subject, no outside domain. The
portal shows this band on its front page; the page with the addresses stays behind this
service's own door. `vlan_names` comes from a deployment-side file (PQCH_VLAN_NAMES), never
the repository, so a VLAN is named only where the deployment says so.
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime, UTC
from pathlib import Path

from pqch.run import Run
from pqch.ui.view import capture_view, runs_of_kind


def vlan_names(path: str | None = None) -> dict[int, str]:
    p = Path(path or os.environ.get("PQCH_VLAN_NAMES", ""))
    if not p.is_file():
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {int(k): str(v) for k, v in raw.items() if str(k).isdigit()}


def _pct(part: float, whole: float) -> float | None:
    return round(100.0 * part / whole, 1) if whole else None


def _share_of(hours: list[dict], pick) -> tuple[float | None, float | None]:
    """(negotiated %, offered %) over every hour's tally, for the slice `pick` returns."""
    hs = hy = off = 0
    for h in hours:
        s = pick(h) or {}
        hs += s.get("handshakes", 0)
        hy += s.get("hybrid", 0)
        off += s.get("hybrid_offered", 0)
    return _pct(hy, hs), _pct(off, hs)


_history_cache: dict[str, tuple[tuple[int, int], dict]] = {}


def _history_point(r: Run) -> dict | None:
    """One closed capture run's outside-negotiated and inside-offered shares, cached by its ledger."""
    try:
        st = r.ledger.path.stat()
    except OSError:
        return None
    key = (st.st_size, st.st_mtime_ns)
    hit = _history_cache.get(r.id)
    if hit and hit[0] == key:
        return hit[1]
    closed = None
    hours = []
    for e in r.ledger.events():
        if e["type"] == "scan.completed" and e["payload"].get("tally"):
            hours.append(e["payload"]["tally"])
        elif e["type"] == "run.closed":
            closed = e["ts"]
    if not closed or not hours:
        return None
    out_neg, _ = _share_of(hours, lambda h: h.get("outside"))
    _, in_off = _share_of(hours, lambda h: h.get("inside"))
    pt = {"closed_at": closed, "outside_negotiated_pct": out_neg, "inside_offered_pct": in_off}
    _history_cache[r.id] = (key, pt)
    return pt


def _certificates(bom: dict | None, today: date) -> dict:
    count, soonest = 0, None
    for c in (bom or {}).get("components", []):
        cp = c.get("cryptoProperties") or {}
        if cp.get("assetType") != "certificate":
            continue
        count += 1
        until = (cp.get("certificateProperties") or {}).get("notValidAfter")
        if until:
            try:
                d = datetime.fromisoformat(until.replace("Z", "+00:00")).date()
            except ValueError:
                continue
            if soonest is None or d < soonest:
                soonest = d
    return {"count": count, "soonest_expiry": soonest.isoformat() if soonest else None,
            "soonest_days": (soonest - today).days if soonest else None}


def _listeners_in_scan(bom: dict | None) -> int:
    seen = set()
    for c in (bom or {}).get("components", []):
        for o in (c.get("evidence") or {}).get("occurrences", []) or []:
            if o.get("location"):
                seen.add(o["location"])
    return len(seen)


def _note(vlan_servers: list[dict], vlan_ssh: list[dict]) -> str | None:
    """One plain sentence about the VLAN's listeners, without naming any of them."""
    refusing = [s for s in vlan_servers if (s.get("posture") or {}).get("posture") == "classical"
                and (s.get("posture") or {}).get("hybrid_offered", 0) > 0]
    if refusing:
        top = max(refusing, key=lambda s: s["handshakes"])
        share = _pct(top["posture"]["hybrid_offered"], top["handshakes"]) or 0
        n = len(refusing)
        return (f"{'one listener refuses' if n == 1 else f'{n} listeners refuse'} hybrid "
                f"though {round(share)}% of its clients offer it")
    pq = [s for s in vlan_servers if (s.get("posture") or {}).get("posture") == "pq"]
    if vlan_servers and len(pq) == len(vlan_servers):
        return "every listener negotiates a hybrid group"
    classical_ssh = [s for s in vlan_ssh if s["kex"] and not any(k["hybrid"] for k in s["kex"])]
    if classical_ssh and not vlan_servers:
        n = len(classical_ssh)
        return f"{'one SSH server' if n == 1 else f'{n} SSH servers'} with classical key exchange only"
    return None


def build(var: Path, cr: Run | None, sr: Run | None, *, names: dict[int, str] | None = None,
          today: date | None = None, history: int = 14) -> dict | None:
    """The summary for the latest closed capture run `cr` and targeted scan `sr`. None without a capture."""
    if not cr or not cr.ledger.exists():
        return None
    view = capture_view(cr)
    if not view or view.get("broken"):
        return None
    names = vlan_names() if names is None else names
    today = today or datetime.now(UTC).date()
    hours = view["hours"]
    out_neg, out_off = _share_of(hours, lambda h: h.get("outside"))
    in_neg, in_off = _share_of(hours, lambda h: h.get("inside"))

    servers, ssh = view["inside_servers"], view["ssh"]
    postures = {"pq": 0, "mixed": 0, "classical": 0}
    for s in servers:
        p = (s.get("posture") or {}).get("posture")
        if p in postures:
            postures[p] += 1

    vlans = []
    for v in view["vlans"]:
        vid = v["vlan"]
        neg, off = _share_of(hours, lambda h, k=str(vid): (h.get("by_vlan") or {}).get(k))
        vs = [s for s in servers if s.get("vlan") == vid]
        vh = [s for s in ssh if s.get("vlan") == vid]
        vlans.append({"vlan": vid, "name": names.get(vid, f"VLAN {vid}"), "clients": v["clients"],
                      "negotiated_pct": neg, "offered_pct": off, "listeners": len(vs) + len(vh),
                      "note": _note(vs, vh)})

    bom = None
    if sr and sr.ledger.exists() and (sr.dir / "workbench.cdx.json").is_file():
        try:
            bom = json.loads((sr.dir / "workbench.cdx.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            bom = None
    scan_closed = None
    if sr and sr.ledger.exists():
        for e in sr.ledger.events():
            if e["type"] == "run.closed":
                scan_closed = e["ts"]

    pts = [p for r in runs_of_kind(var, "capture")[-history:] if (p := _history_point(r))]
    loss = view.get("loss") or {}
    return {
        "ok": True, "run_id": view["run"],
        "captured_from": view["span"][0], "captured_to": view["span"][1], "closed_at": view["closed"],
        "handshakes": view["handshakes"], "hybrid_negotiated": view["hybrid"],
        "clients_inside": len(view["clients"]), "vlans_seen": len(view["vlans"]),
        "outside_names": len(view["outside"]),
        "capture_loss_median_pct": round(loss["median_bp"] / 100, 2) if "median_bp" in loss else None,
        "capture_loss_max_pct": round(loss["max_bp"] / 100, 2) if "max_bp" in loss else None,
        "outside": {"negotiated_pct": out_neg, "offered_pct": out_off},
        "inside": {"negotiated_pct": in_neg, "offered_pct": in_off},
        "listeners_inside": {"tls": len(servers), "ssh": len(ssh), **postures},
        "vlans": vlans,
        "certificates": _certificates(bom, today),
        "history": pts,
        "scan": {"run_id": sr.id if sr and sr.ledger.exists() else None, "closed_at": scan_closed,
                 "listeners": _listeners_in_scan(bom)} if bom or scan_closed else None,
    }
