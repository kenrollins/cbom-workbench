"""A projection of the CBOM into a table, defined as data (`policy/projections/*.yaml`).

`rebuild(events, definition)` builds the workbench CBOM from the ledger and projects it into
the definition's columns, timing the whole of it: nothing is scanned, the ledger is only read.
Each column names the field it reads; a column whose field is absent for a row is empty, and
the count of empty cells per column is returned, so a projection that asks for something the
record does not carry says so.
"""

from __future__ import annotations

import csv
import io
import json
import time
from pathlib import Path

import yaml

from pqch.cbom import project

SCHEMA = "pqch.projection/1"


def load(path: str | Path) -> dict:
    d = yaml.safe_load(Path(path).read_text())
    if d.get("schema") != SCHEMA:
        raise ValueError(f"{path}: expected schema {SCHEMA}")
    for c in d["columns"]:
        if c["from"].split(".", 1)[0] not in ("asset", "service", "item"):
            raise ValueError(f"{path}: column {c['name']!r} reads from {c['from']!r}; asset., service. or item.")
    return d


def _props(c: dict) -> dict:
    out = {}
    for p in c.get("properties", []):
        v = p["value"]
        try:
            out[p["name"]] = json.loads(v) if v[:1] in "[{" else v
        except json.JSONDecodeError:
            out[p["name"]] = v
    return out


def _get(obj, path: list[str]):
    for part in path:
        if obj is None:
            return None
        if isinstance(obj, list):
            obj = obj[int(part)] if part.isdigit() and int(part) < len(obj) else None
        elif isinstance(obj, dict):
            obj = obj.get(part)
        else:
            return None
    return obj


def _read(comp: dict | None, path: str):
    if comp is None:
        return None
    props = _props(comp)
    if path.startswith("pqch:"):
        name, _, rest = path.partition(".")
        return _get(props.get(name), rest.split(".")) if rest else props.get(name)
    return _get(comp, path.split("."))


def table(bom: dict, d: dict) -> tuple[list[str], list[list]]:
    comps = {c["bom-ref"]: c for c in bom.get("components", [])}
    parents: dict[str, list[str]] = {}
    for dep in bom.get("dependencies", []):
        for child in dep["dependsOn"]:
            parents.setdefault(child, []).append(dep["ref"])

    def service_of(ref: str) -> dict | None:
        # Up the chain: asset -> listener or image (or served certificate -> listener) -> service.
        seen, todo = set(), [ref]
        while todo:
            r = todo.pop()
            if r in seen:
                continue
            seen.add(r)
            c = comps.get(r)
            if c and c["type"] == "application":
                return c
            todo.extend(parents.get(r, []))
        return None

    cols = [c["name"] for c in d["columns"]]
    rows = []
    for c in bom.get("components", []):
        p = _props(c)
        if not p.get("pqch:layer") or p.get("pqch:role") not in d["rows"]["roles"]:
            continue
        if p.get("pqch:in-use") == d["rows"].get("in_use_not"):
            continue
        svc = service_of(c["bom-ref"])
        items = (_props(svc).get("pqch:migration") if svc else None) or []
        item = next((i for i in items if i.get("function") == p.get("pqch:role")), None)
        row = []
        for col in d["columns"]:
            src, _, path = col["from"].partition(".")
            if src == "asset":
                v = _read(c, path)
            elif src == "service":
                v = svc and (svc["name"] if path == "name" else _read(svc, path))
            else:
                v = _get(item, path.split(".")) if item else None
            row.append(v)
        rows.append(row)
    rows.sort(key=lambda r: tuple("" if x is None else str(x) for x in r[:2] + r[6:8]))
    return cols, rows


def rebuild(events: list[dict], d: dict) -> dict:
    t0 = time.perf_counter()
    bom = project(events)
    t1 = time.perf_counter()
    cols, rows = table(bom, d)
    t2 = time.perf_counter()
    empty = {c: sum(1 for r in rows if r[i] in (None, "")) for i, c in enumerate(cols)}
    return {"id": d["id"], "title": d["title"], "columns": cols, "rows": rows, "empty": empty,
            "ms_cbom": round((t1 - t0) * 1000), "ms_table": round((t2 - t1) * 1000), "ms_total": round((t2 - t0) * 1000),
            "events": len(events), "head": events[-1]["hash"], "components": len(bom["components"])}


def to_csv(result: dict) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(result["columns"])
    for r in result["rows"]:
        w.writerow(["" if v is None else (json.dumps(v) if isinstance(v, (dict, list)) else v) for v in r])
    return buf.getvalue()
