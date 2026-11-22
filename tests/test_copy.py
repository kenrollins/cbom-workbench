"""A frozen copy of the estate, placed where another tool can see it, scored against the one key.

The scope says what it copies and when, every listener names its original, and the scorer maps the
copy's addresses back before matching: the CBOM keeps the addresses the copy was seen at, the key is
never edited, and the score carries the map it used.
"""

import json
from pathlib import Path

import pytest

from pqch import schemas
from pqch.assessor import load_policy, structure
from pqch.pipeline import copy_refusal, write_cboms, write_score
from pqch.score import address_map, score_bom

from .conftest import JOBS, SCOPE, binding_for, make_run

M0_KEY = Path("eval/answer-keys/mini-agency-m0.yaml")
RANGE = {"172.16.106.11": "10.20.30.102", "172.16.106.21": "10.20.30.108",
         "172.16.106.10": "10.20.30.101", "172.16.106.20": "10.20.30.107"}


def copy_scope() -> dict:
    """The fixture's slice as a copy on another network: each listener re-addressed, naming its original."""
    return {
        **SCOPE, "id": "01M40W6W873YWJMWPKGMK3YBMN", "estate": "external", "owned": False,
        "authorized_by": "the owner, for the test",
        "copy": {"of": "mini-agency", "taken": "2026-11-01T12:00:00Z", "carries": [], "note": "test copy"},
        "endpoints": [{**{k: v for k, v in e.items() if k != "image"}, "host": RANGE[e["host"]],
                       "copy_of": {"host": e["host"]}} for e in SCOPE["endpoints"]],
        "images": [],
    }


def test_the_scope_says_what_it_copies_and_each_listener_names_its_original():
    schemas.validate(copy_scope())
    bad = copy_scope()
    bad["endpoints"][0]["copy_of"] = {"port": 443}
    from jsonschema import ValidationError

    with pytest.raises(ValidationError):
        schemas.validate(bad)
    assert address_map(copy_scope())[("10.20.30.102", 443)] == ("172.16.106.11", 443)
    assert address_map(SCOPE) == {}


def test_only_an_authorized_external_copy_with_every_original_named_is_scanned_as_one():
    assert copy_refusal(SCOPE)                       # owned, not external
    assert copy_refusal(copy_scope()) is None
    s = copy_scope()
    del s["copy"]
    assert "copy" in copy_refusal(s)
    s = copy_scope()
    del s["endpoints"][2]["copy_of"]
    assert "10.20.30.101:443" in copy_refusal(s)


@pytest.fixture
def copy_run(tmp_path, monkeypatch):
    """The fixture's recorded jobs, re-addressed to the copy, recorded under the copy's scope."""
    from tests import conftest

    scope = copy_scope()
    monkeypatch.setattr(conftest, "SCOPE", scope)
    jobs = [(f, p, t, {**tg, "host": RANGE[tg["host"]]}) for f, p, t, tg in JOBS if "host" in tg]
    images = {RANGE[e["host"]]: e["image"] for e in SCOPE["endpoints"]}
    run = make_run(tmp_path, bind=lambda t: binding_for(t, image=images.get(t.get("host"))) if "host" in t else None,
                   jobs=jobs)
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    run.close()
    write_cboms(run)
    return run


def test_a_copy_scores_as_the_original_through_the_map_and_keeps_its_own_addresses(copy_run, key):
    result = write_score(copy_run, M0_KEY)
    wire = result["columns"]["workbench"]["layers"]["wire"]
    assert (wire["covered"], wire["denominator"], wire["false_positives"]) == (22, 23, 0)
    assert result["columns"]["workbench"]["posture"]["correct"] == 4
    assert result["copy"]["of"] == "mini-agency" and result["copy"]["taken"] == "2026-11-01T12:00:00Z"
    assert {(m["host"], m["original"]["host"]) for m in result["copy"]["address_map"]} == {(r, o) for o, r in RANGE.items()}
    # The CBOM itself is of the copy: it names the addresses the copy was seen at, so a consumer of it
    # sees what a sensor on that wire sees. Unmapped, it matches nothing in the key.
    bom = json.loads((copy_run.dir / "workbench.cdx.json").read_text())
    hosts = {json.loads(p["value"])["host"] for c in bom["components"] for p in c.get("properties", [])
             if p["name"] == "pqch:subject" and "host" in json.loads(p["value"])}
    assert hosts <= set(RANGE.values()) and hosts
    assert score_bom(bom, key)["layers"]["wire"]["covered"] == 0


class FakeRunner:
    """The copy's runner, replaying the fixture's recorded jobs at the copy's addresses."""

    def __init__(self):
        self.scope_ = copy_scope()
        self.images = {RANGE[e["host"]]: e["image"] for e in SCOPE["endpoints"]}

    def scope(self):
        from pqch import scope as scope_mod

        return self.scope_, scope_mod.scope_hash(self.scope_)

    def job(self, profile, target, scope_hash, params=None):
        import shutil

        from pqch.common import sha256_hex

        from .conftest import FIX, SCANNER

        fixture, _p, tool, _t = next((f, p, t, tg) for f, p, t, tg in JOBS
                                     if p == profile and "host" in tg and RANGE[tg["host"]] == target["host"])
        raw = self.var / "raw" / f"{target['host']}-{target['port']}.json"
        shutil.copy(FIX / fixture, raw)
        return {"job_id": raw.stem, "profile": profile, "target": target, "tool": tool, "version": "fixture",
                "image": "scanner@" + SCANNER, "image_digest": SCANNER, "status": "ok", "exit_code": 0,
                "started_at": "2026-11-15T12:00:00.000Z", "ended_at": "2026-11-15T12:00:30.000Z",
                "duration_ms": 30000, "raw": f"var/raw/{raw.name}", "raw_sha256": sha256_hex(raw.read_bytes()),
                "stderr_tail": "", "container": {}, "binding": binding_for(target, image=self.images[target["host"]])}


def test_scan_copy_is_its_own_kind_with_the_window_on_the_ledger_and_the_key_committed(tmp_path, monkeypatch):
    from pqch.pipeline import scan_copy
    from pqch.run import Run

    monkeypatch.setenv("PQCH_OPERATOR", "the operator")
    var = tmp_path / "var"
    (var / "raw").mkdir(parents=True)
    client = FakeRunner()
    client.var = var
    run, summary = scan_copy(var, client, M0_KEY, sources="10.20.30.31, 10.20.30.32-47")
    events = list(run.ledger.events())
    types = [e["type"] for e in events]
    assert events[0]["payload"]["kind"] == "scan-copy" and types[1] == "key.committed"
    opened, closed = (next(e for e in events if e["type"] == t) for t in ("window.opened", "window.closed"))
    assert opened["payload"]["sources"] == "10.20.30.31, 10.20.30.32-47" and len(opened["payload"]["listeners"]) == 4
    assert closed["inputs"] == [opened["id"]] and closed["payload"]["jobs"] == 4
    scans = [i for i, t in enumerate(types) if t == "scan.completed"]
    assert types.index("window.opened") < min(scans) < max(scans) < types.index("window.closed")
    assert summary["score"]["columns"]["workbench"]["layers"]["wire"]["covered"] == 22
    assert (run.dir / "workbench.cdx.json").is_file() and (run.dir / "score.json").is_file()
    # Not the latest scan of any estate: the demonstration and the lab keep theirs.
    assert Run.latest(var, "scan") is None and Run.latest(var, "scan-copy").id == run.id


def test_a_scan_copy_refuses_a_scope_that_is_not_a_copy(tmp_path):
    from pqch.pipeline import scan_copy

    client = FakeRunner()
    client.scope_ = {**SCOPE}
    with pytest.raises(ValueError, match="external"):
        scan_copy(tmp_path / "var", client, M0_KEY)


def test_a_document_of_the_copy_is_imported_under_the_copy_scope_and_scored_through_the_map(tmp_path):
    """Another tool's CBOM of the copy names the copy's addresses: under the copy's scope its listeners are
    placed and scored against the key's originals, with the map recorded; under the estate's own scope the
    same document has no listener the workbench can find."""
    from pqch.scout.imported import run_import

    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"tools": {"components": [{"name": "a-sensor", "version": "3.6"}]}},
           "components": [
               {"type": "cryptographic-asset", "bom-ref": "a", "name": "X25519",
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": "key-agree"}},
                "evidence": {"occurrences": [{"location": "10.20.30.102:443"}]}}]}
    p = tmp_path / "sensor.cdx.json"
    p.write_text(json.dumps(doc))
    (tmp_path / "var" / "runs").mkdir(parents=True)
    run, s = run_import(tmp_path / "var", [(p, None)], copy_scope(), key_path=M0_KEY)
    assert s["findings"] == 1 and s["by_layer"] == {"wire": 1}
    assert s["score"]["wire"]["covered"] == 1 and s["score"]["wire"]["false_positives"] == 0
    assert s["copy"]["of"] == "mini-agency" and len(s["copy"]["address_map"]) == 4
    assert next(e for e in run.ledger.events() if e["type"] == "import.completed")["payload"]["copy"]["taken"] == "2026-11-01T12:00:00Z"
    _run, s2 = run_import(tmp_path / "var", [(p, None)], SCOPE, key_path=M0_KEY)
    assert s2["findings"] == 0 and s2["left_out"]["out_of_scope"] == 1 and "copy" not in s2
    assert s2["unplaced_names"] == ["algorithm X25519"]


def test_a_scan_that_fails_part_way_closes_its_window_and_its_run_on_the_ledger(tmp_path, monkeypatch):
    """The runner refuses one job: the window is closed with the reason, the run says it failed and is
    closed like any other, the pointer to the latest copy scan goes back, and the error still surfaces."""
    from pqch.ledger import verify
    from pqch.pipeline import scan_copy
    from pqch.run import Run

    monkeypatch.setenv("PQCH_OPERATOR", "the operator")
    var = tmp_path / "var"
    (var / "raw").mkdir(parents=True)
    (var / "runs").mkdir()
    (var / "runs" / "LATEST_SCAN-COPY").write_text("AN-EARLIER-RUN\n")

    class Refusing(FakeRunner):
        def job(self, profile, target, scope_hash, params=None):
            if target["port"] == 22:
                raise RuntimeError("runner refused: outside the scope")
            return super().job(profile, target, scope_hash, params)

    client = Refusing()
    client.var = var
    with pytest.raises(RuntimeError, match="refused"):
        scan_copy(var, client, M0_KEY, sources="10.20.30.31")
    failed = next(Run(var, d.name) for d in (var / "runs").iterdir() if d.is_dir())
    events = list(failed.ledger.events())
    types = [e["type"] for e in events]
    assert types[-3:] == ["window.closed", "run.failed", "run.closed"] and types.count("window.opened") == 1
    closed = events[-3]["payload"]
    assert closed["aborted"] is True and "refused" in closed["reason"] and "refused" in events[-2]["payload"]["reason"]
    assert verify(events).ok
    assert (var / "runs" / "LATEST_SCAN-COPY").read_text().strip() == "AN-EARLIER-RUN"
    assert not (var / "runs" / "LATEST").exists()
