"""M2 watch mode: what changed since the last scan is recorded, and only that is re-examined."""

import shutil
from pathlib import Path

from pqch.assessor import load_policy, structure
from pqch.pipeline import enrich
from pqch.watch import changed, observe

from .conftest import JOBS, make_run

POLICY = load_policy("policy/pq-algorithms.yaml")


def scan(tmp_path, agency, jobs=None):
    run = make_run(tmp_path, jobs=jobs)
    structure(run, POLICY)
    enrich(run, author="owner")
    counts = observe(run, agency)
    run.close()
    return run, counts


def obs(run):
    return [e["payload"] for e in run.ledger.events() if e["type"] == "change.observed"]


def test_an_unchanged_estate_records_nothing_changed(tmp_path):
    first, c1 = scan(tmp_path, Path("agency"))
    assert c1["previous"] is None
    second, c2 = scan(tmp_path, Path("agency"))
    assert c2 == {"previous": first.id, "appeared": 0, "gone": 0, "config": 0, "items": 0}
    assert obs(second) == []
    assert changed(second, had_previous=True) == {"fingerprints": set(), "items": set()}
    configs = [e["payload"] for e in second.ledger.events() if e["type"] == "config.observed"]
    assert {c["service"] for c in configs} == {"api", "bastion", "portal", "sftp-legacy"}
    assert all(f["sha256"] and f["path"].startswith("agency/") for c in configs for f in c["files"])


def test_a_listener_gone_a_config_edited_and_an_item_moved_are_each_recorded(tmp_path):
    agency = tmp_path / "agency"
    shutil.copytree("agency", agency, ignore=shutil.ignore_patterns("generated"))
    first, _ = scan(tmp_path, agency)
    (agency / "bastion" / "sshd_config").write_text((agency / "bastion" / "sshd_config").read_text() + "# edited\n")
    no_bastion_wire = [j for j in JOBS if j[0] != "ssh-audit-bastion.json"]
    second, c = scan(tmp_path, agency, jobs=no_bastion_wire)
    kinds = {o["kind"] for o in obs(second)}
    assert {"finding-gone", "config-changed", "item-changed"} <= kinds and c["gone"] > 0 and c["config"] == 1
    cfg = next(o for o in obs(second) if o["kind"] == "config-changed")
    assert cfg["service"] == "bastion" and cfg["files"][0]["path"] == "agency/bastion/sshd_config"
    assert cfg["since"]["run"] == first.id
    gone = [o for o in obs(second) if o["kind"] == "finding-gone"]
    assert all(o["subject"]["host"] == "172.16.106.21" for o in gone if o["layer"] == "wire")
    # Bastion's key-establishment item is no longer seen: its state moved, and only it is re-examined.
    ch = changed(second, had_previous=True)
    assert ("bastion", "key-establishment") in ch["items"] and ch["fingerprints"] == set()


def test_a_rebuilt_image_is_still_the_same_estate(tmp_path):
    import copy

    from pqch import scope as scope_mod
    from pqch.run import Run
    from pqch.watch import previous

    from .conftest import SCOPE
    var = tmp_path / "var"
    a = Run.start(var, SCOPE, runner_scope_hash=scope_mod.scope_hash(SCOPE), profile="t")
    rebuilt = copy.deepcopy(SCOPE)
    rebuilt["endpoints"][0]["image"] = rebuilt["endpoints"][0]["image"].split("@")[0] + "@sha256:" + "1" * 64
    b = Run.start(var, rebuilt, runner_scope_hash=scope_mod.scope_hash(rebuilt), profile="t")
    assert previous(b).id == a.id
    other = copy.deepcopy(SCOPE)
    other["endpoints"] = other["endpoints"][:2]
    c = Run.start(var, other, runner_scope_hash=scope_mod.scope_hash(other), profile="t")
    assert previous(c) is None
