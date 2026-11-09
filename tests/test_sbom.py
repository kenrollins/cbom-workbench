"""M9/M10 item 8: the image's SBOM beside the CBOM; a library present is a capability, in use only by
evidence, and the asset it provides is linked to it."""

import json

from pqch.assessor import chains, libraries, load_policy, structure
from pqch.cbom import project, validate
from pqch.scout.normalize import sbom_facts

from .conftest import JOBS, _img, make_run

SBOM_JOBS = [*JOBS, ("syft-portal.cdx.json", "image-sbom", "syft", {"image": _img("portal")})]


def props(c):
    return {p["name"]: p["value"] for p in c.get("properties", [])}


def test_the_sbom_fact_keeps_the_crypto_libraries_and_the_count_and_yields_no_finding():
    raw = open("tests/fixtures/syft-portal.cdx.json", "rb").read()
    job = {"tool": "syft", "version": "1.33.0", "image_digest": "sha256:" + "a" * 64, "profile": "image-sbom", "raw": "var/raw/x.json",
           "raw_sha256": "b" * 64, "ended_at": "2026-11-09T00:00:00Z", "target": {"image": _img("portal")}}
    f = sbom_facts(raw, job)
    assert f["packages"] == 5 and f["tool"] == {"name": "syft", "version": "1.33.0"} and f["spec_version"] == "1.6"
    assert [x["name"] for x in f["crypto_libraries"]] == ["libcrypto3", "libssl3"]
    assert f["crypto_libraries"][1]["purl"].startswith("pkg:apk/alpine/libssl3@3.5.8-r0") and f["crypto_libraries"][1]["licenses"] == ["Apache-2.0"]
    from pqch.scout.normalize import normalize

    assert normalize(raw, job) == []


def test_the_rule_links_the_portals_wire_assets_to_its_libraries_and_the_cbom_carries_provides(tmp_path):
    run = make_run(tmp_path, jobs=SBOM_JOBS)
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(run)
    caps = json.load(open(sorted(__import__("pathlib").Path("policy/snapshots").glob("capabilities-*.json"))[-1]))
    counts = libraries.link(run, caps)
    assert counts["libraries"] == 2 and counts["library_links"] > 0
    events = list(run.ledger.events())
    links = [e for e in events if e["payload"].get("rule_id") == libraries.RULE]
    assert all(e["actor"]["kind"] == "rule" and e["payload"]["kind"] == "provides" and len(e["inputs"]) == 3 for e in links)
    # The capability snapshot names OpenSSL for the portal: libssl3 is the library; libcrypto3 a candidate only if nothing named it.
    named = {e["payload"]["from"]["name"] for e in links}
    assert named == {"libssl3"} or named == {"libssl3", "libcrypto3"}
    bom = project(events)
    assert validate(bom) == []
    libs = {c["name"]: c for c in bom["components"] if c["type"] == "library"}
    assert set(libs) == {"libssl3", "libcrypto3"} and libs["libssl3"]["purl"].startswith("pkg:apk/alpine/libssl3")
    assert props(libs["libssl3"])["pqch:capability"] == "present" and props(libs["libssl3"])["pqch:in-use"] == "true"
    assert libs["libssl3"]["licenses"] == [{"license": {"id": "Apache-2.0"}}]
    prov = next(d for d in bom["dependencies"] if d["ref"] == libs["libssl3"]["bom-ref"])
    refs = {c["bom-ref"] for c in bom["components"]}
    assert prov["provides"] and all(r in refs for r in prov["provides"])
    portal_wire = {c["bom-ref"] for c in bom["components"] if props(c).get("pqch:layer") == "wire" and "172.16.106.10" in props(c).get("pqch:subject", "")}
    assert set(prov["provides"]) == portal_wire
    img = next(d for d in bom["dependencies"] if d["ref"] == "img:pqch-agency/portal")
    assert libs["libssl3"]["bom-ref"] in img["dependsOn"]
    if "libcrypto3" in named:
        assert props(libs["libcrypto3"])["pqch:in-use"] == "true"
    else:
        assert props(libs["libcrypto3"])["pqch:in-use"] == "unknown" and "pqch:provides-count" not in props(libs["libcrypto3"])


def test_a_licence_that_is_not_an_spdx_id_is_written_as_a_name_and_the_document_validates():
    from pqch.cbom import _spdx

    assert _spdx("Apache-2.0") and _spdx("GPL-2.0-only") and not _spdx("LGPL") and not _spdx("Expat") and not _spdx("The")


def test_the_consumer_copy_keeps_the_provides_relation(tmp_path):
    from pqch.cbom import for_consumer

    run = make_run(tmp_path, jobs=SBOM_JOBS)
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(run)
    libraries.link(run, None)
    bom = project(list(run.ledger.events()))
    consumer = for_consumer(bom)                      # a provides-only dependency has no dependsOn: it must survive
    assert any("provides" in d for d in consumer["dependencies"]) and validate(consumer) == []


def test_every_reader_of_the_document_tolerates_a_provides_only_dependency(tmp_path):
    from pqch.cbom import anatomy, tables

    run = make_run(tmp_path, jobs=SBOM_JOBS)
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(run)
    libraries.link(run, None)
    events = list(run.ledger.events())
    bom = project(events)
    assert any("provides" in d and "dependsOn" not in d for d in bom["dependencies"])
    d = anatomy.document(bom)
    assert d["edges"] > 0 and anatomy.default_ref(bom) and anatomy.entries(bom)
    assert anatomy.component(bom, events, anatomy.default_ref(bom))["rows"]
    assert anatomy.diff(bom, bom)["changed"] == []
    assert tables.rebuild(events, tables.load("policy/projections/agency-inventory.yaml"))["rows"]
    from pqch.ask import passages

    assert passages(bom, events)


def test_without_an_sbom_nothing_changes(slice_run):
    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(slice_run)
    assert libraries.link(slice_run) == {"library_links": 0, "libraries": 0, "libraries_in_use": 0}
    bom = project(list(slice_run.ledger.events()))
    assert not any(c["type"] == "library" for c in bom["components"])
