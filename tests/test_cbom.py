import json

from pqch.assessor import load_policy, structure
from pqch.cbom import BASELINES, build_all, project, validate
from pqch.ledger import verify
from pqch.pipeline import write_cboms



def props(component):
    return {p["name"]: p["value"] for p in component.get("properties", [])}


def as_json(obj):
    return json.dumps(obj, sort_keys=True)


def _structured(run):
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    run.close()
    return list(run.ledger.events())


def test_cboms_validate_against_cyclonedx_16(slice_run):
    events = _structured(slice_run)
    assert verify(events).ok
    for name, bom in build_all(events).items():
        assert bom["specVersion"] == "1.6", name
        assert validate(bom) == [], name


def test_projection_is_a_pure_function_of_the_ledger(slice_run):
    events = _structured(slice_run)
    assert as_json(project(events)) == as_json(project(list(slice_run.ledger.events())))
    first = {k: p.read_bytes() for k, p in write_cboms(slice_run).items()}
    for p in slice_run.dir.glob("*.cdx.json"):
        p.unlink()
    second = {k: p.read_bytes() for k, p in write_cboms(slice_run).items()}
    assert first == second


def test_rules_mark_the_unserved_certificate_and_postures(slice_run):
    bom = project(_structured(slice_run))
    by_loc = {}
    for c in bom["components"]:
        by_loc.setdefault(c["evidence"]["occurrences"][0]["location"], []).append(c)
    unserved = [c for loc, cs in by_loc.items() if loc.endswith("/etc/ssl/legacy/portal-2019.crt") for c in cs
                if c["cryptoProperties"]["assetType"] == "certificate"]
    assert [props(c)["pqch:in-use"] for c in unserved] == ["false"]
    served = [c for loc, cs in by_loc.items() if loc.endswith("/etc/nginx/tls/portal.crt") for c in cs
              if c["cryptoProperties"]["assetType"] == "certificate"]
    assert [props(c)["pqch:in-use"] for c in served] == ["true"]
    postures = {props(c)["pqch:subject"]: props(c).get("pqch:posture") for c in bom["components"]
                if props(c).get("pqch:kind") == "listener"}
    assert sorted(postures.values()) == ["classical", "classical", "mixed", "mixed"]


def test_baselines_carry_no_rule_output(slice_run):
    events = _structured(slice_run)
    for name, tools in BASELINES.items():
        bom = project(events, tools=tools, rules=False)
        assert not any("pqch:in-use" in props(c) or "pqch:posture" in props(c) for c in bom["components"]), name
        assert {t for c in bom["components"] for t in props(c).get("pqch:tools", "").split(",") if t} <= tools


def test_a_keystore_is_carried_as_key_material_the_schema_names():
    """CycloneDX 1.6 has no `keystore` type; the finer kind stays in pqch:parameters."""
    from pqch.cbom import _crypto_properties
    asset = {"type": "related-crypto-material", "name": "RSA",
             "parameters": {"kind": ["keystore"], "format": "PKCS12", "key_bits": 2048}}
    props = _crypto_properties(asset)
    assert props["relatedCryptoMaterialProperties"] == {"type": "key", "size": 2048}
    asset["parameters"]["kind"] = ["dh-parameters"]
    assert _crypto_properties(asset)["relatedCryptoMaterialProperties"]["type"] == "other"

