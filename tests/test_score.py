import pytest

from pqch.assessor import load_policy, structure
from pqch.pipeline import write_cboms, write_score
from pqch.score import score_run


# The recorded run is of the M0 slice; it is scored against the key as it was
# then, kept under eval/. The live key (agency/answer-key.yaml) grows with the estate.
M0_KEY = __import__("pathlib").Path("eval/answer-keys/mini-agency-m0.yaml")


@pytest.fixture
def scored(slice_run):
    structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    slice_run.close()
    write_cboms(slice_run)
    return write_score(slice_run, M0_KEY)


def test_three_columns_by_layer(scored):
    cols = scored["columns"]
    wire = {n: (c["layers"]["wire"]["covered"], c["layers"]["wire"]["denominator"]) for n, c in cols.items()}
    assert wire == {"baseline-cbomkit": (0, 23), "baseline-scanners": (22, 23), "workbench": (22, 23)}
    host = {n: (c["layers"]["host"]["covered"], c["layers"]["host"]["false_positives"]) for n, c in cols.items()}
    assert host == {"baseline-cbomkit": (7, 1), "baseline-scanners": (7, 1), "workbench": (7, 0)}


def test_out_of_reach_is_a_known_miss_in_every_column(scored):
    for c in scored["columns"].values():
        assert "legacy-client-kex-records-archive" in c["layers"]["wire"]["missed"]


def test_posture_only_where_stated(scored):
    cols = scored["columns"]
    assert cols["workbench"]["posture"]["correct"] == cols["workbench"]["posture"]["total"] == 4
    assert cols["baseline-scanners"]["posture"] is None


def test_an_unplanted_claim_on_a_keyed_listener_is_a_false_positive(slice_run, scored, key):
    import json

    from pqch.score import score_bom
    bom = json.loads((slice_run.dir / "workbench.cdx.json").read_text())
    fake = json.loads(json.dumps(next(c for c in bom["components"]
                                      if {"name": "pqch:layer", "value": "wire"} in c["properties"])))
    fake["bom-ref"] = "fake"
    for p in fake["properties"]:
        if p["name"] == "pqch:name":
            p["value"] = "ML-KEM-1024"
        if p["name"] == "pqch:role":
            p["value"] = "key-establishment"
    bom["components"].append(fake)
    wire = score_bom(bom, key)["layers"]["wire"]
    assert wire["false_positives"] == 1 and "ML-KEM-1024" in wire["unplanted"][0]
    assert scored["columns"]["workbench"]["layers"]["wire"]["false_positives"] == 0


def test_a_layer_nobody_scanned_is_not_presented_as_a_decoy_avoided(scored):
    from pqch.score import table
    for c in scored["columns"].values():
        assert c["layers"]["code"]["scanned"] is False
    assert table(scored).splitlines()[3].count("not scanned") == 3


def test_everything_read_from_the_unserved_certificate_is_marked_not_in_use(slice_run, scored):
    import json
    bom = json.loads((slice_run.dir / "workbench.cdx.json").read_text())
    at_decoy = [{p["name"]: p["value"] for p in c["properties"]} for c in bom["components"]
                if "portal-2019.crt" in c["evidence"]["occurrences"][0]["location"]]
    assert len(at_decoy) > 1 and {p["pqch:in-use"] for p in at_decoy} == {"false"}


def test_no_not_served_judgement_when_the_image_does_not_hold_what_the_listener_serves(slice_run):
    """A stale scope: the listener's certificate is not in the scoped image, so nothing is judged."""
    from pqch.ledger import Ledger
    events = list(slice_run.ledger.events())
    for e in events:
        if e["type"] == "finding.observed" and e["payload"]["layer"] == "host" \
                and e["payload"]["asset"]["parameters"].get("spki_sha256"):
            e["payload"]["asset"]["parameters"]["spki_sha256"] = "0" * 64
    from tests.test_ledger import rewrite
    rewrite(Ledger(slice_run.ledger.path), events)
    counts = structure(slice_run, load_policy("policy/pq-algorithms.yaml"))
    assert counts["not_in_use"] == 0


def test_refuses_a_run_that_recorded_no_key(slice_run):
    with pytest.raises(ValueError, match="recorded no answer key"):
        score_run(slice_run.dir, __import__("pathlib").Path("agency/answer-key.yaml"), recorded_sha256=None)


def test_refuses_a_key_the_run_did_not_record(slice_run, tmp_path):
    other = tmp_path / "key.yaml"
    other.write_text("schema: pqch.answer-key/1\nitems: []\n")
    with pytest.raises(ValueError, match="the run recorded"):
        score_run(slice_run.dir, other, recorded_sha256="0" * 64)


@pytest.mark.parametrize("ref", ["pqch-agency/portal", "pqch-agency/portal:m0",
                                 "127.0.0.1:5000/pqch-agency/portal@sha256:" + "a" * 64,
                                 "registry.local/pqch-agency/portal:m0"])
def test_the_registry_host_is_not_part_of_an_images_identity(ref):
    from pqch.score import _repo
    assert _repo(ref) == "pqch-agency/portal"


def test_theias_own_cbom_scores_as_the_projected_baseline_when_its_references_are_followed(scored, slice_run):
    """M0 review F-35: the normalizer adds no coverage that theia's own document does not hold."""
    import sys
    sys.path.insert(0, "eval")
    import yaml
    from score_raw_theia import raw_components, score
    key = yaml.safe_load(open("agency/answer-key.yaml"))
    comps = raw_components(slice_run.dir)
    followed = score(comps, key, follow_refs=True)
    by_name = score(comps, key, follow_refs=False)
    host = scored["columns"]["baseline-cbomkit"]["layers"]["host"]
    assert sorted(followed["covered"]) == sorted(host["covered_items"])
    assert followed["flagged_decoys"] == host["flagged_decoys"]
    assert len(by_name["covered"]) < len(followed["covered"])   # theia names a certificate by its subject
