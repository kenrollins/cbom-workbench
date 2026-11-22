"""The alias pack's TLS group ids against the IANA registry held in policy/sources.

The registry file is the CSV IANA serves for "TLS Supported Groups", saved unchanged; the pack's
`source` block records where it was read, when, and its hash. Every id the pack names is either an
id the registry names, carrying the registry's name under the pack's convention, or an id in the
registry's private-use range whose name the pack attributes to a stated source.
"""

from __future__ import annotations

import csv
import hashlib
from pathlib import Path

import yaml

from pqch.scout import names

ROOT = Path(__file__).resolve().parents[1]
PACK = yaml.safe_load(names.PACK_PATH.read_text(encoding="utf-8"))
SOURCE = PACK["source"]
REGISTRY = ROOT / SOURCE["file"]

# The pack's convention (its header): IANA's names, except the two Montgomery curves and the FIPS
# names for ML-KEM.
CONVENTION = {"x25519": "X25519", "x448": "X448",
              "MLKEM512": "ML-KEM-512", "MLKEM768": "ML-KEM-768", "MLKEM1024": "ML-KEM-1024"}
NOT_A_NAME = ("Reserved", "Unassigned")


def _registry() -> tuple[dict[int, dict], list[tuple[int, int]]]:
    """The registry's named ids, and its private-use ranges."""
    named: dict[int, dict] = {}
    private: list[tuple[int, int]] = []
    with REGISTRY.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            value, description = row["Value"], row["Description"]
            low, _, high = value.partition("-")
            if description == "Reserved for Private Use":
                private.append((int(low), int(high or low)))
            elif not description.startswith(NOT_A_NAME):
                assert not high, f"a named range: {value}"
                named[int(low)] = row
    return named, private


def _pack_name(description: str) -> str:
    name = description.removesuffix(" (OBSOLETE)")
    return CONVENTION.get(name, name)


def test_the_saved_registry_is_the_file_the_pack_records():
    assert hashlib.sha256(REGISTRY.read_bytes()).hexdigest() == SOURCE["sha256"]
    assert SOURCE["url"].startswith("https://www.iana.org/assignments/tls-parameters/")
    assert SOURCE["read_first_hand"] and SOURCE["registry_updated"]


def test_every_group_id_the_registry_names_carries_the_registrys_name():
    named, private = _registry()
    assert len(named) > 60 and private == [(508, 511), (65024, 65279)]
    checked = 0
    for group_id, name in names.TLS_GROUP_IDS.items():
        if group_id in named:
            assert name == _pack_name(named[group_id]["Description"]), group_id
            checked += 1
    assert checked == 51
    # The ids named or renamed in version 2 of the pack, by id.
    assert _pack_name(named[25498]["Description"]) == "SecP256r1Kyber768Draft00"
    assert named[25497]["Recommended"] == named[25498]["Recommended"] == "D"
    assert named[4588]["Recommended"] == "Y" and named[4590]["Description"] == "curveSM2MLKEM768"


def test_an_id_the_registry_does_not_name_is_private_use_with_a_stated_source():
    named, private = _registry()
    unnamed = {g for g in names.TLS_GROUP_IDS if g not in named}
    assert unnamed == set(SOURCE["private_use"]["ids"]) == {65072, 65073, 65074}
    assert all(any(low <= g <= high for low, high in private) for g in unnamed)
    assert SOURCE["private_use"]["url"] and SOURCE["private_use"]["sha256"]


def test_every_post_quantum_name_in_the_pack_has_an_id_or_is_an_ssh_exchange():
    carried = set(names.TLS_GROUP_IDS.values()) | set(names.SSH_KEX.values())
    assert names.PQ_KEY_ESTABLISHMENT <= carried
