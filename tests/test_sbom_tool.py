"""M8, FR-05: the minimum elements counted on a CycloneDX SBOM."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import sbom


def test_coverage_counts_each_element_on_libraries_and_the_document():
    doc = {"metadata": {"timestamp": "2026-11-06T00:00:00Z", "tools": {"components": [{"name": "syft"}]},
                        "authors": [{"name": "x"}], "lifecycles": [{"phase": "post-build"}]},
           "components": [
               {"type": "library", "bom-ref": "a", "name": "a", "version": "1", "purl": "pkg:pypi/a@1",
                "publisher": "A", "licenses": [{"license": {"id": "MIT"}}], "hashes": [{"alg": "SHA-256", "content": "0"}]},
               {"type": "library", "bom-ref": "b", "name": "b", "version": "2"},
               {"type": "file", "bom-ref": "f", "name": "/x"}],
           "dependencies": [{"ref": "a", "dependsOn": ["b"]}]}
    c = sbom.coverage(doc)
    assert c["components"] == 2
    assert all(c[k] for k in sbom.DOC_ELEMENTS)
    assert c["component_name"] == 1.0 and c["software_identifiers"] == 0.5 and c["component_hash"] == 0.5
    assert c["dependency_relationship"] == 1.0
