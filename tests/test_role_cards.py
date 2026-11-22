"""M8, FR-07: a role card for every model role the code names, rendered from its sources."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_every_role_the_code_or_a_config_names_has_a_card():
    cards = set(yaml.safe_load((ROOT / "eval" / "role-cards.yaml").read_text())["roles"])
    in_code = set()
    for p in (ROOT / "src" / "pqch").rglob("*.py"):
        in_code |= set(re.findall(r'^ROLE = "([a-z-]+)"', p.read_text(), flags=re.M))
    in_configs = set()
    for c in ("kit/inference.yaml", "config/inference.example.yaml"):
        in_configs |= set(yaml.safe_load((ROOT / c).read_text()).get("roles") or {})
    assert in_code and in_code <= cards, in_code - cards
    assert in_configs <= cards, in_configs - cards


@pytest.mark.skipif(not (ROOT / "spikes/s3/results/scored/report.json").exists(),
                    reason="spike S3's scored report is not in this copy (the public export leaves raw results out)")
def test_the_role_cards_page_is_what_its_sources_render():
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "tools/role_cards.py", "--check"], cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
