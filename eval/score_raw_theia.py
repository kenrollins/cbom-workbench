"""Score cbomkit-theia's own CBOMs against the answer key, without the harness's normalizer,
and compare with the projected CBOMkit-alone baseline (M0 review F-35).

    uv run python eval/score_raw_theia.py var/runs/<run-id> [--key agency/answer-key.yaml] [--json]

The projected baseline passes theia's output through the harness's normalizer: names mapped
to the key's vocabulary, duplicates folded by fingerprint. That is generous to the baseline,
and it means a normalizer bug would move every column together. This scores the raw CBOMs
theia wrote — the files whose hashes the run recorded — with the least interpretation that
still lets a component be compared with a key item:

- location: an occurrence's location equals one of the item's paths, in an image of the
  item's repository;
- type: the component's `cryptoProperties.assetType` equals the item's asset type;
- name: the component's own name begins with the item's algorithm family as a whole word
  (`RSA-2048` is RSA; `private-key` is nothing).

A decoy matched this way is a false positive: theia does not say whether a file is in use.
Then it lists every item on which the two disagree.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pqch.common import sha256_hex  # noqa: E402
from pqch.ledger import Ledger  # noqa: E402
from pqch.score import _repo  # noqa: E402


def raw_components(run_dir: Path) -> list[dict]:
    """Every component of every theia CBOM the run recorded, with the image it came from."""
    var = run_dir.parent.parent
    out = []
    for ev in Ledger(run_dir / "ledger.jsonl").events():
        p = ev["payload"]
        if ev["type"] != "scan.completed" or p.get("tool") != "cbomkit-theia" or not p.get("raw"):
            continue
        data = (var / p["raw"].removeprefix("var/")).read_bytes()
        if sha256_hex(data) != p["raw_sha256"]:
            raise SystemExit(f"{p['raw']} does not match the hash the run recorded")
        bom = json.loads(data)
        repo = _repo(p["target"]["image"])
        refs = {c.get("bom-ref"): c for c in bom.get("components") or [] if c.get("bom-ref")}
        for c in bom.get("components") or []:
            if c.get("type") != "cryptographic-asset":
                continue
            cp = c.get("cryptoProperties", {})
            # theia names a certificate by its subject; its key's algorithm is in the component
            # it points to with subjectPublicKeyRef. Following that is theia's own link.
            key = refs.get(cp.get("certificateProperties", {}).get("subjectPublicKeyRef"), {})
            for occ in c.get("evidence", {}).get("occurrences", []):
                out.append({"image": repo, "path": occ["location"], "name": c.get("name", ""),
                            "ref_name": key.get("name", ""), "type": cp.get("assetType", "")})
    return out


def family_match(name: str, family: str) -> bool:
    return re.match(rf"^{re.escape(family)}(?![A-Za-z0-9])", name, re.I) is not None


def score(components: list[dict], key: dict, *, follow_refs: bool) -> dict:
    present, decoys = [], []
    for item in key["items"]:
        if item["layer"] != "host" or item["class"] not in ("present", "decoy"):
            continue
        hit = any(c["image"] == item["image"] and c["path"] in item["paths"]
                  and c["type"] == item["asset"]["type"]
                  and (family_match(c["name"], item["asset"]["name"])
                       or (follow_refs and family_match(c.get("ref_name", ""), item["asset"]["name"])))
                  for c in components)
        (present if item["class"] == "present" else decoys).append((item["id"], hit))
    return {"covered": [i for i, h in present if h], "missed": [i for i, h in present if not h],
            "present": len(present), "flagged_decoys": [i for i, h in decoys if h], "decoys": len(decoys),
            "components": len(components)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", type=Path)
    ap.add_argument("--key", type=Path, default=ROOT / "agency" / "answer-key.yaml")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    key = yaml.safe_load(args.key.read_text())
    comps = raw_components(args.run_dir)
    by_name = score(comps, key, follow_refs=False)
    raw = score(comps, key, follow_refs=True)
    projected = json.loads((args.run_dir / "score.json").read_text())["columns"]["baseline-cbomkit"]["layers"]["host"]
    proj_covered = set(projected["covered_items"])
    disagree = sorted(set(raw["covered"]) ^ proj_covered)
    result = {
        "by_component_name_only": {"covered": len(by_name["covered"]), "of": by_name["present"],
                                   "flagged_decoys": by_name["flagged_decoys"]},
        "raw": {"covered": len(raw["covered"]), "of": raw["present"], "flagged_decoys": raw["flagged_decoys"],
                "components": raw["components"], "missed": raw["missed"]},
        "projected": {"covered": projected["covered"], "of": projected["present"],
                      "flagged_decoys": projected["flagged_decoys"], "missed": projected["missed"]},
        "items_where_they_disagree": disagree,
        "decoy_flags_agree": sorted(raw["flagged_decoys"]) == sorted(projected["flagged_decoys"]),
    }
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        r, p = result["raw"], result["projected"]
        n = result["by_component_name_only"]
        print(f"theia's own CBOMs, by component name only:          host {n['covered']}/{n['of']}, "
              f"decoys flagged {n['flagged_decoys']}")
        print(f"theia's own CBOMs, following its own key references: host {r['covered']}/{r['of']}, "
              f"decoys flagged {r['flagged_decoys']}, {r['components']} component occurrences")
        print(f"projected baseline (harness normalizer):            host {p['covered']}/{p['of']}, "
              f"decoys flagged {p['flagged_decoys']}")
        print(f"items where they disagree: {disagree or 'none'}; decoy flags agree: {result['decoy_flags_agree']}")
        print(f"missed by both: {sorted(set(r['missed']) & set(p['missed']))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
