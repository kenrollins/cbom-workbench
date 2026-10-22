"""Spike S1: which planned images publish linux/arm64. Reads images.yaml, writes results.json."""

import json
import subprocess
import time
from pathlib import Path

import yaml

HERE = Path(__file__).parent


def platforms(ref: str) -> tuple[str | None, list[str], str | None]:
    out = subprocess.run(["docker", "buildx", "imagetools", "inspect", "--raw", ref],
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        return None, [], out.stderr.strip()[:200]
    doc = json.loads(out.stdout)
    digest = subprocess.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}"],
                            capture_output=True, text=True, timeout=120)
    dg = json.loads(digest.stdout).get("digest") if digest.returncode == 0 else None
    if "manifests" not in doc:
        return dg, ["single-platform manifest (platform in config)"], None
    plats = sorted({f"{m['platform']['os']}/{m['platform']['architecture']}" + (f"/{m['platform']['variant']}" if m['platform'].get('variant') else "")
                    for m in doc["manifests"] if m.get("platform", {}).get("os") not in (None, "unknown")})
    return dg, plats, None


def main() -> None:
    images = yaml.safe_load((HERE / "images.yaml").read_text())["images"]
    # A registry that refuses to answer does not erase an earlier answer: keep the last good
    # reading for each image, with when it was taken.
    prior = {}
    if (HERE / "results.json").exists():
        prior = {r["ref"]: r for r in json.loads((HERE / "results.json").read_text()) if not r.get("error")}
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    seen = {}
    for img in images:
        # The pinned digest is what is read (M0B review F-63); a tag is only a name for people.
        pinned = img.get("digest")
        name = img["ref"].rsplit(":", 1)[0] if ":" in img["ref"].rsplit("/", 1)[-1] else img["ref"]
        dg, plats, err = platforms(f"{name}@{pinned}" if pinned else img["ref"])
        if pinned and not err:
            dg = pinned   # read by digest: what came back is that content, whatever the second call says
        if err and img["ref"] in prior:
            p = prior[img["ref"]]
            seen[img["ref"]] = {k: p[k] for k in ("digest", "platforms", "arm64", "checked_at")} | {"error": None}
            continue
        seen[img["ref"]] = {"digest": dg, "platforms": plats, "error": err, "checked_at": None if err else now,
                            "arm64": any(p.startswith("linux/arm64") for p in plats)}
    results = []
    for img in images:
        s = seen[img["ref"]]
        if img["gb10"]:
            ok = s["arm64"]
        elif img.get("standin"):
            ok = seen.get(img["standin"], {}).get("arm64", False)
        else:
            # Lab-only with no stand-in passes only as a declared build-time tool.
            ok = bool(img.get("build_time"))
        # A registry error is not an answer: the image is unchecked, and S1 cannot pass yet.
        results.append({**img, **s, "pass": None if s["error"] else ok})
    (HERE / "results.json").write_text(json.dumps(results, indent=1) + "\n")
    for r in results:
        print(f"{ {True: 'PASS', False: 'FAIL', None: 'UNCHECKED'}[r['pass']] }  {r['ref']:<40} arm64={r['arm64']!s:<5} gb10={r['gb10']!s:<5} "
              f"{','.join(p.split('/', 1)[1] for p in r['platforms'] if '/' in p)[:60]} {r['error'] or ''}")
    verdict = "passes" if all(r["pass"] is True for r in results) else (
        "fails" if any(r["pass"] is False for r in results) else "is not decided: some images unchecked")
    print(f"S1 {verdict}: {sum(r['pass'] is True for r in results)}/{len(results)} pass, "
          f"{sum(r['pass'] is None for r in results)} unchecked")


if __name__ == "__main__":
    main()
