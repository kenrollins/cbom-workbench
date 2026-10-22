"""Start the slice and the harness from the offline bundle, with no image fetched from anywhere else.

    uv run python bundle/load.py [--lab-overlay workshop/compose.lab.yaml]

1. Checks SHA256SUMS against a hash recorded outside the bundle (--expect-sums), every file
   against SHA256SUMS, and every registry blob against the SHA-256 it is named by.
2. Loads the registry's own image from its tarball and starts it on 127.0.0.1:5000, its data
   read-only from bundle/out/registry.
3. Pulls every image in manifest.json by digest from that registry, and checks it is held
   under that digest.
4. Starts the slice with --pull never and no build, regenerates the scope from what is now
   running, then starts the harness the same way. The runner resolves its scanner images
   through the bundle's registry.

What this does not do: block the host's own route to the internet. That is the operator's to
do (and to record); see the bundle section of the M0 report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "bundle" / "out"
NAME = "pqch-bundle-registry"


def sh(*args, check=True) -> str:
    # The bundle's harness overlay names the bundle's own directory (the runner mounts the
    # agency overlay from it).
    r = subprocess.run(list(args), capture_output=True, text=True, timeout=3600,
                       env={**os.environ, "PQCH_BUNDLE_DIR": str(OUT)})
    if check and r.returncode != 0:
        raise SystemExit(f"failed: {' '.join(args)}\n{r.stderr[-1500:]}")
    return r.stdout.strip()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab-overlay", default=None, help="a deployment overlay for the harness (e.g. the lab's)")
    ap.add_argument("--expect-sums", default=None,
                    help="the SHA-256 of SHA256SUMS that bundle/build.py printed, carried outside the bundle")
    args = ap.parse_args()
    started = time.monotonic()

    # SHA256SUMS sits in the bundle and can be edited along with what it lists. It is checked
    # against a hash recorded elsewhere when one is given; without one, the check below shows
    # only that the bundle agrees with itself.
    sums = hashlib.sha256((OUT / "SHA256SUMS").read_bytes()).hexdigest()
    if args.expect_sums and args.expect_sums != sums:
        raise SystemExit(f"SHA256SUMS hashes to {sums}, not the recorded {args.expect_sums}")
    print(f"SHA256SUMS sha256 {sums} — " + ("matches the recorded hash" if args.expect_sums else
          "checked against nothing: pass --expect-sums with the hash recorded at build"), flush=True)
    for line in (OUT / "SHA256SUMS").read_text().splitlines():
        want, name = line.split("  ", 1)
        if hashlib.sha256((OUT / name).read_bytes()).hexdigest() != want:
            raise SystemExit(f"{name} does not match SHA256SUMS")
    # The registry serves a blob as it lies on disk and does not check it. A client checks what
    # it fetches, but fetches nothing it already holds, so a damaged blob can go unread. Every
    # blob is named by its SHA-256: check them all before anything is served.
    blobs = 0
    for data in sorted((OUT / "registry").glob("docker/registry/v2/blobs/sha256/*/*/data")):
        h = hashlib.sha256()
        with data.open("rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != data.parent.name:
            raise SystemExit(f"registry blob {data.parent.name[:16]}… does not hash to its name: the bundle is damaged")
        blobs += 1
    print(f"checksums ok; {blobs} registry blobs hash to their names", flush=True)

    manifest = json.loads((OUT / "manifest.json").read_text())
    reg = manifest["registry"]
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    sh("docker", "load", "-q", "-i", str(OUT / f"registry-image.{arch}.tar"))
    sh("docker", "rm", "-f", NAME, check=False)
    sh("docker", "run", "-d", "--name", NAME, "-p", f"{reg}:5000",
       "-v", f"{OUT / 'registry'}:/var/lib/registry:ro", "--pull", "never", manifest["registry_image"]["ref"])
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://{reg}/v2/", timeout=2)
            break
        except OSError:
            time.sleep(1)
    print(f"registry up on {reg}, data read-only", flush=True)

    for img in manifest["images"]:
        sh("docker", "pull", "-q", img["bundle_ref"])
        held = json.loads(sh("docker", "image", "inspect", "-f", "{{json .RepoDigests}}", img["bundle_ref"]))
        if img["bundle_ref"] not in held:
            raise SystemExit(f"{img['bundle_ref']} is not held under its digest after the pull")
    print(f"{len(manifest['images'])} images pulled from the bundle's registry, digests held", flush=True)

    agency = ["docker", "compose", "-f", str(ROOT / "agency/compose.yaml"), "-f", str(OUT / "compose.agency.yaml")]
    sh(*agency, "up", "-d", "--pull", "never", "--no-build", "--force-recreate")
    sh("uv", "run", "pqch", "scope", "generate", str(ROOT / "agency/compose.yaml"), str(OUT / "compose.agency.yaml"),
       "--network", "agency_net", "--out", str(ROOT / "var/scope/scope.json"))
    harness = ["docker", "compose", "-f", str(ROOT / "compose.yaml")]
    if args.lab_overlay:
        harness += ["-f", str(ROOT / args.lab_overlay)]
    harness += ["-f", str(OUT / "compose.harness.yaml")]
    sh(*harness, "up", "-d", "--pull", "never", "--no-build", "--force-recreate")
    print(f"slice and harness started from the bundle in {time.monotonic() - started:.1f} s", flush=True)


if __name__ == "__main__":
    sys.exit(main())
