"""Start the slice and the harness from the offline bundle, with no image fetched from anywhere else.

    uv run python bundle/load.py [--lab-overlay workshop/compose.lab.yaml]   (or .venv/bin/python bundle/load.py)

1. Checks SHA256SUMS against something recorded outside the bundle: its hash (--expect-sums), or
   its ML-DSA signature with the release public key (--sums-pub, and --sums-key-id). Without either
   it refuses, unless --unverified is given, and that is recorded in var/bundle-loads.jsonl. Then
   every file against SHA256SUMS, and every registry blob against the SHA-256 it is named by.
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


def check_sums(out: Path, *, expect_sums: str | None, sums_pub: str | None, sums_key_id: str | None,
               unverified: bool, record: Path | None = None) -> str:
    """How SHA256SUMS is vouched for from outside the bundle, or SystemExit. A load with --unverified
    is appended to the record (var/bundle-loads.jsonl) with who ran it and when."""
    sums = hashlib.sha256((out / "SHA256SUMS").read_bytes()).hexdigest()
    how = None
    if expect_sums:
        if expect_sums != sums:
            raise SystemExit(f"SHA256SUMS hashes to {sums}, not the recorded {expect_sums}")
        how = f"sha256 {sums} matches the recorded hash"
    if sums_pub:
        from pqch.release import verify
        try:
            sig = verify(out / "SHA256SUMS", sums_pub, expect_key_id=sums_key_id)
        except (ValueError, FileNotFoundError) as e:
            raise SystemExit(f"SHA256SUMS: {e}") from e
        how = (how + "; " if how else "") + f"signed with {sig['alg']}, key {sig['key_id'][:16]}…" + \
            ("" if sums_key_id else " (key id not given: the key was taken as it came)")
    if how is None:
        if not unverified:
            raise SystemExit("SHA256SUMS is vouched for by nothing outside the bundle: give --expect-sums with the hash "
                             "bundle/build.py printed, or --sums-pub with the release key; --unverified loads it anyway "
                             "and records that it did")
        how = f"sha256 {sums} — UNVERIFIED: loaded with --unverified, recorded"
    if unverified or how.endswith("recorded"):
        rec = record or Path(os.environ.get("PQCH_VAR", ROOT / "var")) / "bundle-loads.jsonl"
        rec.parent.mkdir(parents=True, exist_ok=True)
        with rec.open("a") as f:
            f.write(json.dumps({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "sums_sha256": sums,
                                "verified": not how.endswith("recorded"), "how": how,
                                "user": os.environ.get("USER") or os.getuid()}) + "\n")
    return how


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lab-overlay", default=None, help="a deployment overlay for the harness (e.g. the lab's)")
    ap.add_argument("--expect-sums", default=None,
                    help="the SHA-256 of SHA256SUMS that bundle/build.py printed, carried outside the bundle")
    ap.add_argument("--sums-pub", default=None, help="the release public key, carried outside the bundle")
    ap.add_argument("--sums-key-id", default=None, help="the release key's id, recorded outside the bundle")
    ap.add_argument("--unverified", action="store_true",
                    help="load a bundle whose SHA256SUMS nothing outside it vouches for; recorded")
    args = ap.parse_args()
    started = time.monotonic()
    how = check_sums(OUT, expect_sums=args.expect_sums, sums_pub=args.sums_pub, sums_key_id=args.sums_key_id,
                     unverified=args.unverified)

    # SHA256SUMS sits in the bundle and can be edited along with what it lists. It is checked
    # against a hash recorded elsewhere when one is given; without one, the check below shows
    # only that the bundle agrees with itself.
    print(f"SHA256SUMS: {how}", flush=True)
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

    # The policy-managed services mount their policy file from agency/generated/, which is the
    # deployment's state and is not in the repository. On a host that has none, the starting state
    # comes from agency/baseline/ (what `pqch estate reset` restores); a file already there is the
    # estate's current state and is kept. Without this, Docker creates the mount sources empty, as
    # root, and a proposal for those services finds no file to edit.
    seeded = []
    for base in sorted((ROOT / "agency" / "baseline").glob("*/*")):
        if base.name == "README.md":
            continue
        dest = ROOT / "agency" / "generated" / base.parent.name / base.name
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                dest.write_bytes(base.read_bytes())
            except PermissionError:
                raise SystemExit(f"{dest.parent} is not writable (Docker created it as root when the estate started "
                                 f"without it): remove it, e.g. docker run --rm -v {dest.parent.parent}:/g alpine "
                                 f"rm -rf /g/{dest.parent.name}, and load again")
            seeded.append(f"{base.parent.name}/{base.name}")
    if seeded:
        print(f"starting state from agency/baseline/ for {', '.join(seeded)}", flush=True)

    agency = ["docker", "compose", "-f", str(ROOT / "agency/compose.yaml"), "-f", str(OUT / "compose.agency.yaml")]
    sh(*agency, "up", "-d", "--pull", "never", "--no-build", "--force-recreate")
    # The package under the interpreter running this loader (`uv run python bundle/load.py` or
    # `.venv/bin/python bundle/load.py`): never `uv run`, which re-resolves the project and, on a
    # box whose uv config is offline or no-index, fails or reaches for the network (demo box, 2026-11-04).
    sh(sys.executable, "-m", "pqch.cli", "scope", "generate", str(ROOT / "agency/compose.yaml"), str(OUT / "compose.agency.yaml"),
       "--network", "agency_net", "--out", str(ROOT / "var/scope/scope.json"))
    harness = ["docker", "compose", "-f", str(ROOT / "compose.yaml")]
    if args.lab_overlay:
        harness += ["-f", str(ROOT / args.lab_overlay)]
    harness += ["-f", str(OUT / "compose.harness.yaml")]
    sh(*harness, "up", "-d", "--pull", "never", "--no-build", "--force-recreate")
    print(f"slice and harness started from the bundle in {time.monotonic() - started:.1f} s", flush=True)


if __name__ == "__main__":
    sys.exit(main())
