"""Build the offline bundle: a local registry holding every image the slice and the harness run,
for linux/amd64 and linux/arm64, by digest.

    uv run python bundle/build.py

Writes `bundle/out/`:

    registry/                the registry's data directory: content-addressed blobs
    registry-image.<arch>.tar  the registry's own image, saved by tag (a tag survives load)
    manifest.json            every image: role, source, the bundle reference by digest
    compose.agency.yaml      overlay: the slice's services from the bundle, no build
    compose.harness.yaml     overlay: the harness from the bundle; the runner resolves scanners there
    SHA256SUMS               every file in bundle/out except the registry's blobs, which are
                             named by their SHA-256 and checked against their names at load

Needs the network (build time). `bundle/load.py` needs none of it.

Why a registry and not `docker save`: an image saved by digest loads back untagged, and an
image saved by tag loads back under a new digest (journal lesson 03).
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "bundle" / "out"
PORT = 15000
REG = f"127.0.0.1:{PORT}"
NAME = "pqch-bundle-registry"
REGISTRY_IMAGE = "ghcr.io/distribution/distribution:3.0.0"
REGISTRY_DIGEST = "sha256:4ba3adf47f5c866e9a29288c758c5328ef03396cb8f5f6454463655fa8bc83e2"
SKOPEO = "quay.io/skopeo/stable:v1.20@sha256:47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4"
PLATFORMS = "linux/amd64,linux/arm64"
SLICE = ["portal", "api", "sftp-legacy", "bastion"]
# Rebuild images already in the bundle: each build of the slice makes new keys and certificates.
REBUILD = "--rebuild" in sys.argv
INDEX_TYPES = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])


def sh(*args, check=True, capture=True, timeout=3600) -> str:
    r = subprocess.run(list(args), capture_output=capture, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise SystemExit(f"failed: {' '.join(args)}\n{(r.stderr or '')[-1500:]}")
    return (r.stdout or "").strip()


def digest_of(repo: str, tag: str) -> str:
    req = urllib.request.Request(f"http://{REG}/v2/{repo}/manifests/{tag}", method="HEAD",
                                 headers={"Accept": INDEX_TYPES})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.headers["Docker-Content-Digest"]


def platforms_of(repo: str, ref: str) -> list[str]:
    req = urllib.request.Request(f"http://{REG}/v2/{repo}/manifests/{ref}", headers={"Accept": INDEX_TYPES})
    with urllib.request.urlopen(req, timeout=30) as r:
        doc = json.loads(r.read())
    return sorted({f"{m['platform']['os']}/{m['platform']['architecture']}" for m in doc.get("manifests", [])
                   if m.get("platform", {}).get("os") not in (None, "unknown")})


def start_registry() -> str:
    (OUT / "registry").mkdir(parents=True, exist_ok=True)
    if sh("docker", "ps", "-q", "--filter", f"name=^{NAME}$"):
        return sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", NAME)
    sh("docker", "rm", "-f", NAME, check=False)
    sh("docker", "pull", "-q", f"{REGISTRY_IMAGE}@{REGISTRY_DIGEST}")
    sh("docker", "tag", f"{REGISTRY_IMAGE}@{REGISTRY_DIGEST}", REGISTRY_IMAGE)
    sh("docker", "run", "-d", "--name", NAME, "-p", f"127.0.0.1:{PORT}:5000",
       "-v", f"{OUT / 'registry'}:/var/lib/registry", REGISTRY_IMAGE)
    for _ in range(60):
        try:
            urllib.request.urlopen(f"http://{REG}/v2/", timeout=2)
            break
        except OSError:
            time.sleep(1)
    return sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", NAME)


def build_push(repo: str, context: Path, tag: str = "m0", *, keep: bool = True) -> dict:
    """Build and push one image. `keep` reuses an image already in the bundle: right for the
    slice, whose every build makes new keys; wrong for the harness, which must be the source
    as it stands, so the harness is always built (the build cache makes that cheap)."""
    ref = f"{REG}/{repo}:{tag}"
    if keep and not REBUILD:
        try:
            d = digest_of(repo, tag)
            return {"repo": repo, "source": f"build of {context.relative_to(ROOT)}", "bundle_ref": f"{REG}/{repo}@{d}",
                    "digest": d, "platforms": platforms_of(repo, d)}
        except OSError:
            pass
    sh("docker", "buildx", "build", "--platform", PLATFORMS, "-t", ref, "--push", str(context))
    d = digest_of(repo, tag)
    return {"repo": repo, "source": f"build of {context.relative_to(ROOT)}", "bundle_ref": f"{REG}/{repo}@{d}",
            "digest": d, "platforms": platforms_of(repo, d)}


def copy_pinned(src: str, reg_ip: str) -> dict:
    """Copy a digest-pinned image with all its platforms; the digest must survive unchanged."""
    name, _, digest = src.partition("@")
    first, _, rest = name.partition("/")
    repo = rest if "." in first or ":" in first else name
    try:
        if digest_of(repo, "pinned") == digest:      # already in the bundle, unchanged
            return {"repo": repo, "source": src, "bundle_ref": f"{REG}/{repo}@{digest}", "digest": digest,
                    "platforms": platforms_of(repo, digest)}
    except OSError:
        pass
    for attempt in range(8):
        r = subprocess.run(["docker", "run", "--rm", SKOPEO, "copy", "--all", "--retry-times", "3",
                            "--dest-tls-verify=false", f"docker://{src}", f"docker://{reg_ip}:5000/{repo}:pinned"],
                           capture_output=True, text=True, timeout=1800)
        if r.returncode == 0:
            break
        if ("429" in r.stderr or "toomanyrequests" in r.stderr) and attempt < 7:
            print(f"  rate-limited copying {src}; waiting {300 * (attempt + 1)} s", flush=True)
            time.sleep(300 * (attempt + 1))
            continue
        raise SystemExit(f"copy failed: {src}\n{r.stderr[-1000:]}")
    d = digest_of(repo, "pinned")
    if d != digest:
        raise SystemExit(f"{src}: the bundle holds {d}, not the pinned digest")
    return {"repo": repo, "source": src, "bundle_ref": f"{REG}/{repo}@{d}", "digest": d,
            "platforms": platforms_of(repo, d)}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    reg_ip = start_registry()
    images = []
    print("slice and harness images, built for", PLATFORMS, flush=True)
    for svc in SLICE:
        images.append({"role": "target", "service": svc, **build_push(f"pqch-agency/{svc}", ROOT / "agency" / svc)})
        print("  ", images[-1]["bundle_ref"], images[-1]["platforms"], flush=True)
    commit = sh("git", "-C", str(ROOT), "rev-parse", "HEAD", check=False) or "unknown"
    if sh("git", "-C", str(ROOT), "status", "--porcelain", "--", "src", "Dockerfile", "pyproject.toml", "uv.lock", check=False):
        commit += "-dirty"
    images.append({"role": "harness", "built_from": commit, **build_push("pqch/harness", ROOT, keep=False)})
    print("  ", images[-1]["bundle_ref"], images[-1]["platforms"], flush=True)
    print("scanner images, copied with every platform, digests checked", flush=True)
    profiles = yaml.safe_load((ROOT / "src" / "pqch" / "runner" / "profiles.yaml").read_text())
    for src in sorted({p["image"] for p in profiles.values() if p["image"] != "self"}):
        images.append({"role": "scanner", **copy_pinned(src, reg_ip)})
        print("  ", images[-1]["bundle_ref"], images[-1]["platforms"], flush=True)
    for plat in ("amd64", "arm64"):
        sh("docker", "pull", "-q", "--platform", f"linux/{plat}", f"{REGISTRY_IMAGE}@{REGISTRY_DIGEST}")
        sh("docker", "save", "--platform", f"linux/{plat}", "-o", str(OUT / f"registry-image.{plat}.tar"),
           REGISTRY_IMAGE)
    (OUT / "manifest.json").write_text(json.dumps({
        "registry": REG, "registry_image": {"ref": REGISTRY_IMAGE, "digest": REGISTRY_DIGEST},
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "images": images}, indent=1) + "\n")
    agency = {"services": {i["service"]: {"image": i["bundle_ref"], "build": "!reset"} for i in images
                           if i["role"] == "target"}}
    harness_ref = next(i["bundle_ref"] for i in images if i["role"] == "harness")
    harness = {"services": {
        # The runner recreates a service with the files the estate was started with: the base
        # file and the bundle's overlay, mounted at its own path. bundle/load.py sets PQCH_BUNDLE_DIR.
        "runner": {"image": harness_ref, "build": "!reset",
                   "environment": {"PQCH_REGISTRY": REG, "PQCH_AGENCY_COMPOSE_FILES":
                                   "${PQCH_AGENCY_DIR}/compose.yaml:${PQCH_BUNDLE_DIR}/compose.agency.yaml"},
                   "volumes": ["${PQCH_BUNDLE_DIR}/compose.agency.yaml:${PQCH_BUNDLE_DIR}/compose.agency.yaml:ro"]},
        "signer": {"image": harness_ref}, "app": {"image": harness_ref}}}
    for name, doc in (("compose.agency.yaml", agency), ("compose.harness.yaml", harness)):
        text = "# Generated by bundle/build.py: images from the bundle's registry, by digest.\n" + \
            yaml.safe_dump(doc, sort_keys=False).replace("build: '!reset'", "build: !reset null")
        (OUT / name).write_text(text)
    sums = []
    for p in sorted(OUT.rglob("*")):
        if p.is_file() and "registry" not in p.relative_to(OUT).parts[:1] and p.name != "SHA256SUMS":
            sums.append(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(OUT)}")
    (OUT / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    size = sh("du", "-sh", str(OUT)).split()[0]
    print(f"bundle: {len(images)} images in {OUT}, {size}; harness built from {commit}")
    # SHA256SUMS travels with the bundle and can be edited with it. Its own hash is the one
    # value to carry separately: bundle/load.py --expect-sums <hash>.
    print(f"SHA256SUMS sha256 {hashlib.sha256((OUT / 'SHA256SUMS').read_bytes()).hexdigest()}  <- record this outside the bundle")


if __name__ == "__main__":
    sys.exit(main())
