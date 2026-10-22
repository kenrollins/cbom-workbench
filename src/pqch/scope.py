"""The scope: what the harness may touch (spec/interfaces.md, section 1; ADR-0003).

The harness never discovers targets. For an estate it built, the scope is
generated from the estate's compose file: each service's `x-pqch.endpoints`
and its static address give the listeners, and the local image's index digest
gives the image. The runner refuses anything not listed here.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

from pqch import schemas
from pqch.common import hash_object, ulid

SCHEMA = "pqch.scope/1"
TWIN_NETWORK = "pqch-twin-net"
TWIN_SUBNET = "172.16.107.0/24"


def _read_compose(paths: list[Path]) -> dict:
    if len(paths) == 1:
        return yaml.safe_load(paths[0].read_text())
    # Overlays: let Compose do the merge, then read the result.
    args = ["docker", "compose"] + [a for p in paths for a in ("-f", str(p))] + ["config", "--format", "yaml"]
    out = subprocess.run(args, capture_output=True, text=True, check=True)
    return yaml.safe_load(out.stdout)


def generate(compose_path: str | Path | list, *, network: str | None = None, docker_client=None) -> dict:
    """A colocated, owned scope from the compose file(s) of an estate of the harness's own building."""
    paths = [Path(p) for p in (compose_path if isinstance(compose_path, list) else [compose_path])]
    compose_path = paths[0]
    doc = _read_compose(paths)
    if docker_client is None:
        import docker

        docker_client = docker.from_env()

    nets = doc.get("networks") or {}
    if network is None:
        if len(nets) != 1:
            raise ValueError("compose file defines more than one network; name the target network")
        network = next(iter(nets))

    endpoints, images, twins = [], [], []
    for name, svc in sorted((doc.get("services") or {}).items()):
        meta = svc.get("x-pqch") or {}
        ref = _digest_ref(docker_client, svc["image"]) if svc.get("image") else None
        if ref:
            images.append(ref)
        addr = ((svc.get("networks") or {}).get(network) or {}).get("ipv4_address")
        for ep in meta.get("endpoints", []):
            if not addr:
                raise ValueError(f"service {name} lists endpoints but has no static address on {network}")
            # The compose service that serves the listener: the first link of a dependency chain
            # (listener -> service), asserted by a rule only when the runner finds a container at
            # the address running this image.
            entry = {"host": addr, "port": int(ep["port"]), "transport": ep.get("transport", "tcp"),
                     "protocol": ep["protocol"], "service": name}
            if ep.get("sni"):
                entry["sni"] = ep["sni"]
            if ref:
                entry["image"] = ref
            endpoints.append(entry)
            # The rehearsal copy of the listener: the same port and image at a fixed address on
            # the twin network. Listed apart from the endpoints, so no scan reaches it; the runner
            # probes it only during a rehearsal, and only because the scope names it.
            twin = meta.get("twin")
            if twin and ref:
                twins.append({**{k: entry[k] for k in ("port", "transport", "protocol", "service", "image")},
                              "host": twin["address"], "network": TWIN_NETWORK,
                              **({"sni": entry["sni"]} if "sni" in entry else {})})

    scope = {
        "schema": SCHEMA,
        "id": ulid(),
        "estate": "colocated",
        "owned": True,
        "authorized_by": None,
        "endpoints": endpoints,
        "images": images,
        **({"twins": twins} if twins else {}),
        "sources": [{"repo": str(compose_path.parent), "commit": _git_head(compose_path.parent)}],
        "reach": {"kind": "local"},
    }
    schemas.validate(scope)
    return scope


def _digest_ref(client, image: str) -> str:
    img = client.images.get(image)
    if "@" in image:
        # Already a digest reference, as in an offline bundle: keep it if the image holds it.
        if image in (img.attrs.get("RepoDigests") or []):
            return image
        raise ValueError(f"image {image} is not held under that digest")
    repo = image.rsplit(":", 1)[0] if ":" in image.split("/")[-1] else image
    for d in img.attrs.get("RepoDigests") or []:
        if d.split("@")[0] == repo:
            return d
    raise ValueError(f"image {image} has no index digest; build it with the containerd image store")


def _git_head(path: Path) -> str:
    out = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else "unknown"


def load(path: str | Path) -> tuple[dict, str]:
    """Read and validate a scope; return it with its hash."""
    scope = json.loads(Path(path).read_text())
    schemas.validate(scope)
    return scope, scope_hash(scope)


def scope_hash(scope: dict) -> str:
    return hash_object(scope)


def endpoint(scope: dict, host: str, port: int) -> dict | None:
    for ep in scope["endpoints"]:
        if ep["host"] == host and ep["port"] == port:
            return ep
    return None


def twin(scope: dict, host: str, port: int) -> dict | None:
    for ep in scope.get("twins", []):
        if ep["host"] == host and ep["port"] == port:
            return ep
    return None


def twin_of(scope: dict, service: str, port: int) -> dict | None:
    return next((t for t in scope.get("twins", []) if t["service"] == service and t["port"] == port), None)


def image(scope: dict, ref: str) -> str | None:
    """The scoped digest reference for `ref`, matched exactly or by repository."""
    for r in scope["images"]:
        if ref == r or ref == r.split("@")[0]:
            return r
    return None
