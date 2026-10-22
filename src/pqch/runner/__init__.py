"""The runner: the only container that holds the Docker socket (ADR-0002, decision 9).

It accepts a fixed set of jobs — a named scan profile against one target — and
refuses any target that is not in the scope file it was started with. It sits
on the target network, has no public leg, and is reached by the harness over a
Unix socket on a shared volume.
"""

from __future__ import annotations

import io
import json
import os
import re
import socket
import tarfile
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from importlib import resources
from pathlib import Path

import yaml

from pqch import scope as scope_mod
from pqch.common import ms_between, sha256_hex, ulid, utc_now


def load_profiles() -> dict:
    return yaml.safe_load(resources.files(__package__).joinpath("profiles.yaml").read_text())


class Refused(Exception):
    """A job the runner will not run. `code` is the HTTP status to answer with."""

    def __init__(self, code: int, reason: str):
        super().__init__(reason)
        self.code = code
        self.reason = reason


@dataclass
class JobResult:
    job_id: str
    profile: str
    target: dict
    tool: str
    version: str
    image: str
    image_digest: str
    status: str  # ok | timeout | error
    exit_code: int | None
    started_at: str
    ended_at: str
    duration_ms: int
    raw: str | None = None
    raw_sha256: str | None = None
    stderr_tail: str = ""
    container: dict = field(default_factory=dict)
    binding: dict | None = None
    # The machine the job ran on, and the platform when the scanner was emulated: a
    # duration is never read without them.
    hardware: str = "unlabelled"

    def to_dict(self) -> dict:
        return asdict(self)


class Runner:
    def __init__(self, scope_path: str | Path, raw_dir: str | Path, *, target_network: str,
                 docker_client=None, profiles: dict | None = None, log_dir: str | Path | None = None):
        self.scope_path = Path(scope_path)
        self.raw_dir = Path(raw_dir)
        self.target_network = target_network
        self.profiles = profiles if profiles is not None else load_profiles()
        self._docker = docker_client
        self._scope: tuple[dict, str] | None = None
        self._lock = threading.Lock()
        # Every job, on storage only the runner mounts: what the page checks a verdict's probes against.
        self.jobs_log = Path(log_dir) / "jobs.jsonl" if log_dir else None
        # Emulation smoke tests only: start scanners for another platform, with budgets
        # scaled to match. Neither is set in any deployment; timings taken with them are
        # labelled as emulated and are not measurements of the target hardware.
        self.platform = os.environ.get("PQCH_SCANNER_PLATFORM") or None
        self.budget_scale = float(os.environ.get("PQCH_BUDGET_SCALE", "1"))
        # An offline bundle's registry. A digest names the same bytes wherever they are
        # served from; only the place changes.
        self.registry = os.environ.get("PQCH_REGISTRY") or None
        self.hardware = os.environ.get("PQCH_HARDWARE", "unlabelled")

    def resolve(self, ref: str) -> str:
        """Where to fetch a digest-pinned image: from the bundle's registry when there is one."""
        if not self.registry:
            return ref
        name, _, digest = ref.partition("@")
        first, _, rest = name.partition("/")
        path = rest if rest and ("." in first or ":" in first or first == "localhost") else name
        return f"{self.registry}/{path}@{digest}"

    def _client(self):
        """A Docker client per job: jobs run concurrently and a client is not shared."""
        if self._docker is not None:
            return self._docker
        import docker

        return docker.from_env()

    def scope(self) -> tuple[dict, str]:
        """The scope the runner was started with. Read once; a new scope needs a new runner."""
        with self._lock:
            if self._scope is None:
                self._scope = scope_mod.load(self.scope_path)
            return self._scope

    # ------------------------------------------------------------- checks
    def check(self, profile: str, target: dict, scope_hash: str) -> tuple[dict, dict, dict]:
        """Refuse anything outside the profiles and the scope. Touches no container."""
        prof = self.profiles.get(profile)
        if prof is None:
            raise Refused(400, f"unknown profile {profile!r}")
        scope, held = self.scope()
        if scope_hash != held:
            raise Refused(409, f"scope hash {scope_hash[:12]} is not the scope the runner holds ({held[:12]})")
        if prof["layer"] == "wire":
            host, port = target.get("host"), target.get("port")
            if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
                raise Refused(400, "a wire target is a host string and an integer port")
            ep = scope_mod.endpoint(scope, host, port) or scope_mod.twin(scope, host, port)
            if ep is None:
                raise Refused(403, f"{host}:{port} is not in the scope")
            if ep["protocol"] not in prof["protocols"]:
                raise Refused(403, f"profile {profile} does not scan {ep['protocol']} listeners")
            return prof, scope, ep
        ref = scope_mod.image(scope, str(target.get("image", "")))
        if ref is None:
            raise Refused(403, f"image {target.get('image')!r} is not in the scope")
        return prof, scope, {"image": ref}

    # ---------------------------------------------------------------- run
    def run(self, profile: str, target: dict, scope_hash: str, params: dict | None = None) -> JobResult:
        prof, _scope, resolved = self.check(profile, target, scope_hash)
        values = self.check_params(prof, params or {})
        job_id = ulid()
        args = self._args(prof, resolved, values)
        # A twin is probed on the twin network, where it alone lives; everything else on the target's.
        net_name = resolved.get("network") if prof["layer"] == "wire" else None
        network = (net_name or self.target_network) if prof["network"] == "target" else "none"
        started = utc_now()
        client = self._client()
        image_ref, image_digest = self._image(client, prof)
        container = None
        status, exit_code, raw_bytes, stderr = "error", None, None, ""
        meta: dict = {}
        before = self.binding(client, resolved["host"], net_name) if prof["layer"] == "wire" else None
        try:
            container = client.containers.create(
                image_digest if prof["image"] == "self" else image_ref, command=args, network=network,
                mem_limit=prof.get("mem_limit"), labels={"pqch.job": job_id, "pqch.profile": profile},
                detach=True, platform=self.platform,
            )
            if prof.get("input") == "image-archive":
                self._put_image(client, container, resolved["image"])
            container.start()
            try:
                res = container.wait(timeout=prof["budget_s"] * self.budget_scale)
                exit_code = res.get("StatusCode")
                status = "ok"
            except Exception:  # requests' ReadTimeout: the budget ran out
                container.kill()
                status = "timeout"
            stderr = container.logs(stdout=False, stderr=True).decode(errors="replace")[-2000:]
            out = prof["output"]
            if out.get("stdout"):
                raw_bytes = container.logs(stdout=True, stderr=False)
            elif status == "ok":
                raw_bytes = self._get_file(container, out["file"])
            container.reload()
            meta = {"id": container.id, "network": network}
        except Exception as e:  # docker errors, missing images
            status = "error"
            stderr = (stderr + f"\n{type(e).__name__}: {e}")[-2000:]
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
        ended = utc_now()
        binding = None
        if before is not None:
            after = self.binding(client, resolved["host"], net_name)
            binding = {**before, "stable": after == before}
        result = JobResult(
            job_id=job_id, profile=profile, target=resolved, tool=prof["tool"], version=prof["version"],
            image=image_ref, image_digest=image_digest, status=status,
            exit_code=exit_code, started_at=started, ended_at=ended,
            duration_ms=ms_between(started, ended), stderr_tail=stderr, container=meta,
            binding=binding, hardware=self.hardware,
        )
        if raw_bytes:
            self.raw_dir.mkdir(parents=True, exist_ok=True)
            name = f"{job_id}.{prof['output'].get('ext', 'out')}"
            (self.raw_dir / name).write_bytes(raw_bytes)
            result.raw = f"var/raw/{name}"
            result.raw_sha256 = sha256_hex(raw_bytes)
        self._log_job(result, values)
        return result

    def _log_job(self, r: JobResult, params: dict) -> None:
        if self.jobs_log is None:
            return
        entry = {"job_id": r.job_id, "profile": r.profile, "target": r.target, "params": params,
                 "platform": self.platform, "hardware": r.hardware,
                 "image_digest": r.image_digest, "status": r.status, "started_at": r.started_at,
                 "ended_at": r.ended_at, "raw": r.raw, "raw_sha256": r.raw_sha256, "binding": r.binding}
        with self._lock:
            self.jobs_log.parent.mkdir(parents=True, exist_ok=True)
            with self.jobs_log.open("a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())

    def jobs(self, ids: set[str]) -> list[dict]:
        """The logged jobs with these ids."""
        if self.jobs_log is None or not self.jobs_log.exists():
            return []
        out = []
        with self.jobs_log.open() as f:
            for line in f:
                if any(i in line for i in ids):
                    e = json.loads(line)
                    if e["job_id"] in ids:
                        out.append(e)
        return out

    def binding(self, client, address: str, network: str | None = None) -> dict:
        """The container holding `address` on the target network (or the named one), and the image it runs."""
        found = {"address": address, "container_id": None, "container_name": None,
                 "image": None, "image_digest": None}
        try:
            net = client.networks.get(network or self.target_network)
            for cid, info in (net.attrs.get("Containers") or {}).items():
                if info.get("IPv4Address", "").split("/")[0] == address:
                    c = client.containers.get(cid)
                    found.update(container_id=c.id, container_name=c.name,
                                 image=c.attrs.get("Config", {}).get("Image"),
                                 image_digest=c.attrs.get("Image"))
                    break
        except Exception as e:  # recorded, never guessed
            found["error"] = f"{type(e).__name__}: {e}"[:200]
        return found

    @staticmethod
    def check_params(prof: dict, params: dict) -> dict:
        """A profile's parameters: only the names it declares, each matching its pattern."""
        allowed = prof.get("params", {})
        unknown = set(params) - set(allowed)
        if unknown:
            raise Refused(400, f"profile takes no parameter {sorted(unknown)[0]!r}")
        out = {}
        for name, pattern in allowed.items():
            value = params.get(name, "")
            if not isinstance(value, str) or not re.fullmatch(pattern, value):
                raise Refused(400, f"parameter {name!r} does not match {pattern}")
            out[name] = value
        return out

    def _image(self, client, prof: dict) -> tuple[str, str]:
        """The image a profile runs, and its digest. `self` is the runner's own image."""
        if prof["image"] != "self":
            return self.resolve(prof["image"]), prof["image"].split("@", 1)[1]
        me = client.containers.get(socket.gethostname())
        return me.attrs["Config"]["Image"], me.attrs["Image"]

    @staticmethod
    def _args(prof: dict, resolved: dict, params: dict | None = None) -> list[str]:
        if prof["layer"] != "wire":
            return list(prof["args"])
        sni = resolved.get("sni")
        url = f"https://{sni or resolved['host']}:{resolved['port']}"
        template = prof["args"] if sni or "args_no_sni" not in prof else prof["args_no_sni"]
        values = {"host": resolved["host"], "port": str(resolved["port"]), "sni": sni or resolved["host"],
                  "url": url, **(params or {})}
        return [a.format(**values) for a in template]

    @staticmethod
    def _put_image(client, container, ref: str) -> None:
        """Save the scoped image to a tarball and copy it into the scanner at /scan/image.tar."""
        with tempfile.TemporaryDirectory() as tmp:
            image_tar = os.path.join(tmp, "image.tar")
            with open(image_tar, "wb") as f:
                for chunk in client.images.get(ref).save(named=True):
                    f.write(chunk)
            wrapper = os.path.join(tmp, "wrapper.tar")
            with tarfile.open(wrapper, "w") as t:
                info = tarfile.TarInfo("scan")
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                t.addfile(info)
                t.add(image_tar, arcname="scan/image.tar")
            with open(wrapper, "rb") as f:
                container.put_archive("/", f)

    @staticmethod
    def _get_file(container, path: str) -> bytes | None:
        try:
            stream, _ = container.get_archive(path)
        except Exception:
            return None
        buf = io.BytesIO(b"".join(stream))
        with tarfile.open(fileobj=buf) as t:
            member = t.getmembers()[0]
            f = t.extractfile(member)
            return f.read() if f else None
