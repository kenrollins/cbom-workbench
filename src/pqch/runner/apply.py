"""The runner's apply and recreate jobs (spec section 3, "Who writes the ledger").

The runner applies a change only after reading the run's ledger itself and
finding: a chain that verifies with every checkpoint signed by the signer's
key and every checkpoint the signer recorded still in place; one
`change.proposed` for the change id and a later `approval.granted`, with no
denial; a checkpoint covering that approval; and no earlier apply of that id in
its own log. It acts only on an owned estate, on a service the scope lists,
whose running container belongs to the estate's Compose project.

To apply, it writes the proposal's rendered configuration — checked against
the hash the proposal recorded — and recreates the service with Compose, so
the new container starts from the new file. It records both containers in its
own log, on storage no other service mounts, and returns the same record.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from pathlib import Path

from pqch.common import ms_between, sha256_hex, utc_now
from pqch.ledger import Ledger
from pqch.ledger.checkpoints import verify_signed
from pqch.migrator import render
from pqch.runner import Refused, Runner

SERVICE = re.compile(r"^[a-z0-9][a-z0-9-]*$")


class Applier:
    def __init__(self, runner: Runner, *, runs_dir: str | Path, agency_dir: str | Path, log_dir: str | Path,
                 signer, project: str = "pqch-agency", compose_cmd: list[str] | None = None,
                 compose_files: list[str] | None = None):
        self.runner = runner
        self.runs_dir = Path(runs_dir)
        self.agency_dir = Path(agency_dir)
        self.log_path = Path(log_dir) / "applies.jsonl"
        self.signer = signer
        self.project = project
        self.compose_cmd = compose_cmd or ["docker", "compose"]
        # The files the estate was started with, base first. An estate started with an overlay
        # (the offline bundle's, which names its images by digest) must be recreated with it,
        # or the service comes back from another image.
        self.compose_files = [str(f) for f in compose_files] if compose_files else [str(self.agency_dir / "compose.yaml")]

    # ------------------------------------------------------------------ log
    def log(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines() if line.strip()]

    def _append_log(self, entry: dict) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    # --------------------------------------------------------------- checks
    def _ledger(self, run_id: str) -> list[dict]:
        if not run_id.isalnum():
            raise Refused(400, "bad run id")
        path = self.runs_dir / run_id / "ledger.jsonl"
        if not path.exists():
            raise Refused(404, f"no run {run_id}")
        events = list(Ledger(path).events())
        key = self.signer.key()
        res = verify_signed(events, key["public_key_pem"].encode(), known=self.signer.record(run_id))
        if not res.ok:
            raise Refused(409, f"the ledger does not verify: {res.error}")
        return events

    def authorize(self, run_id: str, change_id: str) -> tuple[list[dict], dict, dict]:
        """The proposal and its approval, or a refusal saying what is missing."""
        events = self._ledger(run_id)
        proposed = [e for e in events if e["type"] == "change.proposed" and e["payload"].get("change_id") == change_id]
        if len(proposed) != 1:
            raise Refused(409, f"{len(proposed)} proposals for change {change_id}; need exactly one")
        prop = proposed[0]
        later = [e for e in events if e["seq"] > prop["seq"] and e["payload"].get("change_id") == change_id]
        if any(e["type"] == "approval.denied" for e in later):
            raise Refused(409, f"change {change_id} was denied")
        approvals = [e for e in later if e["type"] == "approval.granted"]
        if not approvals:
            raise Refused(409, f"change {change_id} has no approval")
        approval = approvals[0]
        covered = [e for e in events if e["type"] == "checkpoint.signed"
                   and e["payload"]["through_seq"] >= approval["seq"]]
        if not covered:
            raise Refused(409, f"no signed checkpoint covers the approval of {change_id} yet")
        if any(e.get("change_id") == change_id and e.get("kind") == "apply" for e in self.log()):
            raise Refused(409, f"change {change_id} has already been applied")
        return events, prop, approval

    def _target(self, prop: dict) -> dict:
        t = prop["payload"]["target"]
        scope, _ = self.runner.scope()
        if not scope.get("owned"):
            raise Refused(403, "the scope is not an owned estate; changes are handed off, never applied")
        if not SERVICE.match(t.get("service", "")):
            raise Refused(400, "bad service name")
        if not any(e["host"] == t["address"] and e["port"] == t["port"] for e in scope["endpoints"]):
            raise Refused(403, f"{t['address']}:{t['port']} is not in the scope")
        return t

    def _container_at(self, client, t: dict):
        """The container the change will replace, refused unless it is the estate's own: the named
        service of the estate's Compose project, started from the same Compose files the runner
        recreates services from, not a one-off or a rehearsal copy, and running the image the scope
        names for this listener. A label can be typed by anyone who can start a container; the files
        it was started from and the image it runs are what tie it to the estate this runner manages."""
        b = self.runner.binding(client, t["address"])
        if not b.get("container_id"):
            raise Refused(409, f"no container holds {t['address']}")
        c = client.containers.get(b["container_id"])
        cfg = c.attrs.get("Config", {})
        labels = cfg.get("Labels") or {}
        if labels.get("com.docker.compose.project") != self.project or \
                labels.get("com.docker.compose.service") != t["service"]:
            raise Refused(403, f"{c.name} is not service {t['service']} of the {self.project} estate")
        files = [f for f in (labels.get("com.docker.compose.project.config_files") or "").split(",") if f]
        if files != self.compose_files:
            raise Refused(403, f"{c.name} was not started from the estate's Compose files ({', '.join(self.compose_files)})")
        if labels.get("com.docker.compose.oneoff") == "True" or "pqch.twin" in labels:
            raise Refused(403, f"{c.name} is a one-off or a rehearsal copy, not the estate's service")
        scope, _ = self.runner.scope()
        want = next((e.get("image") for e in scope["endpoints"] if e["host"] == t["address"] and e["port"] == t["port"]), None)
        if want and "@" in want:
            # The scope pins the image by digest: the container must run exactly that image.
            if c.attrs.get("Image") != want.split("@", 1)[1]:
                raise Refused(403, f"{c.name} runs image {c.attrs.get('Image')}, not the scope's {want} for this listener")
        elif want and (cfg.get("Image") or "").rsplit(":", 1)[0] != want.rsplit(":", 1)[0]:
            raise Refused(403, f"{c.name} runs {cfg.get('Image')}, not the scope's {want} for this listener")
        return b

    def _rehearsed(self, run_id: str, change_id: str, new_sha256: str) -> None:
        """A change a model drafted is applied only after a rehearsal of exactly that file met the
        change's intent: the ledger's verdict says so, and this runner's own log shows it started the
        copy with that file and saw it listen."""
        events = self._ledger(run_id)
        ok = any(e["type"] == "rehearsal.completed" and e["payload"].get("change_id") == change_id
                 and e["payload"].get("config_sha256") == new_sha256
                 and (e["payload"].get("verdict") or {}).get("meets_intent") is True for e in events)
        if not ok:
            raise Refused(409, f"change {change_id} was drafted by a model and has no rehearsal that met its intent")
        if not any(x.get("kind") == "rehearse" and x.get("change_id") == change_id and x.get("run") == run_id
                   and x.get("config_sha256") == new_sha256 and x.get("listening") for x in self.log()):
            raise Refused(409, f"this runner has no record of rehearsing change {change_id} with that file")

    def _service_def(self, service: str) -> dict:
        import yaml

        doc = yaml.safe_load(Path(self.compose_files[0]).read_text())
        svc = (doc.get("services") or {}).get(service)
        if svc is None:
            raise Refused(404, f"no service {service} in the estate's compose file")
        return svc

    def _software(self, service: str) -> str:
        """Which software the service runs, as the estate's own compose file declares it — never
        as a proposal says. A service with no declared policy file takes no change."""
        policy = (self._service_def(service).get("x-pqch") or {}).get("policy") or {}
        if policy.get("software") not in render.SHAPES:
            raise Refused(403, f"service {service} declares no policy file the runner can write")
        return policy["software"]

    # ------------------------------------------------------------- rehearsal
    def rehearse(self, run_id: str, change_id: str) -> dict:
        """Start a copy of the service, from the image the scope names, on the twin network, with the
        proposed policy file — before anyone approves. Nothing in the estate is touched. The copy
        listens at the twin address the scope lists; the verifier probes it there."""
        import docker as docker_mod

        from pqch import scope as scope_mod

        events = self._ledger(run_id)
        props = [e for e in events if e["type"] == "change.proposed" and e["payload"].get("change_id") == change_id]
        if len(props) != 1:
            raise Refused(409, f"{len(props)} proposals for change {change_id}; need exactly one")
        prop = props[0]
        t = self._target(prop)
        p = prop["payload"]
        content = p["new_content"]
        if sha256_hex(content.encode()) != p["new_sha256"]:
            raise Refused(409, "the proposed configuration does not match its recorded hash")
        software = self._software(t["service"])
        if not render.is_rendered_shape(content, software):
            raise Refused(403, f"the proposed configuration holds lines the runner does not write for {software}")
        scope, _ = self.runner.scope()
        twin = scope_mod.twin_of(scope, t["service"], t["port"])
        if twin is None:
            raise Refused(403, f"the scope lists no twin for {t['service']}:{t['port']}")
        svc = self._service_def(t["service"])
        mount = ((svc.get("x-pqch") or {}).get("policy") or {}).get("mount")
        client = self.runner._client()
        net = self._twin_network(client)
        name = f"pqch-twin-{t['service']}"
        self._remove_twin(client, name)
        policy_dir = self.agency_dir / "generated" / "twin" / t["service"]
        policy_dir.mkdir(parents=True, exist_ok=True)
        (policy_dir / render.POLICY_FILE[software]).write_text(content)
        binds = {}
        for v in svc.get("volumes") or []:
            src, _, rest = v.partition(":")
            dst, _, mode = rest.partition(":")
            host = policy_dir if dst == mount else (self.agency_dir / src).resolve() if src.startswith(".") else Path(src)
            binds[str(host)] = {"bind": dst, "mode": mode or "rw"}
        env = svc.get("environment") or {}
        env = [f"{k}={v}" for k, v in env.items()] if isinstance(env, dict) else list(env)
        started = utc_now()
        api = client.api
        cid = api.create_container(
            twin["image"], name=name, environment=env, labels={"pqch.twin": t["service"], "pqch.rehearsal": change_id,
                                                                "pqch.run": run_id},
            host_config=api.create_host_config(binds=binds, mem_limit=svc.get("mem_limit")),
            networking_config=api.create_networking_config({net.name: api.create_endpoint_config(ipv4_address=twin["host"])}),
        )["Id"]
        api.start(cid)
        listening = self._wait_listening(twin["host"], twin["port"], timeout_s=60)
        info = client.containers.get(cid)
        entry = {"kind": "rehearse", "run": run_id, "change_id": change_id, "service": t["service"],
                 "twin": f"{twin['host']}:{twin['port']}", "container": cid, "image_digest": info.attrs.get("Image"),
                 "image": twin["image"], "config_sha256": sha256_hex(content.encode()), "listening": listening,
                 "started_at": started, "ended_at": utc_now()}
        if not listening:
            entry["logs_tail"] = info.logs(tail=15).decode(errors="replace")[-1500:]
            self._remove_twin(client, name)
        self._append_log(entry)
        return entry

    def rehearse_end(self, run_id: str, change_id: str) -> dict:
        client = self.runner._client()
        removed = []
        for c in client.containers.list(all=True, filters={"label": [f"pqch.rehearsal={change_id}", f"pqch.run={run_id}"]}):
            c.remove(force=True)
            removed.append(c.id)
        entry = {"kind": "rehearse-end", "run": run_id, "change_id": change_id, "removed": removed, "at": utc_now()}
        self._append_log(entry)
        return entry

    def _twin_network(self, client):
        """The twin network: internal, its own subnet, created on first use. The runner joins it,
        so it can see a copy listen."""
        from docker.types import IPAMConfig, IPAMPool

        from pqch import scope as scope_mod

        try:
            net = client.networks.get(scope_mod.TWIN_NETWORK)
        except Exception:
            net = client.networks.create(scope_mod.TWIN_NETWORK, driver="bridge", internal=True,
                                         ipam=IPAMConfig(pool_configs=[IPAMPool(subnet=scope_mod.TWIN_SUBNET)]),
                                         labels={"pqch.twin": "network"})
        me = socket.gethostname()            # the runner's own container id, short form
        net.reload()
        if not any(cid.startswith(me) for cid in (net.attrs.get("Containers") or {})):
            try:
                net.connect(me)
            except Exception as e:
                if "already exists" not in str(e):   # connected between the check and the call
                    raise
        return net

    @staticmethod
    def _remove_twin(client, name: str) -> None:
        try:
            c = client.containers.get(name)
        except Exception:
            return
        if (c.attrs.get("Config", {}).get("Labels") or {}).get("pqch.twin"):
            c.remove(force=True)
        else:
            raise Refused(409, f"a container named {name} exists and is not a twin")

    # ------------------------------------------------------------- actions
    def _recreate(self, service: str) -> None:
        files = [a for f in self.compose_files for a in ("-f", f)]
        subprocess.run([*self.compose_cmd, "-p", self.project, *files, "up", "-d",
                        "--no-build", "--no-deps", "--force-recreate", "--pull", "never", service],
                       check=True, capture_output=True, text=True, timeout=120)

    @staticmethod
    def _wait_listening(address: str, port: int, timeout_s: float = 30) -> bool:
        end = time.monotonic() + timeout_s
        while time.monotonic() < end:
            try:
                with socket.create_connection((address, port), timeout=2):
                    return True
            except OSError:
                time.sleep(0.5)
        return False

    def apply(self, run_id: str, change_id: str) -> dict:
        _, prop, approval = self.authorize(run_id, change_id)
        t = self._target(prop)
        p = prop["payload"]
        content = p["new_content"]
        if sha256_hex(content.encode()) != p["new_sha256"]:
            raise Refused(409, "the proposed configuration does not match its recorded hash")
        software = self._software(t["service"])
        if not render.is_rendered_shape(content, software):
            raise Refused(403, f"the proposed configuration holds lines the runner does not write for {software}")
        if prop["actor"]["kind"] == "model":
            self._rehearsed(run_id, change_id, p["new_sha256"])
        # What was approved is what is applied: the diff the approver read must be the diff
        # between the rollback and the new content, and the rollback must be what is deployed.
        rollback = p.get("rollback", "")
        if sha256_hex(rollback.encode()) != p.get("rollback_sha256"):
            raise Refused(409, "the proposal's rollback does not match its recorded hash")
        if p.get("diff") != render.diff(rollback, content, t["service"], software):
            raise Refused(409, "the proposal's diff is not the diff between its rollback and its new content")
        client = self.runner._client()
        before = self._container_at(client, t)
        started = utc_now()
        path = render.target_path(self.agency_dir, t["service"], software)
        if not path.exists():
            raise Refused(409, f"service {t['service']} has no configuration rendered from the policy")
        old = path.read_bytes()
        if old != rollback.encode():
            raise Refused(409, "the proposal's rollback is not the configuration now deployed; propose again")
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content)
        os.replace(tmp, path)
        try:
            self._recreate(t["service"])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            # Leave nothing half done: the old file back, and a line in the log saying so.
            path.write_bytes(old)
            self._append_log({"kind": "apply-failed", "run": run_id, "change_id": change_id,
                              "service": t["service"], "restored": True, "at": utc_now(),
                              "error": str(getattr(e, "stderr", e))[-300:]})
            raise Refused(500, f"recreate failed; the previous configuration was put back: "
                               f"{str(getattr(e, 'stderr', e))[-300:]}") from e
        listening = self._wait_listening(t["address"], t["port"])
        if not listening:
            # Compose started a container and the service never listened: the configuration is
            # one the service cannot load. Put the previous file back and bring the service up
            # on it, so a change that cannot start is not left deployed.
            path.write_bytes(old)
            restored = True
            try:
                self._recreate(t["service"])
                restored = self._wait_listening(t["address"], t["port"])
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                restored = False
            self._append_log({"kind": "apply-failed", "run": run_id, "change_id": change_id,
                              "service": t["service"], "restored": True, "listening_after_restore": restored,
                              "at": utc_now(), "error": "the service did not listen on the new configuration"})
            raise Refused(500, "the service did not come up on the new configuration; the previous "
                               "configuration was put back" + ("" if restored else ", and the service is still down"))
        after = self.runner.binding(client, t["address"])
        ended = utc_now()
        entry = {
            "kind": "apply", "run": run_id, "change_id": change_id, "approval_event": approval["id"],
            "service": t["service"], "address": f"{t['address']}:{t['port']}",
            "config": {"path": f"generated/{t['service']}/{render.POLICY_FILE[software]}", "sha256_before": sha256_hex(old),
                       "sha256_after": sha256_hex(content.encode())},
            "containers": [{"before": before["container_id"], "after": after.get("container_id"),
                            "image_digest": after.get("image_digest")}],
            "listening": listening, "started_at": started, "ended_at": ended,
            "duration_ms": ms_between(started, ended),
        }
        self._append_log(entry)
        return entry

    def recreate(self, run_id: str, change_id: str) -> dict:
        """Recreate the service a change was applied to, with nothing changed, to repeat its verdict."""
        events = self._ledger(run_id)
        if not any(e.get("change_id") == change_id and e.get("kind") == "apply" for e in self.log()):
            raise Refused(409, f"change {change_id} was not applied by this runner")
        prop = next(e for e in events if e["type"] == "change.proposed" and e["payload"].get("change_id") == change_id)
        t = self._target(prop)
        client = self.runner._client()
        before = self._container_at(client, t)
        started = utc_now()
        try:
            self._recreate(t["service"])
        except subprocess.CalledProcessError as e:
            raise Refused(500, f"recreate failed: {e.stderr[-300:]}") from e
        listening = self._wait_listening(t["address"], t["port"])
        after = self.runner.binding(client, t["address"])
        ended = utc_now()
        entry = {"kind": "recreate", "run": run_id, "change_id": change_id, "service": t["service"],
                 "address": f"{t['address']}:{t['port']}",
                 "containers": [{"before": before["container_id"], "after": after.get("container_id"),
                                 "image_digest": after.get("image_digest")}],
                 "listening": listening, "started_at": started, "ended_at": ended,
                 "duration_ms": ms_between(started, ended)}
        self._append_log(entry)
        return entry
