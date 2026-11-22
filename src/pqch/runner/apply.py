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
import threading
import time
from pathlib import Path

from pqch import varmode
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
        # Two requests for the same change both pass the checks until one has written its log line;
        # everything that changes the estate runs one at a time.
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ log
    def log(self) -> list[dict]:
        if not self.log_path.exists():
            return []
        return [json.loads(line) for line in self.log_path.read_text().splitlines() if line.strip()]

    def _append_log(self, entry: dict) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a") as f:
            varmode.private(self.log_path)
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
        res = verify_signed(events, key["public_key_pem"].encode(), known=self.signer.record(run_id),
                            require_alg=os.environ.get("PQCH_CHECKPOINT_ALG") or None)
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
        if os.environ.get("PQCH_SEPARATION_OF_DUTIES") == "1":
            # ADR-0008: the one who asked for the change does not approve it, and an approval counts
            # only with the approver role recorded on it. The requester is whoever recorded the policy
            # (`policy.changed`) or proposed the change as a person; a rule's proposal has no requester.
            who = approval["payload"].get("by")
            requesters = {e["payload"].get("by") for e in events if e["type"] == "policy.changed"} | \
                {e["actor"]["id"] for e in proposed if e["actor"]["kind"] == "human"}
            requesters.discard(None)
            if who in requesters:
                raise Refused(403, f"change {change_id} was requested and approved by the same person ({who}); separation of duties refuses it")
            if approval["payload"].get("role") != "approver":
                raise Refused(403, f"the approval of {change_id} carries no approver role; this deployment requires one")
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
        from pqch import scope as scope_mod
        why = scope_mod.authorization_refusal(scope, now=self.runner._now(),
                                              require_roe=os.environ.get("PQCH_REQUIRE_ROE") == "1",
                                              required=os.environ.get("PQCH_REQUIRE_AUTHORIZATION") == "1")
        if why:
            raise Refused(403, why)
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
        if not run_id.isalnum() or not change_id.isalnum():      # they become a label filter
            raise Refused(400, "bad run or change id")
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

    @staticmethod
    def _write(path: Path, data: bytes) -> None:
        """Replace a policy file whole: a crash mid-write leaves the old file or the new one, never
        an empty or a partial one for the next recreate to start a service from."""
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)

    @staticmethod
    def _why(e: Exception) -> str:
        """Why Compose failed, in words: its stderr when it wrote any, else the exception itself
        (a timeout has no stderr to speak of, and bytes when it has)."""
        err = getattr(e, "stderr", None)
        if isinstance(err, bytes):
            err = err.decode(errors="replace")
        return ((err or "").strip() or str(e))[-300:]

    @staticmethod
    def _refused(code: int, reason: str, entry: dict) -> Refused:
        """A refusal after the estate was touched: it carries the log line, so the caller can put on
        the ledger what state the estate was left in."""
        r = Refused(code, reason)
        r.entry = entry
        return r

    def _bound(self, client, address: str) -> dict:
        """The container at the address after a recreate. Docker lists a new container on its
        network a moment after Compose returns; a lookup that finds none is asked again, briefly."""
        b = self.runner.binding(client, address)
        for _ in range(4):
            if b.get("container_id"):
                break
            time.sleep(0.5)
            b = self.runner.binding(client, address)
        return b

    def _put_back(self, client, path: Path, old: bytes, service: str, endpoints: list[tuple[str, int]],
                  entry: dict) -> dict:
        """The previous file back, and the service up on it: whatever Compose did before it failed
        or ran out of time, the container that serves afterwards was started from the file on disk.
        The entry says what is true afterwards — whether the recreate on the old file worked, whether
        the service listens, and which container holds the address — and goes in the log."""
        self._write(path, old)
        entry["restored"] = True
        try:
            self._recreate(service)
            entry["listening_after_restore"] = all(self._wait_listening(a, p) for a, p in endpoints)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            entry["listening_after_restore"] = False
            entry["restore_error"] = self._why(e)
        after = self.runner.binding(client, endpoints[0][0]) if endpoints else {}
        entry["container_after_restore"] = after.get("container_id")
        entry["at"] = utc_now()
        self._append_log(entry)
        return entry

    def apply(self, run_id: str, change_id: str) -> dict:
        with self._lock:      # one change to the estate at a time: check, write, recreate and log together
            return self._apply(run_id, change_id)

    def _apply(self, run_id: str, change_id: str) -> dict:
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
        self._write(path, content.encode())
        failure, listening = None, False
        try:
            self._recreate(t["service"])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            # Compose failed, or ran out of time — possibly after it had already replaced the
            # container, which would then be serving the new file.
            failure = f"recreate failed: {self._why(e)}"
        if failure is None:
            listening = self._wait_listening(t["address"], t["port"])
            if not listening:
                # Compose started a container and the service never listened: the configuration is
                # one the service cannot load.
                failure = "the service did not come up on the new configuration (it never listened)"
        if failure:
            # Leave nothing half done, in either case: the previous file back and the service up on
            # it, so neither a change that cannot start nor one whose apply was called failed is
            # left serving; and a line in the log saying what is true now.
            entry = self._put_back(client, path, old, t["service"], [(t["address"], t["port"])], {
                "kind": "apply-failed", "run": run_id, "change_id": change_id, "service": t["service"],
                "address": f"{t['address']}:{t['port']}", "error": failure,
                "config": {"sha256_restored": sha256_hex(old), "sha256_refused": sha256_hex(content.encode())},
                "container_before": before["container_id"], "started_at": started})
            raise self._refused(500, f"{failure}; the previous configuration was put back"
                                + (", and the service is up on it" if entry["listening_after_restore"]
                                   else ", and the service is still down"), entry)
        after = self._bound(client, t["address"])
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
        if not after.get("container_id"):
            # Applied and listening, but Docker named no container at the address. Said, not
            # guessed: the verifier binds a verdict to a container and will not bind one to nothing.
            entry["unbound"] = after.get("error") or f"no container holds {t['address']}"
        self._append_log(entry)
        return entry

    def reset(self, run_id: str) -> dict:
        """Put the owned estate back to its starting state: every policy-managed service's file from
        agency/baseline/, then the service recreated from it. Only on a reset run whose ledger verifies
        and records a person's request under a signed checkpoint, once per run."""
        with self._lock:
            return self._reset(run_id)

    def authorize_reset(self, run_id: str) -> tuple[list[dict], dict, dict]:
        """The reset request and its approval, or a refusal saying what is missing. A reset rewrites
        managed configuration, so it passes the same gate as an apply: a person's request, a later
        `approval.granted` naming that request, no denial, a signed checkpoint over the approval,
        and under separation of duties (ADR-0008) an approver's role on an approval given by
        someone other than the one who asked."""
        events = self._ledger(run_id)
        if events[0]["type"] != "run.started" or events[0]["payload"].get("kind") != "reset":
            raise Refused(409, f"run {run_id} is not a reset run")
        req = [e for e in events if e["type"] == "reset.requested"]
        if len(req) != 1:
            raise Refused(409, f"run {run_id} records {len(req)} reset requests; need exactly one")
        request = req[0]
        later = [e for e in events if e["seq"] > request["seq"] and e["payload"].get("change_id") == request["id"]]
        if any(e["type"] == "approval.denied" for e in later):
            raise Refused(409, f"the reset requested in run {run_id} was denied")
        approvals = [e for e in later if e["type"] == "approval.granted"]
        if not approvals:
            raise Refused(409, f"the reset requested in run {run_id} has no approval")
        approval = approvals[0]
        if os.environ.get("PQCH_SEPARATION_OF_DUTIES") == "1":
            who = approval["payload"].get("by")
            if who in {request["payload"].get("by"), request["actor"]["id"]}:
                raise Refused(403, f"the reset was requested and approved by the same person ({who}); "
                                   "separation of duties refuses it")
            if approval["payload"].get("role") != "approver":
                raise Refused(403, "the approval of the reset carries no approver role; this deployment requires one")
        if not any(e["type"] == "checkpoint.signed" and e["payload"]["through_seq"] >= approval["seq"] for e in events):
            raise Refused(409, "no signed checkpoint covers the approval of the reset yet")
        if any(e.get("kind") == "reset" and e.get("run") == run_id for e in self.log()):
            raise Refused(409, f"run {run_id} has already reset the estate")
        return events, request, approval

    def _reset(self, run_id: str) -> dict:
        _, request, approval = self.authorize_reset(run_id)
        scope, _ = self.runner.scope()
        if not scope.get("owned"):
            raise Refused(403, "the scope is not an owned estate; it cannot be reset")
        from pqch import scope as scope_mod
        why = scope_mod.authorization_refusal(scope, now=self.runner._now(),
                                              require_roe=os.environ.get("PQCH_REQUIRE_ROE") == "1",
                                              required=os.environ.get("PQCH_REQUIRE_AUTHORIZATION") == "1")
        if why:                                       # a reset is a change to the estate like any other
            raise Refused(403, why)
        import yaml

        compose = yaml.safe_load(Path(self.compose_files[0]).read_text())
        client = self.runner._client()
        # Everything is checked before anything is written: every managed service has a starting
        # state the runner would write for its software, and whatever holds its address is the
        # estate's own container (ADR-0003: the runner changes only the estate it built).
        todo = []
        for service, d in sorted((compose.get("services") or {}).items()):
            pol = (d.get("x-pqch") or {}).get("policy")
            if not pol or not SERVICE.match(service):
                continue
            software = pol.get("software")
            if software not in render.SHAPES:
                raise Refused(403, f"service {service} declares no policy file the runner can write")
            path = render.target_path(self.agency_dir, service, software)
            base = self.agency_dir / "baseline" / service / path.name
            if not base.exists():
                raise Refused(409, f"no starting state for {service}: {base} is missing")
            new = base.read_bytes()
            try:
                shaped = render.is_rendered_shape(new.decode(), software)
            except UnicodeDecodeError:
                shaped = False
            if not shaped:
                raise Refused(403, f"the starting state for {service} holds lines the runner does not write for {software}")
            eps = [e for e in scope["endpoints"] if e.get("service") == service]
            before = None
            if eps:
                before = self.runner.binding(client, eps[0]["host"]).get("container_id")
                if before:          # a service that is down has no container to check, and is brought up
                    self._container_at(client, {"service": service, "address": eps[0]["host"], "port": eps[0]["port"]})
            todo.append((service, path, new, eps, before))
        started, done = utc_now(), []
        for service, path, new, eps, before in todo:
            old = path.read_bytes() if path.exists() else b""
            self._write(path, new)
            try:
                self._recreate(service)
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                # This service's previous file back and the service up on it; the services already
                # reset stay reset, and the log says which they are.
                entry = self._put_back(client, path, old, service, [(x["host"], x["port"]) for x in eps], {
                    "kind": "reset-failed", "run": run_id, "request_event": request["id"],
                    "approval_event": approval["id"], "services": done, "failed": service,
                    "error": f"recreate of {service} failed: {self._why(e)}", "started_at": started})
                raise self._refused(500, f"{entry['error']}; its previous configuration was put back"
                                    + (", and the service is up on it" if entry["listening_after_restore"]
                                       else ", and the service is still down")
                                    + f"; {len(done)} service(s) before it were reset", entry) from e
            listening = all(self._wait_listening(e["host"], e["port"]) for e in eps)
            after = self._bound(client, eps[0]["host"]).get("container_id") if eps else None
            done.append({"service": service, "file": str(path.relative_to(self.agency_dir)),
                         "before_sha256": sha256_hex(old), "after_sha256": sha256_hex(new), "changed": old != new,
                         "containers": [{"before": before, "after": after}],
                         "listening": listening})
        ended = utc_now()
        entry = {"kind": "reset", "run": run_id, "request_event": request["id"], "approval_event": approval["id"],
                 "services": done, "started_at": started, "ended_at": ended,
                 "duration_ms": ms_between(started, ended)}
        self._append_log(entry)
        return entry

    def recreate(self, run_id: str, change_id: str) -> dict:
        """Recreate the service a change was applied to, with nothing changed, to repeat its verdict."""
        with self._lock:
            return self._recreate_applied(run_id, change_id)

    def _recreate_applied(self, run_id: str, change_id: str) -> dict:
        events = self._ledger(run_id)
        log = self.log()
        if not any(e.get("change_id") == change_id and e.get("kind") == "apply" for e in log):
            raise Refused(409, f"change {change_id} was not applied by this runner")
        prop = next((e for e in events if e["type"] == "change.proposed" and e["payload"].get("change_id") == change_id), None)
        if prop is None:
            raise Refused(409, f"run {run_id} holds no proposal for change {change_id}")
        # A recreate repeats a verdict, so it follows the ledger like the apply did: the apply is on
        # the record under a signed checkpoint, and every recreate this runner already did for the
        # change is on the record too. The socket alone cannot restart the service again and again.
        applied = [e for e in events if e["type"] == "change.applied" and e["payload"].get("change_id") == change_id]
        if not applied or not any(e["type"] == "checkpoint.signed" and e["payload"]["through_seq"] >= applied[0]["seq"]
                                  for e in events):
            raise Refused(409, f"the ledger does not record the apply of {change_id} under a signed checkpoint yet")
        done = sum(1 for e in log if e.get("kind") == "recreate" and e.get("change_id") == change_id and e.get("run") == run_id)
        recorded = sum(1 for e in events if e["type"] == "service.recreated" and e["payload"].get("change_id") == change_id)
        if done > recorded:
            raise Refused(409, f"this runner recreated the service for {change_id} {done} time(s) and the ledger "
                               f"records {recorded}; record the last one (it is in the runner's log) before another")
        t = self._target(prop)
        client = self.runner._client()
        before = self._container_at(client, t)
        started = utc_now()
        try:
            self._recreate(t["service"])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            # Nothing to put back: the file was not changed. Compose may or may not have replaced
            # the container; the log says what holds the address and whether it listens.
            after = self.runner.binding(client, t["address"])
            entry = {"kind": "recreate-failed", "run": run_id, "change_id": change_id, "service": t["service"],
                     "address": f"{t['address']}:{t['port']}", "error": f"recreate failed: {self._why(e)}",
                     "container_before": before["container_id"], "container_after": after.get("container_id"),
                     "listening": self._wait_listening(t["address"], t["port"], timeout_s=5),
                     "started_at": started, "at": utc_now()}
            self._append_log(entry)
            raise self._refused(500, entry["error"], entry) from e
        listening = self._wait_listening(t["address"], t["port"])
        after = self._bound(client, t["address"])
        ended = utc_now()
        entry = {"kind": "recreate", "run": run_id, "change_id": change_id, "service": t["service"],
                 "address": f"{t['address']}:{t['port']}",
                 "containers": [{"before": before["container_id"], "after": after.get("container_id"),
                                 "image_digest": after.get("image_digest")}],
                 "listening": listening, "started_at": started, "ended_at": ended,
                 "duration_ms": ms_between(started, ended)}
        self._append_log(entry)
        return entry
