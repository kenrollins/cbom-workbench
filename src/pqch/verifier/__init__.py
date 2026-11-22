"""The verifier: whether a change landed, decided by probes, never by a model (spec section 5).

A wire-kex check is a pair of probes and a witness:

- positive — one TLS handshake offering only the groups the check must accept;
- negative — one handshake offering only the groups it must refuse, with any
  protocol version, as a client that would downgrade;
- witness — a tool of a different kind repeating the positive probe: testssl.sh,
  whose own handshakes enumerate the groups the listener accepts. If it finds
  the listener accepting any group outside `must_accept`, the status cannot be
  `enforced`: the pair samples, the witness enumerates.

The probes run through the runner, which records the container at the address
for each. The verdict is bound to what was probed: the address, the container
and its image digest, and the served certificate's fingerprint.

Status, from the spec's table: positive accepted and negative refused,
`enforced`; both accepted, `enabled-not-enforced`; positive refused,
`not-landed`; an error or timeout on any probe, `inconclusive`. Also
`inconclusive`: a probe that started before the event it answers, a container
that is not the one the change was applied to, a container that changed during
a probe, a probe or an apply that names no container at all (nothing equals
nothing is not a binding), output that cannot be read, or a witness that
disagrees with the positive probe or does not list the group the negative probe
negotiated. `inconclusive` is never resolved by inference.

A check that takes a listener back to classical (`policy_intent: none`) accepts
more than the one group it probes for; `may_accept` names the rest. The witness
still enumerates and still lowers: a group on `must_refuse`, or one outside
`must_accept` and `may_accept`, rules out `enforced` whatever the pair said.
"""

from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from pqch.runner.client import RunnerRefused
from pqch.scout.names import TLS_GROUPS, dh_groups

SCHEMA = "pqch.verifier/1"
ACTOR = {"kind": "verifier", "id": "pqch-verifier"}
PEM = re.compile(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.S)
# OpenSSL's spelling of the policy's group names, for -groups.
OPENSSL_GROUP = {"secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521"}


def parse_probe(raw: str) -> dict:
    """One s_client handshake: accepted, refused or error; the group; the certificate's SHA-256."""
    exit_ = re.search(r"PQCH_EXIT=(\d+)", raw)
    code = int(exit_.group(1)) if exit_ else None
    group = (re.search(r"Negotiated TLS1\.3 group: (\S+)", raw)
             or re.search(r"(?:Peer|Server) Temp Key: (?:ECDH|DH), ([^,\s]+)", raw)
             or re.search(r"(?:Peer|Server) Temp Key: ([^,\s]+)", raw))
    name = group.group(1) if group else None
    negotiated = TLS_GROUPS.get(name, name) if name and not name.startswith("<") else None
    cert = None
    m = PEM.search(raw)
    if m:
        try:
            cert = x509.load_pem_x509_certificate(m.group(0).encode()).fingerprint(hashes.SHA256()).hex()
        except ValueError:
            cert = None
    if code == 0 and re.search(r"^New, TLS", raw, re.M):
        result = "accepted"
    elif negotiated:
        # The server chose an offered group and sent its key share; the client gave up later
        # (in TLS 1.2, for instance, when the certificate's curve was not among those offered).
        # The server accepted the group: that is what the probe asks.
        result = "accepted"
    elif re.search(r"alert handshake failure|SSL alert number|no suitable|no shared|wrong version number"
                   r"|unsupported protocol|no protocols available", raw):
        result = "refused"
    else:
        result = "error"
    return {"result": result, "negotiated": negotiated, "cert_sha256": cert, "exit": code}


def parse_witness(raw: bytes) -> set[str]:
    """The groups testssl.sh found the listener accepting."""
    seen: set[str] = set()
    doc = json.loads(raw)
    if not isinstance(doc, list):
        raise ValueError("the testssl.sh output is not a list of findings")
    for e in doc:
        if e["id"] in ("FS_KEMs", "FS_ECDHE_curves", "DH_groups"):
            text = (e.get("finding") or "").strip()
            if not text or text.lower().startswith(("no ", "not ")):
                continue
            if e["id"] == "DH_groups":
                seen |= {name for name, _spelling in dh_groups(text)}     # one phrase is one group
            else:
                seen |= {TLS_GROUPS.get(g, g) for g in text.split()}
    return seen


def _probe_record(name: str, job: dict, parsed: dict) -> dict:
    return {"name": name, "job_id": job.get("job_id"), "tool": job["tool"], "tool_version": job["version"],
            "tool_digest": job["image_digest"],
            "started_at": job["started_at"], "ended_at": job["ended_at"], "result": parsed["result"],
            "negotiated": parsed.get("negotiated"), "raw": job.get("raw"), "raw_sha256": job.get("raw_sha256"),
            "container_id": (job.get("binding") or {}).get("container_id"),
            "image_digest": (job.get("binding") or {}).get("image_digest"),
            "stable": (job.get("binding") or {}).get("stable")}


def parse_ssh_probe(raw: str) -> dict:
    """One SSH connection: accepted when the server agreed to a key exchange, refused when no
    method matched, else error. Authentication is never attempted; it is not the question."""
    # OpenSSH logs "kex: algorithm: (no match)" just before it gives up, which names no algorithm.
    # Output that holds both a refusal and an agreed algorithm (a server's banner can carry either
    # text) says two things at once: it is unreadable, never a refusal and never an acceptance.
    refused = re.search(r"no matching key exchange method found|Unable to negotiate", raw)
    m = re.search(r"kex: algorithm: ([A-Za-z0-9@._-]+)", raw)
    if refused and m:
        return {"result": "error", "negotiated": None, "cert_sha256": None}
    if refused:
        return {"result": "refused", "negotiated": None, "cert_sha256": None}
    if m:
        return {"result": "accepted", "negotiated": m.group(1), "cert_sha256": None}
    return {"result": "error", "negotiated": None, "cert_sha256": None}


def parse_ssh_witness(raw: bytes) -> set[str]:
    """The key exchanges ssh-audit found the server offering, by OpenSSH's names."""
    from pqch.scout.names import SSH_KEX_IGNORE

    doc = json.loads(raw)
    if not isinstance(doc, dict) or not isinstance(doc.get("kex"), list):
        # ssh-audit's JSON always carries the list; without it this is not a reading of the server.
        raise ValueError("no key-exchange list in the ssh-audit output")
    return {k["algorithm"] for k in doc["kex"] if not SSH_KEX_IGNORE.match(k["algorithm"])}


# What reading a tool's output can raise when the output is not what the tool writes on a good day:
# a truncated file, an error message where JSON was expected, JSON of another shape.
UNREADABLE = (ValueError, TypeError, KeyError, AttributeError, IndexError)


def parse(name: str, raw: bytes, check: dict) -> dict:
    """A probe's or the witness's raw output, as the verdict records it. Output that cannot be
    read is an error — hence `inconclusive` — never an exception and never a result."""
    if name == "witness":
        try:
            return read_witness(raw, check)
        except UNREADABLE as e:          # json.JSONDecodeError and UnicodeDecodeError are ValueErrors
            return {"result": "error", "unreadable": f"{type(e).__name__}: {e}"[:200]}
    text = raw.decode(errors="replace")
    return parse_ssh_probe(text) if check.get("kind") == "ssh-kex" else parse_probe(text)


def expected_jobs(check: dict) -> dict[str, tuple[str, dict]]:
    """The three runner jobs a wire-kex check prescribes: profile and parameters, by probe name.

    The verifier runs exactly these; a reader checking a verdict against the runner's log
    expects exactly these.
    """
    if check.get("kind") == "ssh-kex":
        return {"positive": ("ssh-kex-probe", {"kex": ",".join(check["must_accept"])}),
                "negative": ("ssh-kex-probe", {"kex": ",".join(check["must_refuse"])}),
                "witness": ("ssh-targeted", {})}
    groups = lambda names: ":".join(OPENSSL_GROUP.get(g, g) for g in names)  # noqa: E731
    pg = "-postgres" if (check.get("target") or {}).get("protocol") == "postgres" else ""
    jobs = {
        "positive": (f"tls-group-probe{pg}", {"groups": groups(check["must_accept"]), "tls13": "-tls1_3"}),
        "negative": (f"tls-group-probe{pg}", {"groups": groups(check["must_refuse"]), "tls13": ""}),
        "witness": (f"tls-witness{pg}", {}),
    }
    # A TLS 1.3 client offering only classical groups is refused outright by a server that
    # requires the hybrid group; it never falls back to TLS 1.2. So the pair cannot see TLS 1.2
    # key establishment — RSA key transport above all — and a `require` check probes it apart.
    if check.get("refuse_tls12"):
        jobs["legacy"] = (f"tls-legacy-probe{pg}", {})
    return jobs


def read_witness(raw: bytes, check: dict) -> dict:
    """The witness's raw output as the verdict records it."""
    accepted = parse_ssh_witness(raw) if check.get("kind") == "ssh-kex" else parse_witness(raw)
    ok = all(g in accepted for g in check["must_accept"])
    return {"result": "accepted" if ok else "refused",
            "negotiated": ",".join(sorted(accepted & set(check["must_accept"]))) or None,
            "accepted_groups": sorted(accepted)}


def decide(check: dict, parsed: dict[str, dict]) -> tuple[str, list[str], list[str]]:
    """Status, the groups the witness found beyond `must_accept`, and any disagreement, from
    the three parsed probes alone. Pure: the same raw outputs always give the same answer."""
    reasons = []
    status = status_of(parsed["positive"]["result"], parsed["negative"]["result"])
    if parsed["witness"]["result"] == "error":
        status = "inconclusive"
    elif status != "inconclusive" and parsed["witness"]["result"] != parsed["positive"]["result"]:
        reasons.append(f"the witness ({parsed['witness']['result']}) disagrees with the positive probe "
                       f"({parsed['positive']['result']})")
    # A negative probe that negotiated something the witness does not find accepted contradicts it:
    # one of the two misread the listener. The witness may lower a verdict, never raise one, so a
    # contradiction in this direction is not settled by either; it is inconclusive, with the reason.
    neg = parsed["negative"]
    w_groups = set(parsed["witness"].get("accepted_groups", []))
    if neg["result"] == "accepted" and parsed["witness"]["result"] != "error" and w_groups \
            and neg.get("negotiated") and neg["negotiated"] not in w_groups:
        reasons.append(f"the negative probe negotiated {neg['negotiated']}, which the witness does not find accepted")
        status = "inconclusive"
    # Enumeration beats sampling: if the witness found the listener accepting any group the
    # check does not name as acceptable, the change is not enforced, whatever the pair said.
    also = sorted(w_groups - set(check["must_accept"]))
    if check.get("policy_intent") == "none":
        # Back to classical: the check probes for one classical group and the listener rightly
        # accepts the others, so those are not extras. A group on `must_refuse` always is: the
        # negative probe was refused and the witness still lists it, and the witness may lower.
        # Where the check names what the listener may keep (`may_accept`), anything else the
        # witness lists is an extra too; a check written before it did is held to `must_refuse`.
        refuse, may = set(check["must_refuse"]), set(check.get("may_accept", []))
        # The witness names a finite-field group it knows only by size `DH-<bits>`; where the check
        # lets the listener keep finite-field groups at all, that is one of them.
        ffdh = any(g.startswith("ffdhe") for g in may)
        extras = [g for g in also if g in refuse or ("may_accept" in check and g not in may
                                                     and not (ffdh and re.fullmatch(r"DH-\d+", g)))]
    else:
        extras = also
    if extras and status == "enforced":
        status = "enabled-not-enforced"
    legacy = parsed.get("legacy")
    if legacy is not None:
        if legacy["result"] == "error":
            status = "inconclusive"
        elif legacy["result"] == "accepted":
            also = sorted(set(also) | {"TLS 1.2"})
            if status == "enforced":
                status = "enabled-not-enforced"
    return status, also, reasons


def status_of(pos: str, neg: str) -> str:
    if "error" in (pos, neg):
        return "inconclusive"
    if pos == "refused":
        return "not-landed"
    return "enforced" if neg == "refused" else "enabled-not-enforced"


def verify(client, scope_hash: str, check: dict, *, change_id: str, after_event: dict,
           expect: dict, read_raw, hardware: str) -> dict:
    """Run the check. `expect` is {container_id, image_digest}: what the change was applied to.

    `read_raw(job)` returns a job's raw output, checked against its recorded hash.
    """
    t = check["target"]
    target = {"host": t["host"], "port": t["port"]}
    jobs = expected_jobs(check)
    reasons: list[str] = []
    results: dict[str, dict] = {}
    if not expect.get("container_id"):
        reasons.append("the change names no container it was applied to; the verdict cannot be bound to one")

    def run(name):
        profile, params = jobs[name]
        try:
            return name, client.job(profile, target, scope_hash, params or None)
        except RunnerRefused as e:
            return name, {"refused": f"{e.code}: {e.reason}"}

    with ThreadPoolExecutor(len(jobs)) as pool:
        for name, job in pool.map(run, jobs):
            results[name] = job

    probes, parsed = [], {}
    for name in jobs:
        job = results[name]
        if "refused" in job:
            reasons.append(f"{name}: the runner refused the job ({job['refused']})")
            parsed[name] = {"result": "error"}
            continue
        if job["status"] != "ok" or not job.get("raw"):
            reasons.append(f"{name}: scan {job['status']}")
            parsed[name] = {"result": "error"}
        else:
            try:
                parsed[name] = parse(name, read_raw(job), check)
            except (*UNREADABLE, OSError) as e:   # the stored output is missing, or not what its record says
                parsed[name] = {"result": "error", "unreadable": f"{type(e).__name__}: {e}"[:200]}
            if parsed[name].get("unreadable"):
                reasons.append(f"{name}: the output could not be read ({parsed[name]['unreadable']}); "
                               f"the tool exited {job.get('exit_code')}")
        rec = _probe_record(name, job, parsed[name])
        if name == "witness" and "accepted_groups" in parsed[name]:
            rec["accepted_groups"] = parsed[name]["accepted_groups"]
        probes.append(rec)
        if job["started_at"] <= after_event["ts"]:
            reasons.append(f"{name}: started at {job['started_at']}, not after {after_event['type']} at {after_event['ts']}")
        b = job.get("binding") or {}
        # Bound to a container, or not bound: an apply that named no container and a probe that
        # found none agree with each other and say nothing about what was probed.
        if not b.get("container_id") or b.get("error"):
            reasons.append(f"{name}: no container was identified at {t['host']} for the probe"
                           + (f" ({b['error']})" if b.get("error") else ""))
        elif b.get("container_id") != expect.get("container_id"):
            reasons.append(f"{name}: the container at {t['host']} is {str(b.get('container_id'))[:12]}, "
                           f"not {str(expect.get('container_id'))[:12]}, the one the change was applied to")
        elif b.get("image_digest") != expect.get("image_digest"):
            reasons.append(f"{name}: the container runs image {b.get('image_digest')}, not {expect.get('image_digest')}")
        if not b.get("stable", False):
            reasons.append(f"{name}: the container at the address changed during the probe")

    status, also, disagreement = decide(check, parsed)
    reasons += disagreement
    if reasons:
        status = "inconclusive"
    cert = parsed["positive"].get("cert_sha256") or parsed["negative"].get("cert_sha256")
    first = next((r for r in probes if r["container_id"]), {})
    meets = (status in ("enforced", "enabled-not-enforced")) if check["intent"] == "enable" else status == "enforced"
    return {
        "schema": SCHEMA,
        "change_id": change_id,
        "kind": check["kind"],
        "intent": check["intent"],
        "status": status,
        "meets_intent": meets,
        "probes": probes,
        "binding": {"address": f"{t['host']}:{t['port']}", "container_id": first.get("container_id"),
                    "image_digest": first.get("image_digest"), "cert_fingerprint": cert},
        "after_event": after_event["id"],
        "durable": "untested",
        "also_accepts": also,
        "reasons": reasons,
        "hardware": hardware,
    }
