"""Build R4's items: findings that disagree about one asset, each from a configuration that was
started and observed. The label is what the wire showed, or — for `cannot-tell` — the fact that two
builds showing the same evidence have different truths. No model.

    uv run python spikes/s3/build_r4.py
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

import lab
from build_r5 import SOFTWARE
from scenarios_r5 import LOC, NG_HEAD, PG_BASE, RSA, SNI, SSH_BASE, N, P, S, ng

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
OBS = HERE / "observations"
EP = {"nginx": 443, "postgres": 5432, "sshd": 22}
ITEMS: list[dict] = []
LABELS: list[dict] = []


def now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def cert_info(name: str) -> dict:
    c = x509.load_pem_x509_certificate((lab.ensure_pki() / f"{name}.crt").read_bytes())
    key = c.public_key()
    alg = type(key).__name__.replace("PublicKey", "").replace("_", "")
    # The class is ECPublicKey in this cryptography release; the first build mapped only
    # "EllipticCurve" and so called one EC key ML-DSA-65 (item r4-03, caught by the development run).
    return {"sha256": c.fingerprint(hashes.SHA256()).hex(), "key": {"RSA": "RSA", "EC": "ECDSA", "EllipticCurve": "ECDSA"}.get(alg, "ML-DSA-65"),
            "key_bits": getattr(key, "key_size", None)}


def subject(service: str, sni: str | None = None, port: int | None = None, host: str = lab.IP) -> dict:
    s = {"kind": "endpoint", "host": host, "port": port or EP[service], "protocol": "ssh" if service == "sshd" else "tls"}
    if sni:
        s["sni"] = sni
    return s


def wire_cert(service: str, obs: dict, **kw) -> dict:
    c = obs["cert"]
    return {"layer": "wire", "tool": "openssl s_client 3.5", "observed_at": now(), "subject": subject(service, **kw),
            "statement": f"the listener serves a certificate with a {c['key_algorithm']} key of {c['bits']} bits, subject CN {c['cn']}, SHA-256 {c['sha256'][:16]}…"}


def wire_groups(service: str, obs: dict, **kw) -> dict:
    parts = []
    if obs["tls13"]:
        parts.append("TLS 1.3 accepted with groups " + (", ".join(obs["tls13_groups"]) or "none of those offered"))
    else:
        parts.append("TLS 1.3 refused")
    if obs["tls12"]:
        parts.append("TLS 1.2 accepted with groups " + (", ".join(obs["tls12_groups"]) or "none of those offered")
                     + ("; RSA key transport accepted" if obs["rsa_key_transport"] else ""))
    else:
        parts.append("TLS 1.2 refused")
    return {"layer": "wire", "tool": "openssl s_client 3.5, one group per handshake", "observed_at": now(),
            "subject": subject(service, **kw), "statement": "; ".join(parts)}


def wire_kex(obs: dict) -> dict:
    return {"layer": "wire", "tool": "ssh-audit 3.9.0", "observed_at": now(), "subject": subject("sshd"),
            "statement": "key-exchange algorithms offered: " + ", ".join(k for k in obs["kex"] if not k.startswith(("ext-info", "kex-strict")))}


def cfg(path: str, text: str, needle: str, **extra) -> dict:
    """A config-layer finding: the line of `path` that contains `needle`."""
    n = next(i for i, ln in enumerate(text.splitlines(), 1) if needle in ln)
    return {"layer": "config", "tool": "configuration scan", "subject": {"kind": "file", "path": path, "line": n},
            "statement": text.splitlines()[n - 1].strip(), **extra}


def host_file(path: str, statement: str, **extra) -> dict:
    return {"layer": "host", "tool": "file in the running image", "subject": {"kind": "file", "path": path}, "statement": statement, **extra}


def save(iid: str, tag: str, raw: str) -> dict:
    (OBS / f"{iid}-{tag}.txt").write_text(raw)
    return {"observation": f"observations/{iid}-{tag}.txt", "sha256": lab.sha256(raw)}


def add(kind: str, service: str, asset: str, findings: list[dict], in_force: str, reason: str | None, evidence: dict) -> None:
    iid = f"r4-{len(ITEMS) + 1:02d}"
    ITEMS.append({"id": iid, "role": "R4", "service": SOFTWARE[service], "asset": asset, "findings": findings})
    LABELS.append({"id": iid, "label": {"in_force": in_force, "reason": reason}, "kind": kind, "evidence": evidence})
    print(f"ok    {iid}  {kind:<16} {in_force} / {reason}", flush=True)


def start_obs(service: str, files: dict, iid_tag: str, **kw) -> tuple[dict, dict]:
    lab.start(service, files)
    obs, raw = lab.observe(service, **kw)
    return obs, save(f"r4-{len(ITEMS) + 1:02d}", iid_tag, raw)


def ngcert(name: str, extra: str = "") -> str:
    return ng(f"        ssl_certificate     /etc/nginx/tls/{name}.crt;\n        ssl_certificate_key /etc/nginx/tls/{name}.key;\n" + extra)


# ------------------------------------------------------------------ not-served: a certificate file no listener serves
def not_served() -> None:
    for service, served, unserved in (("nginx", "rsa2048", "rsa1024-2019"), ("nginx", "ec256", "rsa2048"), ("nginx", "rsa3072", "ec384"),
                                      ("nginx", "mldsa65", "rsa2048"), ("postgres", "ec256", "rsa2048"), ("postgres", "rsa2048", "rsa1024-2019")):
        if service == "nginx":
            d, files, kw = "/etc/nginx/tls", {N: ngcert(served, "        ssl_protocols TLSv1.3;\n" if served == "mldsa65" else "")}, {"sni": SNI}
        else:
            d, files, kw = "/etc/pg/tls", {P: f"listen_addresses = '*'\nssl = on\nssl_cert_file = '/etc/pg/tls/{served}.crt'\nssl_key_file = '/etc/pg/tls/{served}.key'\n"}, {}
        obs, ev = start_obs(service, files, "obs", **kw)
        s, u = cert_info(served), cert_info(unserved)
        assert obs["cert"]["sha256"] == s["sha256"] != u["sha256"], (served, obs["cert"])
        add("not-served", service, f"the certificate presented by {lab.IP}:{EP[service]}",
            [host_file(f"{d}/{unserved}.crt", f"a certificate with a {u['key']} key of {u['key_bits']} bits, SHA-256 {u['sha256'][:16]}…"),
             wire_cert(service, obs, **kw)], "wire", "not-served", {**ev, "served_file": f"{d}/{served}.crt", "served_sha256": s["sha256"]})


# ------------------------------------------------------------------ overridden: a line that loses to another
def overridden() -> None:
    from scenarios_r5 import SCENARIOS
    sc = {s["id"]: s for s in SCENARIOS}
    clean = lambda s: {p: t.replace("  <<CAUSE", "") for p, t in s["files"].items()}  # noqa: E731
    for sid, path, needle, asset in (
            ("n03", N, "    ssl_ecdh_curve X25519;", "the key-exchange groups accepted"),
            ("s02", S, "KexAlgorithms diffie-hellman-group14-sha256", "the key-exchange algorithms offered"),
            ("p02", P, "ssl_groups = 'X25519'", "the key-exchange groups accepted"),
            ("s03", S, "KexAlgorithms curve25519-sha256", "the key-exchange algorithms offered"),
            ("s05", "/etc/ssh/sshd_config.d/10-kex.conf", "KexAlgorithms diffie-hellman-group14-sha256", "the key-exchange algorithms offered")):
        s = sc[sid]
        service, files = s["service"], clean(s)
        kw = {"sni": s["sni"]} if s.get("sni") else {}
        obs, ev = start_obs(service, files, "obs", **kw)
        wire = wire_kex(obs) if service == "sshd" else wire_groups(service, obs, **kw)
        claimed = re.split(r"[ =]+", needle.strip().rstrip(";"))[-1].strip("'")
        seen = obs["kex"] if service == "sshd" else obs["tls13_groups"]
        assert claimed not in seen, f"{sid}: the losing line's value {claimed} is in force: {seen}"
        # Both lines are shown: the one that loses and the one that takes effect. Without the second,
        # nothing in the evidence would tell an override from a stale file.
        win_path, win_line = next((pth, ln.replace("  <<CAUSE", "")) for pth, t in s["files"].items() for ln in t.splitlines() if ln.endswith("  <<CAUSE"))
        add("overridden", service, f"{asset} by {lab.IP}:{EP[service]}",
            [cfg(path, files[path], needle), cfg(win_path, files[win_path], win_line.strip()), wire], "wire", "overridden", ev)


# ------------------------------------------------------------------ default-applies: a commented line, and the default
def default_applies() -> None:
    cases = (
        ("nginx", {N: ng(RSA + "        # ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519:prime256v1;\n")}, N, "# ssl_protocols TLSv1.3;",
         "the TLS versions accepted", lambda o: o["tls12"]),
        ("sshd", {S: SSH_BASE.format("#KexAlgorithms curve25519-sha256\n")}, S, "#KexAlgorithms curve25519-sha256",
         "the key-exchange algorithms offered", lambda o: "mlkem768x25519-sha256" in o["kex"]),
        ("postgres", {P: PG_BASE + "#ssl_groups = 'X25519MLKEM768'\n"}, P, "#ssl_groups = 'X25519MLKEM768'",
         "the key-exchange groups accepted", lambda o: "X25519MLKEM768" not in o["tls13_groups"] and "secp256r1" in o["tls13_groups"]),
        ("nginx", {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        # ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n")}, N, "# ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;",
         "key establishment in TLS 1.2", lambda o: o["rsa_key_transport"]),
    )
    for service, files, path, needle, asset, check in cases:
        kw = {"sni": SNI} if service == "nginx" else {}
        obs, ev = start_obs(service, files, "obs", **kw)
        assert check(obs), (needle, obs)
        wire = wire_kex(obs) if service == "sshd" else wire_groups(service, obs, **kw)
        add("default-applies", service, f"{asset} by {lab.IP}:{EP[service]}", [cfg(path, files[path], needle), wire], "wire", "default-applies", ev)


# ------------------------------------------------------------------ stale-file: the file changed, the process did not
def started_at() -> str:
    return lab.sh("docker", "inspect", "-f", "{{.State.StartedAt}}", lab.NAME).strip()[:19] + "Z"


def put(path: str, text: str) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        f = Path(tmp) / Path(path).name
        f.write_text(text)
        lab.sh("docker", "cp", str(f), f"{lab.NAME}:{path}")
    return now()


STALE = (
    ("nginx", N, ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519:prime256v1;\n"),
     ng(RSA + "        ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519MLKEM768;\n"), "ssl_ecdh_curve X25519MLKEM768;", "the key-exchange groups accepted"),
    ("nginx", N, ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519;\n"),
     ng(RSA + "        ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519;\n"), "ssl_protocols TLSv1.3;", "the TLS versions accepted"),
    ("sshd", S, SSH_BASE.format("KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n"),
     SSH_BASE.format("KexAlgorithms mlkem768x25519-sha256\n"), "KexAlgorithms mlkem768x25519-sha256", "the key-exchange algorithms offered"),
    ("postgres", P, PG_BASE + "ssl_groups = 'X25519:prime256v1'\n", PG_BASE + "ssl_groups = 'X25519MLKEM768'\n",
     "ssl_groups = 'X25519MLKEM768'", "the key-exchange groups accepted"),
)


def stale_file() -> None:
    for service, path, a, b, needle, asset in STALE:
        kw = {"sni": SNI} if service == "nginx" else {}
        lab.start(service, {path: a})
        t0 = started_at()
        time.sleep(2)
        t1 = put(path, b)
        obs, raw = lab.observe(service, **kw)
        ev = save(f"r4-{len(ITEMS) + 1:02d}", "obs", raw)
        hybrid = "mlkem768x25519-sha256" in obs["kex"] if service == "sshd" else ("X25519MLKEM768" in obs["tls13_groups"] and not obs["tls12"]) \
            if "curve" in needle or "groups" in needle else not obs["tls12"]
        assert not hybrid, f"the new file took effect without a restart: {obs}"
        wire = wire_kex(obs) if service == "sshd" else wire_groups(service, obs, **kw)
        add("stale-file", service, f"{asset} by {lab.IP}:{EP[service]}",
            [cfg(path, b, needle, file_modified_at=t1), wire,
             {"layer": "host", "tool": "process table", "subject": {"kind": "process", "service": service}, "statement": f"the service's process started at {t0} and has not been restarted or reloaded"}],
            "wire", "stale-file", {**ev, "process_started_at": t0, "file_replaced_at": t1})


# ------------------------------------------------------------------ tool-limit
def tool_limit() -> None:
    s2 = ROOT / "spikes/s2/results/amd64"
    theia = (s2 / "theia-mldsa.txt").read_text()
    err = next(ln for ln in theia.splitlines() if "unknown algorithm" in ln)
    tj = {e["id"]: e.get("finding", "") for e in json.loads((s2 / "testssl/C3.json").read_text())}
    add("tool-limit", "nginx", "the certificate presented by 172.16.106.40:443",
        [{"layer": "host", "tool": "cbomkit-theia 1.1.2", "subject": {"kind": "file", "image": "pqch-s2/mldsa", "path": "/etc/nginx/tls/c.pem"},
          "statement": "no certificate component reported for this file; the tool logged: " + err.split("msg=")[-1][:120]},
         {"layer": "wire", "tool": "testssl.sh 3.2.4", "subject": {"kind": "endpoint", "host": "172.16.106.40", "port": 443, "protocol": "tls"},
          "statement": f"the listener serves a certificate: key {tj['cert_keySize']}, signature algorithm {tj['cert_signatureAlgorithm']}"}],
        "wire", "tool-limit", {"recorded_in": ["spikes/s2/results/amd64/theia-mldsa.txt", "spikes/s2/results/amd64/testssl/C3.json"],
                               "sha256": [hashlib.sha256((s2 / "theia-mldsa.txt").read_bytes()).hexdigest(), hashlib.sha256((s2 / "testssl/C3.json").read_bytes()).hexdigest()]})
    fx = ROOT / "tests/fixtures"
    comps = json.loads((fx / "theia-bastion.json").read_text()).get("components") or []
    audit = json.loads((fx / "ssh-audit-bastion.json").read_text())
    assert not any("25519" in json.dumps(c) for c in comps) and any(k["algorithm"] == "ssh-ed25519" for k in audit["key"])
    add("tool-limit", "sshd", "the Ed25519 host key of 172.16.106.21:22",
        [{"layer": "host", "tool": "cbomkit-theia 1.1.2", "subject": {"kind": "file", "image": "pqch-agency/bastion", "path": "/etc/ssh/ssh_host_ed25519_key"},
          "statement": f"no component reported for this file; the image's CBOM holds {len(comps)} components, none of them Ed25519"},
         {"layer": "wire", "tool": "ssh-audit 3.9.0", "subject": {"kind": "endpoint", "host": "172.16.106.21", "port": 22, "protocol": "ssh"},
          "statement": "host key algorithms offered: " + ", ".join(sorted({k["algorithm"] for k in audit["key"]}))}],
        "wire", "tool-limit", {"recorded_in": ["tests/fixtures/theia-bastion.json", "tests/fixtures/ssh-audit-bastion.json"]})
    # A client-certificate requirement that the wire tool reads as optional.
    files = {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_client_certificate /etc/nginx/tls/ec256.crt;\n        ssl_verify_client on;\n")}
    lab.start("nginx", files)
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp).chmod(0o777)
        subprocess.run(["docker", "run", "--rm", "--network", lab.NET, "-v", f"{tmp}:/out", "ghcr.io/testssl/testssl.sh@sha256:31213829a371e90afc9beae12a715793190aecebe9b64488ea49f72de7ff3c62",
                        "--quiet", "--color", "0", "--warnings", "off", "--nodns", "none", "--ip", lab.IP, "-S", "--jsonfile", "/out/t.json", f"https://{SNI}:443"],
                       capture_output=True, timeout=600)
        traw = (Path(tmp) / "t.json").read_text()
    client_auth = next(e["finding"] for e in json.loads(traw) if e["id"] == "clientAuth")
    req = lab.sh("docker", "run", "--rm", "--network", lab.NET, "--entrypoint", "sh", lab.HARNESS, "-c",
                 f"printf 'GET / HTTP/1.0\\r\\nHost: {SNI}\\r\\n\\r\\n' | openssl s_client -connect {lab.IP}:443 -servername {SNI} -quiet 2>/dev/null | head -1")
    assert "400" in req and client_auth != "required", (req, client_auth)
    iid = f"r4-{len(ITEMS) + 1:02d}"
    add("tool-limit", "nginx", f"whether {lab.IP}:443 requires a client certificate",
        [cfg(N, files[N], "ssl_verify_client on;"),
         {"layer": "wire", "tool": "testssl.sh 3.2.4", "observed_at": now(), "subject": subject("nginx", sni=SNI), "statement": f"clientAuth: {client_auth}"}],
        "config", "tool-limit", {**save(iid, "testssl", traw), "request_without_a_certificate": req.strip()})
    # A fallback handshake read as acceptance of the group that was offered.
    for service, files, offered, kw in (
            ("postgres", {P: PG_BASE + "ssl_groups = 'X25519MLKEM768:X25519'\n"}, "X448", {}),
            ("nginx", {N: ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_dhparam /etc/nginx/tls/dh2048.pem;\n        ssl_ecdh_curve X25519;\n")}, "P-521", {"sni": SNI})):
        obs, ev = start_obs(service, files, "obs", **kw)
        raw = (HERE / ev["observation"]).read_text()
        line = next(ln for ln in raw.splitlines() if ln.startswith(f"T12 {offered} =>"))
        assert "DH, 2048 bits" in line and lab.NORM.get(offered, offered) not in obs["tls12_groups"] + obs["tls13_groups"], line
        path = P if service == "postgres" else N
        needle = "ssl_groups" if service == "postgres" else "ssl_ecdh_curve X25519;"
        add("tool-limit", service, f"the key-exchange groups accepted by {lab.IP}:{EP[service]}",
            [cfg(path, files[path], needle),
             {"layer": "wire", "tool": "a group sweep that counts any completed handshake", "observed_at": now(), "subject": subject(service, **kw),
              "statement": f"offered only {offered} over TLS 1.2: handshake completed, {line.split('=> ')[1].strip()}; reported as {lab.NORM.get(offered, offered)} accepted"}],
            "config", "tool-limit", ev)


# ------------------------------------------------------------------ other-listener
def two_servers(second_cert: str = "ec384") -> str:
    return ng(RSA, more=f"    server {{\n        listen 443 ssl;\n        server_name other.s3.test;\n        ssl_certificate     /etc/nginx/tls/{second_cert}.crt;\n"
                         f"        ssl_certificate_key /etc/nginx/tls/{second_cert}.key;\n" + LOC + "    }\n")


def two_ports(first: str, second: str) -> str:
    return (NG_HEAD + "http {\n    access_log off;\n    server {\n        listen 443 ssl;\n        server_name lab.s3.test;\n" + first + LOC + "    }\n"
            "    server {\n        listen 8443 ssl;\n        server_name lab.s3.test;\n" + second + LOC + "    }\n}\n")


def other_listener() -> None:
    files = {N: two_servers()}
    lab.start("nginx", files)
    bare, raw1 = lab.observe("nginx")
    named, raw2 = lab.observe("nginx", sni="other.s3.test")
    iid = f"r4-{len(ITEMS) + 1:02d}"
    assert named["cert"]["sha256"] == cert_info("ec384")["sha256"] != bare["cert"]["sha256"]
    add("other-listener", "nginx", f"the certificate presented by {lab.IP}:443 for the server name other.s3.test",
        [cfg(N, files[N], "ec384.crt"), {**wire_cert("nginx", bare), "note": "scanned by address, with no server name"}],
        "config", "other-listener", {"without_sni": save(iid, "no-sni", raw1), "with_sni": save(iid, "sni", raw2)})
    hyb = RSA + "        ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519MLKEM768;\n"
    cls = RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519:prime256v1;\n"
    files = {N: two_ports(hyb, cls)}
    lab.start("nginx", files)
    p443, raw1 = lab.observe("nginx", sni=SNI)
    p8443, raw2 = lab.observe("nginx", sni=SNI, port=8443)
    iid = f"r4-{len(ITEMS) + 1:02d}"
    assert p443["tls13_groups"] == ["X25519MLKEM768"] and not p443["tls12"] and "X25519" in p8443["tls13_groups"]
    add("other-listener", "nginx", f"the key-exchange groups accepted by {lab.IP}:443",
        [cfg(N, files[N], "ssl_ecdh_curve X25519MLKEM768;"), wire_groups("nginx", p8443, sni=SNI, port=8443)],
        "config", "other-listener", {"port_443": save(iid, "443", raw1), "port_8443": save(iid, "8443", raw2)})
    files = {N: ng(RSA + "        ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519MLKEM768;\n")}
    lab.start("nginx", files)
    mine, raw1 = lab.observe("nginx", sni=SNI)
    portal, raw2 = lab.observe_tls("nginx", sni="portal.agency.test", ip="172.16.106.10")
    iid = f"r4-{len(ITEMS) + 1:02d}"
    assert mine["tls13_groups"] == ["X25519MLKEM768"] and "X25519MLKEM768" not in portal["tls13_groups"]
    add("other-listener", "nginx", f"the key-exchange groups accepted by {lab.IP}:443",
        [cfg(N, files[N], "ssl_ecdh_curve X25519MLKEM768;"), wire_groups("nginx", portal, sni="portal.agency.test", host="172.16.106.10")],
        "config", "other-listener", {"this_listener": save(iid, "this", raw1), "the_other_address": save(iid, "other", raw2)})
    ec = "        ssl_certificate     /etc/nginx/tls/ec256.crt;\n        ssl_certificate_key /etc/nginx/tls/ec256.key;\n"
    files = {N: two_ports(RSA, ec)}
    lab.start("nginx", files)
    p443, raw1 = lab.observe("nginx", sni=SNI)
    p8443, raw2 = lab.observe("nginx", sni=SNI, port=8443)
    iid = f"r4-{len(ITEMS) + 1:02d}"
    assert p8443["cert"]["sha256"] == cert_info("ec256")["sha256"] != p443["cert"]["sha256"]
    add("other-listener", "nginx", f"the certificate presented by {lab.IP}:8443",
        [cfg(N, files[N], "ec256.crt"), wire_cert("nginx", p443, sni=SNI)],
        "config", "other-listener", {"port_443": save(iid, "443", raw1), "port_8443": save(iid, "8443", raw2)})


# ------------------------------------------------------------------ host in force: the source moved on, the image did not
def host_in_force() -> None:
    for service, path, deployed, newer, d_needle, n_needle, asset in (
            ("nginx", N, ng(RSA + "        ssl_protocols TLSv1.2 TLSv1.3;\n        ssl_ecdh_curve X25519:secp384r1;\n"),
             ng(RSA + "        ssl_protocols TLSv1.3;\n        ssl_ecdh_curve X25519MLKEM768;\n"), "ssl_ecdh_curve X25519:secp384r1;", "ssl_ecdh_curve X25519MLKEM768;",
             "the key-exchange groups accepted"),
            ("sshd", S, SSH_BASE.format("KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n"), SSH_BASE.format("KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n"),
             "KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256", "KexAlgorithms mlkem768x25519-sha256,curve25519-sha256", "the key-exchange algorithms offered")):
        kw = {"sni": SNI} if service == "nginx" else {}
        obs, ev = start_obs(service, {path: deployed}, "obs", **kw)
        seen = obs["kex"] if service == "sshd" else obs["tls13_groups"]
        assert not any("mlkem" in g.lower() for g in seen), seen
        created = lab.sh("docker", "inspect", "-f", "{{.Created}}", lab.NAME).strip()[:19] + "Z"
        n = next(i for i, ln in enumerate(deployed.splitlines(), 1) if d_needle in ln)
        src = cfg(f"deploy/{service}/{Path(path).name}", newer, n_needle, source="the service's source repository",
                  committed_at=now(), note="committed after the running container was created; the image has not been rebuilt")
        add("host-in-force", service, f"{asset} by {lab.IP}:{EP[service]}",
            [host_file(path, f"line {n}: {d_needle}", container_created_at=created), src], "host", "stale-file", ev)


# ------------------------------------------------------------------ cannot-tell: one set of evidence, two builds, two truths
def pair(service: str, a: dict, b: dict, differ, **kw) -> dict:
    iid = f"r4-{len(ITEMS) + 1:02d}"
    lab.start(service, a)
    oa, ra = lab.observe(service, **kw)
    lab.start(service, b)
    ob, rb = lab.observe(service, **kw)
    assert differ(oa) != differ(ob), f"the two builds do not differ: {differ(oa)}"
    return {"build_a": save(iid, "a", ra), "build_b": save(iid, "b", rb), "truth_a": str(differ(oa)), "truth_b": str(differ(ob))}


def cannot_tell() -> None:
    # 1. Two snippet files, each with a curve line; which one the server includes is not shown.
    a_txt, b_txt = "ssl_ecdh_curve X25519;\n", "ssl_ecdh_curve secp384r1;\n"
    inc = lambda f: ng(RSA + f"        include /etc/nginx/snippets/{f};\n")  # noqa: E731
    both = {"/etc/nginx/snippets/tls-a.conf": a_txt, "/etc/nginx/snippets/tls-b.conf": b_txt}
    ev = pair("nginx", {N: inc("tls-a.conf"), **both}, {N: inc("tls-b.conf"), **both}, lambda o: o["tls13_groups"], sni=SNI)
    add("cannot-tell", "nginx", f"the key-exchange groups accepted by {lab.IP}:443",
        [cfg("/etc/nginx/snippets/tls-a.conf", a_txt, "ssl_ecdh_curve"), cfg("/etc/nginx/snippets/tls-b.conf", b_txt, "ssl_ecdh_curve")],
        "cannot-tell", None, {**ev, "what_is_missing": "which snippet the server block includes"})
    # 2. A file changed after the wire observation; whether the service was restarted is not shown.
    service, path, a, b, needle, asset = STALE[0]
    iid = f"r4-{len(ITEMS) + 1:02d}"
    lab.start(service, {path: a})
    before, raw0 = lab.observe(service, sni=SNI)
    t_obs = now()
    time.sleep(2)
    t_mod = put(path, b)
    stale, ra = lab.observe(service, sni=SNI)
    lab.start(service, {path: b})
    fresh, rb = lab.observe(service, sni=SNI)
    assert stale["tls13_groups"] != fresh["tls13_groups"]
    w = wire_groups(service, before, sni=SNI)
    w["observed_at"] = t_obs
    add("cannot-tell", service, f"{asset} by {lab.IP}:443, now",
        [cfg(path, b, needle, file_modified_at=t_mod), w], "cannot-tell", None,
        {"before": save(iid, "before", raw0), "not_restarted": save(iid, "a", ra), "restarted": save(iid, "b", rb),
         "what_is_missing": "whether the service was restarted after the file changed"})
    # 3. sshd: a drop-in and the main file each set KexAlgorithms; where the Include line sits is not shown.
    drop = "KexAlgorithms ecdh-sha2-nistp384\n"
    main_first = "Include /etc/ssh/sshd_config.d/*.conf\n" + SSH_BASE.format("KexAlgorithms curve25519-sha256\n")
    main_last = SSH_BASE.format("KexAlgorithms curve25519-sha256\n") + "Include /etc/ssh/sshd_config.d/*.conf\n"
    d = "/etc/ssh/sshd_config.d/10-kex.conf"
    ev = pair("sshd", {S: main_first, d: drop}, {S: main_last, d: drop}, lambda o: [k for k in o["kex"] if "nistp384" in k or k == "curve25519-sha256"])
    add("cannot-tell", "sshd", f"the key-exchange algorithms offered by {lab.IP}:22",
        [cfg(S, main_first, "KexAlgorithms curve25519-sha256"), cfg(d, drop, "KexAlgorithms")], "cannot-tell", None,
        {**ev, "what_is_missing": "whether the Include line comes before or after the main file's own KexAlgorithms"})
    for f in ITEMS[-1]["findings"]:
        f["subject"].pop("line", None)          # a line number in the main file would give the order away
    # 4. Postgres: ssl_groups in the main file and in tls.conf; whether and where tls.conf is included is not shown.
    t = "ssl_groups = 'X448:X25519'\n"
    ev = pair("postgres", {P: PG_BASE + "ssl_groups = 'secp384r1'\ninclude 'tls.conf'\n", "/etc/pg/tls.conf": t},
              {P: PG_BASE + "include 'tls.conf'\nssl_groups = 'secp384r1'\n", "/etc/pg/tls.conf": t}, lambda o: o["tls13_groups"])
    add("cannot-tell", "postgres", f"the key-exchange groups accepted by {lab.IP}:5432",
        [{"layer": "config", "tool": "configuration scan", "subject": {"kind": "file", "path": P}, "statement": "ssl_groups = 'secp384r1'"},
         {"layer": "config", "tool": "configuration scan", "subject": {"kind": "file", "path": "/etc/pg/tls.conf"}, "statement": "ssl_groups = 'X448:X25519'"}],
        "cannot-tell", None, {**ev, "what_is_missing": "the order of the include and the main file's own line"})
    # 5. The served certificate is named by a path that is neither of the two files found.
    pki = lab.ensure_pki()
    conf = ng("        ssl_certificate     /etc/nginx/tls/current.crt;\n        ssl_certificate_key /etc/nginx/tls/current.key;\n")
    cur = lambda n: {"/etc/nginx/tls/current.crt": (pki / f"{n}.crt").read_text(), "/etc/nginx/tls/current.key": (pki / f"{n}.key").read_text()}  # noqa: E731
    ev = pair("nginx", {N: conf, **cur("rsa2048")}, {N: conf, **cur("ec256")}, lambda o: o["cert"]["sha256"], sni=SNI)
    r, e = cert_info("rsa2048"), cert_info("ec256")
    add("cannot-tell", "nginx", f"the key algorithm of the certificate presented by {lab.IP}:443",
        [cfg(N, conf, "current.crt"),
         host_file("/etc/nginx/tls/rsa2048.crt", f"a certificate with an RSA key of 2048 bits, SHA-256 {r['sha256'][:16]}…"),
         host_file("/etc/nginx/tls/ec256.crt", f"a certificate with an ECDSA key of 256 bits, SHA-256 {e['sha256'][:16]}…")],
        "cannot-tell", None, {**ev, "what_is_missing": "what /etc/nginx/tls/current.crt holds"})
    # 6. A scan by address on a listener with two server names; nothing shows what the second name serves.
    iid = f"r4-{len(ITEMS) + 1:02d}"
    lab.start("nginx", {N: two_servers("ec384")})
    bare, raw0 = lab.observe("nginx")
    na, ra = lab.observe("nginx", sni="other.s3.test")
    lab.start("nginx", {N: two_servers("rsa2048")})
    nb, rb = lab.observe("nginx", sni="other.s3.test")
    assert na["cert"]["sha256"] != nb["cert"]["sha256"]
    x = cert_info("ec384")
    add("cannot-tell", "nginx", f"the certificate presented by {lab.IP}:443 for the server name other.s3.test",
        [{**wire_cert("nginx", bare), "note": "scanned by address, with no server name"},
         host_file("/etc/nginx/tls/ec384.crt", f"a certificate with an ECDSA key of 384 bits, SHA-256 {x['sha256'][:16]}…")],
        "cannot-tell", None, {"scan_by_address": save(iid, "no-sni", raw0), "build_a": save(iid, "a", ra), "build_b": save(iid, "b", rb),
                              "what_is_missing": "the server block for other.s3.test, or a scan that names it"})


if __name__ == "__main__":
    for step in (not_served, overridden, default_applies, stale_file, tool_limit, other_listener, host_in_force, cannot_tell):
        step()
    lab.stop()
    (HERE / "items" / "r4.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in ITEMS))
    (HERE / "labels" / "r4.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in LABELS))
    print(len(ITEMS), "items")
