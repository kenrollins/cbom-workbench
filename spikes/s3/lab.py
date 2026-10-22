"""Spike S3's lab: start one service from given configuration files on the slice network and
observe what it does on the wire. Used to label R4 and R5 by observation and to score R6.

No model is involved. Only 172.16.106.60, on the network this repository created, is probed.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
NET = "pqch-agency-net"
IP = "172.16.106.60"
NAME = "pqch-s3-lab"
HARNESS = "pqch/harness:m0"
SSHAUDIT = "positronsecurity/ssh-audit@sha256:6d5dee75fe91b5f6279f683f0e7d4374d2ba83e2227c8d9a17097aac2775127d"
PKI = ROOT / "var" / "s3-lab" / "pki"

SERVICES = {
    # image, command, port, how the listener is reached, seconds to wait for it
    "nginx": {"image": "pqch-agency/portal:m0", "cmd": ["nginx", "-g", "daemon off;"], "port": 443, "pki": "/etc/nginx/tls"},
    "sshd": {"image": "pqch-agency/bastion:m0", "cmd": ["/usr/sbin/sshd", "-D", "-e"], "port": 22},
    "sshd-legacy": {"image": "pqch-agency/sftp-legacy:m0", "cmd": ["/usr/sbin/sshd", "-D", "-e"], "port": 22},
    "postgres": {"image": "pqch-s2/postgres:s2", "port": 5432, "starttls": "postgres", "pki": "/etc/pg/tls",
                 "pki_owner": "postgres",
                 "cmd": ["sh", "-c", "exec docker-entrypoint.sh postgres -c config_file=/etc/pg/postgresql.conf "
                                     "-c hba_file=$PGDATA/pg_hba.conf -c ident_file=$PGDATA/pg_ident.conf"],
                 "env": {"POSTGRES_PASSWORD": "s3-only-not-a-secret"}},
    "rabbitmq": {"image": "pqch-s2/rabbitmq:s2", "cmd": None, "port": 5671, "wait": 60},
    "kafka": {"image": "pqch-s2/kafka:s2", "cmd": None, "port": 9093, "wait": 90},
}

G13 = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "X25519", "X448", "P-256", "P-384",
       "P-521", "ffdhe2048", "ffdhe3072", "brainpoolP256r1tls13"]
G12 = ["X25519", "X448", "P-256", "P-384", "P-521", "brainpoolP256r1"]
NORM = {"prime256v1": "secp256r1", "P-256": "secp256r1", "P-384": "secp384r1", "P-521": "secp521r1",
        "secp384r1": "secp384r1", "secp521r1": "secp521r1"}


def sh(*args: str, check: bool = True, timeout: int = 600, input_: str | None = None) -> str:
    r = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, input=input_)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)[:200]}\n{r.stderr[-800:]}")
    return r.stdout


def ensure_pki() -> Path:
    """Test keys and certificates for the lab, generated once with the harness image's OpenSSL 3.5."""
    if (PKI / "mldsa65.crt").exists():
        return PKI
    PKI.mkdir(parents=True, exist_ok=True)
    PKI.chmod(0o777)
    script = """set -e; cd /pki
req() { openssl req -x509 -nodes -days 825 -subj "/O=S3 lab/CN=$1" -addext "subjectAltName=DNS:$1" -keyout $2.key -out $2.crt "${@:3}" 2>/dev/null; }
req lab.s3.test rsa2048 -newkey rsa:2048 -sha256
req lab.s3.test rsa3072 -newkey rsa:3072 -sha256
req lab.s3.test ec256 -newkey ec -pkeyopt ec_paramgen_curve:P-256
req other.s3.test ec384 -newkey ec -pkeyopt ec_paramgen_curve:P-384
req lab.s3.test rsa1024-2019 -newkey rsa:1024 -sha1
req lab.s3.test mldsa65 -newkey ML-DSA-65
openssl dhparam -out dh2048.pem 2048 2>/dev/null
chmod 644 *.key"""
    sh("docker", "run", "--rm", "--network", "none", "-u", "0", "-v", f"{PKI}:/pki", "--entrypoint", "bash", HARNESS, "-c", script)
    return PKI


def stop() -> None:
    sh("docker", "rm", "-f", NAME, check=False)


def start(service: str, files: dict[str, str], *, ip: str = IP) -> None:
    """Create the service's container, copy `files` (absolute path -> text) and the lab PKI in, start it,
    and wait for its port. Raises if the service never listens."""
    spec = SERVICES[service]
    stop()
    env = [a for k, v in (spec.get("env") or {}).items() for a in ("-e", f"{k}={v}")]
    args = ["docker", "create", "--name", NAME, "--network", NET, "--ip", ip, "--memory", "1g", *env, spec["image"]]
    if spec.get("cmd"):
        args += spec["cmd"]
    sh(*args)
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "root"
        for path, text in files.items():
            p = stage / path.lstrip("/")
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        if spec.get("pki"):
            d = stage / spec["pki"].lstrip("/")
            d.mkdir(parents=True, exist_ok=True)
            for f in ensure_pki().iterdir():
                (d / f.name).write_bytes(f.read_bytes())
                (d / f.name).chmod(0o600 if f.suffix == ".key" else 0o644)
        for top in sorted(stage.iterdir()):
            sh("docker", "cp", "-a", str(top), f"{NAME}:/")
    sh("docker", "start", NAME)
    if spec.get("pki_owner"):
        sh("docker", "exec", "-u", "0", NAME, "chown", "-R", spec["pki_owner"], spec["pki"], check=False)
    deadline = time.monotonic() + spec.get("wait", 30)
    probe = f"import socket,sys\ntry:\n socket.create_connection(('{ip}',{spec['port']}),2).close()\nexcept OSError: sys.exit(1)"
    while time.monotonic() < deadline:
        state = sh("docker", "inspect", "-f", "{{.State.Running}}", NAME, check=False).strip()
        if state == "true" and subprocess.run(
                ["docker", "run", "--rm", "--network", NET, "--entrypoint", "python", HARNESS, "-c", probe],
                capture_output=True).returncode == 0:
            time.sleep(1.0)
            return
        if state == "false":
            break
        time.sleep(1.0)
    logs = sh("docker", "logs", "--tail", "15", NAME, check=False) + \
        subprocess.run(["docker", "logs", "--tail", "15", NAME], capture_output=True, text=True).stderr
    raise RuntimeError(f"{service} did not listen on {ip}:{spec['port']}\n{logs[-1200:]}")


def observe_tls(service: str, *, sni: str | None = None, ip: str = IP, port: int | None = None) -> tuple[dict, str]:
    """One group per handshake, TLS 1.3 and TLS 1.2 forced separately (journal lesson 10), plus RSA key
    transport, finite-field DHE and the served certificate. Returns the parsed observation and the raw text."""
    spec = SERVICES[service]
    conn = f"-connect {ip}:{port or spec['port']}" + (f" -servername {sni}" if sni else "") + \
        (f" -starttls {spec['starttls']}" if spec.get("starttls") else "")
    script = (
        f"for g in {' '.join(G13)}; do printf \"T13 $g => \"; openssl s_client {conn} -tls1_3 -groups $g </dev/null 2>&1 | "
        "grep -E 'Negotiated TLS1.3 group|Temp Key' | head -1; echo; done; "
        f"for g in {' '.join(G12)}; do printf \"T12 $g => \"; openssl s_client {conn} -tls1_2 -groups $g </dev/null 2>&1 | "
        "grep -E 'Temp Key' | head -1; echo; done; "
        f"printf 'KRSA => '; openssl s_client {conn} -tls1_2 -cipher kRSA </dev/null 2>&1 | grep -E '^New, ' | head -1; echo; "
        f"printf 'KDHE => '; openssl s_client {conn} -tls1_2 -cipher kDHE </dev/null 2>&1 | grep -E 'Temp Key' | head -1; echo; "
        f"printf 'V12 => '; openssl s_client {conn} -tls1_2 </dev/null 2>&1 | grep -E '^New, ' | head -1; echo; "
        f"printf 'V13 => '; openssl s_client {conn} -tls1_3 </dev/null 2>&1 | grep -E '^New, ' | head -1; echo; "
        f"printf 'CERT => '; openssl s_client {conn} </dev/null 2>/dev/null | openssl x509 -noout -text -fingerprint -sha256 2>&1 | "
        "grep -E 'Public Key Algorithm|Public-Key|Subject:|sha256 Fingerprint|ASN1 OID' | tr -s ' ' | tr '\\n' '|'; echo")
    raw = sh("docker", "run", "--rm", "--network", NET, "--entrypoint", "sh", HARNESS, "-c", script)
    obs: dict = {"tls13_groups": [], "tls12_groups": [], "rsa_key_transport": False, "dhe_bits": None,
                 "tls12": False, "tls13": False, "cert": None}
    for line in raw.splitlines():
        m = re.match(r"(T13|T12) (\S+) => (.*)", line)
        if m:
            offered, got = m.group(2), m.group(3)
            g = re.search(r"Negotiated TLS1\.3 group: (\S+)|Temp Key: (?:ECDH, )?([^,\s]+)", got)
            name = (g.group(1) or g.group(2)) if g else None
            dh = re.search(r"Temp Key: DH, (\d+) bits", got)
            if dh and offered == f"ffdhe{dh.group(1)}":
                name = offered
            if name and NORM.get(name, name).lower() == NORM.get(offered, offered).lower():
                obs["tls13_groups" if m.group(1) == "T13" else "tls12_groups"].append(NORM.get(offered, offered))
        elif line.startswith("KRSA =>"):
            obs["rsa_key_transport"] = "Cipher is" in line and "(NONE)" not in line
        elif line.startswith("KDHE =>"):
            d = re.search(r"DH, (\d+) bits", line)
            obs["dhe_bits"] = int(d.group(1)) if d else None
        elif line.startswith(("V12 =>", "V13 =>")):
            obs["tls12" if line.startswith("V12") else "tls13"] = "Cipher is" in line and "(NONE)" not in line
        elif line.startswith("CERT =>"):
            alg = re.search(r"Public Key Algorithm: ([^|]+)", line)
            bits = re.search(r"Public-Key: \((\d+) bit", line)
            cn = re.search(r"CN ?= ?([^|,]+)", line)
            fp = re.search(r"Fingerprint=([0-9A-F:]+)", line)
            if alg:
                obs["cert"] = {"key_algorithm": alg.group(1).strip(), "bits": int(bits.group(1)) if bits else None,
                               "cn": cn.group(1).strip() if cn else None,
                               "sha256": fp.group(1).replace(":", "").lower() if fp else None}
    return obs, raw


def observe_ssh(*, ip: str = IP) -> tuple[dict, str]:
    raw = subprocess.run(["docker", "run", "--rm", "--network", NET, SSHAUDIT, "-j", ip],
                         capture_output=True, text=True, timeout=120).stdout
    doc = json.loads(raw)
    return {"banner": doc["banner"]["raw"], "kex": [k["algorithm"] for k in doc["kex"]],
            "hostkeys": sorted({k["algorithm"] for k in doc["key"]})}, raw


def observe(service: str, **kw) -> tuple[dict, str]:
    return observe_ssh() if service.startswith("sshd") else observe_tls(service, **kw)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()
