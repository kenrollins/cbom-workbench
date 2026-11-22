#!/usr/bin/env python
"""What each estate image's cryptographic runtime can do, asked of the runtime itself.

The supplier blocker (`blocker/supplier/1`) reads the file this writes. A service is blocked
by its supplier in a role when the software it runs cannot offer a post-quantum algorithm in
that role whatever its configuration says: the runtime's own list has none. That is a property
of the image, measured here with no network, the raw output of every probe kept with its hash.

    uv run python tools/probe_capabilities.py [--out policy/snapshots/capabilities-YYYY-MM-DD.json]

Images are the estate's own (agency/compose.yaml), run with `--network none` and the entry
point replaced, so nothing listens and nothing is reached. Where an image carries no tool that
can list what its library supports (the nginx images ship no `openssl` command), the probe
records the library package and names an image of the same package build whose capability
was observed on the wire; the assessor treats that as `same-build` evidence and says so.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "eval" / "capabilities"

ALPINE_LIB = "apk info -v 2>/dev/null | grep -E '^(libssl3|libcrypto3|openssl)-' ; nginx -V 2>&1 | grep -o 'built with OpenSSL [^ ]*'"
FIPS = ("echo fips-module: $(find / -xdev -name fips.so 2>/dev/null | head -1); "
        "for c in /etc/ssl/openssl.cnf /usr/lib/ssl/openssl.cnf /opt/openssl/etc/ssl/openssl.cnf; do "
        "[ -f $c ] && echo config $c: $(grep -E '^\\s*(fips|activate)\\s*=' $c | tr '\\n' ' '); done; "
        "for c in /opt/openssl/etc/ssl/fipsmodule.cnf; do [ -f $c ] && echo fipsmodule $c: $(grep -E '^\\s*#?\\s*activate' $c); done")

# Per service: the software, how to ask it, and how to read the answer.
PROBES = {
    "portal": {"software": "nginx 1.28 on OpenSSL 3.5 (Alpine)", "cmd": ALPINE_LIB, "same_build": ["api", "pq-gateway"]},
    "api": {"software": "nginx 1.28 on OpenSSL 3.5 (Alpine)", "cmd": ALPINE_LIB, "same_build": ["api", "pq-gateway"]},
    "pq-gateway": {"software": "nginx 1.28 on OpenSSL 3.5 (Alpine)", "cmd": ALPINE_LIB, "same_build": ["api", "pq-gateway"]},
    "records-db": {"software": "PostgreSQL 18 on OpenSSL 3.5 (Debian)",
                   "cmd": "postgres --version; openssl version; echo '## kem'; openssl list -kem-algorithms; echo '## sig'; openssl list -signature-algorithms"},
    "queue": {"software": "RabbitMQ 4 on Erlang/OTP",
              "cmd": "erl -noshell -eval 'io:format(\"## groups~n~p~n## sig~n~p~n## otp~n~p~n## lib~n~p~n\", "
                     "[ssl:groups(), [A || A <- ssl:signature_algs(default, '\"'\"'tlsv1.3'\"'\"'), is_atom(A)], "
                     "erlang:system_info(otp_release), crypto:info_lib()]), halt().'"},
    "legacy-app": {"software": "Tomcat 8.5 on Java 8 (Temurin)",
                   "cmd": "java -version 2>&1; J=${JAVA_HOME:-/opt/java/openjdk}; for j in $J/lib/jsse.jar $J/lib/rt.jar; do "
                          "echo \"## $j mlkem $(unzip -p $j | grep -a -c -i -E 'mlkem|ml-kem') mldsa $(unzip -p $j | grep -a -c -i -E 'mldsa|ml-dsa')\"; done; "
                          "echo \"## kem-api $(unzip -l $J/lib/rt.jar | grep -c 'javax/crypto/KEM')\""},
    "sftp-legacy": {"software": "OpenSSH 6.6 (Ubuntu 14.04)", "cmd": "ssh -V 2>&1; echo '## kex'; ssh -Q kex; echo '## key'; ssh -Q key"},
    "bastion": {"software": "OpenSSH 10.0 (Alpine)",
                "cmd": "sshd -V 2>&1 | head -1; echo '## kex'; sshd -T -f /dev/null 2>/dev/null | grep -i '^kexalgorithms ' | cut -d' ' -f2 | tr ',' '\\n'; "
                       "echo '## key'; sshd -T -f /dev/null 2>/dev/null | grep -i '^hostkeyalgorithms ' | cut -d' ' -f2 | tr ',' '\\n'"},
}

PQ_KEX = re.compile(r"ml-?kem|mlkem|sntrup", re.I)
PQ_SIG = re.compile(r"ml-?dsa|mldsa|slh-?dsa", re.I)


def run(image: str, cmd: str) -> bytes:
    p = subprocess.run(["docker", "run", "--rm", "--network", "none", "--entrypoint", "sh", image, "-c", cmd],
                       capture_output=True, timeout=180)
    return p.stdout + p.stderr


def section(text: str, name: str) -> list[str]:
    m = re.search(rf"^## {re.escape(name)}\b.*?\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    return [ln.strip() for ln in m.group(1).splitlines() if ln.strip()] if m else []


def read(service: str, text: str) -> dict:
    """The runtime's post-quantum names in each role, from its own list."""
    if service == "records-db":
        kem, sig = section(text, "kem"), section(text, "sig")
        return {"kex": sorted({m for ln in kem for m in re.findall(r"ML-KEM-\d+", ln)}),
                "sig": sorted({m for ln in sig for m in re.findall(r"(ML-DSA-\d+|SLH-DSA-[A-Za-z0-9-]+)", ln)})}
    if service == "queue":
        groups = " ".join(section(text, "groups"))
        sigs = " ".join(section(text, "sig"))
        return {"kex": sorted(set(PQ_KEX.findall(groups))), "sig": sorted(set(PQ_SIG.findall(sigs)))}
    if service == "legacy-app":
        counts = {k: int(v) for k, v in re.findall(r"(mlkem|mldsa) (\d+)", text)}
        return {"kex": ["ML-KEM"] if counts.get("mlkem") else [], "sig": ["ML-DSA"] if counts.get("mldsa") else []}
    if service in ("sftp-legacy", "bastion"):
        return {"kex": [k for k in section(text, "kex") if PQ_KEX.search(k)],
                "sig": [k for k in section(text, "key") if PQ_SIG.search(k)]}
    return {"kex": None, "sig": None}       # no tool in the image lists them: see same_build


def fips(text: str) -> dict:
    module = re.search(r"fips-module: (\S+)", text)
    active = bool(re.search(r"^\s*activate\s*=\s*1", text, re.M)) and not re.search(r"fipsmodule \S+: #\s*activate", text)
    return {"module_present": bool(module), "module_path": module.group(1) if module else None,
            "active": bool(module) and active}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    taken = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw_dir = RAW / taken[:10]
    raw_dir.mkdir(parents=True, exist_ok=True)
    compose = yaml.safe_load((ROOT / "agency" / "compose.yaml").read_text())["services"]
    out = {"schema": "pqch.capabilities/1", "taken_at": taken, "estate": "mini-agency",
           "method": "each image run with --network none and its entry point replaced; the runtime's own list", "services": {}}
    for service, p in PROBES.items():
        image = compose[service]["image"]
        digest = subprocess.run(["docker", "image", "inspect", "-f", "{{.Id}}", image], capture_output=True,
                                text=True).stdout.strip()
        data = run(image, p["cmd"] + "; echo '## fips'; " + FIPS)
        path = raw_dir / f"{service}.txt"
        path.write_bytes(data)
        text = data.decode(errors="replace")
        lib = re.findall(r"(libssl3-[\w.-]+|OpenSSL \d+\.\d+\.\d+|OpenSSH_[\w.]+|openjdk version \"[^\"]+\"|\"2\d\")", text)
        out["services"][service] = {
            "image": image, "image_id": digest, "software": p["software"], "library": sorted(set(lib)),
            "pq": read(service, text), "fips": fips(text), "same_build": p.get("same_build"),
            "raw": str(path.relative_to(ROOT)), "sha256": hashlib.sha256(data).hexdigest(),
        }
        print(service, out["services"][service]["pq"], out["services"][service]["fips"], sorted(set(lib)), flush=True)
    # The nginx images ship no tool that lists their library's algorithms; check they carry the
    # same library build, so the capability observed on the wire for one holds for the others.
    builds = {s: tuple(v["library"]) for s, v in out["services"].items() if v.get("same_build")}
    out["same_build_check"] = {"builds": {s: list(b) for s, b in builds.items()}, "identical": len(set(builds.values())) == 1}
    path = Path(a.out or ROOT / f"policy/snapshots/capabilities-{taken[:10]}.json")
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(path, "same build:", out["same_build_check"]["identical"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
