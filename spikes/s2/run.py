"""Spike S2: fill the scanner truth matrix for one architecture.

    uv run python spikes/s2/run.py amd64|arm64 [--only C1,C3]

Starts each tool as a container for that platform on the slice network, saves its raw
output under results/<arch>/ with its SHA-256, and judges each cell against the truth
written in README.md. Touches only 172.16.106.0/24. See README.md for the matrix,
the predictions and the pass criterion, all written before this ran.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
NET = "pqch-agency-net"
TESTSSL = "ghcr.io/testssl/testssl.sh@sha256:31213829a371e90afc9beae12a715793190aecebe9b64488ea49f72de7ff3c62"
SSHAUDIT = "positronsecurity/ssh-audit@sha256:6d5dee75fe91b5f6279f683f0e7d4374d2ba83e2227c8d9a17097aac2775127d"
THEIA = "ghcr.io/cbomkit/cbomkit-theia@sha256:46a72eadc9849b919fc4c72e1c851f9783e03c35db8fad49ba99341ac97f8dea"
ZEEK = "zeek/zeek:lts"
OPENSSL_IMAGE = {"amd64": "pqch/harness:m0", "arm64": "pqch/harness:m0b-arm64"}
OPENGREP = {"amd64": "opengrep_manylinux_x86", "arm64": "opengrep_manylinux_aarch64"}
OPENGREP_URL = "https://github.com/opengrep/opengrep/releases/download/v1.30.0/"
GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM512", "MLKEM768", "MLKEM1024",
          "X25519", "X448", "P-256", "P-384", "P-521", "ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144",
          "ffdhe8192", "brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13"]
# TLS 1.2-only curves: offered beside TLS 1.3 they are never used, so they are swept with -tls1_2.
GROUPS_TLS12 = ["brainpoolP256r1", "brainpoolP384r1", "brainpoolP512r1"]
# RFC 7919 named finite-field groups for TLS 1.2 DHE: offered with DHE suites only.
FFDHE_TLS12 = ["ffdhe2048", "ffdhe3072", "ffdhe4096", "ffdhe6144", "ffdhe8192"]
NORM = {"prime256v1": "P-256", "secp256r1": "P-256", "secp384r1": "P-384", "secp521r1": "P-521", "x25519": "X25519",
        "x448": "X448"}

TLS_TARGETS = {
    "C1-api": {"host": "172.16.106.11", "port": 443, "sni": "api.agency.test"},
    "C1-portal": {"host": "172.16.106.10", "port": 443, "sni": "portal.agency.test"},
    "C3": {"host": "172.16.106.40", "port": 443, "sni": "mldsa.s2.test"},
    "C4": {"host": "172.16.106.42", "port": 5432, "starttls": "postgres"},
    "C5": {"host": "172.16.106.43", "port": 5671},
    "C6": {"host": "172.16.106.44", "port": 9093},
    "C7": {"host": "172.16.106.41", "port": 443, "sni": "mtls.s2.test"},
}


def run(args: list[str], timeout: int = 3600) -> tuple[int, str, float]:
    t = time.monotonic()
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout + r.stderr, time.monotonic() - t
    except subprocess.TimeoutExpired as e:
        return -1, f"TIMEOUT after {timeout} s\n{e.stdout or ''}", time.monotonic() - t


class Recorder:
    def __init__(self, arch: str):
        self.arch = arch
        self.dir = HERE / "results" / arch
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cells: dict[str, dict] = {}

    def save(self, name: str, text: str) -> str:
        p = self.dir / name
        p.write_text(text)
        return hashlib.sha256(text.encode()).hexdigest()

    def cell(self, cap: str, tool: str, outcome: str, detail: str, raw: dict[str, str], seconds: float) -> None:
        self.cells[f"{cap}|{tool}"] = {"capability": cap, "tool": tool, "outcome": outcome, "detail": detail,
                                       "raw_sha256": raw, "seconds": round(seconds, 1)}
        print(f"  {cap:<4} {tool:<12} {outcome:<8} {detail}", flush=True)

    def write(self) -> None:
        old = json.loads((self.dir.parent / f"{self.arch}.json").read_text()) if (self.dir.parent / f"{self.arch}.json").exists() else {}
        old.update(self.cells)
        (self.dir.parent / f"{self.arch}.json").write_text(json.dumps(old, indent=1, sort_keys=True) + "\n")


# ------------------------------------------------------------------ testssl.sh
def testssl(rec: Recorder, key: str, t: dict) -> tuple[dict | None, str, float]:
    out = rec.dir / "testssl"
    out.mkdir(exist_ok=True)
    out.chmod(0o777)
    (out / f"{key}.json").unlink(missing_ok=True)   # testssl.sh appends to an existing file
    target = f"https://{t['sni']}:{t['port']}" if t.get("sni") else f"{t['host']}:{t['port']}"
    args = ["docker", "run", "--rm", "--platform", f"linux/{rec.arch}", "--network", NET, "-v", f"{out}:/out",
            TESTSSL, "--quiet", "--color", "0", "--warnings", "off", "--nodns", "none", "-S", "-f",
            "--jsonfile", f"/out/{key}.json"]
    if t.get("sni"):
        args += ["--ip", t["host"]]
    if t.get("starttls"):
        args += ["--starttls", t["starttls"]]
    _code, text, secs = run([*args, target], timeout=3600)
    rec.save(f"testssl-{key}.log", text)
    jf = out / f"{key}.json"
    if not jf.exists() or jf.stat().st_size == 0:
        return None, text, secs
    return {e["id"]: e.get("finding", "") for e in json.loads(jf.read_text())}, jf.read_text(), secs


DH_BITS = {"RFC3526/Oakley Group 14": 2048, "RFC3526/Oakley Group 15": 3072, "RFC3526/Oakley Group 16": 4096,
           "RFC2409/Oakley Group 2": 1024, "RFC7919/ffdhe2048": 2048, "RFC7919/ffdhe3072": 3072}


def ffdh(name: str) -> str:
    """Finite-field groups are compared by size: tools name the same group by RFC 3526, by
    RFC 7919, or by the bits a TLS 1.2 server chose."""
    m = re.match(r"(?:DHE-|ffdhe)(\d+)$", name)
    return f"FFDH-{m.group(1)}" if m else name


def testssl_groups(r: dict) -> set[str]:
    g = set()
    for k in ("FS_KEMs", "FS_ECDHE_curves"):
        v = (r.get(k) or "").strip()
        if v and not v.lower().startswith(("no ", "not ")):
            g |= {NORM.get(x, x) for x in v.split()}
    dh = (r.get("DH_groups") or "").strip()
    if dh and not dh.lower().startswith(("no ", "not ")):
        if dh in DH_BITS:
            g.add(f"DHE-{DH_BITS[dh]}")
        else:
            g |= {f"DHE-{t[5:]}" if t.startswith("ffdhe") else f"DHE-{t}" for t in dh.split()}
    return {ffdh(x) for x in g}


# ------------------------------------------------------------- openssl s_client
def sclient(rec: Recorder, key: str, t: dict) -> tuple[set[str], str, str, float]:
    """Sweep every group one handshake at a time; read the certificate once."""
    conn = f"-connect {t['host']}:{t['port']}" + (f" -servername {t['sni']}" if t.get("sni") else "") + \
        (f" -starttls {t['starttls']}" if t.get("starttls") else "")
    script = "for g in " + " ".join(GROUPS) + "; do printf \"GROUP $g \"; " \
             f"openssl s_client {conn} -groups $g </dev/null 2>&1 | grep -E 'Temp Key|Negotiated TLS1.3 group' | head -1; echo; done; " \
             "for g in " + " ".join(GROUPS_TLS12) + "; do printf \"GROUP $g \"; " \
             f"openssl s_client {conn} -tls1_2 -groups $g </dev/null 2>&1 | grep -E 'Temp Key|Negotiated TLS1.3 group' | head -1; echo; done; " \
             "for g in " + " ".join(FFDHE_TLS12) + "; do printf \"FFDHE $g \"; " \
             f"openssl s_client {conn} -tls1_2 -cipher kDHE -groups $g </dev/null 2>&1 | grep -E 'Temp Key: DH' | head -1; echo; done; " \
             f"printf 'DHE '; openssl s_client {conn} -tls1_2 -cipher kDHE </dev/null 2>&1 | " \
             "grep -E '^(Server|Peer) Temp Key: DH' | head -1 || true; echo; " \
             f"openssl s_client {conn} </dev/null 2>/dev/null | openssl x509 -noout -text 2>&1 | " \
             "grep -E 'Public Key Algorithm|Signature Algorithm|Public-Key' | head -3"
    _code, text, secs = run(["docker", "run", "--rm", "--platform", f"linux/{rec.arch}", "--network", NET,
                            "--entrypoint", "sh", OPENSSL_IMAGE[rec.arch], "-c", script], timeout=3600)
    sha = rec.save(f"sclient-{key}.txt", text)
    # A group is accepted only when it is the one negotiated: offered one group alone, a server
    # may fall back to TLS 1.2 finite-field DHE, which is not that group.
    accepted = set()
    for m in re.finditer(r"GROUP (\S+) ([^\n]*)", text):
        offered, line = m.group(1), m.group(2)
        got = re.search(r"Negotiated TLS1\.3 group: (\S+)|Temp Key: (?:ECDH, )?([^,\s]+)", line)
        name = (got.group(1) or got.group(2)) if got else None
        dh = re.search(r"Temp Key: DH, (\d+) bits", line)
        if dh and offered == f"ffdhe{dh.group(1)}":
            name = offered      # OpenSSL names a finite-field group by its size
        if name and NORM.get(name, name).lower() == NORM.get(offered, offered).lower():
            accepted.add(offered)
    for m in re.finditer(r"FFDHE ffdhe(\d+) [^\n]*Temp Key: DH, (\d+) bits", text):
        if m.group(1) == m.group(2):
            accepted.add(f"DHE-{m.group(1)}")   # TLS 1.2 DHE in that RFC 7919 group
    dhe = re.search(r"DHE [^\n]*Temp Key: DH, (\d+) bits", text)
    if dhe:
        accepted.add(f"DHE-{dhe.group(1)}")   # TLS 1.2 DHE, parameters chosen by the server
    cert = " | ".join(line.strip() for line in text.splitlines() if "Algorithm" in line or "Public-Key" in line)
    return {ffdh(x) for x in accepted}, cert, sha, secs


def tls_cells(rec: Recorder, only: set[str]) -> None:
    truth_groups = {}
    for key, t in TLS_TARGETS.items():
        cap = key.split("-")[0]
        if only and cap not in only:
            continue
        if cap == "C6" and not _up("pqch-s2-s2-kafka-1"):
            for tool in ("testssl.sh", "s_client"):
                rec.cell(cap, tool, "not run", "Kafka target not started (image not pulled)", {}, 0)
            continue
        groups, cert, sha, secs = sclient(rec, key, t)
        truth_groups[key] = groups
        r, raw, tsecs = testssl(rec, key, t)
        tsha = hashlib.sha256(raw.encode()).hexdigest()
        tg = testssl_groups(r) if r else set()
        tcert = f"{(r or {}).get('cert_keySize', '')} / {(r or {}).get('cert_signatureAlgorithm', '')}".strip(" /")
        if cap == "C1":
            continue  # judged across both C1 targets below
        if cap == "C3":
            s_ok = "ML-DSA-65" in cert
            rec.cell(cap, "s_client", "correct" if s_ok else "wrong", cert[:120], {"s_client": sha}, secs)
            if r is None:
                rec.cell(cap, "testssl.sh", "fails", raw.strip().splitlines()[-1][:120] if raw.strip() else "no output", {"testssl": tsha}, tsecs)
            elif "ML-DSA" in tcert.upper() or "MLDSA" in tcert.upper():
                rec.cell(cap, "testssl.sh", "correct", tcert[:120], {"testssl": tsha}, tsecs)
            elif tcert:
                rec.cell(cap, "testssl.sh", "wrong", f"reports '{tcert[:100]}'", {"testssl": tsha}, tsecs)
            else:
                rec.cell(cap, "testssl.sh", "blind", f"groups {sorted(tg)}; no certificate reported", {"testssl": tsha}, tsecs)
            continue
        # C4..C7: groups and certificate, judged against the s_client sweep and the target's design.
        s_out = "correct" if groups and cert else ("blind" if not groups else "wrong")
        rec.cell(cap, "s_client", s_out, f"groups {sorted(groups)}; {cert[:70]}", {"s_client": sha}, secs)
        if r is None:
            rec.cell(cap, "testssl.sh", "fails", raw.strip().splitlines()[-1][:120] if raw.strip() else "no output", {"testssl": tsha}, tsecs)
        else:
            missing, extra = groups - tg, tg - groups
            if not tg and not tcert:
                out = "blind"
            elif extra:
                out = "wrong"
            elif missing:
                out = "partial"
            else:
                out = "correct"
            rec.cell(cap, "testssl.sh", out, f"groups {sorted(tg)}" + (f", missing {sorted(missing)}" if missing else "")
                     + (f", claims {sorted(extra)}" if extra else "") + f"; cert {tcert[:50]}", {"testssl": tsha}, tsecs)
    if "C1-api" in truth_groups:
        api, portal = truth_groups["C1-api"], truth_groups["C1-portal"]
        ok = "X25519MLKEM768" in api and "X25519MLKEM768" not in portal
        rec.cell("C1", "s_client", "correct" if ok else "wrong", f"api {sorted(api)}; portal {sorted(portal)}", {}, 0)
        ta = testssl_groups(json_of(rec, "C1-api"))
        tp = testssl_groups(json_of(rec, "C1-portal"))
        ok = "X25519MLKEM768" in ta and "X25519MLKEM768" not in tp
        rec.cell("C1", "testssl.sh", "correct" if ok else "wrong", f"api {sorted(ta)}; portal {sorted(tp)}", {}, 0)


def json_of(rec: Recorder, key: str) -> dict:
    p = rec.dir / "testssl" / f"{key}.json"
    return {e["id"]: e.get("finding", "") for e in json.loads(p.read_text())} if p.exists() else {}


def _up(name: str) -> bool:
    code, text, _ = run(["docker", "inspect", "-f", "{{.State.Running}}", name], timeout=30)
    return code == 0 and text.strip() == "true"


# ------------------------------------------------------------------- ssh-audit
def ssh_cells(rec: Recorder) -> None:
    res = {}
    for name, host in (("bastion", "172.16.106.21"), ("legacy", "172.16.106.20")):
        _code, text, secs = run(["docker", "run", "--rm", "--platform", f"linux/{rec.arch}", "--network", NET,
                                SSHAUDIT, "-j", host], timeout=1800)
        sha = rec.save(f"ssh-audit-{name}.json", text)
        try:
            res[name] = ({k["algorithm"] for k in json.loads(text)["kex"]}, sha, secs)
        except (ValueError, KeyError):
            res[name] = (set(), sha, secs)
    ok = "mlkem768x25519-sha256" in res["bastion"][0] and "mlkem768x25519-sha256" not in res["legacy"][0]
    rec.cell("C2", "ssh-audit", "correct" if ok else ("blind" if not res["bastion"][0] else "wrong"),
             f"bastion has mlkem: {'mlkem768x25519-sha256' in res['bastion'][0]}; legacy has: "
             f"{'mlkem768x25519-sha256' in res['legacy'][0]}", {k: v[1] for k, v in res.items()},
             res["bastion"][2] + res["legacy"][2])


# ----------------------------------------------------------------------- theia
def theia_cell(rec: Recorder) -> None:
    tar = rec.dir / "mldsa-image.tar"
    run(["docker", "save", "-o", str(tar), "pqch-s2/mldsa:s2"], timeout=600)
    _code, text, secs = run(["docker", "run", "--rm", "--platform", f"linux/{rec.arch}", "--network", "none",
                            "-v", f"{rec.dir}:/scan:ro", THEIA, "image", "-p", "certificates",
                            "docker-archive:/scan/mldsa-image.tar"], timeout=7200)
    tar.unlink(missing_ok=True)
    sha = rec.save("theia-mldsa.txt", text)
    try:
        bom = json.loads(text[text.index("{"):text.rindex("}") + 1])
        comps = [c for c in (bom.get("components") or []) if "/etc/nginx/tls/c.pem" in json.dumps(c.get("evidence", {}))]
    except ValueError:
        comps = []
    names = sorted({c.get("name", "") for c in comps})
    oids = sorted({c.get("cryptoProperties", {}).get("oid", "") for c in comps} - {""})
    if any("ML-DSA" in n.upper() or "MLDSA" in n.upper() for n in names) or "2.16.840.1.101.3.4.3.18" in oids:
        out = "correct"
    elif comps:
        out = "wrong"
    else:
        out = "blind"
    warn = [line for line in text.splitlines() if "c.pem" in line or ("certificate" in line.lower() and "error" in line.lower())]
    rec.cell("C3", "theia", out, f"components at the file: {names or 'none'}; {(warn[:1] or [''])[0][:80]}", {"theia": sha}, secs)


# ------------------------------------------------------------------------ Zeek
def zeek_cells(rec: Recorder) -> None:
    if not _up("pqch-s2-s2-client-1"):
        rec.cell("C8", "zeek", "not run", "client not running", {}, 0)
        return
    code, _text, _ = run(["docker", "image", "inspect", ZEEK], timeout=30)
    if code != 0:
        for cap in ("C1", "C8"):
            rec.cell(cap, "zeek", "not run", "Zeek image not pulled (Docker Hub rate limit)", {}, 0)
        return
    logs = rec.dir / "zeek"
    logs.mkdir(exist_ok=True)
    logs.chmod(0o777)
    name = f"s2-zeek-{rec.arch}"
    run(["docker", "rm", "-f", name], timeout=30)
    run(["docker", "run", "-d", "--name", name, "--platform", f"linux/{rec.arch}", "--network", "container:pqch-s2-s2-client-1",
         "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN", "-v", f"{logs}:/logs", "-v", f"{HERE / 'zeek'}:/scripts:ro",
         "-w", "/logs", ZEEK, "zeek", "-C", "-i", "eth0", "/scripts/groups.zeek", "LogAscii::use_json=T"], timeout=120)
    time.sleep(60 if rec.arch == "amd64" else 240)
    run(["docker", "stop", "-t", "10", name], timeout=120)
    _, zlog, _ = run(["docker", "logs", name], timeout=60)
    run(["docker", "rm", "-f", name], timeout=30)
    if "pcap_error" in zlog:
        sha = {"zeek_stderr": rec.save("zeek-stderr.txt", zlog)}
        why = zlog.strip().splitlines()[-1][:120]
        for cap in ("C8", "C1"):
            rec.cell(cap, "zeek", "fails", f"Zeek could not open its capture interface: {why}", sha, 0)
        return
    cg = (logs / "client_groups.log").read_text() if (logs / "client_groups.log").exists() else ""
    ssl = (logs / "ssl.log").read_text() if (logs / "ssl.log").exists() else ""
    sha = {"client_groups": rec.save("zeek-client_groups.log", cg), "ssl": rec.save("zeek-ssl.log", ssl)}
    offered = [json.loads(line).get("offered", []) for line in cg.splitlines() if line.startswith("{")]
    ok8 = any(4588 in o for o in offered)
    rec.cell("C8", "zeek", "correct" if ok8 else ("blind" if not offered else "wrong"),
             f"{len(offered)} client hellos; first offered {offered[0] if offered else 'none'} (4588 = X25519MLKEM768)", sha, 0)
    # C1 is judged on both sides: the hybrid group with the hybrid listener, and never with
    # the classical one (M0B review F-62: the first run only ever saw api).
    by_server: dict[str, set] = {}
    for line in ssl.splitlines():
        if line.startswith("{"):
            entry = json.loads(line)
            by_server.setdefault(entry.get("id.resp_h", "?"), set()).add(str(entry.get("curve", "?")))
    api, portal = by_server.get("172.16.106.11", set()), by_server.get("172.16.106.10", set())
    hybrid_api = any("MLKEM" in c.upper() or "4588" in c for c in api)
    hybrid_portal = any("MLKEM" in c.upper() or "4588" in c for c in portal)
    outcome = "blind" if not api or not portal else ("correct" if hybrid_api and not hybrid_portal else "wrong")
    rec.cell("C1", "zeek", outcome, f"negotiated, ssl.log curve: api {sorted(api)}; portal {sorted(portal)}", sha, 0)


# -------------------------------------------------------------------- Opengrep
def opengrep_cell(rec: Recorder) -> None:
    bindir = HERE / "results" / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    binary = bindir / OPENGREP[rec.arch]
    if not binary.exists():
        run(["curl", "-sSL", "-o", str(binary), OPENGREP_URL + OPENGREP[rec.arch]], timeout=600)
        binary.chmod(0o755)
    _code, text, secs = run(["docker", "run", "--rm", "--platform", f"linux/{rec.arch}", "--network", "none",
                            "-v", f"{bindir}:/bin-og:ro", "-v", f"{HERE / 'ruby'}:/src:ro", "-e", "HOME=/tmp",
                            "--entrypoint", f"/bin-og/{OPENGREP[rec.arch]}", OPENSSL_IMAGE[rec.arch],
                            "scan", "--json", "--quiet", "--config", "/src/rules.yaml", "/src/sample.rb"], timeout=3600)
    sha = rec.save("opengrep.json", text)
    try:
        hits = [(r["path"], r["start"]["line"]) for r in json.loads(text[text.index("{"):])["results"]]
    except ValueError:
        hits = []
    ok = hits == [("/src/sample.rb", 6)]
    rec.cell("C9", "opengrep", "correct" if ok else ("blind" if not hits else "wrong"),
             f"hits {hits}; binary sha256 {hashlib.sha256(binary.read_bytes()).hexdigest()[:16]}", {"opengrep": sha}, secs)


def main() -> None:
    arch = sys.argv[1]
    only = set(sys.argv[sys.argv.index("--only") + 1].split(",")) if "--only" in sys.argv else set()
    rec = Recorder(arch)
    print(f"S2 on {arch}", flush=True)
    if not only or only & {"C1", "C3", "C4", "C5", "C6", "C7"}:
        tls_cells(rec, only)
    if not only or "C2" in only:
        ssh_cells(rec)
    if not only or "C3" in only:
        theia_cell(rec)
    if not only or only & {"C1", "C8"}:
        zeek_cells(rec)
    if not only or "C9" in only:
        opengrep_cell(rec)
    rec.write()


if __name__ == "__main__":
    main()
