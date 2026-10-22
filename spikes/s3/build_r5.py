"""Build R5's items and labels by observation: start each scenario, see the finding on the wire,
change the cause line, and see the finding go. No model.

    uv run python spikes/s3/build_r5.py [id ...]
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import lab
from scenarios_r5 import SCENARIOS

HERE = Path(__file__).resolve().parent
MARK = "  <<CAUSE"
SOFTWARE = {"nginx": "nginx 1.28 on OpenSSL 3.5 (Alpine 3.22)", "sshd": "OpenSSH 10.0 (Alpine 3.22)",
            "sshd-legacy": "OpenSSH 6.6.1 (Ubuntu 14.04)", "postgres": "PostgreSQL 18 on OpenSSL 3.5 (Debian 13)",
            "rabbitmq": "RabbitMQ 4 on Erlang/OTP 27", "kafka": "Apache Kafka 4.1.0 (KRaft, JVM TLS)"}
SSH_STD = {"curve25519-sha256": "X25519", "ecdh-sha2-nistp256": "secp256r1", "ecdh-sha2-nistp384": "secp384r1",
           "mlkem768x25519-sha256": "X25519MLKEM768", "sntrup761x25519-sha512": "sntrup761x25519",
           "diffie-hellman-group14-sha1": "DH-2048", "diffie-hellman-group1-sha1": "DH-1024", "ssh-ed25519": "Ed25519"}


def holds(obs: dict, pred: tuple) -> bool:
    kind = pred[0]
    if kind == "tls13_group":
        return pred[1] in obs["tls13_groups"]
    if kind == "tls12_group":
        return pred[1] in obs["tls12_groups"]
    if kind == "rsa_kx":
        return obs["rsa_key_transport"]
    if kind == "dhe":
        return obs["dhe_bits"] == pred[1]
    if kind in ("tls12", "tls13"):
        return obs[kind]
    if kind == "cert":
        c = obs["cert"] or {}
        return c.get("key_algorithm") == pred[1] and c.get("bits") == pred[2]
    if kind == "kex":
        return pred[1] in obs["kex"]
    if kind == "hostkey":
        return pred[1] in obs["hostkeys"]
    raise ValueError(kind)


def finding(sc: dict) -> dict:
    """The wire finding as the scout would state it (pqch.finding/1 fields that matter here)."""
    spec = lab.SERVICES[sc["service"]]
    ssh = sc["service"].startswith("sshd")
    subject = {"kind": "endpoint", "host": lab.IP, "port": spec["port"], "protocol": "ssh" if ssh else "tls"}
    if sc.get("sni"):
        subject["sni"] = sc["sni"]
    p = sc["finding"]
    asset = {
        "tls13_group": lambda: {"type": "algorithm", "role": "key-establishment", "name": p[1], "parameters": {"tls_version": "1.3", "accepted": True}},
        "tls12_group": lambda: {"type": "algorithm", "role": "key-establishment", "name": p[1], "parameters": {"tls_version": "1.2", "accepted": True}},
        "rsa_kx": lambda: {"type": "algorithm", "role": "key-establishment", "name": "RSA", "parameters": {"mode": "key-transport", "tls_version": "1.2"}},
        "dhe": lambda: {"type": "algorithm", "role": "key-establishment", "name": f"DH-{p[1]}", "parameters": {"tls_version": "1.2", "kind": "finite-field DHE"}},
        "tls12": lambda: {"type": "protocol", "role": "other", "name": "TLS 1.2", "parameters": {"accepted": True}},
        "tls13": lambda: {"type": "protocol", "role": "other", "name": "TLS 1.3", "parameters": {"accepted": True}},
        "cert": lambda: {"type": "certificate", "role": "signature", "name": {"id-ecPublicKey": "ECDSA", "rsaEncryption": "RSA"}.get(p[1], p[1]),
                         "parameters": {"key_bits": p[2], "served": True}},
        "kex": lambda: {"type": "algorithm", "role": "key-establishment", "name": SSH_STD.get(p[1], p[1]), "parameters": {"ssh_names": [p[1]], "offered": True}},
        "hostkey": lambda: {"type": "algorithm", "role": "signature", "name": SSH_STD.get(p[1], p[1]), "parameters": {"ssh_names": [p[1]], "offered": True}},
    }[p[0]]()
    return {"layer": "wire", "subject": subject, "asset": asset}


def numbered(text: str) -> str:
    return "\n".join(f"{i:>4}  {line}" for i, line in enumerate(text.splitlines(), 1))


def build(sc: dict) -> tuple[dict, dict]:
    files, cause = {}, None
    for path, text in sc["files"].items():
        lines = text.splitlines()
        marked = [i for i, ln in enumerate(lines, 1) if ln.endswith(MARK)]
        if marked:
            cause = {"file": path, "line_start": marked[0], "line_end": marked[-1]}
        files[path] = "\n".join(ln[: -len(MARK)] if ln.endswith(MARK) else ln for ln in lines) + "\n"
    default = sc.get("cause") == "default"
    assert default != bool(cause), f"{sc['id']}: a scenario has a marked cause line or is default, not both"
    kw = {"sni": sc["sni"]} if sc.get("sni") else {}
    lab.start(sc["service"], files)
    obs, raw = lab.observe(sc["service"], **kw)
    assert holds(obs, sc["finding"]), f"{sc['id']}: the finding is not on the wire: {obs}"
    (HERE / "observations" / f"r5-{sc['id']}-base.txt").write_text(raw)
    evidence = {"base_observation": f"observations/r5-{sc['id']}-base.txt", "base_sha256": lab.sha256(raw)}
    if default:
        rx = re.compile(rf"^\s*{sc['directive']}", re.I)
        stripped = {p: "".join(ln for ln in t.splitlines(True) if not rx.match(ln)) for p, t in files.items()}
        removed = sum(t.count("\n") for t in files.values()) - sum(t.count("\n") for t in stripped.values())
        evidence["directive"] = sc["directive"]
        evidence["uncommented_lines_naming_it"] = removed
        if removed:
            lab.start(sc["service"], stripped)
            obs2, raw2 = lab.observe(sc["service"], **kw)
            assert holds(obs2, sc["finding"]), f"{sc['id']}: the finding went when the directive's lines were removed; it is not a default"
            (HERE / "observations" / f"r5-{sc['id']}-mutant.txt").write_text(raw2)
            evidence.update(mutation=f"every uncommented line naming {sc['directive']} removed; the finding stayed",
                            mutant_observation=f"observations/r5-{sc['id']}-mutant.txt", mutant_sha256=lab.sha256(raw2))
        label = {"cause": "default"}
    else:
        mutant = dict(files)
        for old, new in sc["mutate"]:
            assert any(old in t for t in mutant.values()), f"{sc['id']}: mutation text not found: {old!r}"
            mutant = {p: t.replace(old, new) for p, t in mutant.items()}
        lab.start(sc["service"], mutant)
        obs2, raw2 = lab.observe(sc["service"], **kw)
        assert not holds(obs2, sc["finding"]), f"{sc['id']}: the finding is still there after the cause line was changed"
        (HERE / "observations" / f"r5-{sc['id']}-mutant.txt").write_text(raw2)
        evidence.update(mutation="; ".join(f"{o.strip()!r} -> {n.strip()!r}" for o, n in sc["mutate"]) + "; the finding went",
                        mutant_observation=f"observations/r5-{sc['id']}-mutant.txt", mutant_sha256=lab.sha256(raw2))
        label = cause
    item = {"id": f"r5-{sc['id']}", "role": "R5", "service": SOFTWARE[sc["service"]], "finding": finding(sc),
            "files": [{"path": p, "text": numbered(t)} for p, t in files.items()]}
    return item, {"id": item["id"], "label": label, "evidence": evidence}


if __name__ == "__main__":
    only = set(sys.argv[1:])
    items_p, labels_p = HERE / "items" / "r5.jsonl", HERE / "labels" / "r5.jsonl"
    have_i = {json.loads(x)["id"]: json.loads(x) for x in items_p.read_text().splitlines()} if items_p.exists() else {}
    have_l = {json.loads(x)["id"]: json.loads(x) for x in labels_p.read_text().splitlines()} if labels_p.exists() else {}
    failed = []
    for sc in SCENARIOS:
        if only and sc["id"] not in only:
            continue
        try:
            item, label = build(sc)
            have_i[item["id"]], have_l[item["id"]] = item, label
            print(f"ok    {item['id']}  {label['label']}", flush=True)
        except (AssertionError, RuntimeError) as e:
            failed.append(sc["id"])
            print(f"FAIL  r5-{sc['id']}  {str(e)[:400]}", flush=True)
    lab.stop()
    order = [f"r5-{s['id']}" for s in SCENARIOS]
    items_p.write_text("".join(json.dumps(have_i[i], ensure_ascii=False) + "\n" for i in order if i in have_i))
    labels_p.write_text("".join(json.dumps(have_l[i], ensure_ascii=False) + "\n" for i in order if i in have_l))
    print(f"{len(have_i)} items; failed: {failed or 'none'}")
