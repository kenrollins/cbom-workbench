"""Build R6's items: each starting configuration observed, and one solution per intent applied and
verified to show the item can be done. Blocked items record what the runtime itself lists. No model.

    uv run python spikes/s3/build_r6.py
"""

from __future__ import annotations

import json
from pathlib import Path

import change_check
import lab
from build_r5 import SOFTWARE, numbered
from scenarios_r6 import BLOCKED, LAYOUTS

HERE = Path(__file__).resolve().parent


def findings(service: str, obs: dict, sni: str | None) -> list[dict]:
    spec = lab.SERVICES[service]
    subject = {"kind": "endpoint", "host": lab.IP, "port": spec["port"], "protocol": "tls"}
    if sni:
        subject["sni"] = sni
    out = [{"layer": "wire", "subject": subject, "asset": {"type": "algorithm", "role": "key-establishment", "name": g,
                                                         "parameters": {"tls_version": v, "accepted": True}}}
           for v, key in (("1.3", "tls13_groups"), ("1.2", "tls12_groups")) for g in obs[key]]
    if obs["rsa_key_transport"]:
        out.append({"layer": "wire", "subject": subject, "asset": {"type": "algorithm", "role": "key-establishment", "name": "RSA",
                                                                 "parameters": {"mode": "key-transport", "tls_version": "1.2"}}})
    if obs["dhe_bits"]:
        out.append({"layer": "wire", "subject": subject, "asset": {"type": "algorithm", "role": "key-establishment",
                                                                 "name": f"DH-{obs['dhe_bits']}", "parameters": {"tls_version": "1.2"}}})
    return out


def main() -> None:
    items, labels = [], []
    for lay in LAYOUTS:
        kw = {"sni": lay["sni"]} if lay.get("sni") else {}
        lab.start(lay["service"], lay["files"])
        obs, raw = lab.observe(lay["service"], **kw)
        (HERE / "observations" / f"r6-{lay['id']}-before.txt").write_text(raw)
        hybrid = "X25519MLKEM768" in obs["tls13_groups"]
        classical = bool(set(obs["tls13_groups"] + obs["tls12_groups"]) - {"X25519MLKEM768"}) or obs["rsa_key_transport"] or bool(obs["dhe_bits"])
        for intent in ("enable", "require"):
            met = hybrid if intent == "enable" else (hybrid and not classical)
            files = dict(lay["files"])
            for old, new in lay["solve"][intent]:
                assert any(old in t for t in files.values()), f"{lay['id']}/{intent}: {old!r} not found"
                files = {p: t.replace(old, new) for p, t in files.items()}
            lab.start(lay["service"], files)
            res = change_check.verify(lay["service"], intent, **kw)
            iid = f"r6-{lay['id']}-{intent}"
            ok = res["meets_intent"] and (met == (not lay["solve"][intent]))
            print(f"{'ok  ' if ok else 'FAIL'}  {iid}  already met before: {met}; with one solution: {res['status']} {res['also_accepts']}", flush=True)
            items.append({"id": iid, "role": "R6", "service": SOFTWARE[lay["service"]], "intent": intent,
                          "findings": findings(lay["service"], obs, lay.get("sni")),
                          "files": [{"path": p, "text": numbered(t)} for p, t in lay["files"].items()]})
            labels.append({"id": iid, "label": {"blocked": "none"}, "scored_by": "running the reply (change_check.run_plan)",
                           "evidence": {"before_observation": f"observations/r6-{lay['id']}-before.txt", "before_sha256": lab.sha256(raw),
                                        "intent_already_met_before": met, "a_solution_exists": res["meets_intent"],
                                        "solution_status": res["status"], "solution_probe_sha256": res["raw_sha256"]}})
    for lay in BLOCKED:
        lab.start(lay["service"], lay["files"])
        obs, raw = lab.observe(lay["service"])
        (HERE / "observations" / f"r6-{lay['id']}-before.txt").write_text(raw)
        if lay["service"] == "rabbitmq":
            own = lab.sh("docker", "exec", lab.NAME, "rabbitmqctl", "eval", "{ssl:groups(), erlang:system_info(otp_release)}.", check=False).strip()
        else:
            own = lab.sh("docker", "exec", lab.NAME, "sh", "-c", "java -XshowSettings:security:tls -version 2>&1 | grep -i -E 'version|mlkem|x25519|secp' | head -12", check=False).strip()
        (HERE / "observations" / f"r6-{lay['id']}-runtime.txt").write_text(own + "\n")
        no_hybrid = not any("MLKEM" in g.upper() for g in obs["tls13_groups"]) and "mlkem" not in own.lower()
        for intent in ("enable", "require"):
            iid = f"r6-{lay['id']}-{intent}"
            print(f"{'ok  ' if no_hybrid else 'FAIL'}  {iid}  blocked: the runtime lists no ML-KEM group ({own[:70]!r})", flush=True)
            items.append({"id": iid, "role": "R6", "service": SOFTWARE[lay["service"]], "intent": intent,
                          "findings": findings(lay["service"], obs, None),
                          "files": [{"path": p, "text": numbered(t)} for p, t in lay["files"].items()]})
            labels.append({"id": iid, "label": {"blocked": "supplier"},
                           "evidence": {"before_observation": f"observations/r6-{lay['id']}-before.txt", "before_sha256": lab.sha256(raw),
                                        "runtime_own_list": f"observations/r6-{lay['id']}-runtime.txt", "no_ml_kem_group": no_hybrid}})
    lab.stop()
    (HERE / "items" / "r6.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in items))
    (HERE / "labels" / "r6.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in labels))
    print(len(items), "items")


if __name__ == "__main__":
    main()
