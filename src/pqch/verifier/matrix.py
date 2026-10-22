"""The compatibility matrix: kinds of client against the server as it runs and as the change proposes.

Before a person approves a change, the question is not only whether it lands but who it shuts out. A
`require` change refuses every client that cannot offer the hybrid group; an `enable` change refuses
no one. The matrix answers it by probe, the way the verifier answers everything: one handshake per
kind of client, against the listener as deployed and against a copy started in the twin with the
proposed file. No model takes part.

The clients are profiles, not products: what each offers is stated, and a reader maps their own
clients onto them. The result is a `matrix.completed` event in the change run, beside the rehearsal.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from pqch.run import Run
from pqch.runner.client import RunnerRefused
from pqch.scout import read_raw
from pqch.verifier import ACTOR, _probe_record, parse_probe, parse_ssh_probe

# Each client: what it offers, and the runner job that offers exactly that.
TLS_CLIENTS = [
    {"id": "pq-only", "label": "post-quantum only", "offers": "X25519MLKEM768, TLS 1.3",
     "job": ("tls-group-probe", {"groups": "X25519MLKEM768", "tls13": "-tls1_3"})},
    {"id": "hybrid-first", "label": "hybrid first, classical fallback", "offers": "X25519MLKEM768, X25519, P-256; TLS 1.3 or 1.2",
     "job": ("tls-group-probe", {"groups": "X25519MLKEM768:X25519:P-256", "tls13": ""})},
    {"id": "classical-13", "label": "classical, TLS 1.3", "offers": "X25519, P-256, P-384; TLS 1.3",
     "job": ("tls-group-probe", {"groups": "X25519:P-256:P-384", "tls13": "-tls1_3"})},
    {"id": "tls12", "label": "TLS 1.2 only", "offers": "OpenSSL's default groups and suites, TLS 1.2",
     "job": ("tls-legacy-probe", {})},
]
SSH_CLIENTS = [
    {"id": "pq-only", "label": "post-quantum only", "offers": "mlkem768x25519-sha256",
     "job": ("ssh-kex-probe", {"kex": "mlkem768x25519-sha256"})},
    {"id": "hybrid-first", "label": "hybrid first, classical fallback",
     "offers": "mlkem768x25519-sha256, sntrup761x25519-sha512, curve25519-sha256, ecdh-sha2-nistp256",
     "job": ("ssh-kex-probe", {"kex": "mlkem768x25519-sha256,sntrup761x25519-sha512,curve25519-sha256,ecdh-sha2-nistp256"})},
    {"id": "classical", "label": "classical", "offers": "curve25519-sha256, ecdh-sha2-nistp256, diffie-hellman-group14-sha256",
     "job": ("ssh-kex-probe", {"kex": "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256"})},
]


def clients_for(check: dict) -> list[dict]:
    if check.get("kind") == "ssh-kex":
        return SSH_CLIENTS
    pg = (check.get("target") or {}).get("protocol") == "postgres"
    return [{**c, "job": (c["job"][0] + ("-postgres" if pg else ""), c["job"][1])} for c in TLS_CLIENTS]


def effect(today: str, proposed: str) -> str:
    """What the change does to one kind of client."""
    if today == "accepted" and proposed == "refused":
        return "shut out"
    if today == "refused" and proposed == "accepted":
        return "let in"
    if today == proposed == "accepted":
        return "unchanged, served"
    if today == proposed == "refused":
        return "unchanged, refused"
    return "cannot tell"


def run_matrix(run: Run, client, signer, change_id: str, *, hardware: str = "unlabelled") -> dict:
    events = list(run.ledger.events())
    prop = next(e for e in events if e["type"] == "change.proposed" and e["payload"]["change_id"] == change_id)
    check = prop["payload"]["check"]
    scope_hash = events[0]["payload"]["scope_hash"]
    clients = clients_for(check)
    live = {"host": check["target"]["host"], "port": check["target"]["port"]}
    parse = parse_ssh_probe if check.get("kind") == "ssh-kex" else parse_probe

    def probe(target, c):
        profile, params = c["job"]
        try:
            job = client.job(profile, target, scope_hash, params or None)
        except RunnerRefused as e:
            return {"name": c["id"], "result": "error", "why": f"the runner refused the job ({e.code}: {e.reason})"}
        if job["status"] != "ok" or not job.get("raw"):
            return {"name": c["id"], "result": "error", "why": f"scan {job['status']}"}
        return _probe_record(c["id"], job, parse(read_raw(run.var, job).decode(errors="replace")))

    entry = client.rehearse(run.id, change_id)
    try:
        twin = None
        if entry["listening"]:
            host, port = entry["twin"].rsplit(":", 1)
            twin = {"host": host, "port": int(port)}
        with ThreadPoolExecutor(len(clients) * 2) as pool:
            today = list(pool.map(lambda c: probe(live, c), clients))
            proposed = list(pool.map(lambda c: probe(twin, c), clients)) if twin else [
                {"name": c["id"], "result": "error", "why": "the copy did not start with the proposed file"} for c in clients]
    finally:
        client.rehearse_end(run.id, change_id)
    rows = []
    for c, t, p in zip(clients, today, proposed):
        rows.append({"client": c["id"], "label": c["label"], "offers": c["offers"], "today": t, "proposed": p,
                     "effect": effect(t["result"], p["result"])})
    payload = {"change_id": change_id, "intent": prop["payload"]["intent"], "target": prop["payload"]["target"],
               "twin": entry["twin"], "twin_container": entry["container"], "config_sha256": entry["config_sha256"],
               "rows": rows, "shut_out": [r["label"] for r in rows if r["effect"] == "shut out"],
               "hardware": hardware}
    ev = run.ledger.append("matrix.completed", ACTOR, payload, inputs=[prop["id"]])
    if signer is not None:
        run.checkpoint(signer)
    return ev
