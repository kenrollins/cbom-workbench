"""The importer reads documents as their authors write them, and scores them as it scores a scan.

Two shapes: components as assets (the facts in the standard fields, placed by `host:port`), and
components as listeners (a passive sensor's export: the facts in properties, placed by `src=…`).
Every address here is invented; the documents are hand-made to the shapes, not taken from any tool's
output.
"""

import json
from pathlib import Path

from pqch import scope as scope_mod
from pqch.assessor import load_policy, structure
from pqch.pipeline import remediated_changes, remediated_rows, write_cboms, write_score
from pqch.run import Run
from pqch.scout.imported import _tool, key_spelling, locate, run_import

from .conftest import SCOPE, make_run

M0_KEY = Path("eval/answer-keys/mini-agency-m0.yaml")
PORTAL, API, LEGACY, BASTION = "172.16.106.10:443", "172.16.106.11:443", "172.16.106.20:22", "172.16.106.21:22"


def _import(tmp_path, components, **kw):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"timestamp": "2026-11-20T00:00:00Z"},
           "components": components, **kw.pop("extra", {})}
    p = tmp_path / "doc.cdx.json"
    p.write_text(json.dumps(doc))
    (tmp_path / "var" / "runs").mkdir(parents=True, exist_ok=True)
    return run_import(tmp_path / "var", [(p, None)], SCOPE, key_path=M0_KEY, **kw)


def test_the_workbenchs_own_document_scores_as_the_scan_that_made_it(tmp_path):
    """Round trip: project a scored run, import its CBOM, and the import covers what the scan covered,
    with no false positive. The certificate's family comes through the key it references; the listener
    summaries and the referenced keys and algorithms are counted, not reported as unplaced."""
    run = make_run(tmp_path)
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    run.close()
    write_cboms(run)
    native = write_score(run, M0_KEY)["columns"]["workbench"]["layers"]["wire"]
    _r, s = run_import(run.var, [(run.dir / "workbench.cdx.json", None)], SCOPE, key_path=M0_KEY)
    wire = s["score"]["wire"]
    assert s["tool"] == "cbom-workbench"
    assert (wire["covered"], wire["denominator"], wire["false_positives"]) == (native["covered"], native["denominator"], 0)
    assert sorted(wire["covered_items"]) == sorted(native["covered_items"]) and "portal-cert" in wire["covered_items"]
    # What stays unplaced is the host layer's files, which need `PATH=IMAGE` to be found again.
    assert s["left_out"]["out_of_scope"] == 0 and s["left_out"]["referenced"] > 0 and s["left_out"]["listeners"] == 4
    assert not any(n.startswith(("related-crypto-material RSA public key", "algorithm sha256")) for n in s["unplaced_names"])


def test_a_sensors_listener_components_become_the_findings_a_scan_would_make(tmp_path):
    comps = [
        {"bom-ref": "1", "type": "cryptographic-asset", "name": f"address={API}, name=api.agency.test",
         "properties": [{"name": "Supported Groups", "value": "x25519 (0x001d),X25519MLKEM768 (0x11ec)"}],
         "evidence": {"occurrences": [{"location": f"src={API}, dst=198.51.100.30, msg=Server Hello, count=3"}]},
         "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
             "type": "tls", "version": "TLS 1.3 (0x0304),TLS 1.2 (0x0303)",
             "cipherSuites": [{"name": "TLS_AES_256_GCM_SHA384 (0x1302)"}, {"name": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)"}]}}},
        {"bom-ref": "2", "type": "cryptographic-asset", "name": f"address={BASTION}, type=server",
         "properties": [{"name": "Key Exchange Algorithm", "value": "curve25519-sha256,mlkem768x25519-sha256"},
                        {"name": "Host Key Algorithm", "value": "Ed25519,RSA-3072"},
                        {"name": "Encryption Algorithm", "value": "chacha20-poly1305@openssh.com"}],
         "evidence": {"occurrences": [{"location": f"src={BASTION}, dst=198.51.100.30, msg=Server Key Exchange, count=1"}]},
         "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "ssh", "version": "2.0"}}},
        {"bom-ref": "3", "type": "library", "name": "OpenSSH_10.0",
         "evidence": {"occurrences": [{"location": f"src={BASTION}, dst=198.51.100.30, count=1"}]}},
        # The served certificate and the authority that issued it, both seen at the listener.
        {"bom-ref": "4", "type": "cryptographic-asset", "name": "akid=aa:01, serial=0b:cd",
         "properties": [{"name": "Subject Public Key Algorithm", "value": "ECDSA-P-256"}, {"name": "Signature Algorithm", "value": "ECDSA-SHA256"},
                        {"name": "Subject Key Identifier", "value": "bb:02"}],
         "evidence": {"occurrences": [{"location": f"Active discovery query for {API}"}]},
         "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"subjectName": "api.agency.test", "issuerName": "Some CA"}}},
        {"bom-ref": "5", "type": "cryptographic-asset", "name": "akid=aa:01, serial=01",
         "properties": [{"name": "Subject Public Key Algorithm", "value": "RSA-4096"}, {"name": "Subject Key Identifier", "value": "aa:01"}],
         "evidence": {"occurrences": [{"location": f"src={API}, dst=198.51.100.30, count=1"}]},
         "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"subjectName": "Some CA", "issuerName": "Some CA"}}},
        # A client's offer, located by its destination: says nothing about what the listener accepts.
        {"bom-ref": "6", "type": "cryptographic-asset", "name": "ja4=t13d0000_aaaa_bbbb",
         "properties": [{"name": "Supported Groups", "value": "x448 (0x001e),secp521r1 (0x0019)"}],
         "evidence": {"occurrences": [{"location": f"src=198.51.100.30, dst={API}, sni=api.agency.test, msg=Client Hello, count=1"}]},
         "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "TLS 1.3 (0x0304)"}}},
        # A server the scope does not list.
        {"bom-ref": "7", "type": "cryptographic-asset", "name": "address=203.0.113.9:443, name=elsewhere.example",
         "properties": [{"name": "Supported Groups", "value": "x25519 (0x001d)"}],
         "evidence": {"occurrences": [{"location": "src=203.0.113.9:443, dst=198.51.100.30, msg=Server Hello, count=1"}]},
         "cryptoProperties": {"assetType": "protocol", "protocolProperties": {"type": "tls", "version": "TLS 1.3 (0x0304)"}}},
    ]
    vuln = {"vulnerabilities": [{"id": "RULE-1", "source": {"name": "a rule"}, "ratings": [{"severity": "RULE_SEVERITY_HIGH"}],
                                 "detail": "the tool's own judgement", "affects": [{"ref": "2"}]}]}
    run, s = _import(tmp_path, comps, tool="a sensor", observed="selected", conditions="one client, an afternoon", extra=vuln)
    got = {(f["subject"]["host"], f["asset"]["type"], f["asset"]["role"], f["asset"]["name"])
           for f in (e["payload"] for e in run.ledger.events() if e["type"] == "finding.observed")}
    api, bastion = "172.16.106.11", "172.16.106.21"
    assert {(api, "algorithm", "key-establishment", "X25519"), (api, "algorithm", "key-establishment", "X25519MLKEM768"),
            (api, "protocol", "other", "TLS 1.3"), (api, "protocol", "other", "TLS 1.2"),
            (api, "certificate", "signature", "ECDSA"), (api, "certificate", "other", "RSA"),
            (bastion, "algorithm", "key-establishment", "X25519"), (bastion, "algorithm", "key-establishment", "X25519MLKEM768"),
            (bastion, "algorithm", "signature", "Ed25519"), (bastion, "algorithm", "signature", "RSA"),
            (bastion, "protocol", "other", "SSH 2.0")} == got
    # The client's groups were never placed on the server, and the issuing authority is not a claim.
    assert not any(name in ("X448", "secp521r1") for *_x, name in got)
    wire = s["score"]["wire"]
    assert wire["false_positives"] == 0 and {"api-kex-x25519", "api-kex-x25519mlkem768", "api-cert", "bastion-hostkey-rsa"} <= set(wire["covered_items"])
    assert s["left_out"]["client_side"] == 1 and s["left_out"]["out_of_scope"] == 1 and s["unplaced"] == 1
    assert s["observation"] == {"observed": "selected", "conditions": "one client, an afternoon"}
    assert s["reported_violations"][0]["affects"] == [f"address={BASTION}, type=server"]
    assert (s["tool"], s["version"]) == ("a sensor", "unstated")
    ssh = next(e["payload"] for e in run.ledger.events() if e["type"] == "finding.observed" and e["payload"]["asset"]["name"] == "SSH 2.0")
    assert ssh["asset"]["parameters"]["software"] == "OpenSSH_10.0" and ssh["source"]["grade"] == "reported"
    rsa = next(e["payload"] for e in run.ledger.events() if e["type"] == "finding.observed"
               and e["payload"]["asset"]["name"] == "RSA" and e["payload"]["subject"]["port"] == 22)
    assert rsa["asset"]["parameters"]["key_bits"] == 3072


def test_true_facts_in_ordinary_forms_are_credited_not_charged(tmp_path):
    def alg(ref, name, prim, at, **ap):
        return {"type": "cryptographic-asset", "bom-ref": ref, "name": name, "evidence": {"occurrences": [{"location": at}]},
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": {"primitive": prim, **ap}}}

    comps = [
        {"type": "cryptographic-asset", "bom-ref": "k", "name": "ssh-ed25519", "evidence": {"occurrences": [{"location": BASTION}]},
         "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": {"type": "public-key"}}},
        alg("s", "sha256WithRSAEncryption", "signature", PORTAL),
        alg("r", "RSA-2048", "signature", PORTAL),
        alg("e", "ECDHE", "key-agree", "portal.agency.test:443", curve="x25519"),      # placed by the name the scope gives
        alg("w", "Wobble-9000", "key-agree", PORTAL),
        {"type": "cryptographic-asset", "bom-ref": "c", "name": "CN=portal.agency.test", "evidence": {"occurrences": [{"location": PORTAL}]},
         "cryptoProperties": {"assetType": "certificate", "certificateProperties": {"subjectName": "CN=portal.agency.test"}},
         "properties": [{"name": "Subject Public Key Algorithm", "value": "RSA-2048"}]},
    ]
    _run, s = _import(tmp_path, comps)
    wire = s["score"]["wire"]
    assert {"bastion-hostkey-ed25519", "portal-kex-x25519", "portal-cert"} <= set(wire["covered_items"])
    # RSA named with its size at the portal is a claim the key calls wrong (the portal's RSA is a
    # certificate, and RSA key transport there is a decoy); a name no table knows is not.
    assert wire["unrecognised"] == ["172.16.106.10:443 key-establishment Wobble-9000"]
    assert all("sha256WithRSAEncryption" not in c and "Wobble" not in c for c in wire["unplanted"])
    assert s["tool"] == "unnamed tool"


def test_spellings_locations_and_the_documents_author():
    assert key_spelling("RSA-2048") == ("RSA", {"key_bits": 2048})
    assert key_spelling("ECDSA-P-256") == ("ECDSA", {"curve": "P-256"})
    assert key_spelling("ECDSA public key") == ("ECDSA", {}) and key_spelling("Ed25519") == ("Ed25519", {})
    assert key_spelling("ML-DSA-65 public key")[0] == "ML-DSA-65"
    assert locate(f"src={API}, dst=198.51.100.3, msg=Server Hello, count=1", SCOPE)[0] == "server"
    assert locate(f"src=198.51.100.3, dst={API}, sni=x, msg=Client Hello, count=1", SCOPE)[0] == "client"
    assert locate("src=203.0.113.1:443, dst=198.51.100.3, count=1", SCOPE) == ("elsewhere", None)
    assert locate("somewhere in the building", SCOPE) == ("", None)
    bom = {"metadata": {"tools": {"components": [{"name": "ssh-audit", "version": "3.9.0"}, {"name": "cbom-workbench", "version": "m0"}]}}}
    assert _tool(bom) == ("cbom-workbench", "m0")
    assert _tool(bom, "a self-test") == ("a self-test", "unstated") and _tool({}) == ("unnamed tool", "unstated")


# ------------------------------------------------------------------------------- the remediated rule
def _change(var, ts_order, target, intent, content, *, landed=True, change_id=None):
    """A change run whose one change reached its last verdict; `ts_order` only orders the fixtures."""
    run = Run.start(var, SCOPE, runner_scope_hash=scope_mod.scope_hash(SCOPE), profile="change", kind="change")
    cid = change_id or f"CH{ts_order:02d}"
    actor = {"kind": "rule", "id": "test"}
    run.ledger.append("change.proposed", actor, {"change_id": cid, "target": target, "intent": intent, "new_content": content})
    run.ledger.append("verdict.issued", actor, {"change_id": cid, "status": "enforced", "meets_intent": landed, "durable": landed})
    return run, cid


def _row(missed, listeners):
    return {"missed": list(missed), "present": 10, "out_of_reach": 1, "denominator": 11, "listeners": listeners}


def test_only_the_latest_landed_change_excuses_and_never_the_group_it_requires(tmp_path, key):
    var = tmp_path / "var"
    (var / "runs").mkdir(parents=True)
    portal = {"service": "portal", "address": "172.16.106.10", "port": 443}
    api = {"service": "api", "address": "172.16.106.11", "port": 443}
    _change(var, 1, portal, "require", "ssl_ecdh_curve X25519MLKEM768;\n")
    _change(var, 2, portal, "none", "ssl_ecdh_curve X25519:prime256v1;\n")          # rolled back: nothing remediated
    _r, kept = _change(var, 3, api, "require", "ssl_ecdh_curve X25519MLKEM768;\n")
    later = Run.start(var, SCOPE, runner_scope_hash=scope_mod.scope_hash(SCOPE), profile="x")
    first = next(later.ledger.events())
    changes = remediated_changes(var, first)
    assert set(changes) == {("172.16.106.11", 443)} and changes[("172.16.106.11", 443)]["change_id"] == kept
    missed = ["portal-kex-x25519", "api-kex-x25519", "api-kex-x25519mlkem768", "api-cert"]
    row = _row(missed, ["172.16.106.10:443", "172.16.106.11:443"])
    remediated_rows(var, first, key, [row])
    # The api's classical group went with the change; the hybrid it requires is still there to be
    # found, a certificate is not a key exchange, and the portal's change was rolled back.
    assert [m["item"] for m in row["remediated"]] == ["api-kex-x25519"]
    assert row["missed"] == ["portal-kex-x25519", "api-kex-x25519mlkem768", "api-cert"]
    assert (row["present"], row["denominator"]) == (9, 10)
    # A column that holds nothing for the listener did not look: its misses stay misses.
    blind = _row(missed, ["172.16.106.10:443"])
    remediated_rows(var, first, key, [blind])
    assert blind["remediated"] == [] and blind["denominator"] == 11


def test_a_copy_is_excused_only_what_it_is_declared_to_carry(tmp_path, key):
    var = tmp_path / "var"
    (var / "runs").mkdir(parents=True)
    api = {"service": "api", "address": "172.16.106.11", "port": 443}
    _r, cid = _change(var, 1, api, "require", "ssl_ecdh_curve X25519MLKEM768;\n")
    from pqch.common import utc_now

    def first_of(carries):
        scope = {**SCOPE, "copy": {"of": "mini-agency", "taken": "2099-01-01T00:00:00Z", "carries": carries}}
        return {"ts": utc_now(), "payload": {"scope": scope}}

    assert remediated_changes(var, first_of([cid])) and not remediated_changes(var, first_of([]))
