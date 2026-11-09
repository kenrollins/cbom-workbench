"""M6: the writer fills the standard's fields and references, writes the consumers' names beside its
own (ADR-0007), and a not-in-use entry travels as state and as the consumer copy."""

import json
from pathlib import Path

from pqch.assessor import chains, load_policy, structure
from pqch.cbom import build_all, for_consumer, project, validate

from .conftest import JOBS, make_run

CIPHER_JOBS = [("testssl-portal-ciphers.json" if f == "testssl-portal.json" else f, p, t, g) for f, p, t, g in JOBS]


def props(c: dict) -> dict:
    return {p["name"]: (json.loads(p["value"]) if p["value"][:1] in "[{" else p["value"]) for p in c.get("properties", [])}


def built(tmp_path):
    run = make_run(tmp_path, jobs=CIPHER_JOBS)
    structure(run, load_policy("policy/pq-algorithms.yaml"))
    chains.link_services(run)
    return run, project(list(run.ledger.events()))


def test_a_tls_listener_carries_version_cipher_suites_and_references(tmp_path):
    _, bom = built(tmp_path)
    byref = {c["bom-ref"]: c for c in bom["components"]}
    portal = byref["listener:172.16.106.10:443"]
    pp = portal["cryptoProperties"]["protocolProperties"]
    assert pp["type"] == "tls" and pp["version"] == "1.3"
    assert {s["name"] for s in pp["cipherSuites"]} == {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                                       "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"}
    assert next(s for s in pp["cipherSuites"] if s["name"] == "TLS_AES_128_GCM_SHA256")["identifiers"] == ["0x1301"]
    assert pp["cryptoRefArray"] and all(r in byref for r in pp["cryptoRefArray"])
    p = props(portal)
    assert p["pqch:tls-versions"] == ["TLS 1.2", "TLS 1.3"] and "RSA-PSS-RSAE+SHA256" in p["pqch:tls-signature-schemes"]
    assert p["pqch:tls-groups"] == ["X25519", "secp256r1"] and p["Supported Groups"] == "X25519, secp256r1"
    assert validate(bom) == []


def test_an_ssh_listener_carries_its_version_and_the_algorithms_the_standard_has_no_field_for(tmp_path):
    _, bom = built(tmp_path)
    byref = {c["bom-ref"]: c for c in bom["components"]}
    bastion = byref["listener:172.16.106.21:22"]
    pp = bastion["cryptoProperties"]["protocolProperties"]
    assert pp["type"] == "ssh" and pp["version"] == "2.0"
    p = props(bastion)
    assert "mlkem768x25519-sha256" in p["pqch:ssh-key-exchange"] and "ssh-ed25519" in p["pqch:ssh-host-key"]
    assert p["Key Exchange Algorithm"].startswith(p["pqch:ssh-key-exchange"][0]) and p["Host Key Algorithm"]
    assert p["pqch:ssh-encryption"] and p["Encryption Algorithm"] and p["pqch:ssh-mac"] and p["pqch:ssh-software"].startswith("OpenSSH")


def test_a_certificate_references_its_signature_algorithm_and_public_key_inside_the_document(tmp_path):
    _, bom = built(tmp_path)
    byref = {c["bom-ref"]: c for c in bom["components"]}
    certs = [c for c in bom["components"] if (c.get("cryptoProperties") or {}).get("assetType") == "certificate" and props(c).get("pqch:layer") == "wire"]
    assert certs
    for c in certs:
        cp = c["cryptoProperties"]["certificateProperties"]
        sig = byref[cp["signatureAlgorithmRef"]]
        assert props(sig)["pqch:kind"] == "referenced" and sig["cryptoProperties"]["algorithmProperties"]["primitive"] == "signature"
        assert sig["cryptoProperties"].get("oid")                                   # sha256WithRSAEncryption and the like
        key = byref[cp["subjectPublicKeyRef"]]
        rcm = key["cryptoProperties"]["relatedCryptoMaterialProperties"]
        assert rcm["type"] == "public-key" and rcm["id"].startswith("spki-sha256:") and rcm["algorithmRef"] in byref
        alg = byref[rcm["algorithmRef"]]["cryptoProperties"]["algorithmProperties"]
        assert "classicalSecurityLevel" in alg or byref[rcm["algorithmRef"]]["name"].startswith("ML-DSA")
        assert alg.get("parameterSetIdentifier") or alg.get("curve") or byref[rcm["algorithmRef"]]["name"].startswith("ML-DSA")
        p = props(c)
        assert p["pqch:signature-algorithm"] == p["Signature Algorithm"] and "-" in p["Subject Public Key Algorithm"]
    rsa2048 = next(c for c in bom["components"] if c["bom-ref"] == "alg:signature:RSA-2048")
    assert rsa2048["cryptoProperties"]["algorithmProperties"]["classicalSecurityLevel"] == 112
    assert rsa2048["cryptoProperties"]["oid"] == "1.2.840.113549.1.1.1"
    hybrid = next(c for c in bom["components"] if c["name"] == "X25519MLKEM768" and props(c).get("pqch:layer") == "wire")
    assert hybrid["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert hybrid["cryptoProperties"]["algorithmProperties"]["primitive"] == "kem"


def test_referenced_components_carry_no_layer_and_leave_the_score_alone(tmp_path):
    import yaml

    from pqch.score import score_bom

    _, bom = built(tmp_path)
    refd = [c for c in bom["components"] if props(c).get("pqch:kind") == "referenced"]
    assert refd and all("pqch:layer" not in props(c) and "evidence" not in c for c in refd)
    key = yaml.safe_load(Path("eval/answer-keys/mini-agency-m0.yaml").read_text())
    with_refs = score_bom(bom, key)
    stripped = {**bom, "components": [c for c in bom["components"] if props(c).get("pqch:kind") != "referenced"]}
    assert score_bom(stripped, key)["layers"] == with_refs["layers"]


def test_not_in_use_travels_as_state_and_as_the_consumer_copy(tmp_path):
    run, _ = built(tmp_path)
    run.close()
    docs = build_all(list(run.ledger.events()))
    full, consumer = docs["workbench"], docs["workbench-consumer"]
    unused = {c["bom-ref"] for c in full["components"] if props(c).get("pqch:in-use") == "false"}
    assert unused                                                                     # the retired certificate and what it carries
    keys_unused = [c for c in full["components"] if c["bom-ref"] in unused and (c.get("cryptoProperties") or {}).get("assetType") == "related-crypto-material"]
    assert keys_unused and all(c["cryptoProperties"]["relatedCryptoMaterialProperties"]["state"] == "deactivated" for c in keys_unused)
    assert {c["bom-ref"] for c in consumer["components"]} == {c["bom-ref"] for c in full["components"]} - unused
    assert not any(x in unused for d in consumer["dependencies"] for x in [d["ref"], *d["dependsOn"]])
    meta = {p["name"]: p["value"] for p in consumer["metadata"]["properties"]}
    assert meta["pqch:projection"] == "workbench-consumer" and json.loads(meta["pqch:consumer-copy"])["dropped"] == len(unused)
    assert validate(consumer) == [] and consumer["serialNumber"] != full["serialNumber"]
    assert for_consumer(full) == consumer
    assert (run.dir / "workbench-consumer.cdx.json").exists() is False       # build_all does not write; write_cboms does
