"""Normalizers against raw output captured from the M0 slice (tests/fixtures)."""

from pathlib import Path

from pqch import schemas
from pqch.scout.normalize import normalize
from pqch.scout.normalize import testssl as tls_findings

FIX = Path(__file__).parent / "fixtures"
DIGEST = "sha256:" + "c" * 64


def job(tool, target, profile):
    return {"tool": tool, "version": "x", "image_digest": DIGEST, "profile": profile, "target": target,
            "ended_at": "2026-10-03T12:00:00.000Z", "raw": "var/raw/x.json", "raw_sha256": "d" * 64}


def names(findings, role=None, type_=None):
    return sorted(f["asset"]["name"] for f in findings
                  if (role is None or f["asset"]["role"] == role) and (type_ is None or f["asset"]["type"] == type_))


def run(fixture, tool, target, profile):
    out = normalize((FIX / fixture).read_bytes(), job(tool, target, profile))
    for f in out:
        schemas.validate(f)
    assert len({f["fingerprint"] for f in out}) == len(out)
    return out


def test_testssl_hybrid_endpoint():
    out = run("testssl-api.json", "testssl.sh", {"host": "172.16.106.11", "port": 443, "sni": "api.agency.test"}, "tls-targeted")
    assert names(out, "key-establishment") == ["X25519", "X25519MLKEM768"]
    cert = [f for f in out if f["asset"]["type"] == "certificate"]
    assert len(cert) == 1 and cert[0]["asset"]["name"] == "ECDSA"
    assert cert[0]["asset"]["parameters"]["curve"] == "P-256"
    assert len(cert[0]["asset"]["parameters"]["spki_sha256"]) == 64


def test_testssl_classical_endpoint():
    out = run("testssl-portal.json", "testssl.sh", {"host": "172.16.106.10", "port": 443}, "tls-targeted")
    assert names(out, "key-establishment") == ["X25519", "secp256r1"]
    assert names(out, type_="certificate") == ["RSA"]


def test_ssh_audit_legacy_folds_and_normalizes():
    out = run("ssh-audit-legacy.json", "ssh-audit", {"host": "172.16.106.20", "port": 22}, "ssh-targeted")
    assert names(out, "key-establishment") == ["DH-1024", "DH-2048", "DH-GEX", "X25519",
                                                "secp256r1", "secp384r1", "secp521r1"]
    assert names(out, "signature") == ["DSA", "ECDSA", "Ed25519", "RSA"]
    gex = next(f for f in out if f["asset"]["name"] == "DH-GEX")
    assert len(gex["asset"]["parameters"]["ssh_names"]) == 2


def test_ssh_audit_current_drops_pseudo_algorithms():
    out = run("ssh-audit-bastion.json", "ssh-audit", {"host": "172.16.106.21", "port": 22}, "ssh-targeted")
    assert names(out, "key-establishment") == ["X25519", "X25519MLKEM768", "sntrup761x25519"]
    rsa = next(f for f in out if f["asset"]["name"] == "RSA")
    assert rsa["asset"]["parameters"]["key_bits"] == 3072
    assert "ssh_fingerprint_sha256" in rsa["asset"]["parameters"]


def test_theia_certificates_and_keys():
    out = run("theia-portal.json", "cbomkit-theia", {"image": "pqch-agency/portal@" + DIGEST}, "image-theia")
    certs = {f["subject"]["path"]: f for f in out if f["asset"]["type"] == "certificate"}
    assert set(certs) == {"/etc/nginx/tls/portal.crt", "/etc/ssl/legacy/portal-2019.crt"}
    assert certs["/etc/ssl/legacy/portal-2019.crt"]["asset"]["parameters"]["key_bits"] == 1024
    key = [f for f in out if f["subject"]["path"] == "/etc/nginx/tls/portal.key"]
    assert [f["asset"]["name"] for f in key] == ["RSA"]


def test_theia_never_guesses_an_algorithm():
    out = run("theia-legacy.json", "cbomkit-theia", {"image": "pqch-agency/sftp-legacy@" + DIGEST}, "image-theia")
    dsa = [f for f in out if f["subject"]["path"] == "/etc/ssh/ssh_host_dsa_key"]
    assert [f["asset"]["name"] for f in dsa] == ["unknown"]
    ecdsa = next(f for f in out if f["subject"]["path"] == "/etc/ssh/ssh_host_ecdsa_key")
    assert set(ecdsa["asset"]["parameters"]["kind"]) == {"private-key", "public-key"}
    assert "ssh_fingerprint_sha256" in ecdsa["asset"]["parameters"]


def _theia(digest):
    return run("theia-portal.json", "cbomkit-theia", {"image": "pqch-agency/portal@" + digest}, "image-theia")


def test_host_subject_names_the_repository_and_source_carries_the_digest():
    out = _theia(DIGEST)
    assert {f["subject"]["image"] for f in out} == {"pqch-agency/portal"}
    assert {f["source"]["subject_digest"] for f in out} == {DIGEST}


def test_a_rebuilt_image_holding_the_same_keys_gives_the_same_fingerprints():
    a = {f["fingerprint"] for f in _theia("sha256:" + "1" * 64)}
    b = {f["fingerprint"] for f in _theia("sha256:" + "2" * 64)}
    assert a == b


def test_same_place_same_family_different_key_is_a_different_finding():
    import json as _json

    raw = (FIX / "theia-portal.json").read_bytes()
    doc = _json.loads(raw)
    # Swap the served certificate's public key for the decoy's: same path, same family (RSA).
    pub = {c["bom-ref"]: c for c in doc["components"] if c.get("bom-ref")}
    certs = [c for c in doc["components"] if c.get("cryptoProperties", {}).get("assetType") == "certificate"]
    served = next(c for c in certs if c["evidence"]["occurrences"][0]["location"] == "/etc/nginx/tls/portal.crt")
    decoy = next(c for c in certs if c is not served)
    served_key = pub[served["cryptoProperties"]["certificateProperties"]["subjectPublicKeyRef"]]
    decoy_key = pub[decoy["cryptoProperties"]["certificateProperties"]["subjectPublicKeyRef"]]
    served_key["cryptoProperties"]["relatedCryptoMaterialProperties"]["value"] = \
        decoy_key["cryptoProperties"]["relatedCryptoMaterialProperties"]["value"]
    j = job("cbomkit-theia", {"image": "pqch-agency/portal@" + DIGEST}, "image-theia")
    before = next(f for f in normalize(raw, j) if f["asset"]["type"] == "certificate"
                  and f["subject"]["path"] == "/etc/nginx/tls/portal.crt")
    after = next(f for f in normalize(_json.dumps(doc).encode(), j) if f["asset"]["type"] == "certificate"
                 and f["subject"]["path"] == "/etc/nginx/tls/portal.crt")
    assert before["asset"]["name"] == after["asset"]["name"] == "RSA"
    assert before["asset"]["identity"] != after["asset"]["identity"]
    assert before["fingerprint"] != after["fingerprint"]


def test_identity_forms():
    wire = run("ssh-audit-legacy.json", "ssh-audit", {"host": "172.16.106.20", "port": 22}, "ssh-targeted")
    keys = [f for f in wire if f["asset"]["role"] == "signature"]
    assert all(f["asset"]["identity"].startswith("openssh-sha256:") for f in keys)
    host = run("theia-legacy.json", "cbomkit-theia", {"image": "pqch-agency/sftp-legacy@" + DIGEST}, "image-theia")
    ecdsa = [f for f in host if f["subject"]["path"] == "/etc/ssh/ssh_host_ecdsa_key"]
    assert len(ecdsa) == 1 and ecdsa[0]["asset"]["identity"].startswith("spki-sha256:")
    dsa = [f for f in host if f["subject"]["path"] == "/etc/ssh/ssh_host_dsa_key"]
    assert "identity" not in dsa[0]["asset"]


def test_rsa_key_transport_is_a_key_establishment_finding():
    """M0B review F-62: Postgres with hybrid groups configured still accepts TLS_RSA_WITH_* suites."""
    raw = (FIX / "testssl-postgres-rsa-kx.json").read_bytes()
    job = {"tool": "testssl.sh", "version": "3.2.4", "image_digest": "sha256:" + "e" * 64, "profile": "tls-targeted",
           "target": {"host": "172.16.106.42", "port": 5432}, "ended_at": "2026-10-05T19:40:00.000Z",
           "raw": "var/raw/x.json", "raw_sha256": "0" * 64}
    found = {(f["asset"]["role"], f["asset"]["name"]): f for f in tls_findings(raw, job)}
    kx = found[("key-establishment", "RSA")]
    # A job's target without a protocol is a plain TLS listener; with one, the finding is about
    # that listener (the scope's `postgres`), so the rules and the key find it at the same subject.
    assert kx["subject"]["protocol"] == "tls"
    pg = tls_findings(raw, {**job, "profile": "tls-starttls-postgres",
                            "target": {"host": "172.16.106.42", "port": 5432, "protocol": "postgres"}})
    assert {f["subject"]["protocol"] for f in pg} == {"postgres"}
    assert kx["asset"]["type"] == "algorithm" and kx["asset"]["parameters"]["mode"] == "key-transport"
    assert "TLS_RSA_WITH_AES_256_GCM_SHA384" in kx["asset"]["parameters"]["suites"]
    assert kx["asset"]["parameters"]["tls_versions"] == ["TLSv1.2"]
    # The groups are still there beside it: one listener, both kinds of key establishment.
    assert ("key-establishment", "X25519MLKEM768") in found and ("key-establishment", "X25519") in found


def test_a_listener_with_only_ecdhe_suites_yields_no_key_transport():
    job = {"tool": "testssl.sh", "version": "3.2.4", "image_digest": "sha256:" + "e" * 64, "profile": "tls-targeted",
           "target": {"host": "172.16.106.10", "port": 443}, "ended_at": "2026-10-05T19:40:00.000Z",
           "raw": "var/raw/x.json", "raw_sha256": "0" * 64}
    names_ = {(f["asset"]["role"], f["asset"]["name"]) for f in tls_findings((FIX / "testssl-portal.json").read_bytes(), job)}
    assert ("key-establishment", "RSA") not in names_


def test_a_finite_field_group_named_by_a_phrase_is_one_finding():
    """testssl.sh says `RFC3526/Oakley Group 14`; split on spaces that was three algorithms, one of them `14`."""
    from pqch.scout import names as n
    assert n.dh_groups("RFC3526/Oakley Group 14") == [("DH-2048", "RFC3526/Oakley Group 14")]
    assert n.dh_groups("Unknown DH group (2048 bits)") == [("DH-2048", "Unknown DH group (2048 bits)")]
    assert [x for x, _ in n.dh_groups("ffdhe2048 ffdhe3072")] == ["ffdhe2048", "ffdhe3072"]
    raw = (FIX / "testssl-postgres-rsa-kx.json").read_bytes()
    kex = names(tls_findings(raw, job("testssl.sh", {"host": "172.16.106.42", "port": 5432}, "tls-targeted")), role="key-establishment")
    assert "DH-2048" in kex and not {"14", "Group", "RFC3526/Oakley"} & set(kex)
