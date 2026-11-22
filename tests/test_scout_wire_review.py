"""The wire scout after the 2026-11 review: a scan the tool says did not happen is not a clean scan,
one certificate the library cannot read does not lose the listener, and the names are the pack's."""

import datetime
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

from pqch import scout
from pqch.assessor import gaps
from pqch.scout import names
from pqch.scout.keys import parse_certificate_pem
from pqch.scout.normalize import normalize, sbom_facts, tool_problem
from tests.conftest import make_run

FIX = Path(__file__).parent / "fixtures"
JOB = {"version": "x", "image_digest": "sha256:" + "c" * 64, "ended_at": "2026-10-03T12:00:00.000Z",
       "raw": "var/raw/x.json", "raw_sha256": "d" * 64}
TLS = {**JOB, "tool": "testssl.sh", "profile": "tls-targeted", "target": {"host": "172.16.106.10", "port": 443}}
SSH = {**JOB, "tool": "ssh-audit", "profile": "ssh-targeted", "target": {"host": "172.16.106.20", "port": 22}}


# ------------------------------------------------------------ a scan that did not happen
def test_the_tools_own_words_say_a_listener_was_not_reached():
    """Both shapes are real raw output (addresses replaced): testssl.sh exits 246 with a FATAL
    scanProblem, ssh-audit exits 1 with a line of text where its JSON would be."""
    t = tool_problem((FIX / "testssl-unreachable.json").read_bytes(), TLS)
    assert t["reached"] is False and t["reason"].startswith("Can't connect to '192.0.2.10:443'")
    s = tool_problem((FIX / "ssh-audit-unreachable.txt").read_bytes(), SSH)
    assert s == {"reason": "[exception] cannot connect to 192.0.2.10 port 22: timed out", "output": False, "reached": False}
    # A scan that read its listener has no problem, whatever its exit code was.
    assert tool_problem((FIX / "testssl-portal.json").read_bytes(), TLS) is None
    assert tool_problem((FIX / "ssh-audit-legacy.json").read_bytes(), SSH) is None


def test_an_unreached_listener_is_recorded_as_unreached_and_is_not_counted_as_reached(tmp_path):
    jobs = [("testssl-unreachable.json", "tls-targeted", "testssl.sh", {"host": "172.16.106.10", "port": 443}),
            ("ssh-audit-unreachable.txt", "ssh-targeted", "ssh-audit", {"host": "172.16.106.20", "port": 22}),
            ("testssl-api.json", "tls-targeted", "testssl.sh", {"host": "172.16.106.11", "port": 443, "sni": "api.agency.test"})]
    run = make_run(tmp_path, jobs=jobs)
    events = list(run.ledger.events())
    scans = {e["payload"]["target"]["host"]: e["payload"] for e in events if e["type"] == "scan.completed"}
    for host in ("172.16.106.10", "172.16.106.20"):
        p = scans[host]
        assert p["status"] == "unreached" and p["runner_status"] == "ok" and p["reached"] is False
        assert "connect" in p["reason"] and p["findings"] == 0 and "normalize_error" not in p
        assert not scout.scan_ok(p)
    assert scans["172.16.106.11"]["status"] == "ok" and scout.scan_ok(scans["172.16.106.11"])
    reached = gaps._reached(events)["listeners"]["reached"]
    assert reached == 1


def test_a_scan_that_failed_to_normalize_or_exited_badly_is_never_replayed(tmp_path):
    var = tmp_path / "var"
    run = make_run(tmp_path, jobs=[])
    target = {"image": "pqch-agency/portal@sha256:" + "1" * 64}
    base = {"profile": "image-theia", "target": target, "tool": "cbomkit-theia", "version": "x", "image_digest": "sha256:" + "c" * 64,
            "started_at": "2026-10-03T12:00:00.000Z", "ended_at": "2026-10-03T12:00:30.000Z", "duration_ms": 1,
            "raw": "var/raw/t.json", "raw_sha256": "0" * 64, "findings": 0}
    run.ledger.append("scan.completed", scout.RUNNER_ACTOR, {**base, "status": "ok", "exit_code": 1})
    run.ledger.append("scan.completed", scout.RUNNER_ACTOR, {**base, "status": "ok", "exit_code": 0, "normalize_error": "ValueError: x"})
    assert scout.find_prior_scan(var, "image-theia", target, "other") is None
    run.ledger.append("scan.completed", scout.RUNNER_ACTOR, {**base, "status": "ok", "exit_code": 0})
    assert scout.find_prior_scan(var, "image-theia", target, "other") is not None


# ------------------------------------------------------------ certificates
def _cert(subject, issuer, key, signer, *, ca=False):
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.UTC)
    name = lambda cn: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])  # noqa: E731
    return (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer)).public_key(key.public_key())
            .serial_number(7).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, ca, ca, False, False), True)
            .sign(signer, hashes.SHA256()))


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _unknown_key_certificate() -> tuple[str, str]:
    """A certificate whose key algorithm the library does not load: an Ed25519 key signed by an EC
    CA, with the SPKI's algorithm OID changed from 1.3.101.112 to 1.3.101.127. Returns the PEM and
    the SHA-256 of its SubjectPublicKeyInfo."""
    ca, leaf = ec.generate_private_key(ec.SECP256R1()), ed25519.Ed25519PrivateKey.generate()
    der = _cert("odd.agency.test", "ca.agency.test", leaf, ca).public_bytes(serialization.Encoding.DER)
    oid = bytes.fromhex("06032b6570")
    assert der.count(oid) == 1
    spki = leaf.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    patched = der.replace(oid, bytes.fromhex("06032b657f"))
    pem = x509.load_der_x509_certificate(patched).public_bytes(serialization.Encoding.PEM).decode()
    return pem, hashlib.sha256(spki.replace(oid, bytes.fromhex("06032b657f"))).hexdigest()


def test_a_certificate_with_a_key_the_library_cannot_load_is_still_parsed():
    pem, spki_sha256 = _unknown_key_certificate()
    info = parse_certificate_pem(pem)
    assert info["family"] == "unknown" and info["key_algorithm_oid"] == "1.3.101.127"
    assert info["spki_sha256"] == spki_sha256                  # the SPKI element alone, cut from the certificate
    assert info["subject"] == "CN=odd.agency.test" and "key_parse_error" in info


def test_one_unreadable_certificate_does_not_lose_the_listeners_other_findings():
    pem, _ = _unknown_key_certificate()
    entries = [{"id": "FS_KEMs", "finding": "X25519MLKEM768"},
               {"id": "cipher-tls1_3_x1302", "finding": "TLSv1.3   x1302   TLS_AES_256_GCM_SHA384   any   AESGCM   256   TLS_AES_256_GCM_SHA384"},
               {"id": "cert_signatureAlgorithm", "finding": "SHA256 with RSA"}, {"id": "cert_keySize", "finding": "? 0 bits"},
               {"id": "cert_fingerprintSHA256", "finding": "AB" * 32},
               ]

    def scan(cert_text):
        out = normalize(json.dumps([*entries, {"id": "cert", "finding": cert_text}]).encode(), TLS)
        by = {(f["asset"]["type"], f["asset"]["name"]) for f in out}
        assert ("algorithm", "X25519MLKEM768") in by and ("protocol", "TLS 1.3") in by
        certs = [f for f in out if f["asset"]["type"] == "certificate"]
        assert len(certs) == 1 and certs[0]["asset"]["name"] == "unknown"
        return certs[0]["asset"]

    # A key algorithm the library does not load: everything else the certificate says is kept.
    odd = scan(pem)
    assert odd["parameters"]["key_algorithm_oid"] == "1.3.101.127" and odd["identity"].startswith("spki-sha256:")
    assert odd["parameters"]["subject"] == "CN=odd.agency.test"
    # A certificate that cannot be read at all: what the tool said of it, and why it was not read.
    broken = scan("-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----")
    assert broken["parameters"]["parse_error"] and broken["parameters"]["cert_sha256"] == "ab" * 32
    assert broken["parameters"]["signature"] == "SHA256 with RSA" and "identity" not in broken


def test_the_chain_a_server_sends_reaches_the_ledger_on_its_leaf():
    """testssl.sh writes each certificate above the leaf as `intermediate_cert <#n>` (ids as in the
    lab's raw output; the certificates are made here)."""
    root_key, mid_key, leaf_key = (ec.generate_private_key(ec.SECP384R1()), ec.generate_private_key(ec.SECP384R1()),
                                   ec.generate_private_key(ec.SECP256R1()))
    root = _cert("root.agency.test", "root.agency.test", root_key, root_key, ca=True)
    mid = _cert("issuing.agency.test", "root.agency.test", mid_key, root_key, ca=True)
    leaf = _cert("www.agency.test", "issuing.agency.test", leaf_key, mid_key)
    entries = [{"id": "cert", "finding": _pem(leaf)}, {"id": "cert_commonName", "finding": "www.agency.test"},
               {"id": "cert_commonName_wo_SNI", "finding": "default.agency.test"},
               {"id": "intermediate_cert <#2>", "finding": _pem(root)}, {"id": "intermediate_cert <#1>", "finding": _pem(mid)},
               {"id": "intermediate_cert_fingerprintSHA256 <#1>", "finding": "00"},
               {"id": "intermediate_cert_badOCSP", "finding": "intermediate certificate(s) is/are ok"}]
    out = normalize(json.dumps(entries).encode(), TLS)
    certs = [f for f in out if f["asset"]["type"] == "certificate"]
    assert len(certs) == 1                                     # the listener's certificate is still exactly the leaf
    p = certs[0]["asset"]["parameters"]
    assert p["subject"] == "CN=www.agency.test" and p["common_name_without_sni"] == "default.agency.test"
    chain = p["served_chain"]
    assert [(c["position"], c["subject"], c["family"], c["curve"], c["is_ca"]) for c in chain] == [
        (1, "CN=issuing.agency.test", "ECDSA", "P-384", True), (2, "CN=root.agency.test", "ECDSA", "P-384", True)]
    assert chain[1]["self_signed"] is True and chain[0]["not_after"].startswith("2027-01-01") and len(chain[0]["spki_sha256"]) == 64


# ------------------------------------------------------------ names
def test_group_ids_are_named_as_the_registry_names_them_and_the_pack_says_which_are_post_quantum():
    assert names.tls_group(25497) == "X25519Kyber768Draft00" and names.tls_group(25498) == "SecP256r1Kyber768Draft00"
    assert names.tls_group(65072) == "X25519Kyber512Draft00" and names.tls_group(65074) == "SecP256r1Kyber768Draft00"
    assert names.tls_group(41) == "curveSM2" and names.tls_group(4590) == "curveSM2MLKEM768"
    assert {513, 4587, 4588, 4589, 4590, 25497, 25498, 65072, 65073, 65074} <= names.PQ_GROUP_IDS
    assert not {23, 29, 41, 256} & names.PQ_GROUP_IDS
    assert names.is_pq_key_establishment("ML-KEM-768") and names.is_pq_key_establishment("sntrup761x25519")
    assert not names.is_pq_key_establishment("X25519")
    assert names.PACK["version"] == 3


def test_a_protocol_version_has_one_name_whoever_spelled_it():
    for spelling, name in (("TLSv1", "TLS 1.0"), ("TLSv10", "TLS 1.0"), ("TLSv1.3", "TLS 1.3"), ("TLSv13", "TLS 1.3"),
                           ("SSLv3", "SSL 3.0"), ("DTLSv12", "DTLS 1.2"), ("unknown-64282", "unknown-64282")):
        assert names.tls_version_name(spelling) == name
    # testssl.sh's own cipher lines for a legacy listener (the line shapes are the lab's raw output).
    entries = [{"id": "cipher-tls1_xc014", "finding": "TLSv1   xc014   ECDHE-RSA-AES256-SHA              ECDH 256   AES   256   TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"},
               {"id": "cipher-tls1_x35", "finding": "TLSv1   x35     AES256-SHA                        RSA        AES   256   TLS_RSA_WITH_AES_256_CBC_SHA"},
               {"id": "cipher-ssl3_x35", "finding": "SSLv3   x35     AES256-SHA                        RSA        AES   256   TLS_RSA_WITH_AES_256_CBC_SHA"}]
    out = normalize(json.dumps(entries).encode(), TLS)
    assert sorted(f["asset"]["name"] for f in out if f["asset"]["type"] == "protocol") == ["SSL 3.0", "TLS 1.0"]
    kx = next(f for f in out if f["asset"]["name"] == "RSA")
    assert kx["asset"]["parameters"]["tls_versions"] == ["SSL 3.0", "TLS 1.0"]


def test_a_fixed_prime_named_by_its_source_folds_onto_its_group():
    assert names.dh_groups("RFC7919/ffdhe2048") == [("ffdhe2048", "RFC7919/ffdhe2048")]
    phrase = "RFC5114/1024-bit DSA group with 160-bit prime order subgroup"
    assert names.dh_groups(phrase) == [("DH-1024", phrase)]
    assert names.dh_groups("something else entirely") == [("something else entirely", "something else entirely")]


def test_a_key_name_with_its_kind_spelled_out_is_still_its_family():
    assert names.key_family("RSA public key") == "RSA" and names.key_family("ECDSA public key") == "ECDSA"
    assert names.key_family("ML-DSA-65 public key") == "ML-DSA-65" and names.key_family("ML-DSA-65") == "ML-DSA-65"
    assert names.key_family("RSA-2048") == "RSA" and names.key_family("private-key") == "unknown"


# ------------------------------------------------------------ ssh
def _ssh(kex):
    return normalize(json.dumps({"banner": {"protocol": "2.0", "raw": "SSH-2.0-dropbear"}, "kex": kex, "key": [],
                                 "enc": [], "mac": []}).encode(), SSH)


def test_dropbears_kexguess2_marker_is_not_a_key_exchange():
    out = _ssh([{"algorithm": "curve25519-sha256"}, {"algorithm": "kexguess2@matt.ucc.asn.au"}, {"algorithm": "kex-strict-s-v00@openssh.com"}])
    assert [f["asset"]["name"] for f in out if f["asset"]["role"] == "key-establishment"] == ["X25519"]
    proto = next(f for f in out if f["asset"]["type"] == "protocol")
    assert proto["asset"]["parameters"]["key_exchange"] == ["curve25519-sha256"]


def test_the_group_exchange_modulus_the_server_handed_over_is_kept():
    out = normalize((FIX / "ssh-audit-legacy.json").read_bytes(), SSH)
    gex = next(f for f in out if f["asset"]["name"] == "DH-GEX")
    assert gex["asset"]["parameters"]["gex_modulus_bits_observed"] == 1024 and "key_bits" not in gex["asset"]["parameters"]
    assert "dissent" not in gex["asset"]
    # Two spellings that were handed different sizes: the first stands and the disagreement is recorded.
    out = _ssh([{"algorithm": "diffie-hellman-group-exchange-sha256", "keysize": 4096},
                {"algorithm": "diffie-hellman-group-exchange-sha1", "keysize": 1024}])
    gex = next(f for f in out if f["asset"]["name"] == "DH-GEX")
    assert gex["asset"]["parameters"]["gex_modulus_bits_observed"] == 4096
    assert gex["asset"]["dissent"] == {"gex_modulus_bits_observed": ["4096", "1024"]}


# ------------------------------------------------------------ one address, several names
def test_a_listener_listed_under_two_names_is_scanned_once_for_each():
    eps = [{"host": "192.0.2.1", "port": 443, "protocol": "tls", "sni": "a.example"},
           {"host": "192.0.2.1", "port": 443, "protocol": "tls", "sni": "b.example"},
           {"host": "10.0.0.2", "port": 443, "protocol": "tls", "sni": "c.example"},
           {"host": "192.0.2.3", "port": 22, "protocol": "ssh"}, {"host": "192.0.2.3", "port": 22, "protocol": "ssh"}]
    assert scout.plan({"endpoints": eps, "images": []}) == [
        ("tls-targeted", {"host": "192.0.2.1", "port": 443, "sni": "a.example"}),
        ("tls-targeted", {"host": "192.0.2.1", "port": 443, "sni": "b.example"}),
        ("tls-targeted", {"host": "10.0.0.2", "port": 443}),
        ("ssh-targeted", {"host": "192.0.2.3", "port": 22})]


# ------------------------------------------------------------ the SBOM's libraries
def test_a_name_service_module_is_not_a_cryptography_library():
    doc = {"specVersion": "1.6", "components": [
        {"type": "library", "name": n, "version": "1", "purl": f"pkg:deb/debian/{n}@1"}
        for n in ("libnss-wrapper", "libnss3", "krb5-locales", "libkrb5-3", "libssl3")]}
    facts = sbom_facts(json.dumps(doc).encode(), {"tool": "syft", "target": {"image": "x@sha256:1"}})
    assert [x["name"] for x in facts["crypto_libraries"]] == ["libnss3", "libssl3"]
