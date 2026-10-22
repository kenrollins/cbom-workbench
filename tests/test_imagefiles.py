"""The harness's own reader of key material in an image (pqch-image-files/1), on an archive built here."""

import io
import json
import tarfile
from datetime import datetime, timedelta, UTC

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from pqch.scout import imagefiles
from pqch.scout.normalize import normalize


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, issuer_name, pub, signer, *, ca=False, cert_sign=False, key_usage=True):
    now = datetime.now(UTC)
    b = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer_name)).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(now).not_valid_after(now + timedelta(days=30))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if key_usage:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=cert_sign,
                                          crl_sign=cert_sign, encipher_only=False, decipher_only=False), critical=True)
    return b.sign(signer, hashes.SHA256())


def _layer(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _archive(path, layers: list[bytes]) -> None:
    with tarfile.open(path, "w") as t:
        names = []
        for i, data in enumerate(layers):
            n = f"blobs/sha256/{i:064x}"
            info = tarfile.TarInfo(n)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
            names.append(n)
        m = json.dumps([{"Config": "blobs/sha256/cfg", "RepoTags": ["t/img:1"], "Layers": names}]).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(m)
        t.addfile(info, io.BytesIO(m))


@pytest.fixture(scope="module")
def archive(tmp_path_factory):
    d = tmp_path_factory.mktemp("img")
    ca_key = ec.generate_private_key(ec.SECP384R1())
    ca = _cert("Test CA", "Test CA", ca_key.public_key(), ca_key, ca=True, cert_sign=True)
    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf = _cert("www.test", "Test CA", leaf_key.public_key(), ca_key)
    # what `openssl req -x509` makes: self-signed, CA:TRUE, no keyUsage — a server certificate, not a CA's
    selfsigned = _cert("old.test", "old.test", leaf_key.public_key(), leaf_key, ca=True, key_usage=False)
    ssh_key = ed25519.Ed25519PrivateKey.generate()
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM)  # noqa: E731
    p12 = pkcs12.serialize_key_and_certificates(b"tomcat", leaf_key, leaf, [ca], serialization.BestAvailableEncryption(b"changeit"))
    p12_locked = pkcs12.serialize_key_and_certificates(b"x", leaf_key, leaf, None, serialization.BestAvailableEncryption(b"not-tried"))
    base = _layer({
        "etc/tls/ca.crt": pem(ca), "etc/tls/www.crt": pem(leaf) + pem(ca),
        "etc/tls/www.key": leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
        "etc/ssl/legacy/old.crt": pem(selfsigned),
        "etc/ssh/ssh_host_ed25519_key": ssh_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()),
        "etc/ssh/ssh_host_ed25519_key.pub": ssh_key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH),
        "opt/app/conf/keystore.p12": p12, "opt/app/conf/locked.p12": p12_locked,
        "etc/nginx/nginx.conf": b"ssl_certificate /etc/tls/www.crt;\nssl_certificate_key /etc/tls/www.key;\nssl_client_certificate /etc/tls/ca.crt;\n",
        "opt/app/conf/server.xml": b'<Certificate certificateKeystoreFile="conf/keystore.p12" certificateKeystorePassword="changeit"/>',
        "etc/tls/removed.crt": pem(leaf), "usr/lib/libfoo.so": b"\x7fELF" + b"\x00" * 100,
    })
    upper = _layer({"etc/tls/.wh.removed.crt": b""})
    p = d / "image.tar"
    _archive(p, [base, upper])
    return p, {"ca_spki": ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)}


def test_reads_certificates_keys_and_keystores_and_honours_whiteouts(archive):
    path, _ = archive
    doc = imagefiles.scan(str(path), "t/img:1")
    by = {}
    for e in doc["entries"]:
        by.setdefault(e["path"], []).append(e)
    assert "/etc/tls/removed.crt" not in by and "/usr/lib/libfoo.so" not in by
    ca, = by["/etc/tls/ca.crt"]
    assert ca["type"] == "certificate" and ca["name"] == "ECDSA" and ca["parameters"]["is_ca"] is True
    assert ca["parameters"]["referenced_by"] == ["/etc/nginx/nginx.conf"]
    www = by["/etc/tls/www.crt"]
    assert [e["name"] for e in www] == ["RSA", "ECDSA"] and www[0]["parameters"]["is_ca"] is False
    assert www[0]["parameters"]["key_bits"] == 2048 and www[0]["parameters"]["issuer"].startswith("CN=Test CA")
    old, = by["/etc/ssl/legacy/old.crt"]
    assert old["parameters"]["basic_constraints_ca"] is True and old["parameters"]["is_ca"] is False
    key, = by["/etc/tls/www.key"]
    assert key["type"] == "related-crypto-material" and key["name"] == "RSA" and key["parameters"]["kind"] == "private-key"
    assert key["parameters"]["spki_sha256"] == www[0]["parameters"]["spki_sha256"]
    ssh, = by["/etc/ssh/ssh_host_ed25519_key"]
    assert ssh["name"] == "Ed25519" and ssh["parameters"]["ssh_fingerprint_sha256"]
    pub, = by["/etc/ssh/ssh_host_ed25519_key.pub"]
    assert pub["parameters"]["ssh_fingerprint_sha256"] == ssh["parameters"]["ssh_fingerprint_sha256"]
    ks = by["/opt/app/conf/keystore.p12"]
    assert ks[0]["parameters"]["kind"] == "keystore" and ks[0]["parameters"]["password"] == "changeit"
    assert ks[0]["parameters"]["holds"] == ["private-key", "certificate", "ca-certificate"] and ks[0]["name"] == "RSA"
    assert ks[0]["parameters"]["referenced_by"] == ["/opt/app/conf/server.xml"]
    locked, = by["/opt/app/conf/locked.p12"]
    assert locked["parameters"]["opened"] is False and locked["name"] == "unknown"


def test_normalizes_to_host_findings_with_identities(archive):
    path, _ = archive
    raw = json.dumps(imagefiles.scan(str(path), "t/img:1")).encode()
    job = {"tool": "pqch-image-files", "version": "1", "image_digest": "sha256:" + "a" * 64, "profile": "image-files",
           "target": {"image": "t/img@sha256:" + "b" * 64}, "ended_at": "2026-10-19T19:00:00.000Z",
           "raw": "var/raw/x.json", "raw_sha256": "0" * 64}
    findings = normalize(raw, job)
    assert all(f["layer"] == "host" and f["subject"]["kind"] == "file" and f["subject"]["image"] == "t/img" for f in findings)
    assert all(f["source"]["subject_digest"] == "sha256:" + "b" * 64 for f in findings)
    certs = [f for f in findings if f["asset"]["type"] == "certificate" and f["subject"]["path"] == "/etc/tls/www.crt"]
    assert {f["asset"]["name"] for f in certs} == {"RSA", "ECDSA"}
    leaf = next(f for f in certs if f["asset"]["name"] == "RSA")
    assert leaf["asset"]["identity"].startswith("spki-sha256:") and leaf["asset"]["role"] == "signature"
    key = next(f for f in findings if f["subject"]["path"] == "/etc/tls/www.key")
    assert key["asset"]["parameters"]["kind"] == ["private-key"] and key["asset"]["identity"] == leaf["asset"]["identity"]
