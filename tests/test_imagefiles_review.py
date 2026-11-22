"""The image reader after the 2026-11 review: root-level whiteouts and dotfiles, hard links, a
keystore named for one format and written in another, and the key forms it passed over."""

import io
import tarfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from pqch.scout import imagefiles
from tests.test_imagefiles import _archive, _cert, _layer

PEM = serialization.Encoding.PEM


@pytest.fixture(scope="module")
def material():
    key = rsa.generate_private_key(65537, 2048)
    cert = _cert("www.test", "www.test", key.public_key(), key)
    return key, cert


def _links(links: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, target in links.items():
            info = tarfile.TarInfo(name)
            info.type, info.linkname = tarfile.LNKTYPE, target
            t.addfile(info)
    return buf.getvalue()


@pytest.mark.parametrize("whiteout", [".wh.app", "./.wh.app", "/.wh.app"])
def test_a_directory_removed_at_the_root_in_a_later_layer_is_gone(tmp_path, material, whiteout):
    """`RUN rm -rf /app` writes `.wh.app` at the layer's root; stripping the leading dot hid it."""
    _key, cert = material
    base = _layer({"app/tls/server.crt": cert.public_bytes(PEM), "app/tls/server.pem": cert.public_bytes(PEM),
                   "etc/tls/kept.crt": cert.public_bytes(PEM)})
    _archive(tmp_path / "i.tar", [base, _layer({whiteout: b""})])
    files, layers, _, _ = imagefiles.files_of(str(tmp_path / "i.tar"))
    assert sorted(files) == ["etc/tls/kept.crt"] and layers == 2


def test_an_opaque_root_and_a_root_level_dotfile_keep_their_meaning_and_name(tmp_path, material):
    _key, cert = material
    base = _layer({"old/a.crt": cert.public_bytes(PEM)})
    upper = _layer({".wh..wh..opq": b"", "./.env.pem": cert.public_bytes(PEM), ".ssh/id.pub.pem": cert.public_bytes(PEM)})
    _archive(tmp_path / "i.tar", [base, upper])
    doc = imagefiles.scan(str(tmp_path / "i.tar"))
    assert sorted({e["path"] for e in doc["entries"]}) == ["/.env.pem", "/.ssh/id.pub.pem"]


def test_a_hard_link_to_key_material_is_that_material_under_its_own_name(tmp_path, material):
    _key, cert = material
    base = _layer({"etc/x/real.pem": cert.public_bytes(PEM), "usr/lib/libfoo.so": b"\x7fELF" + b"\x00" * 100})
    upper = _links({"etc/x/hard.pem": "etc/x/real.pem", "./etc/y/other.pem": "./etc/x/real.pem", "usr/lib/libbar.so": "usr/lib/libfoo.so"})
    _archive(tmp_path / "i.tar", [base, upper])
    doc = imagefiles.scan(str(tmp_path / "i.tar"))
    by_path = {e["path"]: e["parameters"]["spki_sha256"] for e in doc["entries"]}
    assert sorted(by_path) == ["/etc/x/hard.pem", "/etc/x/real.pem", "/etc/y/other.pem"] and len(set(by_path.values())) == 1


def test_a_keystore_is_what_its_bytes_say_not_what_it_is_named(material):
    """keytool has written PKCS#12 into .jks and .keystore files since JDK 9."""
    key, cert = material
    p12 = pkcs12.serialize_key_and_certificates(b"tomcat", key, cert, None, serialization.BestAvailableEncryption(b"changeit"))
    for name in ("opt/app/keystore.jks", "opt/app/.keystore", "opt/app/keystore.p12"):
        entries = imagefiles.read_file(name, p12)
        store = entries[0]
        assert store["name"] == "RSA" and store["parameters"]["format"] == "PKCS12" and store["parameters"]["opened"] is True
        assert store["parameters"]["key_bits"] == 2048 and [e["type"] for e in entries[1:]] == ["certificate"]
    jks = imagefiles.read_file("opt/app/keystore.p12", b"\xfe\xed\xfe\xed" + b"\x00" * 64)[0]
    assert jks["parameters"]["format"] == "JKS" and jks["parameters"]["opened"] is False
    jceks = imagefiles.read_file("opt/app/store", b"\xce\xce\xce\xce" + b"\x00" * 64)[0]
    assert jceks["parameters"]["format"] == "JCEKS" and jceks["parameters"]["opened"] is False
    odd = imagefiles.read_file("opt/app/keystore.jks", b"BCFKS-or-something-else")[0]
    assert odd["parameters"]["format"] == "unrecognised" and odd["parameters"]["opened"] is False


def test_a_jceks_store_without_an_extension_is_a_candidate(tmp_path):
    _archive(tmp_path / "i.tar", [_layer({"opt/app/store": b"\xce\xce\xce\xce" + b"\x00" * 64})])
    files, *_ = imagefiles.files_of(str(tmp_path / "i.tar"))
    assert list(files) == ["opt/app/store"]


def test_the_key_forms_the_reader_passed_over(material):
    key, _ = material
    legacy = key.private_bytes(PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.BestAvailableEncryption(b"pw"))
    assert b"Proc-Type: 4,ENCRYPTED" in legacy
    e = imagefiles.read_file("etc/tls/server.key", legacy)[0]
    assert e["name"] == "RSA" and e["parameters"]["opened"] is False and e["parameters"]["why"] == "encrypted"
    pkcs1 = key.public_key().public_bytes(PEM, serialization.PublicFormat.PKCS1)
    assert pkcs1.startswith(b"-----BEGIN RSA PUBLIC KEY-----")
    e = imagefiles.read_file("etc/tls/server.pub.pem", pkcs1)[0]
    assert e["name"] == "RSA" and e["parameters"]["kind"] == "public-key" and e["parameters"]["key_bits"] == 2048
    ec_key = ec.generate_private_key(ec.SECP256R1())
    der = ec_key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    e = imagefiles.read_file("etc/tls/a.der", der)[0]
    assert e["name"] == "ECDSA" and e["parameters"]["kind"] == "public-key" and len(e["parameters"]["spki_sha256"]) == 64


def test_what_the_reader_did_not_read_is_counted_not_dropped(tmp_path, material, monkeypatch):
    monkeypatch.setattr(imagefiles, "LARGE", 64)
    base = _layer({"etc/tls/huge.pem": b"x" * 200, "etc/tls/gone.pem": b"y" * 200, "etc/tls/ok.crt": b"z" * 10})
    bad = b"\x28\xb5\x2f\xfd" + b"\x00" * 600                        # a zstd frame header: a layer tarfile cannot open
    _archive(tmp_path / "i.tar", [base, _layer({"etc/tls/.wh.gone.pem": b""}), bad])
    doc = imagefiles.scan(str(tmp_path / "i.tar"))
    assert doc["larger_than_limit"] == ["/etc/tls/huge.pem"]
    assert doc["layers"] == 3 and len(doc["unread_layers"]) == 1 and doc["unread_layers"][0]["layer"].endswith("2")
