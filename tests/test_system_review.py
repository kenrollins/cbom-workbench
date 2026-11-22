"""The system packer after the 2026-11 review: links, pipes, the size limit, paths that leave the
root, and a Secure Boot database with one entry that does not parse."""
from __future__ import annotations

import datetime as dt
import importlib
import io
import json
import os
import struct
import tarfile
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pqch.scout import system

norm = importlib.import_module("pqch.scout.normalize")


def _packed(root, paths, **kw) -> tuple[dict, list[str]]:
    data = system.pack(root, {"name": "s", "paths": paths, **kw}, prefix="scan/root/")
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        return json.loads(tar.extractfile("scan/root/" + system.MANIFEST).read()), sorted(tar.getnames())


def test_a_link_inside_a_scoped_directory_is_followed_within_the_root_or_listed_never_dropped(tmp_path):
    """certbot's layout: live/<site>/privkey.pem is a link into archive/. And the links a packer must
    not follow: out of the system root, to a directory, or to nothing."""
    host = tmp_path / "host"
    (host / "etc/le/archive/site").mkdir(parents=True)
    (host / "etc/le/live/site").mkdir(parents=True)
    (host / "etc/le/archive/site/privkey1.pem").write_text("-----BEGIN PRIVATE KEY-----\n")
    (host / "etc/ssl").mkdir()
    (host / "etc/ssl/ca.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    (tmp_path / "outside.pem").write_text("the reader's own file, not the system's\n")
    live = host / "etc/le/live/site"
    os.symlink("../../archive/site/privkey1.pem", live / "privkey.pem")       # relative, inside the root
    os.symlink("/etc/ssl/ca.pem", live / "chain.pem")                          # absolute: taken under the system's root
    os.symlink(str(tmp_path / "outside.pem"), live / "escape.pem")             # absolute; under the root it is absent
    os.symlink("../../../../../outside.pem", live / "climb.pem")               # climbs out of the root
    os.symlink("../../archive", live / "dir")                                  # a directory
    os.symlink("nowhere.pem", live / "dangling.pem")
    manifest, names = _packed(host, ["/etc/le/live"])
    assert "scan/root/etc/le/live/site/privkey.pem" in names and "scan/root/etc/le/live/site/chain.pem" in names
    assert manifest["files"] == 2
    assert manifest["links_followed"] == [{"path": "/etc/le/live/site/chain.pem", "target": "/etc/ssl/ca.pem"},
                                          {"path": "/etc/le/live/site/privkey.pem", "target": "../../archive/site/privkey1.pem"}]
    why = {x["path"].rsplit("/", 1)[1]: x["why"] for x in manifest["links_not_followed"]}
    assert why == {"climb.pem": "its target is outside the system root", "dir": "its target is a directory",
                   "dangling.pem": "its target is absent", "escape.pem": "its target is absent"}
    assert not any("outside" in n or "escape" in n or "climb" in n for n in names)
    # The reader carries the lists on, and the ledger's platform fact has them, with the route.
    out = tmp_path / "x"
    with tarfile.open(fileobj=io.BytesIO(system.pack(host, {"name": "s", "paths": ["/etc/le/live"]}))) as tar:
        tar.extractall(out, filter="data")
    doc = system.files_scan(str(out))
    facts = norm.platform_facts(json.dumps(doc).encode(), {"tool": "pqch-system-files", "target": {"system": "s"},
                                                          "container": {"read_via": "ssh scan@srv9.example"}})
    assert len(facts["links_not_followed"]) == 4 and len(facts["links_followed"]) == 2
    assert facts["read_via"] == "ssh scan@srv9.example"


def test_a_pipe_in_a_scoped_directory_is_listed_and_never_opened(tmp_path):
    host = tmp_path / "host"
    (host / "run/app").mkdir(parents=True)
    os.mkfifo(host / "run/app/control")
    (host / "run/app/tls.pem").write_text("-----BEGIN CERTIFICATE-----\n")
    manifest, names = _packed(host, ["/run/app", "/run/app/control"])        # returns: opening the pipe would not
    assert manifest["not_regular"] == ["/run/app/control", "/run/app/control"] and manifest["files"] == 1
    assert "scan/root/run/app/tls.pem" in names


def test_a_file_is_read_to_the_limit_and_no_further(tmp_path, monkeypatch):
    host = tmp_path / "host"
    (host / "etc").mkdir(parents=True)
    (host / "etc/big.pem").write_bytes(b"x" * 100)
    (host / "etc/ok.pem").write_bytes(b"x" * 10)
    monkeypatch.setattr(system, "MAX_FILE", 10)
    manifest, _ = _packed(host, ["/etc"])
    assert manifest["larger_than_1MiB"] == ["/etc/big.pem"] and manifest["files"] == 1


def test_a_scoped_path_that_leaves_the_system_root_is_refused(tmp_path):
    host = tmp_path / "ff" / "host"
    (host / "etc").mkdir(parents=True)
    (tmp_path / "ff" / "secrets").mkdir()
    (tmp_path / "ff" / "secrets" / "c.env").write_text("REDFISH_PASSWORD=x\n")
    os.symlink(str(tmp_path / "ff" / "secrets"), host / "etc" / "door")
    paths = ["/../secrets", "/etc/../../secrets/c.env", "/etc/door/c.env"]
    manifest, names = _packed(host, paths, trust_store="/../secrets")
    assert names == ["scan/root/" + system.MANIFEST] and manifest["files"] == 0
    assert manifest["unreadable"] == sorted(f"{p} (outside the system root; refused)" for p in paths)
    assert manifest["trust_store_certificates"] is None


def test_one_unparseable_certificate_does_not_lose_a_secure_boot_database():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Platform Key")])
    start = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
    good = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(1)
            .not_valid_before(start).not_valid_after(start + dt.timedelta(days=3650)).sign(key, hashes.SHA256())
            ).public_bytes(serialization.Encoding.DER)
    owner = uuid.uuid4().bytes_le

    def siglist(body: bytes) -> bytes:
        entry = owner + body
        return system._X509.bytes_le + struct.pack("<III", 28 + len(entry), 0, len(entry)) + entry

    certs, hashes_, other = system.signature_list(siglist(b"\x30\x03not a certificate") + siglist(good))
    assert [c["subject"] for c in certs] == ["CN=Platform Key"] and hashes_ == 0 and other == ["unparsed-x509"]
