"""A server as an estate: packing its paths, reading its files and firmware, its controller's
configuration, the PostgreSQL TLS probe, recordings' identifier replacement, and the projection's
device and firmware components."""
from __future__ import annotations

import datetime as dt
import importlib
import io
import json
import os
import struct
import tarfile
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID

from pqch.scout import system
from pqch.systems import _HardwareIds, sanitize_pairs

# pqch.scout exports a function named normalize, which hides the module of that name.
norm = importlib.import_module("pqch.scout.normalize")

GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
IMAGE_DB = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"


def _cert(cn: str, key=None, days: int = 3650, start: dt.datetime | None = None) -> bytes:
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    start = start or dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
    c = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(start).not_valid_after(start + dt.timedelta(days=days))
         .sign(key, hashes.SHA256()))
    return c.public_bytes(serialization.Encoding.DER)


def _esl(certs: list[bytes], hashes_: int = 0) -> bytes:
    """An EFI_SIGNATURE_LIST per certificate, then one list of SHA-256 hashes."""
    out = b""
    owner = uuid.uuid4().bytes_le
    for der in certs:
        ssize = 16 + len(der)
        out += uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").bytes_le + struct.pack("<III", 28 + ssize, 0, ssize) + owner + der
    if hashes_:
        ssize = 16 + 32
        body = b"".join(owner + bytes([i]) * 32 for i in range(hashes_))
        out += uuid.UUID("c1c41626-504c-4092-aca9-41f936934328").bytes_le + struct.pack("<III", 28 + len(body), 0, ssize) + body
    return out


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    (r / "etc/ssh").mkdir(parents=True)
    pub = ed25519.Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    (r / "etc/ssh/ssh_host_ed25519_key.pub").write_bytes(pub + b" host\n")
    secret = r / "etc/ssh/ssh_host_ed25519_key"
    secret.write_text("not readable")
    os.chmod(secret, 0)
    (r / "etc/ssl/certs").mkdir(parents=True)
    for i in range(3):
        (r / f"etc/ssl/certs/ca{i}.pem").write_text("x")
    efi = r / "sys/firmware/efi/efivars"
    efi.mkdir(parents=True)
    attrs = b"\x07\x00\x00\x00"
    (efi / f"SecureBoot-{GLOBAL}").write_bytes(attrs + b"\x00")
    (efi / f"PK-{GLOBAL}").write_bytes(attrs + _esl([_cert("Vendor Platform Key", rsa.generate_private_key(public_exponent=65537, key_size=3072))]))
    (efi / f"KEK-{GLOBAL}").write_bytes(attrs + _esl([_cert("Microsoft Corporation KEK CA 2011", days=6000, start=dt.datetime(2011, 6, 24, tzinfo=dt.UTC))]))
    (efi / f"db-{IMAGE_DB}").write_bytes(attrs + _esl([_cert("Microsoft Corporation UEFI CA 2011", days=6000, start=dt.datetime(2011, 6, 27, tzinfo=dt.UTC)),
                                                       _cert("Vendor db key", ec.generate_private_key(ec.SECP384R1()))]))
    (efi / f"dbx-{IMAGE_DB}").write_bytes(attrs + _esl([], hashes_=4))
    dmi = r / "sys/class/dmi/id"
    dmi.mkdir(parents=True)
    for k, v in {"sys_vendor": "Vendor Inc.", "product_name": "Server 9000", "bios_vendor": "Vendor Inc.", "bios_version": "2.4.4",
                 "bios_date": "09/27/2024"}.items():
        (dmi / k).write_text(v + "\n")
    tpm = r / "sys/class/tpm/tpm0"
    (tpm / "pcr-sha256").mkdir(parents=True)
    (tpm / "tpm_version_major").write_text("2\n")
    return r


SYSDEF = {"name": "srv1", "addresses": ["192.0.2.10"], "paths": ["/etc/ssh", "/etc/absent"], "firmware": True,
          "trust_store": "/etc/ssl/certs"}


def _unpack(data: bytes, dest):
    tarfile.open(fileobj=io.BytesIO(data)).extractall(dest, filter="data")


def test_pack_reads_only_scoped_paths_and_lists_what_it_could_not(root, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads everything")
    data = system.pack(root, SYSDEF)
    names = tarfile.open(fileobj=io.BytesIO(data)).getnames()
    assert "etc/ssh/ssh_host_ed25519_key.pub" in names
    assert "etc/ssh/ssh_host_ed25519_key" not in names
    assert not any(n.startswith("etc/ssl/") for n in names), "the trust store is counted, not packed"
    m = json.loads(tarfile.open(fileobj=io.BytesIO(data)).extractfile(system.MANIFEST).read())
    assert "/etc/ssh/ssh_host_ed25519_key" in m["unreadable"]
    assert "/etc/absent (absent)" in m["unreadable"]
    assert m["trust_store_certificates"] == 3


def test_files_reader_and_its_host_subject(root, tmp_path):
    out = tmp_path / "out"
    _unpack(system.pack(root, SYSDEF, prefix=""), out)
    doc = system.files_scan(str(out))
    assert [e["name"] for e in doc["entries"]] == ["Ed25519"]
    job = {"tool": "pqch-system-files", "version": "1", "image_digest": "sha256:" + "0" * 64, "profile": "system-files",
           "target": {"system": "srv1"}, "ended_at": "2026-11-04T00:00:00Z", "raw": "var/raw/x.json", "raw_sha256": "0" * 64}
    f = norm.imagefiles(json.dumps(doc).encode(), job)
    assert f[0]["subject"] == {"kind": "file", "host": "srv1", "path": "/etc/ssh/ssh_host_ed25519_key.pub"}
    facts = norm.platform_facts(json.dumps(doc).encode(), job)
    assert facts["trust_store_certificates"] == 3 and "/etc/ssh/ssh_host_ed25519_key" in facts["unreadable"]


def test_firmware_reader_parses_the_secure_boot_databases(root, tmp_path):
    out = tmp_path / "out"
    _unpack(system.pack(root, SYSDEF), out)
    doc = system.firmware_scan(str(out))
    assert doc["secure_boot"] == {"enabled": False, "setup_mode": None, "readable": True}
    assert doc["device"]["product_name"] == "Server 9000" and doc["device"]["bios_version"] == "2.4.4"
    assert doc["databases"]["PK"]["certificates"][0]["key_bits"] == 3072
    assert {c["key_algorithm"] for c in doc["databases"]["db"]["certificates"]} == {"RSA", "ECDSA"}
    assert doc["databases"]["dbx"]["sha256_hashes"] == 4
    assert doc["tpm"]["pcr_banks"] == ["sha256"]
    job = {"tool": "pqch-system-firmware", "version": "1", "image_digest": "sha256:" + "0" * 64, "profile": "system-firmware",
           "target": {"system": "srv1"}, "ended_at": "2026-11-04T00:00:00Z", "raw": "var/raw/x.json", "raw_sha256": "0" * 64}
    f = norm.system_firmware(json.dumps(doc).encode(), job)
    comps = sorted(x["subject"]["component"] for x in f)
    assert comps == ["secure-boot:KEK", "secure-boot:PK", "secure-boot:db", "secure-boot:db", "tpm"]
    assert all(x["layer"] == "platform" for x in f)
    assert len({x["fingerprint"] for x in f}) == 5, "each certificate keeps its own identity"
    facts = norm.platform_facts(json.dumps(doc).encode(), job)
    assert facts["firmware"][0]["name"] == "BIOS" and facts["settings"]["secure_boot"] is False


def test_controller_configuration_and_identity_certificates():
    doc = {"schema": "pqch-controller-redfish/1", "resources": {
        "/redfish/v1/Managers/iDRAC.Embedded.1": {"FirmwareVersion": "7.10.90.00", "Model": "16G Monolithic"},
        "/redfish/v1/UpdateService/FirmwareInventory/Installed-159-2.4.4__BIOS.Setup.1-1": {"Name": "BIOS", "Version": "2.4.4"},
        "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1": {"Attributes": {
            "SSHCrypto.1.KexAlgorithms": "curve25519-sha256,ecdh-sha2-nistp256",
            "SSHCrypto.1.HostKeyAlgorithms": "rsa-sha2-512,ssh-ed25519",
            "SNMP.1.AgentEnable": "Enabled", "SNMP.1.SNMPProtocol": "All", "SNMP.1.TrapFormat": "SNMPv1",
            "WebServer.1.TLSProtocol": "TLS 1.2 and Higher", "Security.1.FIPSMode": "Disabled",
            "SecurityCertificate.1.CertificateType": "FACTORY_IDENTITY_CERT", "SecurityCertificate.1.IssuerCommonName": "Vendor HWID SUBCA",
            "SecurityCertificate.1.CertValidTo": "Nov 29 00:00:10 2036 GMT", "SecurityCertificate.1.SubjectCommonName": "x"}}}}
    job = {"tool": "pqch-controller-redfish", "version": "1", "image_digest": "sha256:" + "0" * 64, "profile": "controller-redfish",
           "target": {"controller": "192.0.2.12", "port": 443, "of": "srv1"}, "ended_at": "2026-11-04T00:00:00Z",
           "raw": "var/raw/x.json", "raw_sha256": "0" * 64}
    f = norm.controller_redfish(json.dumps(doc).encode(), job)
    names = {(x["subject"]["component"], x["asset"]["name"]) for x in f}
    assert ("bmc:ssh-config", "X25519") in names and ("bmc:ssh-config", "secp256r1") in names
    assert ("bmc:snmp", "SNMP") in names
    cert = next(x for x in f if x["subject"]["component"] == "bmc:certificate:factory_identity_cert")
    assert cert["asset"]["name"] == "unknown" and cert["asset"]["parameters"]["not_after"].startswith("2036-11-29")
    assert all(x["subject"]["host"] == "srv1" for x in f)
    facts = norm.platform_facts(json.dumps(doc).encode(), job)
    assert facts["controller"]["firmware_version"] == "7.10.90.00" and facts["firmware"] == [{"name": "BIOS", "version": "2.4.4", "id": "Installed-159-2.4.4"}]


def test_postgres_tls_refusal_is_a_finding():
    job = {"tool": "pqch-postgres-tls-offer", "version": "1", "image_digest": "sha256:" + "0" * 64, "profile": "postgres-tls-offer",
           "target": {"host": "192.0.2.10", "port": 5432, "protocol": "postgres"}, "ended_at": "2026-11-04T00:00:00Z",
           "raw": "var/raw/x.json", "raw_sha256": "0" * 64}
    f = norm.postgres_tls_offer(json.dumps({"answer": "N"}).encode(), job)
    assert f[0]["asset"]["parameters"]["tls_offered"] is False and f[0]["layer"] == "wire"
    assert norm.postgres_tls_offer(json.dumps({"answer": None}).encode(), job) == []


def test_identifier_replacement_covers_its_other_spellings():
    pairs = dict(sanitize_pairs({"ABC1234": "DEMO000", "10.0.0.5": "192.0.2.5"}))
    assert pairs[b"ABC1234".hex()] == b"DEMO000".hex()
    assert pairs["abc1234"] == "demo000"
    hw = _HardwareIds()
    t = hw("mac AC:B4:80:29:90:2B and ac-b4-80-29-90-2b, uuid 4c4c4544-0059-4310-8052-c6c04f363634 twice 4C4C4544-0059-4310-8052-C6C04F363634")
    assert "AC:B4:80" not in t and "ac-b4-80" not in t and "4c4c4544" not in t.lower()
    assert t.count("00000000-0000-4000-8000-000000000000") == 2, "one stand-in per value, whatever its case"
    assert "00:00:5E:00:53:00" in t and "00-00-5e-00-53-00" in t, "the same MAC keeps the same stand-in in both spellings"
