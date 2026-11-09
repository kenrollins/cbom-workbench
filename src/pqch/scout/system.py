"""Reading a server's own files and firmware: `pqch-system-files/1` and `pqch-system-firmware/1`.

A system in an external scope names the paths that may be read and whether its firmware is read
(`systems` in pqch.scope/1). The runner packs exactly those into an archive (`pack`), as the user it
runs as, and hands it to a reader in a container with no network, the way an image's archive is
handed to the image readers. Nothing is written to the system, and a file the runner cannot read is
listed as unreadable rather than skipped in silence.

- `pqch system-files <dir>` reads key material with the image reader's own parser (certificates,
  public and private keys, keystores) and reports the trust store as a count.
- `pqch system-firmware <dir>` reads the firmware's identity (DMI), the TPM's version and banks, and
  the UEFI Secure Boot state and its four trust databases: the platform key, the key-exchange keys,
  the allowed signers (db) and the revoked (dbx).

A private key's material never leaves the reader: what is recorded is its kind, algorithm and size.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import struct
import sys
import tarfile
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from pqch.scout import imagefiles

FILES_SCHEMA = "pqch-system-files/1"
FIRMWARE_SCHEMA = "pqch-system-firmware/1"
MANIFEST = ".pqch-manifest.json"
MAX_FILE = 1 << 20

# What the firmware reader needs, under the system root. The Secure Boot variables are named by
# their EFI GUIDs: the global variable GUID for SecureBoot, PK and KEK; the image security
# database GUID for db and dbx.
_GLOBAL = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
_IMAGE_DB = "d719b2cb-3d3a-4596-a3bc-dad00e67656f"
EFIVARS = [f"SecureBoot-{_GLOBAL}", f"SetupMode-{_GLOBAL}", f"PK-{_GLOBAL}", f"KEK-{_GLOBAL}",
           f"db-{_IMAGE_DB}", f"dbx-{_IMAGE_DB}"]
DMI = ["sys_vendor", "product_name", "board_vendor", "board_name", "bios_vendor", "bios_version", "bios_date"]


# --------------------------------------------------------------- packing (in the runner)
def pack(root: str | Path, system: dict, prefix: str = "") -> bytes:
    """A tar of the system's scoped paths, read under `root`, plus its firmware's files when the
    scope asks for them. The archive's paths are the system's own; a manifest lists what could not
    be read. Symbolic links are followed only for the firmware's sysfs entries, which are links."""
    root = Path(root)
    buf = io.BytesIO()
    unreadable, skipped_large, files = [], [], 0

    def add(tar: tarfile.TarFile, path: str, data: bytes) -> None:
        info = tarfile.TarInfo(prefix + path.lstrip("/"))
        info.size, info.mode = len(data), 0o444
        tar.addfile(info, io.BytesIO(data))

    def read(src: Path, path: str, tar: tarfile.TarFile) -> None:
        nonlocal files
        try:
            if src.stat().st_size > MAX_FILE:
                skipped_large.append(path)
                return
            add(tar, path, src.read_bytes())
            files += 1
        except PermissionError:
            unreadable.append(path)
        except OSError as e:  # a sysfs entry that cannot be read, a vanished file
            unreadable.append(f"{path} ({type(e).__name__})")

    with tarfile.open(fileobj=buf, mode="w") as tar:
        for scoped in system["paths"]:
            src = root / scoped.lstrip("/")
            if src.is_symlink() or not src.exists():
                unreadable.append(f"{scoped} (absent)" if not src.exists() else f"{scoped} (a link; not followed)")
                continue
            if src.is_file():
                read(src, scoped, tar)
                continue
            for dirpath, _dirnames, filenames in os.walk(src, followlinks=False, onerror=lambda e: unreadable.append(
                    "/" + str(Path(e.filename).relative_to(root)))):
                for name in sorted(filenames):
                    f = Path(dirpath) / name
                    if f.is_symlink():
                        continue
                    read(f, "/" + str(f.relative_to(root)), tar)
        trust = system.get("trust_store")
        trust_count = None
        if trust:
            d = root / trust.lstrip("/")
            trust_count = sum(1 for p in d.glob("*") if p.suffix in (".pem", ".crt")) if d.is_dir() else None
        if system.get("firmware"):
            for v in EFIVARS:
                src = root / "sys/firmware/efi/efivars" / v
                if src.exists():
                    read(src, f"/sys/firmware/efi/efivars/{v}", tar)
            for k in DMI:
                src = root / "sys/class/dmi/id" / k
                if src.exists():
                    read(src, f"/sys/class/dmi/id/{k}", tar)
            tpm = root / "sys/class/tpm/tpm0"
            if tpm.exists():
                for rel in ("tpm_version_major", "device/description"):
                    if (tpm / rel).exists():
                        read(tpm / rel, f"/sys/class/tpm/tpm0/{rel}", tar)
                banks = sorted(p.name.removeprefix("pcr-") for p in tpm.glob("pcr-*"))
                add(tar, "sys/class/tpm/tpm0/.pcr-banks", json.dumps(banks).encode())
        add(tar, MANIFEST, json.dumps({"system": system["name"], "paths": system["paths"], "files": files,
                                        "unreadable": sorted(unreadable), "larger_than_1MiB": sorted(skipped_large),
                                        "trust_store": trust, "trust_store_certificates": trust_count,
                                        "firmware": bool(system.get("firmware")),
                                        "read_as_uid": os.getuid()}, indent=1).encode())
    return buf.getvalue()


def remote_pack(system: dict, prefix: str = "", *, ssh: str = "ssh", timeout: int = 300) -> bytes:
    """The same archive, packed on a remote system over SSH: the packer's own source is sent to the
    remote's python3 on stdin, the system's definition as its argument, and the tar comes back on
    stdout. Nothing is installed on the remote and nothing is written to it; the remote reads as the
    user SSH logs in as, and the manifest's `read_as_uid` says which. Host-key checking is strict
    against the scope's known_hosts file; a host not in it is refused."""
    import inspect
    import subprocess

    via = system["via"]
    src = "\n".join([
        "import io, json, os, sys, tarfile",
        "from pathlib import Path",
        f"MANIFEST = {MANIFEST!r}", f"MAX_FILE = {MAX_FILE!r}", f"EFIVARS = {EFIVARS!r}", f"DMI = {DMI!r}",
        inspect.getsource(pack),
        "root = os.environ.get('PQCH_REMOTE_ROOT', '/')",
        "sys.stdout.buffer.write(pack(root, json.loads(sys.argv[1]), prefix=sys.argv[2]))",
    ])
    cmd = [ssh, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={via['known_hosts']}"]
    if via.get("port"):
        cmd += ["-p", str(via["port"])]
    if via.get("identity"):
        cmd += ["-i", via["identity"], "-o", "IdentitiesOnly=yes"]
    remote = {k: v for k, v in system.items() if k != "via"}
    cmd += [f"{via['user']}@{via['host']}", via.get("python", "python3"), "-", json.dumps(remote), prefix]
    res = subprocess.run(cmd, input=src.encode(), capture_output=True, timeout=timeout)
    if res.returncode != 0:
        raise RuntimeError(f"ssh to {via['user']}@{via['host']} failed ({res.returncode}): {res.stderr.decode(errors='replace')[-500:]}")
    return res.stdout


# --------------------------------------------------------------- the file reader
def files_scan(directory: str) -> dict:
    root = Path(directory)
    manifest = json.loads((root / MANIFEST).read_text()) if (root / MANIFEST).exists() else {}
    texts: dict[str, bytes] = {}
    candidates: dict[str, bytes] = {}
    for f in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = str(f.relative_to(root))
        if rel == MANIFEST or rel.startswith("sys/"):
            continue
        data = f.read_bytes()
        candidates[rel] = data
        if len(data) < 256 * 1024 and b"\x00" not in data[:4096]:
            texts[rel] = data
    entries = []
    for rel, data in candidates.items():
        refs = [r for r in imagefiles.references(rel, texts) if r != "/" + rel]
        for e in imagefiles.read_file(rel, data):
            entries.append({"path": "/" + rel, **e, "parameters": {**e["parameters"], "referenced_by": refs}})
    return {"schema": FILES_SCHEMA, "system": manifest.get("system"), "paths": manifest.get("paths"),
            "files_read": len(candidates), "unreadable": manifest.get("unreadable", []),
            "larger_than_1MiB": manifest.get("larger_than_1MiB", []),
            "trust_store": manifest.get("trust_store"), "trust_store_certificates": manifest.get("trust_store_certificates"),
            "read_as_uid": manifest.get("read_as_uid"), "entries": entries}


# --------------------------------------------------------------- the firmware reader
_X509 = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
_SHA256 = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")


def _key(k) -> tuple[str, int | None, str | None]:
    if isinstance(k, rsa.RSAPublicKey):
        return "RSA", k.key_size, None
    if isinstance(k, ec.EllipticCurvePublicKey):
        return "ECDSA", k.key_size, k.curve.name
    if isinstance(k, ed25519.Ed25519PublicKey):
        return "Ed25519", 256, None
    if isinstance(k, ed448.Ed448PublicKey):
        return "Ed448", 456, None
    if isinstance(k, dsa.DSAPublicKey):
        return "DSA", k.key_size, None
    return type(k).__name__, None, None


def signature_list(data: bytes) -> tuple[list[dict], int, list[str]]:
    """An EFI_SIGNATURE_LIST sequence: the X.509 certificates in it, the number of SHA-256 hashes,
    and any other signature types by GUID."""
    certs, hashes, other, off = [], 0, [], 0
    while off + 28 <= len(data):
        stype = uuid.UUID(bytes_le=data[off:off + 16])
        lsize, hsize, ssize = struct.unpack("<III", data[off + 16:off + 28])
        if lsize < 28 or ssize < 16:
            break
        body = data[off + 28 + hsize: off + lsize]
        for i in range(0, len(body) - ssize + 1, ssize):
            sig = body[i + 16:i + ssize]
            if stype == _X509:
                c = x509.load_der_x509_certificate(sig)
                family, bits, curve = _key(c.public_key())
                from cryptography.hazmat.primitives import serialization
                spki = c.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
                certs.append({"subject": c.subject.rfc4514_string(), "issuer": c.issuer.rfc4514_string(),
                              "spki_sha256": hashlib.sha256(spki).hexdigest(),
                              "key_algorithm": family, "key_bits": bits, **({"curve": curve} if curve else {}),
                              "signature": c.signature_algorithm_oid._name,
                              "not_before": c.not_valid_before_utc.isoformat(), "not_after": c.not_valid_after_utc.isoformat(),
                              "serial": format(c.serial_number, "x"), "self_signed": c.subject == c.issuer})
            elif stype == _SHA256:
                hashes += 1
            else:
                other.append(str(stype))
        off += lsize
    return certs, hashes, sorted(set(other))


def firmware_scan(directory: str) -> dict:
    root = Path(directory)
    manifest = json.loads((root / MANIFEST).read_text()) if (root / MANIFEST).exists() else {}

    def text(rel: str) -> str | None:
        p = root / rel
        return p.read_text(errors="replace").strip() if p.exists() else None

    def var(name: str) -> bytes | None:
        p = root / "sys/firmware/efi/efivars" / name
        return p.read_bytes()[4:] if p.exists() else None   # the first four bytes are the attributes

    device = {k: text(f"sys/class/dmi/id/{k}") for k in DMI}
    sb = var(EFIVARS[0])
    setup = var(EFIVARS[1])
    databases, dbx_hashes = {}, None
    for label, name in (("PK", EFIVARS[2]), ("KEK", EFIVARS[3]), ("db", EFIVARS[4]), ("dbx", EFIVARS[5])):
        data = var(name)
        if data is None:
            databases[label] = None
            continue
        certs, hashes, other = signature_list(data)
        databases[label] = {"certificates": certs, "sha256_hashes": hashes, "other_types": other}
        if label == "dbx":
            dbx_hashes = hashes
    banks = text("sys/class/tpm/tpm0/.pcr-banks")
    tpm = None
    if text("sys/class/tpm/tpm0/tpm_version_major"):
        tpm = {"version": text("sys/class/tpm/tpm0/tpm_version_major"), "description": text("sys/class/tpm/tpm0/device/description"),
               "pcr_banks": json.loads(banks) if banks else []}
    return {"schema": FIRMWARE_SCHEMA, "system": manifest.get("system"), "device": device,
            "secure_boot": {"enabled": bool(sb and sb[0] == 1) if sb is not None else None,
                            "setup_mode": bool(setup and setup[0] == 1) if setup is not None else None,
                            "readable": sb is not None},
            "databases": databases, "dbx_sha256_hashes": dbx_hashes, "tpm": tpm,
            "unreadable": [u for u in manifest.get("unreadable", []) if "/sys/" in u]}


def postgres_tls_offer(host: str, port: int) -> dict:
    """PostgreSQL's SSLRequest, and the server's one-byte answer: S (TLS offered) or N (refused)."""
    import socket
    s = socket.create_connection((host, port), timeout=10)
    try:
        s.sendall(struct.pack("!ii", 8, 80877103))
        b = s.recv(1)
    finally:
        s.close()
    ans = b.decode(errors="replace") if b else None
    return {"schema": "pqch-postgres-tls-offer/1", "host": host, "port": port, "answer": ans,
            "tls_offered": ans == "S" if ans in ("S", "N") else None}


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) == 3 and args[0] == "postgres-tls-offer":
        json.dump(postgres_tls_offer(args[1], int(args[2])), sys.stdout)
        sys.stdout.write("\n")
        return 0
    if len(args) != 2 or args[0] not in ("files", "firmware"):
        print("usage: pqch system-files <dir> | pqch system-firmware <dir>", file=sys.stderr)
        return 2
    doc = files_scan(args[1]) if args[0] == "files" else firmware_scan(args[1])
    json.dump(doc, sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
