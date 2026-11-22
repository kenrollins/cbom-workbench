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
    scope asks for them. The archive's paths are the system's own; a manifest lists everything that
    was passed over and why: unreadable, too large, not a regular file (a pipe, a socket or a device
    is never opened), or a symbolic link. A link to a regular file inside the system root is read
    under the link's own path and listed with its target; any other link is listed and not followed.
    A scoped path that leaves the root (`..`) is refused. This function is also sent as source to a
    remote python (`remote_pack`), so it uses nothing but the standard library and its own names."""
    import stat as stat_mod

    root = Path(root)
    real_root = os.path.realpath(root)
    buf = io.BytesIO()
    unreadable, skipped_large, not_regular, links_followed, links_not_followed = [], [], [], [], []
    files = 0

    def inside(path) -> bool:
        return os.path.commonpath([real_root, os.path.realpath(path)]) == real_root

    def add(tar: tarfile.TarFile, path: str, data: bytes) -> None:
        info = tarfile.TarInfo(prefix + path.lstrip("/"))
        info.size, info.mode = len(data), 0o444
        tar.addfile(info, io.BytesIO(data))

    def read(src: Path, path: str, tar: tarfile.TarFile) -> None:
        nonlocal files
        try:
            if not stat_mod.S_ISREG(os.stat(src).st_mode):
                not_regular.append(path)        # opening a pipe blocks; a device never ends
                return
            with open(src, "rb") as f:
                data = f.read(MAX_FILE + 1)     # the size is what was read, not what stat claimed
            if len(data) > MAX_FILE:
                skipped_large.append(path)
                return
            add(tar, path, data)
            files += 1
        except PermissionError:
            unreadable.append(path)
        except OSError as e:  # a sysfs entry that cannot be read, a vanished file
            unreadable.append(f"{path} ({type(e).__name__})")

    def link(src: Path, path: str, tar: tarfile.TarFile) -> None:
        """A symbolic link under a scoped directory. Its target is resolved against the system's
        root, never the reader's own filesystem: an absolute target is taken under `root`."""
        try:
            target = os.readlink(src)
        except OSError as e:
            links_not_followed.append({"path": path, "target": None, "why": type(e).__name__})
            return
        hop, where = target, src
        for _ in range(8):
            where = Path(os.path.normpath(root / hop.lstrip("/") if hop.startswith("/") else where.parent / hop))
            if not where.is_symlink():
                break
            try:
                hop = os.readlink(where)
            except OSError:
                break
        try:
            if where.is_symlink():
                why = "a chain of links too long to follow"
            elif not inside(where):
                why = "its target is outside the system root"
            elif not os.path.exists(where):
                why = "its target is absent"
            elif not stat_mod.S_ISREG(os.stat(where).st_mode):
                why = "its target is a directory" if os.path.isdir(where) else "its target is not a regular file"
            else:
                why = None
        except OSError as e:
            why = type(e).__name__
        if why:
            links_not_followed.append({"path": path, "target": target, "why": why})
            return
        before = files
        read(where, path, tar)
        if files > before:
            links_followed.append({"path": path, "target": target})

    with tarfile.open(fileobj=buf, mode="w") as tar:
        for scoped in system["paths"]:
            src = root / scoped.lstrip("/")
            if ".." in Path(scoped).parts or not inside(src.parent):
                unreadable.append(f"{scoped} (outside the system root; refused)")
                continue
            if src.is_symlink() or not src.exists():
                unreadable.append(f"{scoped} (absent)" if not src.exists() else f"{scoped} (a link; not followed)")
                continue
            if not src.is_dir():
                read(src, scoped, tar)
                continue
            for dirpath, dirnames, filenames in os.walk(src, followlinks=False, onerror=lambda e: unreadable.append(
                    "/" + str(Path(e.filename).relative_to(root)))):
                for name in sorted(dirnames):
                    d = Path(dirpath) / name
                    if d.is_symlink():      # os.walk does not descend into it; say so
                        link(d, "/" + str(d.relative_to(root)), tar)
                for name in sorted(filenames):
                    f = Path(dirpath) / name
                    if f.is_symlink():
                        link(f, "/" + str(f.relative_to(root)), tar)
                        continue
                    read(f, "/" + str(f.relative_to(root)), tar)
        trust = system.get("trust_store")
        trust_count = None
        if trust and ".." not in Path(trust).parts:
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
                banks = sorted(p.name[len("pcr-"):] for p in tpm.glob("pcr-*"))
                add(tar, "sys/class/tpm/tpm0/.pcr-banks", json.dumps(banks).encode())
        add(tar, MANIFEST, json.dumps({"system": system["name"], "paths": system["paths"], "files": files,
                                        "unreadable": sorted(unreadable), "larger_than_1MiB": sorted(skipped_large),
                                        "not_regular": sorted(not_regular),
                                        "links_followed": sorted(links_followed, key=lambda x: x["path"]),
                                        "links_not_followed": sorted(links_not_followed, key=lambda x: x["path"]),
                                        "trust_store": trust, "trust_store_certificates": trust_count,
                                        "firmware": bool(system.get("firmware")),
                                        "read_as_uid": os.getuid()}, indent=1).encode())
    return buf.getvalue()


# What may stand in an SSH route (the scope's `via`). Every value becomes one argument of the local
# ssh, and `python` one word of the remote command: none may read as an option or carry anything a
# shell would interpret.
_VIA = {"user": r"[A-Za-z_][A-Za-z0-9._-]*", "host": r"[A-Za-z0-9][A-Za-z0-9.:_-]*", "python": r"[A-Za-z0-9_./][A-Za-z0-9_./-]*",
        "known_hosts": r"/[^\s]+", "identity": r"/[^\s]+"}


def ssh_route(via: dict) -> dict:
    """The scope's SSH route, checked. Raises ValueError naming the field that is not acceptable; a
    route with no known_hosts file is refused, since host-key checking is never off."""
    import re

    out = {"python": "python3", **{k: v for k, v in via.items() if v is not None}}
    for field in ("host", "user", "known_hosts"):
        if not out.get(field):
            raise ValueError(f"the SSH route names no {field}")
    for field, pattern in _VIA.items():
        if field in out and not (isinstance(out[field], str) and re.fullmatch(pattern, out[field])):
            raise ValueError(f"the SSH route's {field} is not acceptable: {str(out[field])[:60]!r}")
    if "port" in out and not (isinstance(out["port"], int) and not isinstance(out["port"], bool) and 0 < out["port"] < 65536):
        raise ValueError("the SSH route's port is not a port number")
    return out


def remote_source(system: dict, prefix: str = "") -> str:
    """The program the remote python reads on stdin: the packer's own source, with the system's
    definition and the archive prefix inside it as literals. Nothing of the scope is on the remote
    command line, so no remote shell ever reads a scoped value."""
    import inspect

    remote = {k: v for k, v in system.items() if k != "via"}
    return "\n".join([
        "from __future__ import annotations",       # the annotations below need no python 3.10
        "import io, json, os, sys, tarfile",
        "from pathlib import Path",
        f"MANIFEST = {MANIFEST!r}", f"MAX_FILE = {MAX_FILE!r}", f"EFIVARS = {EFIVARS!r}", f"DMI = {DMI!r}",
        inspect.getsource(pack),
        f"SYSTEM = json.loads({json.dumps(remote)!r})",
        f"PREFIX = {prefix!r}",
        "root = os.environ.get('PQCH_REMOTE_ROOT', '/')",
        "sys.stdout.buffer.write(pack(root, SYSTEM, prefix=PREFIX))",
        "",
    ])


def remote_pack(system: dict, prefix: str = "", *, ssh: str = "ssh", timeout: int = 300) -> bytes:
    """The same archive, packed on a remote system over SSH: the packer's own source, carrying the
    system's definition, is sent to the remote's python3 on stdin and the tar comes back on stdout.
    The remote command is the interpreter and `-` and nothing else. Nothing is installed on the
    remote and nothing is written to it; the remote reads as the user SSH logs in as, and the
    manifest's `read_as_uid` says which. Host-key checking is strict against the scope's known_hosts
    file alone: no configuration file is read (`-F none`), the system-wide known-hosts file is not
    consulted, and a host not in the scope's file is refused."""
    import shlex
    import subprocess

    via = ssh_route(system["via"])
    cmd = [ssh, "-F", "none", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
           "-o", f"UserKnownHostsFile={via['known_hosts']}", "-o", "GlobalKnownHostsFile=/dev/null"]
    if via.get("port"):
        cmd += ["-p", str(via["port"])]
    if via.get("identity"):
        cmd += ["-i", via["identity"], "-o", "IdentitiesOnly=yes"]
    # `--` ends the options: the destination can never be read as one.
    cmd += ["--", f"{via['user']}@{via['host']}", shlex.quote(via["python"]), "-"]
    res = subprocess.run(cmd, input=remote_source(system, prefix).encode(), capture_output=True, timeout=timeout)
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
            "not_regular": manifest.get("not_regular", []), "links_followed": manifest.get("links_followed", []),
            "links_not_followed": manifest.get("links_not_followed", []),
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
    and any other signature types by GUID. An entry marked X.509 that does not parse is listed among
    the other types as `unparsed-x509`; it does not lose the rest of the database."""
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
                try:
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
                except Exception:       # one entry the library cannot read; the rest of the list stands
                    other.append("unparsed-x509")
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
