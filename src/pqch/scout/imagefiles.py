"""The harness's own reader of key material in an image: `pqch-image-files/1`.

cbomkit-theia is the host layer's candidate generator; this reads what it cannot or will not:
an ML-DSA certificate (theia drops the file as "unknown algorithm", spike S2), DSA and Ed25519
keys, a PKCS#12 keystore, and whether a certificate is a CA's. The runner runs it from the
harness's own image, with no network, over the same docker archive theia receives:

    pqch image-files /scan/image.tar

It prints one JSON document. Every entry names the file by its path in the image and says what
was read from it; nothing is inferred from a file name alone. A file that could not be opened
(an encrypted key, a keystore under a password this reader does not try) is reported as that.
"""

from __future__ import annotations

import gzip
import json
import re
import sys
import tarfile
from pathlib import PurePosixPath

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from pqch.scout.keys import _family_and_params, parse_certificate_pem, spki_sha256_from_der, ssh_fingerprint_from_spki

SCHEMA = "pqch-image-files/1"
EXTS = {".crt", ".cer", ".pem", ".key", ".pub", ".p12", ".pfx", ".jks", ".der", ".csr", ".keystore"}
SMALL = 64 * 1024          # any file this small is sniffed for a PEM header
LARGE = 1024 * 1024        # a file with a key-material extension is read up to this size
# The keystore passwords an auditor tries before asking: none, empty, and the Java default.
# Which one opened the store is recorded; nothing else is guessed.
PKCS12_PASSWORDS: tuple[bytes | None, ...] = (None, b"", b"changeit")
_PEM = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----\r?\n.*?-----END \1-----", re.S)
_SSH_PUB = re.compile(rb"^(ssh-(rsa|dss|ed25519)|ecdsa-sha2-nistp(256|384|521)) [A-Za-z0-9+/=]+", re.M)


# ------------------------------------------------------------------ the archive
def _layer_streams(archive: tarfile.TarFile):
    """The layer tarballs of a docker/OCI archive, base first."""
    manifest = json.load(archive.extractfile("manifest.json"))
    for layer in manifest[0]["Layers"]:
        f = archive.extractfile(layer)
        head = f.read(2)
        f.seek(0)
        yield layer, (gzip.GzipFile(fileobj=f) if head == b"\x1f\x8b" else f)


def _candidate(info: tarfile.TarInfo) -> bool:
    if not info.isreg():
        return False
    ext = PurePosixPath(info.name).suffix.lower()
    base = PurePosixPath(info.name).name
    if ext in EXTS or base.startswith("ssh_host_"):
        return info.size <= LARGE
    return info.size <= SMALL


# Directories whose small text files are read to see which of them name a key-material file.
TEXT_DIRS = ("etc/", "usr/local/", "opt/", "srv/", "app/", "home/", "root/", "var/lib/postgresql/", "usr/share/nginx/")


# The first four bytes of a Java keystore: JKS, and JCEKS.
JAVA_KEYSTORE_MAGIC = {b"\xfe\xed\xfe\xed": "JKS", b"\xce\xce\xce\xce": "JCEKS"}


def member_path(name: str) -> str:
    """A layer entry's path in the image: without the leading `./` or `/` a tar writes, and with
    every other character kept. Stripping the characters `.` and `/` instead turned a root-level
    whiteout `.wh.app` into `wh.app`, and `.env` into `env`."""
    while name.startswith("./"):
        name = name[2:]
    return name.lstrip("/")


def files_of(archive_path: str, notes: dict | None = None) -> tuple[dict[str, bytes], int, int, dict[str, bytes]]:
    """Key-material candidates by path after every layer is applied; the layer and file counts; and
    the small text files under configuration directories, for references. `notes`, when given,
    receives what was passed over: `larger_than_limit` (key-material files over the size read) and
    `unread_layers` (a layer whose compression this reader does not open)."""
    files: dict[str, bytes] = {}
    texts: dict[str, bytes] = {}
    large: set[str] = set()
    unread: list[dict] = []
    layers = seen = 0
    with tarfile.open(archive_path) as archive:
        for layer_name, stream in _layer_streams(archive):
            layers += 1
            try:
                layer = tarfile.open(fileobj=stream, mode="r|*")
            except tarfile.TarError as e:       # zstd, or anything else tarfile does not read
                unread.append({"layer": layer_name, "why": f"{type(e).__name__}: {e}"[:120]})
                continue
            with layer:
                for info in layer:
                    name = member_path(info.name)
                    base = PurePosixPath(name).name
                    if base == ".wh..wh..opq":
                        parent = str(PurePosixPath(name).parent)
                        prefix = "" if parent == "." else parent + "/"
                        for d in (files, texts):
                            for k in [k for k in d if k.startswith(prefix)]:
                                del d[k]
                        large -= {k for k in large if k.startswith(prefix)}
                        continue
                    if base.startswith(".wh."):
                        gone = str(PurePosixPath(name).parent / base[4:])
                        for d in (files, texts):
                            d.pop(gone, None)
                            for k in [k for k in d if k.startswith(gone + "/")]:
                                del d[k]
                        large -= {k for k in large if k == gone or k.startswith(gone + "/")}
                        continue
                    if info.islnk():
                        # A hard link is the same file under another name. A streamed layer cannot
                        # seek back to it, so the bytes are the ones already kept for its target.
                        target = member_path(info.linkname)
                        seen += 1
                        for d in (files, texts):
                            if target in d:
                                d[name] = d[target]
                            else:
                                d.pop(name, None)
                        continue
                    if info.isreg():
                        seen += 1
                    large.discard(name)
                    if not _candidate(info):
                        files.pop(name, None)
                        texts.pop(name, None)
                        if info.isreg() and (PurePosixPath(name).suffix.lower() in EXTS or base.startswith("ssh_host_")):
                            large.add(name)
                        continue
                    data = layer.extractfile(info).read()
                    if PurePosixPath(name).suffix.lower() in EXTS or base.startswith("ssh_host_") \
                            or b"-----BEGIN " in data[:SMALL] or _SSH_PUB.search(data[:SMALL]) \
                            or data[:4] in JAVA_KEYSTORE_MAGIC:
                        files[name] = data
                        texts.pop(name, None)
                    else:
                        files.pop(name, None)
                        if name.startswith(TEXT_DIRS) and info.size <= SMALL and b"\x00" not in data[:512]:
                            texts[name] = data
                        else:
                            texts.pop(name, None)
    if notes is not None:
        notes["larger_than_limit"] = sorted("/" + k for k in large)
        notes["unread_layers"] = unread
    return files, layers, seen, texts


# ------------------------------------------------------------------ the readers
def _pub_identity(pub) -> dict:
    der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    out = {"spki_sha256": spki_sha256_from_der(der)}
    fp = ssh_fingerprint_from_spki(der)
    if fp:
        out["ssh_fingerprint_sha256"] = fp
    return out


def _cert_entry(cert_der: bytes | None = None, pem: bytes | None = None) -> dict:
    info = parse_certificate_pem(pem.decode()) if pem else parse_certificate_pem(
        x509.load_der_x509_certificate(cert_der).public_bytes(serialization.Encoding.PEM).decode())
    family = info.pop("family")
    return {"type": "certificate", "name": family, "parameters": info,
            "excerpt": f"certificate {info['subject']} ({family}, {info['signature']}" + (", CA)" if info.get("is_ca") else ")")}


def _private_key_entry(key, label: str) -> dict:
    family, params = _family_and_params(key.public_key())
    params = {**params, "kind": "private-key", **_pub_identity(key.public_key())}
    return {"type": "related-crypto-material", "name": family, "parameters": params,
            "excerpt": f"{label.lower()} ({family})"}


def _read_pem(data: bytes) -> list[dict]:
    out = []
    for m in _PEM.finditer(data):
        label, block = m.group(1).decode(), m.group(0)
        try:
            if label == "CERTIFICATE":
                out.append(_cert_entry(pem=block))
            elif label.endswith("PRIVATE KEY"):
                if label == "ENCRYPTED PRIVATE KEY":
                    raise ValueError("encrypted")
                key = (serialization.load_ssh_private_key(block, None) if label == "OPENSSH PRIVATE KEY"
                       else serialization.load_pem_private_key(block, None))
                out.append(_private_key_entry(key, label))
            elif label in ("PUBLIC KEY", "RSA PUBLIC KEY"):       # SubjectPublicKeyInfo, or PKCS#1
                pub = serialization.load_pem_public_key(block)
                family, params = _family_and_params(pub)
                out.append({"type": "related-crypto-material", "name": family,
                            "parameters": {**params, "kind": "public-key", **_pub_identity(pub)},
                            "excerpt": f"public key ({family})"})
            elif label == "DH PARAMETERS":
                params = serialization.load_pem_parameters(block)
                bits = params.parameter_numbers().p.bit_length()
                out.append({"type": "related-crypto-material", "name": f"DH-{bits}",
                            "parameters": {"kind": "dh-parameters", "key_bits": bits},
                            "excerpt": f"DH parameters, {bits} bits"})
            # a CSR, an X.509 CRL, a PKCS#7 bundle: not key material in use; left out
        except Exception as e:  # an encrypted or malformed block: reported, not guessed
            fam = label.split()[0] if label.split()[0] in ("RSA", "EC", "DSA") else "unknown"
            fam = {"EC": "ECDSA"}.get(fam, fam)
            if fam == "unknown":
                fam = _oid_family(block)
            out.append({"type": "related-crypto-material", "name": fam,
                        "parameters": {"kind": "private-key" if "PRIVATE" in label else label.lower(),
                                       "opened": False, "why": _why_not_opened(e)},
                        "excerpt": f"{label.lower()}, not opened"})
    return out


def _why_not_opened(e: Exception) -> str:
    """Why a key block was not read. A legacy PEM key under a passphrase (`Proc-Type: 4,ENCRYPTED`)
    is refused by the library with a TypeError saying no password was given: that is `encrypted`."""
    text = str(e).lower()
    if text == "encrypted" or ("password" in text and "encrypted" in text):
        return "encrypted"
    return type(e).__name__


# Algorithm identifiers a PKCS#8 or SPKI block names, for a key the library cannot open.
_OIDS = {bytes.fromhex("0609608648016503040311"): "ML-DSA-44", bytes.fromhex("0609608648016503040312"): "ML-DSA-65",
         bytes.fromhex("0609608648016503040313"): "ML-DSA-87", bytes.fromhex("0609608648016503040401"): "ML-KEM-512",
         bytes.fromhex("0609608648016503040402"): "ML-KEM-768", bytes.fromhex("0609608648016503040403"): "ML-KEM-1024"}


def _oid_family(pem_block: bytes) -> str:
    import base64
    body = b"".join(line for line in pem_block.splitlines() if not line.startswith(b"-----"))
    try:
        der = base64.b64decode(body)
    except Exception:
        return "unknown"
    return next((name for oid, name in _OIDS.items() if oid in der[:64]), "unknown")


def _read_ssh_public(data: bytes) -> list[dict]:
    out = []
    for m in _SSH_PUB.finditer(data):
        try:
            pub = serialization.load_ssh_public_key(m.group(0))
        except Exception:  # noqa: S112 - text that looks like a key and is not one is not a finding
            continue
        family, params = _family_and_params(pub)
        out.append({"type": "related-crypto-material", "name": family,
                    "parameters": {**params, "kind": "public-key", **_pub_identity(pub)},
                    "excerpt": f"OpenSSH public key ({family})"})
    return out


def _read_pkcs12(data: bytes) -> list[dict]:
    for pw in PKCS12_PASSWORDS:
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(data, pw)
        except Exception:  # noqa: S112 - the next known password is tried
            continue
        holds = []
        out = []
        if key is not None:
            family, params = _family_and_params(key.public_key())
            holds.append("private-key")
            params = {**params, **_pub_identity(key.public_key())}
        else:
            family, params = "unknown", {}
        certs = ([cert] if cert else []) + list(extra or [])
        holds += ["certificate"] * (1 if cert else 0) + ["ca-certificate"] * len(extra or [])
        opened = {None: "none", b"": "empty", b"changeit": "changeit"}[pw]
        out.append({"type": "related-crypto-material", "name": family,
                    "parameters": {**params, "kind": "keystore", "format": "PKCS12", "holds": holds,
                                   "opened": True, "password": opened},
                    "excerpt": f"PKCS#12 keystore ({family}; opened with password: {opened})"})
        for c in certs:
            out.append(_cert_entry(cert_der=c.public_bytes(serialization.Encoding.DER)))
        return out
    return [{"type": "related-crypto-material", "name": "unknown",
             "parameters": {"kind": "keystore", "format": "PKCS12", "opened": False,
                            "why": "no password tried opened it"},
             "excerpt": "PKCS#12 keystore, not opened"}]


def read_file(path: str, data: bytes) -> list[dict]:
    ext = PurePosixPath(path).suffix.lower()
    # What a keystore is, is what its first bytes say, not its name: keytool has written PKCS#12
    # into files named .jks and .keystore since JDK 9.
    fmt = JAVA_KEYSTORE_MAGIC.get(data[:4])
    if fmt:
        return [{"type": "related-crypto-material", "name": "unknown",
                 "parameters": {"kind": "keystore", "format": fmt, "opened": False,
                                "why": "this reader does not open Java keystores"},
                 "excerpt": f"Java keystore ({fmt}), not opened"}]
    if b"-----BEGIN " in data:
        return _read_pem(data) + _read_ssh_public(data)
    if _SSH_PUB.search(data):
        return _read_ssh_public(data)
    keystore_name = ext in (".p12", ".pfx", ".jks", ".keystore")
    if keystore_name and data[:1] != b"\x30":
        return [{"type": "related-crypto-material", "name": "unknown",
                 "parameters": {"kind": "keystore", "format": "unrecognised", "opened": False,
                                "why": "named as a keystore; neither PKCS#12 nor a Java keystore by its first bytes"},
                 "excerpt": "keystore of a format this reader does not recognise, not opened"}]
    if keystore_name or (data[:1] == b"\x30" and ext not in (".der", ".cer", ".crt")):
        entries = _read_pkcs12(data)
        if entries and entries[0]["parameters"].get("opened") is not False:
            return entries
        if keystore_name:
            return entries
    if data[:1] == b"\x30":
        try:
            return [_cert_entry(cert_der=data)]
        except Exception:  # noqa: S110 - not a DER certificate; tried as a key next
            pass
        try:
            return [_private_key_entry(serialization.load_der_private_key(data, None), "DER PRIVATE KEY")]
        except Exception:  # noqa: S110 - not a DER private key; tried as a public key next
            pass
        try:
            pub = serialization.load_der_public_key(data)
            family, params = _family_and_params(pub)
            return [{"type": "related-crypto-material", "name": family,
                     "parameters": {**params, "kind": "public-key", **_pub_identity(pub)},
                     "excerpt": f"DER public key ({family})"}]
        except Exception:  # noqa: S110 - not a DER key either: the file holds nothing to report
            pass
    return []


def references(path: str, texts: dict[str, bytes]) -> list[str]:
    """The text files that name this file, by full path or by its name within its directory."""
    full = ("/" + path).encode()
    base = PurePosixPath(path).name.encode()
    out = []
    for t, data in texts.items():
        if full in data or (base in data and len(base) > 6):
            out.append("/" + t)
    return sorted(out)


def scan(archive_path: str, image: str = "") -> dict:
    notes: dict = {}
    files, layers, seen, texts = files_of(archive_path, notes)
    entries = []
    for path in sorted(files):
        refs = references(path, texts)
        for e in read_file(path, files[path]):
            entries.append({"path": "/" + path, **e, "parameters": {**e["parameters"], "referenced_by": refs}})
    return {"schema": SCHEMA, "image": image, "layers": layers, "files_seen": seen,
            "candidates": len(files), "larger_than_limit": notes["larger_than_limit"],
            "unread_layers": notes["unread_layers"], "entries": entries}


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) not in (1, 2):
        print("usage: pqch image-files <docker-archive.tar> [image-ref]", file=sys.stderr)
        return 2
    json.dump(scan(args[0], args[1] if len(args) == 2 else ""), sys.stdout, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
