"""Signing what the workbench ships with the algorithm it recommends (FR-05): ML-DSA over a bundle's
SHA256SUMS, verified with a public key carried outside the bundle (lesson 07).

    python -m pqch.release keygen <dir> [--alg ML-DSA-65|ML-DSA-87]   # release.key (0600) and release.pub
    python -m pqch.release sign <SHA256SUMS> --key <dir>/release.key    # writes SHA256SUMS.sig
    python -m pqch.release verify <SHA256SUMS> --pub release.pub [--key-id <sha256>]

The signature is over the file's bytes; `.sig` holds the algorithm, the key id (SHA-256 of the public
key's SubjectPublicKeyInfo) and the base64 signature, as JSON. This uses the `cryptography` library's
ML-DSA, which is not a validated module (FR-02): the signature says the sums are the builder's, not
that a FIPS 140-3 module made it.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

KEYS = {"ML-DSA-65": mldsa.MLDSA65PrivateKey, "ML-DSA-87": mldsa.MLDSA87PrivateKey}


def key_id(pub) -> str:
    import hashlib

    return hashlib.sha256(pub.public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()


def _alg(pub) -> str:
    return "ML-DSA-87" if isinstance(pub, mldsa.MLDSA87PublicKey) else "ML-DSA-65" if isinstance(
        pub, mldsa.MLDSA65PublicKey) else type(pub).__name__


def keygen(out: str | Path, alg: str = "ML-DSA-65") -> str:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    k = KEYS[alg].generate()
    priv = out / "release.key"
    fd = os.open(priv, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()))
    (out / "release.pub").write_bytes(k.public_key().public_bytes(serialization.Encoding.PEM,
                                                                  serialization.PublicFormat.SubjectPublicKeyInfo))
    return key_id(k.public_key())


def sign(path: str | Path, key_path: str | Path) -> dict:
    k = serialization.load_pem_private_key(Path(key_path).read_bytes(), None)
    data = Path(path).read_bytes()
    sig = {"schema": "pqch.release-signature/1", "alg": _alg(k.public_key()), "key_id": key_id(k.public_key()),
           "signature": base64.b64encode(k.sign(data)).decode()}
    Path(str(path) + ".sig").write_text(json.dumps(sig, indent=1) + "\n")
    return sig


def verify(path: str | Path, pub_path: str | Path, *, sig_path: str | Path | None = None,
           expect_key_id: str | None = None) -> dict:
    """The signature record, when `path` verifies; raises ValueError otherwise."""
    from cryptography.exceptions import InvalidSignature

    sig = json.loads(Path(sig_path or str(path) + ".sig").read_text())
    pub = serialization.load_pem_public_key(Path(pub_path).read_bytes())
    kid = key_id(pub)
    if sig.get("key_id") != kid:
        raise ValueError(f"signed with key {str(sig.get('key_id'))[:16]}…, not this public key's {kid[:16]}…")
    if expect_key_id and kid != expect_key_id:
        raise ValueError(f"the public key is {kid[:16]}…, not the expected {expect_key_id[:16]}…")
    if sig.get("alg") != _alg(pub):
        raise ValueError(f"the signature says {sig.get('alg')}, the key is {_alg(pub)}")
    try:
        pub.verify(base64.b64decode(sig["signature"]), Path(path).read_bytes())
    except InvalidSignature as e:
        raise ValueError(f"{path} does not verify against its signature") from e
    return sig


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m pqch.release")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("keygen")
    g.add_argument("dir")
    g.add_argument("--alg", choices=sorted(KEYS), default="ML-DSA-65")
    s = sub.add_parser("sign")
    s.add_argument("path")
    s.add_argument("--key", required=True)
    v = sub.add_parser("verify")
    v.add_argument("path")
    v.add_argument("--pub", required=True)
    v.add_argument("--key-id")
    a = ap.parse_args(argv)
    if a.cmd == "keygen":
        print(json.dumps({"key_id": keygen(a.dir, a.alg), "dir": a.dir}))
    elif a.cmd == "sign":
        print(json.dumps({k: v for k, v in sign(a.path, a.key).items() if k != "signature"}))
    else:
        try:
            sig = verify(a.path, a.pub, expect_key_id=a.key_id)
        except ValueError as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1
        print(json.dumps({"ok": True, "alg": sig["alg"], "key_id": sig["key_id"]}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
