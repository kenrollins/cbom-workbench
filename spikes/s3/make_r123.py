"""Write R1, R2 and R3's items and labels. The labels here were written by the build session
(Claude Fable 5.1), each with the evidence that settles it; see labels/README.md. No model under
test is involved, and nothing in an item is composed: R1 and R2 items are real lines and real
tool spellings taken in the seeded order of candidates/, R3 names come from sources/r3-names.yaml.

    uv run python spikes/s3/make_r123.py
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
SEED = "pqch-s3-2026-10-05"
NEG = {"is_crypto_use": False, "family": "none", "role": "other", "key_bits": None}


def use(family: str, role: str, bits: int | None, why: str) -> dict:
    return {"is_crypto_use": True, "family": family, "role": role, "key_bits": bits, "citation": why}


def non(why: str) -> dict:
    return {**NEG, "citation": why}


# ----------------------------------------------------------------------------------------- R1
# Keyed by index in candidates/r1.jsonl. Every candidate up to the last one taken was judged, in
# order; those not listed here were not a use and arrived after their repository's quota of four
# non-uses was full (labels/r1-draw-log.jsonl lists each).
R1 = {
    # 18F/identity-idp (Ruby)
    0: non("A string: the description of an RSpec `context`. Nothing executes."),
    1: non("A hash literal's value, the string 'chunk1', in a spec."),
    2: non("`method(:encrypt_raw_kms)` refers to the application's own method; no cryptographic library is called on this line."),
    3: non("`encryptor.encrypt(...)` calls the application's own encryptor object; the library call is inside it, not on this line."),
    5: use("RSA", "signature", None, "`JWT.encode(` with the algorithm argument 'RS256' three lines below (line 20): RSASSA-PKCS1-v1_5 with SHA-256, a signature."),
    11: use("RSA", "signature", 2048, "`OpenSSL::PKey::RSA.new 2048` generates a 2048-bit RSA key; line 8 names it `threatmetrix_signing_key`."),
    12: use("RSA", "signature", None, "`OpenSSL::PKey::RSA.new(<file>.read)` parses an RSA private key; lines 852-859 sign a JWT with it using 'RS256'. No size is stated."),
    22: use("SHA-2", "hash", None, "`OpenSSL::Digest::SHA256.hexdigest(salt)`: a SHA-256 digest."),
    23: use("scrypt", "other", None, "`SCrypt::Password.new(scrypted).digest`: the scrypt gem's API on an scrypt hash; a password-hashing function is `other` among the six roles."),
    24: use("RSA", "signature", None, "`JWT.decode(` with verification on (`true`, line 99) and `algorithm: 'RS256'` (line 100): an RSA signature verification."),
    34: use("RSA", "signature", None, "`JWT::JWK.import(key).public_key` imports a JWK; lines 11-12 assert every key is `alg` RS256 and `use` sig."),
    36: use("HMAC", "mac", None, "`JWT.encode(..., 'HS256', ...)`: HMAC with SHA-256."),
    # CMSgov/dpc-app (Java)
    60: non("`Mockito.verify(...)` checks a mock was called; it is the test library's verify, not a signature verification."),
    61: non("A comment."),
    62: non("`Mockito.verify(...)`, as above."),
    63: non("`SecretHelpers.generateSecretKey(this.random)` calls the application's own helper; no cryptographic library is called on this line."),
    65: non("A comment."),
    66: non("`.dest(\"token-expiration\")` names a command-line argument."),
    64: use("RSA", "signature", None, "`keyFactory.generatePublic(keySpec)` on the `KeyFactory.getInstance(\"RSA\")` of line 103; lines 106-109 verify a SHA256withRSA signature with the key."),
    69: use("unspecified", "other", None, "`KeyPairGenerator.getInstance(keyType.getName())`: the algorithm is a parameter, RSA or EC (lines 183-186); no use of the key pair is shown."),
    74: use("unspecified", "other", None, "`KeyFactory.getInstance(keyType).generatePublic(spec)`: `keyType` is \"RSA\" or \"EC\" (line 153); no use of the key is shown."),
    77: use("RSA", "signature", None, "`Signature.getInstance(\"SHA256withRSA\")`, then `initSign` and `sign` on the next lines."),
    85: use("RSA", "encryption", None, "`KeyPairGenerator.getInstance(\"RSA\")`; the test encrypts and decrypts with `Cipher.getInstance(\"RSA\")` (lines 183-199). No size is given."),
    88: use("RSA", "encryption", None, "`KeyFactory.getInstance(\"RSA\").generatePublic(spec)`; the key initialises the RSA cipher on the next line."),
    # CMSgov/bluebutton-web-server (Python)
    92: non("JSON test data: the string \"token\"."),
    94: non("`except jwt.PyJWTError:` names an exception class; nothing is called."),
    96: non("A string literal: an error message."),
    98: non("A migration field whose `verbose_name` is the string 'PBKDF2 of User ID'; nothing is computed."),
    93: use("SHA-2", "hash", None, "`hashlib.sha256(...).hexdigest()`."),
    95: use("HMAC", "mac", None, "`jwt.encode(` with `algorithm='HS256'` (line 483): HMAC with SHA-256."),
    97: use("unspecified", "other", None, "`jwt.decode(..., options={'verify_signature': False})` is a direct call into the JWT library, so it is a use; it names no algorithm and, with verification off, runs no signature primitive. Ruling 3 in labels/README.md."),
    99: use("SHA-2", "hash", None, "`hashlib.sha256(` ... `).hexdigest()` across lines 425-427."),
    101: use("SHA-2", "hash", None, "`hashlib.sha256(verifier.encode('ASCII')).digest()`."),
    110: use("PBKDF2", "other", None, "`pbkdf2(hicn, salt, iterations)` — Django's `django.utils.crypto.pbkdf2` (imported at line 10 of the file); a key-derivation function is `other`."),
    111: use("SHA-2", "hash", None, "`hashlib.sha256(...).hexdigest()`."),
    117: use("SHA-2", "hash", None, "`hashlib.sha256(...).hexdigest()`."),
}
R1_CUTOFF = {"18F/identity-idp": 36, "CMSgov/dpc-app": 88, "CMSgov/bluebutton-web-server": 117}

# ----------------------------------------------------------------------------------------- R2
R2_EXCLUDED_FIELDS = {"cipher suite", "FS_ciphers", "Cipher"}     # compound names: a suite is several algorithms
R2_NAMES = yaml.safe_load((HERE / "sources" / "r2-names.yaml").read_text())
ANY_KEY_ROLE = ["signature", "encryption", "key-establishment", "other"]
A, K = "algorithm", "related-crypto-material"
R2 = {  # spelling -> (name, asset_type, role or list of acceptable roles, citation)
    "1.2.840.10045.4.3.2": ("ECDSA", A, "signature", "OID ecdsa-with-SHA256, ANSI X9.62 / RFC 5758 section 3.2."),
    "hmac-md5-96": ("HMAC-MD5", A, "mac", "RFC 4253 section 6.4: HMAC-MD5 truncated to 96 bits."),
    "ECDSA with SHA256": ("ECDSA", A, "signature", "testssl.sh's wording of a certificate's signature algorithm."),
    "ML-DSA-65": ("ML-DSA-65", A, "signature", "FIPS 204 parameter set, already the standard name."),
    "brainpoolP512r1": ("brainpoolP512r1", A, "key-establishment", "IANA TLS Supported Groups 28 (RFC 7027); reported under the ECDHE curves a listener accepts."),
    "rsaEncryption": ("RSA", A, ANY_KEY_ROLE, "OID 1.2.840.113549.1.1.1 (RFC 8017), the algorithm of a certificate's public key; an RSA key signs or decrypts, so any key role is accepted."),
    "ECDH, secp521r1, 521 bits": ("secp521r1", A, "key-establishment", "OpenSSL's `Temp Key` line: an ECDH exchange on secp521r1."),
    "ext-info-s": ("unknown", None, None, "RFC 8308: an indicator that the server supports extension negotiation, listed among key-exchange names; it negotiates nothing."),
    "X25519, 253 bits": ("X25519", A, "key-establishment", "OpenSSL's `Temp Key` line for X25519 (RFC 7748)."),
    "DH, 3072 bits": ("DH-3072", A, "key-establishment", "OpenSSL's `Temp Key` line for finite-field Diffie-Hellman: it states the size and not the group, so the name is the size (journal lesson 10); a named group would be invented."),
    "hmac-ripemd160-etm@openssh.com": ("HMAC-RIPEMD-160", A, "mac", "OpenSSH's encrypt-then-MAC variant of hmac-ripemd160 (PROTOCOL, section 1.6)."),
    "offered": ("unknown", None, None, "A word from testssl.sh's sentence about KEMs, not a name."),
    "ECDSA+SHA384": ("ECDSA", A, "signature", "A TLS 1.2 signature-and-hash pair (RFC 5246 section 7.4.1.4.1)."),
    "RSA-3072": ("RSA", K, ANY_KEY_ROLE, "cbomkit-theia's name for an RSA key of 3072 bits; theia types it related-crypto-material (tests/fixtures/theia-portal.json)."),
    "umac-64-etm@openssh.com": ("UMAC-64", A, "mac", "RFC 4418 UMAC with a 64-bit tag, OpenSSH's encrypt-then-MAC variant."),
    "brainpoolP256r1": ("brainpoolP256r1", A, "key-establishment", "IANA TLS Supported Groups 26 (RFC 7027)."),
    "rijndael-cbc@lysator.liu.se": ("AES-256", A, "encryption", "OpenSSH's cipher table lists it as an alias of aes256-cbc (cipher.c)."),
    "RSA+SHA384": ("RSA", A, "signature", "A TLS 1.2 signature-and-hash pair: RSASSA-PKCS1-v1_5 with SHA-384."),
    "RSA+SHA224": ("RSA", A, "signature", "As above, with SHA-224."),
    "1.2.840.113549.1.1.11": ("RSA", A, "signature", "OID sha256WithRSAEncryption (RFC 8017, appendix A.2.4)."),
    "aes128-cbc": ("AES-128", A, "encryption", "RFC 4253 section 6.3."),
    "blowfish-cbc": ("Blowfish", A, "encryption", "RFC 4253 section 6.3."),
    "api.agency.test": ("unknown", None, None, "A certificate's subject name, which cbomkit-theia uses as the component's name; not an algorithm."),
    "ECDSA+SHA256": ("ECDSA", A, "signature", "A TLS 1.3 signature scheme reported as a pair."),
    "SHA1-RSA": ("RSA", A, "signature", "cbomkit-theia's name for sha1WithRSAEncryption; theia types it an algorithm with primitive signature (tests/fixtures/theia-portal.json)."),
    "RSA+SHA1": ("RSA", A, "signature", "A TLS 1.2 signature-and-hash pair."),
    "arcfour": ("RC4", A, "encryption", "RFC 4253 section 6.3: arcfour is RC4."),
    "RSA+SHA256": ("RSA", A, "signature", "A TLS 1.2 signature-and-hash pair."),
    "hmac-sha2-256-etm@openssh.com": ("HMAC-SHA-256", A, "mac", "RFC 6668 hmac-sha2-256, OpenSSH's encrypt-then-MAC variant."),
    "RSA-PSS-RSAE+SHA512": ("RSA", A, "signature", "TLS 1.3 scheme rsa_pss_rsae_sha512 (RFC 8446 section 4.2.3); the family is RSA."),
    "id-ecPublicKey": ("ECDSA", A, ANY_KEY_ROLE, "OID 1.2.840.10045.2.1 (RFC 5480), the algorithm of a certificate's elliptic-curve public key; the project names such a key by its signature family, ECDSA (agency/answer-key.yaml, Names)."),
    "brainpoolP384r1": ("brainpoolP384r1", A, "key-establishment", "IANA TLS Supported Groups 27 (RFC 7027)."),
    "private-key": ("unknown", None, None, "cbomkit-theia's name for a key whose algorithm it did not state; an algorithm is never inferred (src/pqch/scout/names.py)."),
    "RSA-2048": ("RSA", K, ANY_KEY_ROLE, "cbomkit-theia's name for an RSA key of 2048 bits."),
    "DH, 8192 bits": ("DH-8192", A, "key-establishment", "As `DH, 3072 bits`: the size is stated, the group is not."),
    "No": ("unknown", None, None, "The first word of testssl.sh's `No KEMs offered`."),
}

# ----------------------------------------------------------------------------------------- R3
R3_RULE = {  # family -> (quantum_vulnerable, citation in the memo's Appendix A)
    "ecdh": (True, "section 2, row 1: Elliptic Curve Diffie-Hellman (ECDH) Key Exchange"),
    "mqv": (True, "section 2, row 2: Menezes-Qu-Vanstone (MQV) Key Exchange"),
    "ecdsa": (True, "section 2, row 3: ECDSA"),
    "finite-field-dh": (True, "section 2, row 4: Diffie-Hellman (DH) Key Exchange and variants"),
    "rsa": (True, "section 2, rows 5 and 6: RSA Signature Algorithm; RSA Key Establishment"),
    "dsa": (True, "section 2, row 7: Digital Signature Algorithm"),
    "eddsa": (True, "section 2, row 8 and footnote 13: an asymmetric algorithm not enumerated and not one of section 1's three"),
    "ml-kem": (False, "section 1, item 1: FIPS 203 ML-KEM"),
    "ml-dsa": (False, "section 1, item 2: FIPS 204 ML-DSA"),
    "slh-dsa": (False, "section 1, item 3: FIPS 205 SLH-DSA"),
    "hybrid": (False, "section 3: a hybrid combines a traditional algorithm with a PQC one, and an attacker must break both"),
    "symmetric-cipher": (False, "section 2 lists asymmetric algorithms only, and footnote 13 extends it to asymmetric algorithms only"),
    "hash-or-mac": (False, "section 2 lists asymmetric algorithms only, and footnote 13 extends it to asymmetric algorithms only"),
}


def split_dev(ids: list[str], role: str, groups: dict[str, list[str]] | None = None) -> set[str]:
    """Six development items, by seeded shuffle; for R1, two per repository."""
    rng = random.Random(f"{SEED}/dev/{role}")
    if groups:
        return {i for g in sorted(groups) for i in rng.sample(sorted(groups[g]), 2)}
    return set(rng.sample(sorted(ids), 6))


def write(role: str, items: list[dict], labels: list[dict], groups=None) -> None:
    dev = split_dev([i["id"] for i in items], role, groups)
    for i in items:
        i["set"] = "dev" if i["id"] in dev else "scored"
    (HERE / "items" / f"{role}.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in items))
    (HERE / "labels" / f"{role}.jsonl").write_text("".join(json.dumps(i, ensure_ascii=False) + "\n" for i in labels))
    print(role, len(items), "items;", sum(i["set"] == "scored" for i in items), "scored,", len(dev), "dev")


def r1() -> None:
    cands = [json.loads(x) for x in (HERE / "candidates" / "r1.jsonl").read_text().splitlines()]
    items, labels, log, groups = [], [], [], {}
    for idx, c in enumerate(cands):
        if idx > R1_CUTOFF[c["repo"]]:
            continue
        taken = idx in R1
        log.append({"candidate": idx, "repo": c["repo"], "path": c["path"], "line": c["line"],
                    "judged": ("use" if R1[idx]["is_crypto_use"] else "not a use") if taken else "not a use",
                    "taken": taken, "why_not": None if taken else "the repository's quota of non-uses was already full"})
        if not taken:
            continue
        iid = f"r1-{idx:03d}"
        groups.setdefault(c["repo"], []).append(iid)
        items.append({"id": iid, "role": "R1", "repo": c["repo"], "commit": c["commit"], "language": c["language"],
                      "path": c["path"], "line": c["line"], "flagged": c["text"], "context": c["context"]})
        lab = dict(R1[idx])
        labels.append({"id": iid, "label": {k: lab[k] for k in ("is_crypto_use", "family", "role", "key_bits")},
                       "citation": lab["citation"]})
    (HERE / "labels" / "r1-draw-log.jsonl").write_text("".join(json.dumps(x) + "\n" for x in log))
    write("r1", items, labels, groups)


def r2() -> None:
    cands = [json.loads(x) for x in (HERE / "candidates" / "r2.jsonl").read_text().splitlines()]
    cap, picked, rest = {}, [], []
    for c in cands:
        if c["field"] in R2_EXCLUDED_FIELDS:
            continue
        k = (c["tool"], c["field"])
        if len(picked) < 36 and cap.get(k, 0) < 6:
            cap[k] = cap.get(k, 0) + 1
            picked.append(c)
        else:
            rest.append(c)
    # At least five that are not algorithms: replace the last-drawn algorithms with the next non-algorithms in order.
    is_unknown = lambda c: R2.get(c["spelling"], ("?",))[0] == "unknown"  # noqa: E731
    while sum(is_unknown(c) for c in picked) < 5:
        nxt = next(c for c in rest if c["spelling"] in R2 and is_unknown(c))
        rest.remove(nxt)
        drop = max(i for i, c in enumerate(picked) if not is_unknown(c))
        picked[drop] = nxt
    items, labels = [], []
    for n, c in enumerate(picked, 1):
        name, typ, role, why = R2[c["spelling"]]
        assert name in R2_NAMES["names"] or name == "unknown", name
        iid = f"r2-{n:02d}"
        items.append({"id": iid, "role": "R2", "tool": c["tool"], "field": c["field"], "spelling": c["spelling"], "seen_in": c["seen_in"]})
        labels.append({"id": iid, "label": {"name": name, "asset_type": typ, "role": role}, "citation": why})
    write("r2", items, labels)


def r3() -> None:
    src = yaml.safe_load((HERE / "sources" / "r3-names.yaml").read_text())["names"]
    random.Random(f"{SEED}/r3").shuffle(src)
    items, labels = [], []
    for n, row in enumerate(src[:36], 1):
        vulnerable, cite = R3_RULE[row["family"]]
        asset = {"type": row.get("type", "algorithm"), "role": row["role"], "name": row["name"]}
        if row.get("parameters"):
            asset["parameters"] = row["parameters"]
        iid = f"r3-{n:02d}"
        items.append({"id": iid, "role": "R3", "finding": {"layer": "wire", "asset": asset}, "policy": "sources/m-26-15-appendix-a.txt"})
        labels.append({"id": iid, "label": {"quantum_vulnerable": vulnerable, "function": row["function"], "family": row["family"]},
                       "citation": f"OMB M-26-15, Appendix A, {cite}. {row['why']}"})
    write("r3", items, labels)


if __name__ == "__main__":
    r1()
    r2()
    r3()
