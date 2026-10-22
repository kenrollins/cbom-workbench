You read one flagged line of source code and say whether it is a cryptographic use.

The rule. The flagged line is a cryptographic use only if that line itself, as code that executes, calls an API of a cryptographic library or names the algorithm for one: generating, parsing or importing a key; signing or verifying; encrypting or decrypting; computing a digest or a MAC; deriving a key or hashing a password; creating, parsing or verifying a token or certificate. Libraries count whatever the language: OpenSSL, Digest, JWT and SCrypt in Ruby; java.security, javax.crypto and Bouncy Castle in Java; hashlib, hmac, jwt, cryptography and Django's crypto helpers in Python.

It is not a use if the line is a comment, a string, documentation or data; an import; a declaration or definition that runs no library call (a method signature, a class, an attribute, a column); a mock or test assertion; or a call to the application's own method or object whose name merely contains a word such as encrypt, sign, verify, digest, token, key or fingerprint. A wrapper is not a use even if the wrapped code, elsewhere, calls a library. Code in a test file is judged the same way as any other code.

A call into a token library is a use even when it is told not to verify.

If it is a use, also give:
- family: the algorithm named on the flagged line, or else the one the shown context fixes. One of: RSA, ECDSA, EC, Ed25519, DSA, DH, AES, 3DES, ChaCha20, SHA-1, SHA-2, SHA-3, MD5, HMAC, PBKDF2, scrypt, bcrypt, X.509, unspecified. Use unspecified when the context allows more than one algorithm or names none. JWT algorithm RS256 is RSA; HS256 is HMAC; SHA-256, SHA-384 and SHA-512 are SHA-2.
- role: what the operation, or the key it handles, is used for in the shown context. One of: key-establishment, signature, encryption, hash, mac, other. A digest is hash; an HMAC is mac; a key-derivation or password-hashing function is other; a key that is generated or parsed with no use shown is other.
- key_bits: the key size in bits when a number on the line or in the context states it; otherwise null.

If it is not a use, answer family "none", role "other", key_bits null.

Answer with JSON only.
---
Repository: {repo}
File: {path} ({language})
Flagged line: {line}

{context}
