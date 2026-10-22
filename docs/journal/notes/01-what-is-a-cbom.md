---
id: note-01-what-is-a-cbom
type: note
title: "What is a CBOM, and what is in one?"
date: 2026-10-21
audience: [leader, architect, engineer]
tags: [cbom, discovery, policy]
rung: all
one_line: "A CBOM is a CycloneDX bill of materials whose components are cryptographic assets — algorithms, certificates, protocols and key material — with their properties and dependencies; the format is an Ecma standard, the content an agency must put in one is not yet fixed, and the practice of building and using one is where the field is still improvising."
claims:
  - text: "CycloneDX, the format a CBOM is written in, is ratified by Ecma International as ECMA-424; CBOM support is part of CycloneDX 1.6 and higher."
    provenance: "cited: OWASP, Authoritative Guide to CBOM, 'About the Guide' and 'Introduction' (PDF sha256 77d94047e6085580…, read 2026-10-08)"
  - text: "CycloneDX 1.6 defines four cryptographic asset types — algorithm, certificate, protocol, related-crypto-material — fifteen algorithm primitives, and a dependency element with dependsOn and provides."
    provenance: "cited: CycloneDX 1.6.1 JSON schema, vendored at src/pqch/cbom/schema/bom-1.6.schema.json"
  - text: "OMB M-26-15 requires each agency to populate a central CBOM from software composition analysis, static and dynamic testing, and network scanning; Executive Order 14412 directs CISA and NIST to publish the minimum elements of a CBOM within 270 days, which falls on 2027-03-19."
    provenance: "cited: OMB M-26-15, Appendix A, section 6, read first-hand 2026-10-03; EO 14412 as recorded in BRIEF.md's facts table with its caveat (read through a summarizing tool; the 270-day date computed)"
  - text: "The workbench's CBOM for the eight-service mini-agency holds 254 components — 47 assets seen on the wire, 182 in images, 9 listeners, 8 services and 8 images — validated against the CycloneDX 1.6.1 schema; a served certificate's entry carries 10 fields the standard defines and 13 the project adds, every one traced to the ledger event it came from."
    provenance: "measured 2026-10-21, scan run 01M5DG85J78FF3FVG3GDH26SWZ on the xr7620 (x86_64), the /cbom page (src/pqch/cbom/anatomy.py)"
  - text: "A second projection of the same ledger, a flat agency inventory of 62 rows, rebuilds in 19 ms from 535 events with no scan; two CBOMs from consecutive scans of the unchanged estate compare as 254 components unchanged."
    provenance: "measured 2026-10-21, the same run and the one before it (01M5DFXYNNG08S8ADTDF48WYFE); src/pqch/cbom/tables.py, policy/projections/agency-inventory.yaml"
reuse: [whitepaper, talk, customer-question]
---

# What is a CBOM, and what is in one?

## The answer

A Cryptography Bill of Materials is an inventory of the cryptographic assets
in a system — the algorithms, certificates, keys and protocols — written as a
CycloneDX bill of materials, the same format used for software bills of
materials, with cryptographic assets as a component type of their own and
dependencies between them. CycloneDX is ratified by Ecma International as
ECMA-424, and CBOM support has been part of it since version 1.6. That much
is standard. What an agency must *put* in one is not yet fixed: OMB M-26-15
requires a central CBOM fed from three kinds of evidence, and Executive Order
14412 has told CISA and NIST to publish the minimum elements of a CBOM by
March 2027. Until then each agency decides what its CBOM contains, and every
vendor fills the gap with its own fields. This project's position is that a
CBOM is worth having only when every entry carries its evidence, when it is
a projection of a record rather than a document someone edits, and when it is
the thing a change is made from and verified against.

## The concept

A bill of materials for cryptography answers the question a spreadsheet
cannot: *what cryptography is actually in use, where, and what depends on
it*. The OWASP guide puts the purpose plainly: discovering, managing and
reporting on cryptographic assets is "the first step on the migration journey
to quantum-safe systems and applications", and the trouble is that
cryptography is "typically buried deep within components". So a CBOM reuses
the machinery built for software supply chains — CycloneDX's components,
evidence and dependencies — and adds the vocabulary cryptography needs.

Three ideas carry it:

- **A cryptographic asset is a component.** CycloneDX 1.6 adds
  `cryptographic-asset` beside application, library, container, file and the
  rest. An algorithm, a certificate, a key, a protocol is a thing in the
  inventory with a name, a reference and properties.
- **Properties say which variant.** The guide's example is the one that
  matters for this project: the presence of SHA-1 versus HMAC-SHA-1 "makes a
  difference", so a CBOM captures the parameter set, the curve, the mode, the
  key size, and the quantum security level, not just a family name.
- **Dependencies say what uses what.** The guide distinguishes a library that
  *provides* an algorithm from an application that *uses* it, and a protocol
  that uses an algorithm (its example: "TLS 1.3 uses ECDH/secp256r1"). That is
  the chain from a listener to the key exchange it negotiates to the
  certificate it serves to the key file behind it.

## The mechanism

CycloneDX 1.6's schema defines a CBOM precisely. The asset types and the
fields that matter most, from the schema this project validates against:

| `assetType` | Carries | Fields the schema defines |
|---|---|---|
| `algorithm` | A cryptographic function | `primitive` (one of fifteen: `kem`, `key-agree`, `signature`, `pke`, `hash`, `mac`, `block-cipher`, `stream-cipher`, `ae`, `kdf`, `drbg`, `xof`, `combiner`, `other`, `unknown`), `parameterSetIdentifier`, `curve`, `mode`, `padding`, `cryptoFunctions`, `classicalSecurityLevel`, `nistQuantumSecurityLevel`, `executionEnvironment`, `implementationPlatform`, `certificationLevel` |
| `certificate` | An X.509 or other certificate | `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef`, `subjectPublicKeyRef`, `certificateFormat`, `certificateExtension` |
| `protocol` | TLS, SSH, IPsec, IKE, SSTP, WPA | `type`, `version`, `cipherSuites`, `ikev2TransformTypes`, `cryptoRefArray` |
| `related-crypto-material` | Keys and other material | `type` (private-key, public-key, secret-key, key, ciphertext, signature, digest, nonce, seed, salt, shared-secret, token, password, credential, …), with size, format, state, and an `algorithmRef` |

Every cryptographic asset may carry an `oid`, the object identifier that
names it unambiguously (ecdsa-with-SHA256 is 1.2.840.10045.4.3.2, whatever a
tool calls it). Relationships go in the document's `dependencies` list: each
entry names a component by its `bom-ref` and lists what it `dependsOn` and
what it `provides`. Evidence — where the asset was seen — goes under
`evidence.occurrences`, with a location.

What the schema does not define is as important. There is no field for who
owns an asset, when it must be migrated, which policy puts it in which queue,
whether a file found in an image is actually in use, or what observation the
entry rests on. CycloneDX's answer is `properties`: name-value pairs under a
namespace the producer chooses. That is where a vendor's schema, or this
project's, lives.

### What the policy requires

OMB M-26-15, Appendix A, section 6, names the three sources an agency's
automated inventory draws on — software composition analysis, static and
dynamic testing "to find cryptographic functions in code", and network
scanners "to detect protocols and cipher suites" — and says they populate "a
central Cryptographic Bill of Materials". It does not say what fields that
CBOM holds. Executive Order 14412 directs CISA and NIST to publish the
minimum elements of a CBOM within 270 days of 2026-06-22, which is
2027-03-19. Until that is published, "a CBOM" means "a CycloneDX document
with cryptographic assets in it", and two agencies' CBOMs need not agree on
anything else.

## Worked example

The workbench's CBOM for the eight-service mini-agency (scan run
`01M5DG85J78FF3FVG3GDH26SWZ`, 2026-10-21) is a CycloneDX 1.6 document of 254
components: 47 cryptographic assets seen on the wire, 182 in images, 9
listeners, 8 services and 8 images. By the standard's four asset types, 139
are related cryptographic material (keys, keystores), 62 algorithms, 19
certificates and 9 protocols. Its `dependencies` list carries the chain from
each service to its listeners and images, from a listener to what it
negotiates and serves, and from a served certificate to the file holding its
key.

One entry: the certificate the records database serves after PostgreSQL's
TLS upgrade, as the document carries it (two long values shortened):

```json
{
  "type": "cryptographic-asset",
  "bom-ref": "fp:03f50533afef3d47…",
  "name": "RSA",
  "cryptoProperties": {
    "assetType": "certificate",
    "certificateProperties": {
      "certificateFormat": "X.509",
      "subjectName": "CN=records-db.agency.test,O=Mini Agency",
      "issuerName": "CN=Mini Agency Internal CA,O=Mini Agency",
      "notValidBefore": "2026-10-19T18:44:39Z",
      "notValidAfter": "2029-01-21T18:44:39Z"
    }
  },
  "evidence": {"occurrences": [{"location": "172.16.106.30:5432"}]},
  "properties": [
    {"name": "pqch:layer", "value": "wire"},
    {"name": "pqch:subject", "value": "{\"host\":\"172.16.106.30\",\"kind\":\"endpoint\",\"port\":5432,\"protocol\":\"postgres\"}"},
    {"name": "pqch:asset-type", "value": "certificate"},
    {"name": "pqch:role", "value": "signature"},
    {"name": "pqch:name", "value": "RSA"},
    {"name": "pqch:parameters", "value": "{\"key_bits\":2048,\"signature\":\"ecdsa-with-SHA384\",\"spki_sha256\":\"74092eaa…\", …}"},
    {"name": "pqch:fingerprint", "value": "03f50533afef3d47…"},
    {"name": "pqch:evidence", "value": "01M5DGB4PY85H2ANQA75X4H3PK"},
    {"name": "pqch:tools", "value": "testssl.sh"},
    {"name": "pqch:in-use", "value": "true"},
    {"name": "pqch:verifiable-by", "value": "cert-parse"},
    {"name": "pqch:family", "value": "rsa-sig"},
    {"name": "pqch:quantum-vulnerable", "value": "true"}
  ]
}
```

Read it field by field, as the workbench's CBOM page does:

| Field | Defined by | Says | From |
|---|---|---|---|
| `type`, `cryptoProperties.assetType` | CycloneDX | a cryptographic asset, a certificate | the scanner's observation |
| `certificateProperties.*` | CycloneDX | whom it names, who signed it, when it is valid | testssl.sh's parse of the served certificate |
| `evidence.occurrences` | CycloneDX | where it was seen: the listener | the same observation |
| `bom-ref`, `pqch:fingerprint` | CycloneDX / project | the identity of the observation; the same certificate in the next scan has the same reference | a hash of layer, subject, type, role, name and key |
| `pqch:evidence` | project | the ledger event holding the tool's output, its path and SHA-256 | the scan |
| `pqch:role`, `pqch:family`, `pqch:quantum-vulnerable` | project | a signature, RSA, quantum-vulnerable | the rule `quantum/vulnerable/1` reading OMB M-26-15's table |
| `pqch:verifiable-by` | project | a change to it is confirmed by parsing the served certificate | the rule `verifier/class/1` |

The standard says what the asset is and where; the extension says what the
entry rests on and what follows from it. The chain is in the standard's own
terms: the listener `listener:172.16.106.30:5432` depends on this certificate,
and the certificate depends on the file `/etc/pg-tls/server.crt` in the
`records-db` image, joined by a rule that found the same public key in both.
Above the listener, the `records-db` application component carries what no
scan can discover — mission function "benefits records", a data lifetime of
75 years, high-value asset, owner "Records office" — each labelled supplied,
with the person and the event that recorded it, and what the policy rules
made of it: prioritized by all three of the memo's criteria, its key
establishment in the queue due 2030-12-31.

Three things can be done with this document that a spreadsheet cannot do:

- **Project it again.** A flat inventory of 62 rows, one per asset in use for
  key establishment or signatures, with the system, owner, queue and
  evidence, is rebuilt from the same 535 ledger events in 19 ms; no scanner
  runs. Its field list is a data file. When the minimum elements are
  published, meeting them is another such file.
- **Compare it.** Two CBOMs of the same estate are compared component by
  component, because an observation's reference is its fingerprint: two
  consecutive scans of the unchanged estate compare as 254 unchanged.
- **Hand it to a model.** The investigator is given one entry's observation,
  the service its chain leads to, and that service's build files, and asked
  which line causes it; for the jump host's X25519 entry it named line 4 of
  `sshd_config` in two steps and 23 s on Nemotron 3.5 Super VL. The answer is
  recorded as the model's claim beside the entry, never in it.

Two baselines are written from the same ledger in the same format, so the
workbench's CBOM can be scored against an answer key beside CBOMkit alone and
all the scanners alone.

## What follows

- **Ask for the format, not the brand.** A CBOM that is not CycloneDX 1.6 or
  later is a vendor's private inventory. The format is the one thing already
  settled, and it is what the tooling — CBOMkit, the viewers, the scanners —
  reads and writes.
- **Ask what each entry rests on.** The schema allows a CBOM with no evidence
  at all. An entry without a tool, an observation and a hash is an assertion.
- **Expect the minimum elements, and plan for more.** When CISA and NIST
  publish them, a CBOM built on evidence will meet them by projection; one
  built as a document will need re-collecting.
- **Ask to see one entry, field by field.** Which fields are the standard's,
  which are the producer's, and what each rests on. A CBOM whose producer
  cannot answer that for every field is not auditable.
- **Treat the CBOM as a projection.** Here it is rebuilt from the ledger on
  demand and never edited; a change to the estate is an event, and the CBOM
  follows. That is what makes it the thing a change is made from and verified
  against ([note 08](08-what-verified-means.md)) and what an auditor can check
  ([note 12](12-what-an-auditable-record-contains.md)).

## Scope

Covered: the CycloneDX 1.6 CBOM model as the schema defines it, what M-26-15
and EO 14412 require of a federal CBOM today, and how this project's CBOM
uses the standard parts and the extension namespace, on the eight-service
mini-agency; the anatomy, the second projection and the comparison as the
workbench's CBOM page shows them.

Not covered: the minimum elements CISA and NIST will publish, which do not
exist yet; CBOMs for firmware and hardware; the CycloneDX 1.7 changes; how
commercial platforms map their inventories to the format. The EO 14412
figures are carried from the project's facts table, which records that they
were read through a summarizing tool and are to be checked against the
source before publication.

## References

- OWASP CycloneDX, *Authoritative Guide to CBOM* — the definition, the five
  design goals, the asset-type table, and the provides/uses distinction.
- CycloneDX 1.6.1 JSON schema (`bom-1.6.schema.json`, vendored in this
  repository) — the asset types, primitives and fields in the table above.
- OMB M-26-15, Appendix A, section 6 — the three evidence sources and the
  central CBOM.
- Executive Order 14412 (2026-06-22) — the minimum-elements direction to CISA
  and NIST; 270 days computed.
- IBM Research, *Managing cryptography with CBOMkit* — the open-source
  tooling that originated the model, used here as a baseline.
