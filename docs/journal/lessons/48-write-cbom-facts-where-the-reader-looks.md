---
id: lesson-48-write-cbom-facts-where-the-reader-looks
type: lesson
title: "Write each CBOM fact in CycloneDX's own field; where the standard has none, name the property as the tools you feed read it"
date: 2026-11-01
audience: [engineer, architect]
rung: structured
tags: [cbom, cyclonedx, interoperability]
one_line: "Two valid CycloneDX 1.6 CBOMs of the same estate can share almost nothing a policy engine reads: the standard leaves the TLS key-exchange group and every SSH algorithm without a field, so each tool invents property names, and a tool that also skips the fields the standard does define is judged on nothing."
claims:
  - text: "CycloneDX 1.6's protocolProperties has type, version, cipherSuites, ikev2TransformTypes and cryptoRefArray: no field for the key-exchange group a TLS server selected, and none for an SSH server's key exchange, host-key or encryption algorithms."
    provenance: "cited: CycloneDX 1.6 JSON schema, definitions.cryptoProperties (src/pqch/cbom/schema/bom-1.6.schema.json)"
  - text: "Until 2026-11-09 the workbench's CBOM writer filled, of the standard's crypto fields, only assetType, algorithmProperties.primitive (curve or parameterSetIdentifier on 3 of 62 algorithms), the certificate names and dates, protocolProperties.type, and relatedCryptoMaterialProperties.type and size; never protocolProperties.version or cipherSuites, certificateProperties.signatureAlgorithmRef or subjectPublicKeyRef, or a key's algorithmRef. Since then it fills every one of those it has the fact for, references resolving to components inside the document, and writes the consumers' property names beside its own (ADR-0007)."
    provenance: "computed 2026-11-01 over the CBOM of mini-agency run 01M5JFEP7D145D2T38TW0S6631 (250 components), counting every scalar path under cryptoProperties; the writer's fields after 2026-11-09 in src/pqch/cbom/__init__.py and tests/test_interop.py"
reuse: [whitepaper, customer-question, runbook]
---

# Write each CBOM fact in CycloneDX's own field; where the standard has none, name the property as the tools you feed read it

## The rule

A CBOM (cryptography bill of materials: an inventory of the algorithms, keys, certificates and protocols an
estate uses) is only as useful as the tools that can read it. Write every fact that CycloneDX defines a field for
in that field. Where the standard has no field, choose the property name deliberately, after reading how the
tools that will consume the CBOM name it, and write it down as a decision.

## Why

CycloneDX 1.6 is a schema, not a vocabulary for everything a scanner sees. It defines:

| Asset | Standard fields that a policy can judge |
|---|---|
| Protocol | `type` (tls, ssh, ipsec, ike, …), `version`, `cipherSuites` (name, IANA identifiers, algorithm references), `ikev2TransformTypes`, `cryptoRefArray` (references to the algorithms in use, without their roles) |
| Certificate | subject, issuer, validity dates, `signatureAlgorithmRef`, `subjectPublicKeyRef`, format, extension |
| Algorithm | primitive, parameter set, curve, mode, padding, functions, classical and NIST quantum security levels |
| Key and other material | type, size, state, dates, `algorithmRef` |

It has no field for two facts that matter most in a post-quantum inventory:

- **The key-exchange group a TLS server selected** (X25519MLKEM768 or plain X25519, for example), which is
  where post-quantum key exchange shows. A cipher suite in TLS 1.3 does not name it.
- **Any SSH algorithm**: key exchange, host key, encryption. IKEv2 has its own transform list; SSH has nothing.

Each tool fills those gaps with free-form `properties`, under names it chose. Two tools that both write valid
CycloneDX therefore agree on the envelope and disagree on where the facts sit, and a policy engine reads only
the places its own tool writes. A tool that also keeps the facts the standard *does* define in its own
properties, as this workbench does with its `pqch:` properties, leaves a consumer nothing to judge at all.

## When it applies

Whenever a CBOM leaves the tool that wrote it: imported into another scanner, a policy engine, an asset system,
or handed to an auditor's tooling. It does not apply to a field only the workbench reads (its ledger links and
evidence), which can stay in `pqch:` properties.

It does not mean adopting one vendor's names as the standard. The names for the missing fields are a choice
between consumers, and writing a fact twice (the workbench's property and a consumer's) is legitimate while the
standard is silent.

## How to apply it

1. For each fact the CBOM writer emits, check the CycloneDX schema (`src/pqch/cbom/schema/bom-1.6.schema.json`,
   `definitions.cryptoProperties`) for a field before writing a property.
2. Link by reference where the schema does: a certificate to its signature algorithm and public key, a key to
   its algorithm, an endpoint's cipher suites to their algorithms.
3. For a fact with no field, list the property names the target consumers read, choose one, and record the choice
   and the alternatives in an ADR. That includes whether a certificate is in use.
4. Name an algorithm so that it can be judged alone. A consumer may read the algorithm's name and nothing else, so
   a name that carries the size or curve (`RSA-2048`, `ECDSA-P-256`), or a filled `parameterSetIdentifier` and
   `curve`, is safer than a family name with the size kept elsewhere.
5. Test the result in the consumer: import the CBOM and confirm that a planted weakness is reported.

Steps 1 to 4 are applied in the workbench's writer since 2026-11-09 (ADR-0007 records the names chosen and the
alternatives); step 5, the re-upload to a consumer, is still to be done with the next access to one.
