# ADR-0007: Where CycloneDX 1.6 has no field, write the fact twice: under the workbench's name and under the name the consumers read

- **Status:** Accepted
- **Date:** 2026-11-09
- **Deciders:** Ken Rollins
- **Builds on:** ADR-0001 (the ledger is the system of record; the CBOM is a projection)

## Context

CycloneDX 1.6 defines, for a cryptographic asset, an algorithm's primitive, parameter set, curve,
functions and security levels; a certificate's names, dates, format and two references, to the
algorithm it was signed with and to its public key; a key's type, size, identity, state and a
reference to its algorithm; and a protocol's type, version, cipher suites and a reference array to
the assets on it. It has no field for the key-exchange group a TLS server selected or accepts, and
none for an SSH server's key-exchange, host-key, encryption or MAC algorithms. It has no field that
says whether a certificate is in use.

Until this decision the workbench's writer filled few of the fields the standard does define and
kept nearly every judged fact in its own `pqch:` properties (lesson 48). Uploaded to a commercial
policy engine, the CBOM was inventoried and judged on nothing: the engine reads the standard's
fields and its own named properties, and found neither. Reshaped with the standard's fields alone it
drew twenty findings, fifteen of them false, because the engine judged each certificate's key by its
algorithm's family name and nothing else; reshaped with the engine's property names it drew nine,
all correct, four of them on two certificates the workbench had marked not in use.

Three things follow. The standard's fields must be filled wherever the finding has the fact, with
references that resolve inside the document. For a fact the standard has no field for, a property
name has to be chosen, and the consumers already read particular names. And "not in use" has to
travel somehow, or a consumer will raise findings on retired material.

## Decision

1. **Every standard field the finding has the fact for is filled.** A TLS listener's
   `protocolProperties` carry `type`, `version` (the highest accepted), `cipherSuites` (every suite
   accepted at any version, by IANA name with its hex identifier) and `cryptoRefArray` (every asset
   on the listener). An SSH listener carries `type: ssh` and the protocol version from its banner. A
   PostgreSQL listener that negotiates TLS is typed `tls`. A certificate carries
   `signatureAlgorithmRef` and `subjectPublicKeyRef`; a key carries `algorithmRef` and `id` (its
   SubjectPublicKeyInfo hash). An algorithm carries `parameterSetIdentifier`, `curve`,
   `classicalSecurityLevel` computed from its key size by SP 800-57 Part 1 Rev. 5 Table 2,
   `nistQuantumSecurityLevel` for a post-quantum set from FIPS 203 and 204, and its `oid`. The
   identifiers and categories are data (`policy/algorithm-ids.yaml`), each with its source.
2. **A reference points at a component of the document.** The algorithm a certificate was signed
   with, the algorithm of a key and a certificate's public key are not findings of their own, so
   the projection adds one component per distinct value (`alg:signature:<x509 name>`,
   `alg:<role>:<name>[-<size>|-<curve>]`, `key:spki-sha256:<hash>`), marked `pqch:kind:
   referenced` and carrying no layer. The scorer, the inventory projection and the answer key
   ignore them; a consumer's reference resolves.
3. **For a fact with no field, the property is written twice**: under the workbench's name
   (`pqch:tls-groups`, `pqch:ssh-key-exchange`, `pqch:ssh-host-key`, `pqch:ssh-encryption`,
   `pqch:ssh-mac`, `pqch:signature-algorithm`) and under the name the consumers surveyed read
   (`Supported Groups`; `Key Exchange Algorithm`, `Host Key Algorithm`, `Encryption Algorithm`;
   `Signature Algorithm`, `Subject Public Key Algorithm`). The `pqch:` name is the one this project's
   own readers use; the other is a courtesy to tools that read a fixed name, and is dropped the day
   the standard gains the field.
4. **A name a consumer can judge alone.** A component's `name` stays the family (`RSA`, `ECDSA`),
   which is the answer key's convention and the rules'; the size or curve is in the standard's
   fields and in the referenced algorithm's name (`RSA-2048`, `ECDSA-P-256`), and the certificate's
   `Subject Public Key Algorithm` property carries it the way the surveyed engine reads it.
5. **"Not in use" travels two ways.** A key the rules found no listener serving carries
   `relatedCryptoMaterialProperties.state: deactivated`, the one in-use signal the standard has a
   field for. And every run writes a second document, `workbench-consumer.cdx.json`, which is the
   same projection with every entry marked `pqch:in-use: false` left out, the dependencies that
   named them pruned, and the count and reason in its metadata. The full document remains the
   record; the consumer copy is a view of it for an engine that cannot read `pqch:in-use`.

## Alternatives considered

- **Write only the standard's fields and wait for the standard.** Rejected: the groups and the SSH
  algorithms are what the migration is about, and a document that cannot carry them is not an
  inventory of the estate's cryptography. The draft after 1.6 was not checked for new fields; when
  it is, a field that exists replaces the property.
- **Write only the consumers' names.** Rejected: they are one vendor's spellings, and adopting them
  as the project's own would make the writer answer to a product rather than to the evidence. Both
  names cost nothing and keep the project's vocabulary its own.
- **Rename components to carry the size (`RSA-2048`).** Rejected: the answer key, the family tables
  and the rules name by family, and the fingerprint includes the name; a rename would re-key every
  entry for the sake of one reader. The size travels in the fields and the referenced component.
- **Leave never-served material out of the only document.** Rejected: the record would then omit
  what the scanner found. A second document that says what it left out keeps both.
- **Emit cipher-suite algorithm references.** Deferred: a suite's symmetric cipher and hash are not
  findings, and inventing components for them would put unobserved entries beside observed ones.
  The suite is carried by name and identifier, which is what the surveyed consumer reads.

## Amendment, 2026-11-21: the consumers' names carry the consumers' spellings

A review of the writer against the reshaped copy a surveyed engine judged correctly found that
decision 3 wrote the consumers' *names* and the workbench's *values*. An allow-list matches a value
by its spelling, so a name alone is not read. Decided:

6. **A property under a consumer's name is spelled as that consumer spells it.** `Signature
   Algorithm` is hash then family (`SHA256-RSA`, `SHA1-RSA`, `ECDSA-SHA384`), from
   `consumer_signature_names` in `policy/algorithm-ids.yaml`; `Host Key Algorithm` is family with
   size or curve (`RSA-2048`, `ECDSA-P-256`, `Ed25519`), taken from the listener's own host-key
   findings; `Supported Groups` is IANA's name with its registry value (`x25519 (0x001d)`); a list
   is joined by a comma with no space. The `pqch:` property beside each keeps the workbench's
   spelling (the X.509 name, the SSH wire names, the standard group names) and is the one this
   project's readers use.
7. **A cipher suite's `identifiers` are one entry per byte** (`["0xc0", "0x2f"]`), as the
   standard's own examples write them. This replaces the single four-digit string of decision 1.
8. **A per-version protocol entry is typed.** The entry for one accepted version (`TLS 1.2`) carries
   `type: tls`, its `version` and the suites accepted under it, and an SSH one `type: ssh`, where
   both were `other`. A reader of that entry alone no longer takes it for an unknown protocol.
9. **The listener's `version` stays the highest accepted in the full document, and lists every
   version in the consumer copy.** The consumer copy writes
   `TLS 1.3 (0x0304),TLS 1.2 (0x0303)`, the form the surveyed engine's version rule reads, and
   leaves the per-version entries out (folded into their listener, counted in the metadata), so
   an engine that judges every protocol component judges each listener once. The copy also leaves
   out a referenced component once nothing kept points at it. The consumer copy is therefore the
   document to hand a policy engine; the full document is the record.
10. **Versions are compared by number.** A scan names a version `TLS 1.3` and a capture `TLSv13`;
    the projection parses both and takes the highest numerically. Existing ledgers are not renamed.
11. **A document says which run it is and what its lists mean.** `pqch:run` is the run's id (it was
    the scope's, on every run); `pqch:scope` carries the scope's. `pqch:observation: accepted` says
    a listener's lists are everything the server took when offered, which is an upper bound, and not
    what a period's clients selected, which is what a passive tool means by the same names. The
    serial number is a name-based UUID (RFC 4122 version 5) of the ledger head and the projection,
    so each of a run's documents has its own.

What is still unproven is the same as before: the re-upload. The spellings above reproduce the
reshaped copy that drew correct verdicts in the first test; the writer's own output has not been
through the engine since.

## Consequences

- A consumer that reads the standard's fields sees versions, suites, the signature algorithm and
  key behind each certificate, each key's algorithm with its size, and security levels; one that
  reads the surveyed names sees the groups and the SSH algorithms. Lesson 48's step 5, the proof
  by re-upload, is still to be done with the next access to a consumer.
- The document gains referenced components (one per distinct algorithm, signature algorithm and
  public key) that carry no layer; counts on the pages that count by layer are unchanged, and the
  component total rises.
- `tests/test_interop.py` holds the writer to this: every reference resolves, a PostgreSQL listener
  that negotiates TLS is typed `tls`, the consumer copy drops the not-in-use entries and the
  referenced components only they pointed at, folds the per-version entries and counts each, every
  document of a run has its own serial, and the schema and the reference check still pass.
