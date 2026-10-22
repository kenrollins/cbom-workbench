# S3 labels — how each was made, and how to check one

Every label carries the evidence that settles it. A reader checking a label needs
only the item, the label's `citation` or `evidence`, and — for R4 to R6 — the saved
observation it points at. No label rests on a model's word, and no model under test
saw an item.

| Role | Who or what wrote the label | Where the evidence is |
|---|---|---|
| R1 | The build session (Claude Fable 5.1), by the rule below | `citation`: the quoted line and what in it decides each field |
| R2 | The build session, from RFCs, the IANA registries and OIDs | `citation` |
| R3 | A table lookup: the name's family (`sources/r3-names.yaml`, with its citation) and the memo's own table (`sources/m-26-15-appendix-a.txt`) | `citation` |
| R4 | Observation: the configuration was started in the lab and probed | `evidence`, with files under `observations/` |
| R5 | Observation, twice: with the cause line as written, and with it changed | `evidence` |
| R6 | None — a reply is run. The six `blocked` items record what the runtime lists | `evidence` |

## R1: the rule, the draw and the rulings

**The rule.** The flagged line is a cryptographic use when the line itself, as code
that executes, calls an API of a cryptographic library or names the algorithm for
one. It is not a use when it is a comment, a string, data, an import, a declaration
or definition, a mock or assertion, or a call to the application's own wrapper —
even a wrapper whose body, elsewhere, calls a library. Test code is judged like any
other code. The prompt states the same rule.

`family` is the algorithm named on the line, else the one the shown context fixes,
else `unspecified`. `role` is what the operation or its key is used for in the
shown context; a key generated or parsed with no use shown, a key-derivation
function and a password hash are `other`. `key_bits` is given only when a number
states it. For an item that is not a use, only `is_crypto_use` is scored.

**The draw.** `draw.py r1` greps each pinned repository for two pattern classes —
library names, and words that only read like cryptography — drops imports, keeps at
most two lines per file, and shuffles with a fixed seed. Candidates are then taken
from the top, in order, until a repository has eight uses and four non-uses; when
its sixty candidates hold fewer than eight uses, the remainder is filled with the
next non-uses in order. `r1-draw-log.jsonl` lists every candidate up to the last
one taken, how it was judged, and whether it was taken.

| Repository | Uses | Non-uses | Uses among its 60 candidates up to the cut |
|---|---|---|---|
| `18F/identity-idp` (Ruby) | 8 | 4 | 8 of the first 37 |
| `CMSgov/dpc-app` (Java) | 6 | 6 | 6 of the first 29; no more in the rest |
| `CMSgov/bluebutton-web-server` (Python) | 8 | 4 | 8 of the first 26 |

The first draw kept `import` lines and one line per file; Java then yielded three
call sites in sixty candidates. The draw rule was changed before any item was
labeled, and the first draw was discarded.

**Rulings** — places where the rule had to be applied to a case it does not name.
The second reader should look at these first.

1. A call to the application's own encryptor or helper (`encryptor.encrypt(...)`,
   `SecretHelpers.generateSecretKey(...)`, `method(:encrypt_raw_kms)`) is not a use,
   though the wrapped code is cryptographic. The role being tested reads a flagged
   line; following a wrapper to its body is the investigator's loop, not this call.
2. `Mockito.verify(...)` is not a use: it is the mocking library's verification.
3. `jwt.decode(..., options={'verify_signature': False})` is a use — a direct call
   into the token library — with family `unspecified` and role `other`, because it
   names no algorithm and runs no signature primitive. A reader who holds that a
   call which verifies nothing is not a cryptographic use would label it the other
   way; it is one item (`r1-097`).
4. `SCrypt::Password.new(hash).digest` is a use of the scrypt library, role `other`.
5. `except jwt.PyJWTError:` is not a use: it names a class and calls nothing.
6. A key generated for a test that then encrypts with it (`r1-085`, `r1-088`) takes
   the role the shown context gives it, `encryption`.

## R2

`draw.py r2` collects every spelling in the saved tool output that the scout's name
table does not map, in a seeded order. The first 36 are taken, at most six per tool
field, leaving out cipher-suite fields (a suite names several algorithms at once).
The draw held four spellings that are not algorithms where the design asks for at
least five; the last-drawn algorithm (`DH, 6144 bits`) was replaced by the next
non-algorithm in order (`No`).

The name is one of `sources/r2-names.yaml` or `unknown`. Where a standard gives a
key more than one use — an RSA or elliptic-curve public key — the label's `role` is
a list and any member is correct. For `unknown`, only the name is scored.

## R3

The policy text is OMB M-26-15, Appendix A, sections 1 to 3 and footnote 13, taken
from the PDF with `pdftotext` (SHA-256 of the PDF in the file's header). The label
is mechanical: `quantum_vulnerable` is true for a family in section 2's table, or an
asymmetric family outside section 1 (footnote 13: EdDSA); false for section 1's
three algorithms, for a hybrid (section 3), and for symmetric ciphers, hashes and
MACs, which the table does not cover. Names whose status that text does not settle
— LMS, XMSS, sntrup761x25519, FALCON, HQC — are left out. CNSA 2.0 was to be a
second source; NSA's site refused the download on 2026-10-05, so it was not read
first-hand and is not used. Hash-based signatures are therefore represented only by
SLH-DSA.

The table carries one sentence that reads oddly — "Symmetric-key-based protocols
should also be avoided" — and is kept as printed. The labels do not take it to mean
that a symmetric cipher is quantum-vulnerable.

## R4

`build_r4.py` starts each configuration in the lab (`lab.py`), probes it, and writes
the findings from what it saw. Seven kinds:

| Kind | Items | Label | What was observed |
|---|---|---|---|
| not-served | 6 | wire / not-served | The served certificate's fingerprint is the configured file's and not the other file's |
| overridden | 5 | wire / overridden | The losing line's value is not among what the listener accepts |
| default-applies | 4 | wire / default-applies | The behaviour is there with the line commented out |
| stale-file | 4 | wire / stale-file | The file was replaced in the running container; the listener still behaves as before |
| tool-limit | 5 | wire or config / tool-limit | Two from saved S2 and slice output (a file scanner blind to a certificate and to a host key); a client-certificate requirement the wire tool reports as optional while the server answers 400; two fallback handshakes read as acceptance |
| other-listener | 4 | config / other-listener | The asset's own listener, probed by name or port, does what the configuration says; the wire finding shown is of another name, port or address |
| host in force | 2 | host / stale-file | The running file is the older one; the listener does what it says |
| cannot-tell | 6 | cannot-tell | Two builds that produce the same shown evidence and different truths, both observed; `what_is_missing` names the fact that would decide it |

For `cannot-tell`, only `in_force` is scored.

## R5

`build_r5.py` runs each scenario of `scenarios_r5.py` twice. With the files as
written the finding must be on the wire. With the cause line's value changed it
must be gone — that is what makes the line the cause. For a `default` item, every
uncommented line naming the directive is removed and the finding must stay. A
scenario that fails either check is not an item. Nine of the 36 are `default`.

## R6

`build_r6.py` observes each starting configuration and applies one solution per
intent, verified with the verifier's own probes and decision (`change_check.py`),
to show the item can be done. The solution is not a label and is compared with
nothing. One item (`r6-e-enable`) starts with the intent already met — nginx on
OpenSSL 3.5 accepts X25519MLKEM768 by default — and the right reply is no edits.
The six `blocked` items are RabbitMQ 4 and Kafka 4.1, whose runtimes list no ML-KEM
group; the label is `supplier`.

## The second reader's sample

`python spikes/s3/sample.py` prints six scored items per role, chosen by seeded
shuffle, with each label and its evidence. Record the check in
`labels/SECOND-READER.md`: who read which items, on what date, and any label
changed. `run.py` refuses a scored run until that file exists and every item,
label and prompt file hashes to a value recorded in `spikes/s3/README.md`.
