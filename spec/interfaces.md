# Interfaces

The five contracts everything else in cbom-workbench depends on: the scope, the
finding, the ledger event, the inference seam and the verifier. They are kept
small on purpose. Anything not stated here is an implementation detail and may
change without notice.

## Conventions

- **Encoding.** JSON, UTF-8. Timestamps are RFC 3339 in UTC with a `Z` suffix.
  Durations are integer milliseconds. There are no floating-point numbers in
  any hashed object.
- **Identifiers.** ULIDs, as 26-character strings. Hashes are lowercase hex
  SHA-256 unless stated.
- **Canonical form.** RFC 8785 (JSON Canonicalization Scheme). Because hashed
  objects carry no floats, this is the object serialized with keys sorted, no
  insignificant whitespace, and non-ASCII characters unescaped.
- **Versioning.** Every object carries `schema`, of the form `pqch.<name>/<major>`.
  Adding an optional field does not change the major. Removing a field,
  changing a meaning or adding a required field does. A reader rejects a major
  it does not know and ignores fields it does not know.
- **References.** One object refers to another by id, never by copying it.
  Raw tool output is referred to by path and SHA-256.

| Interface | Schema id | Status |
|---|---|---|
| Scope | `pqch.scope/1` | draft until M0 is done |
| Finding | `pqch.finding/1` | draft until M0 is done |
| Ledger event | `pqch.event/1` | draft until M0 is done |
| Checkpoint | `pqch.checkpoint/1` | draft until spike S4 passes |
| Inference seam | `pqch.inference/1` | draft until M0 is done |
| Verifier | `pqch.verifier/1` | draft until M0A is done |

"Draft" means the major may be changed without a bump. Once a milestone
freezes a schema, the versioning rule applies.

---

## 1. Scope — `pqch.scope/1`

What the harness may touch. It never discovers targets; it reads this file,
and the runner refuses anything outside it (ADR-0003).

```json
{
  "schema": "pqch.scope/1",
  "id": "01JD…",
  "estate": "colocated",
  "owned": true,
  "authorized_by": null,
  "endpoints": [
    {"host": "172.16.106.10", "port": 443, "transport": "tcp", "protocol": "tls", "sni": "portal.agency.test",
     "image": "registry.local/agency/portal@sha256:…"}
  ],
  "images": ["registry.local/agency/portal@sha256:…"],
  "sources": [{"repo": "agency/", "commit": "…"}],
  "reach": {"kind": "local"}
}
```

| Field | Meaning |
|---|---|
| `estate` | `colocated`, `remote` or `external` |
| `owned` | `true` only when the harness generated this scope from an estate it built. The apply job requires it, and separately checks that each container was created by the runner |
| `authorized_by` | Required when `estate` is `external`: who authorized the scan, as free text |
| `endpoints` | The only addresses and ports a wire scan may touch. Each `host` is one address; a range is not expressible in `/1`. Optional `image`: the scoped image that serves this listener, when the scope is generated from an estate the harness built; rules use it to ask whether a certificate in an image is served by any of that image's listeners. Optional `service`: the compose service that serves the listener, written by the generator; the rule `link/service/1` asserts the listener's and the image's link to that service only when the runner found a container at the address running the scope's image for the whole scan |
| `images`, `sources` | Where host and code evidence may be read from. Either may be empty |
| `reach` | `{"kind": "local"}` or `{"kind": "ssh-docker", "context": "<name>"}` |
| `twins` | Optional, for an owned estate: per listener that can take a change, its rehearsal copy — the same port, service and image at a fixed address on the twin network (`network`). Not endpoints: no scan reaches them. The runner probes a twin only because the scope lists it, and starts one only to rehearse a proposal |
| `captures` | Optional, for an `external` estate: passive capture points, each the `interface` the sensor listens on, the `host` it is on, the `vlans` the mirror carries and, as free text, the `mirror` that feeds it. Nothing is ever sent on a capture point. A run of passive capture is opened with the harness's own hash of the scope, since no runner enforces a scope on which nothing is sent; its `run.started` carries `"kind": "capture"` |

The scope's hash is the SHA-256 of its canonical form.

`host` and `sni` are passed to scanners as arguments, so they are restricted:
they begin with a letter or digit and hold only letters, digits, `.`, `-`, `_`
and, for `host`, `:`. `protocol` is lowercase letters, digits and `-`.

The runner reads the scope once, when it starts, and serves it to the harness;
a new scope needs a new runner. The service that serves the UI has no write
access to it.

---

## 2. Finding — `pqch.finding/1`

One observation by one tool. A finding says what was seen and where. It does
not say whether it matters: quantum vulnerability, deadline and priority are
assessments, recorded as separate ledger events that refer to the finding.

```json
{
  "schema": "pqch.finding/1",
  "id": "01JD…",
  "observed_at": "2026-10-04T15:02:11Z",
  "layer": "wire",
  "source": {"tool": "testssl.sh", "version": "3.2.3", "image_digest": "sha256:…", "profile": "tls-targeted"},
  "subject": {"kind": "endpoint", "host": "172.16.106.10", "port": 443, "protocol": "tls", "sni": "portal.agency.test"},
  "asset": {
    "type": "algorithm",
    "role": "key-establishment",
    "name": "X25519",
    "parameters": {"tls_version": "1.3", "offered": ["X25519", "secp256r1"]}
  },
  "evidence": {"raw": "var/raw/01JD….json", "sha256": "…", "excerpt": "Server key exchange: X25519"},
  "fingerprint": "…"
}
```

| Field | Values and meaning |
|---|---|
| `layer` | `wire`, `host` or `code` |
| `source` | The tool, its version, the digest of the image it ran from, and the named scan profile. For a file in an image, `subject_digest` is the digest of the image that was scanned |
| `subject.kind` | `endpoint` (`host`, `port`, `protocol`, optional `sni` and `vlan`) · `client` (`host`, `protocol`, optional `vlan`): a client seen connecting out, from passive capture — what it offered, never what it serves · `file` (`image` or `host`, `path`) · `call-site` (`repo`, `commit`, `path`, `line`). A file's `image` is the image repository, without tag or digest, so that a rebuilt image's findings are comparable with the last build's. `vlan` is the 802.1Q tag the capture saw, when there was one |
| `asset.type` | `algorithm`, `certificate`, `protocol` or `related-crypto-material` — the CycloneDX asset types |
| `asset.role` | `key-establishment`, `signature`, `encryption`, `hash`, `mac` or `other` |
| `asset.name` | The standard name: `ML-KEM-768`, `X25519MLKEM768`, `RSA`, `ECDSA`, `ML-DSA-65`. Tool spellings are normalized to these |
| `asset.parameters` | Free-form, tool-specific detail: key size, curve, validity dates, offered groups |
| `asset.identity` | Optional. Which key this is, where the evidence shows one: `spki-sha256:<hex>`, the SHA-256 of the public key's SubjectPublicKeyInfo, or `openssh-sha256:<base64>`, the OpenSSH fingerprint of an SSH host key when only that is known. A private key whose public half sits in the same file takes that public key's identity |
| `evidence` | The raw output by path and hash, and a short excerpt a person can read |
| `fingerprint` | SHA-256 of the canonical form of the object `{"layer", "subject", "type", "role", "name", "identity"}`, the last four taken from `asset`, with `identity` `null` when the finding has none. Two findings with one fingerprint are the same observation; this is how re-scans are compared and duplicates folded. The same place, kind and family with a different key is a different finding; the same file in a rebuilt image, holding the same key, is the same one |

A finding is immutable. A re-scan produces new findings; it never edits one.

---

## 3. Ledger event — `pqch.event/1`

A ledger is one file, `ledger.jsonl`: one event per line, appended and never
rewritten. Each run has its own ledger, at `var/runs/<run-id>/ledger.jsonl`,
whose event 0 is `run.started`. It is the system of record (ADR-0001). The CBOM and the SQLite
index are both rebuilt from it and may be deleted at any time.

```json
{
  "schema": "pqch.event/1",
  "seq": 42,
  "id": "01JD…",
  "ts": "2026-10-04T15:02:12Z",
  "type": "finding.observed",
  "actor": {"kind": "scanner", "id": "testssl.sh"},
  "inputs": ["01JD…"],
  "payload": {},
  "evidence": [{"ref": "var/raw/01JD….json", "sha256": "…"}],
  "prev": "…",
  "hash": "…"
}
```

| Field | Meaning |
|---|---|
| `seq` | Integer, starting at 0, increasing by exactly 1 |
| `type` | One of the types below |
| `actor.kind` | `scanner`, `rule`, `model`, `human`, `verifier`, `runner` or `controller`. A `model` actor also carries `tier`, `model` and `hardware` |
| `inputs` | Ids of the events this one was derived from. Following them backward answers "why" |
| `payload` | An object whose shape is set by `type` |
| `evidence` | References to raw material, each with its hash |
| `prev` | The `hash` of the event at `seq - 1`. For `seq` 0, sixty-four zeros |
| `hash` | SHA-256 of the canonical form of the event with the `hash` field removed |

### The hash chain

To verify a ledger: read events in order; check `seq` increases by 1; check
`prev` equals the previous event's `hash`; recompute `hash`. Any edit, removal
from the middle or reordering breaks the chain at that point.

A chain whose hashes are right must also make sense. A ledger is invalid if:
event 0 is not `run.started`; an `id` repeats; an entry in `inputs` is not the
id of an earlier event in the same ledger; a `ts` is earlier than the previous
event's; an event's actor kind is not one the table below allows for its type;
or a finding's `fingerprint` is not the hash of that finding. A line that
cannot be read fails verification at that line.

The chain alone does not detect events removed from the end, or a file
rewritten whole with every hash recomputed: anyone who can write the file can
do both. Signed checkpoints, with the latest one recorded outside the system,
are what close that.

### Who writes the ledger

An actor names who did a thing; it does not say who wrote the line. This is
who writes each kind of event, what makes it trustworthy, and where that stops.

- **One writer.** The harness process — the service that serves the UI — is the
  only process that appends to a run's ledger. Every other component returns a
  result to it, or refuses.
- **Runner events** (`run.started`, `scan.completed`, `change.applied`,
  `service.recreated`, `run.closed`) are written from the runner's own job
  result, returned over its socket. The runner keeps its own log of every job
  it ran — id, profile, target, start, end, raw output hash, binding — and of
  every change it applied and every service it recreated, on storage only it
  mounts. A reader compares each `change.applied` and `service.recreated`, and
  each probe a verdict cites by `job_id`, with that log (section 5, "Checking
  a verdict against the runner's record").
- **The runner checks before it acts.** It applies a change only after reading
  the run's ledger itself, read-only, and finding: a chain that verifies; a
  `change.proposed` and a later `approval.granted` for that change id; a
  checkpoint, signed by the signer's key, covering the approval; and no
  earlier apply of that id in its own log. It acts only on a service the scope
  lists, in an estate the scope marks `owned`. It writes only configuration of
  the shape the policy renders — protocol and key-exchange lines — whatever
  the proposal holds; a comment line holds printable ASCII only. It recreates
  the service with every Compose file the estate was started with, and puts
  the previous file back, and the service up on it, if Compose fails or the
  service does not listen on the new one; that attempt is logged as
  `apply-failed`, never as an apply. What was approved is what is applied: the runner recomputes the
  diff between the proposal's `rollback` and its new content and refuses a
  proposal whose `diff` differs, or whose `rollback` is not the configuration
  now deployed.
- **Human events** (`approval.granted`, `approval.denied`, `policy.changed`,
  `key.committed`) are written by the harness from an authenticated request.
  The payload says who (`by`) and how they were authenticated
  (`authenticated_by`): through the page, the user name the front door sets
  after its single sign-on, which it strips from any client request first;
  from the command line, the name the operator gives, authenticated only by
  their shell access to the harness container. The page believes the sign-on
  header only on a connection from an address configured as the front door's;
  with none configured it cannot approve at all. A request with neither
  cannot approve.
- **Verifier events** (`verdict.issued`) are computed by the verifier, which
  calls no model, from probe results the runner returns, each with the hash of
  its raw output.
- **Checkpoints** are signed by the signer, which verifies the chain first.

Where this stops: the harness process is trusted to write events as they
happened, though not their times beyond the signer's bracket, and not a
verdict beyond what the runner's job log and raw output bear out. Whoever controls that process, or can connect from the front door's
own address, can write an approval no person gave, and the runner, the signer
and the checkpoints will all accept it. The same holds for a verdict: the raw
output of its probes is written by the runner where the harness cannot change
it, but the `verdict.issued` event is the harness's; a reader recomputes it
from the runner's record and shows no status as verified, and no
time-to-change, when the two differ. Timestamps are the harness's, held to the
signer's clock by its bracket. What remains is the approval itself, and how
long a person's decision waited before the harness wrote it down: closing
that needs approvals signed by the approver's own key; until then the page
says so.

### Event types

| Type | Actor | Payload carries |
|---|---|---|
| `run.started` | `runner` | The run's id, the scope and its hash, the profile, the versions of every schema in use. Always `seq` 0 of a run |
| `key.committed` | `human` | The answer key's path and hash |
| `scan.completed` | `runner` | One runner job: profile, target, tool and version, scanner image digest, start and end, duration in milliseconds, `hardware` (the machine the job ran on, with the platform when the scanner was emulated), status (`ok`, `timeout`, `error`), exit code, the raw output by path and hash, and the number of findings it yielded. For a wire scan, `binding`: the address, the id and name of the container the runner found holding it, that container's image and image digest, and `stable` — whether it was the same container at the start and end of the scan. `replayed_from` names the earlier run and event when the result is replayed rather than re-run |
| `finding.observed` | `scanner` | A `pqch.finding/1` object. `inputs` names the `scan.completed` event it came from |
| `assessment.made` | `rule` or `model` | Finding ids in `inputs`; the classification, the rule id that fired, the deadline and queue. Two assessments carry no finding of their own: `verifier/class/1`, whose subject is a finding class (`layer`, `type`, `role`) and whose classification names the `pqch.verifier/1` kind that can confirm a change to it, with every finding of the class in `inputs`; and the Managed rung's rules over a policy pack (`policy/packs/*.yaml`, `pqch.policy-pack/1`), each with `source` naming the pack, the PDF's hash and the section: `quantum/vulnerable/1` per algorithm name, `pack/scope/1` and `priority/m-26-15/1` per service, `queue/m-26-15/1` per service and function (`state`, `queue`, `deadline`, `deadline_basis` stated or computed), `deadline/tls13/1` per TLS listener, and `blocker/supplier/1` and `blocker/validated-module/1` per open item, each resting on a dated snapshot (`policy/snapshots/`); and `conflict/resolve/1`, whose `finding` is the one judged, `disagrees_with` the findings it conflicts with, and whose classification is `in_force` (`wire`, `host`, `config`, `cannot-tell`) and `reason` (`not-served`, `default-applies`, `overridden`, `other-listener`, `stale-file`, `tool-limit`, or null). A model's explanation of a conflict is a separate `assessment.made` with the model actor, `used_by_rules: false` and `agrees_with_rule`; no rule reads it |
| `link.asserted` | `rule`, `model` or `human` | One link of a dependency chain: from, to, kind, and whether it is `discovered` or `supplied`. `from` and `to` are each a finding's event id (a link between two observations: `link/public-key/1`) or a subject object — `{"kind": "endpoint", host, port, protocol}`, `{"kind": "image", image}`, `{"kind": "service", name}`, `{"kind": "fact", name, value}`. A supplied link has a `human` actor, `status: supplied`, a `source` (the owner's file by path and hash) and that file in `evidence`; the CBOM labels it supplied and the score never counts it as coverage |
| `change.proposed` | `rule` or `model` | The change id, the target, the intent (`enable` or `require`), the diff, the rollback, and the verifier check that will count. A proposal from a `model` carries `drafted`: the role, the prompt's hash, its context (the scan run, the CBOM entries for the listener, the trace, the files with their hashes) and every call with whether it was usable. The runner applies a model's proposal only after a rehearsal of that exact file met the change's intent, by the ledger's verdict and its own log |
| `rehearsal.completed` | `verifier` | The change id, the twin address and container, the image (the scope's), the hash of the file rehearsed, and the verdict of the change's own check run against the copy — or `did-not-start` with the copy's log |
| `matrix.completed` | `verifier` | The compatibility matrix for a proposed change: for each kind of client (what it offers, and the runner job that offers exactly that), the probe record against the listener as deployed and against a copy started in the twin with the proposed file, and the effect (`shut out`, `let in`, `unchanged, served`, `unchanged, refused`, `cannot tell`); the twin, its container and the proposed file's hash; `shut_out`, the kinds of client the change would refuse. Evidence for the approver; no verdict reads it |
| `policy.changed` | `human` | The policy file's path and hash, and what it now says for each target. The start of time-to-change |
| `approval.granted`, `approval.denied` | `human` | The change id; `by` and `authenticated_by` (see "Who writes the ledger") |
| `change.applied` | `runner` | The change id and the containers acted on — for each, the container before and after, and the image digest. Only ever on an owned estate |
| `service.recreated` | `runner` | A service recreated with no change to its configuration, so that a verdict can be repeated; the containers before and after |
| `change.observed` | `scanner` | A change seen arriving that the harness did not apply — the operator's own change, or drift. Written by watch mode at the end of a scan against the previous scan of the same scope: `kind` is `finding-appeared`, `finding-gone`, `config-changed` or `item-changed`, with `since` naming the earlier run (and event) it differs from |
| `config.observed` | `scanner` | Per service, the path and SHA-256 of every configuration file the service was built from, at the time of the scan; what `config-changed` compares |
| `verdict.issued` | `verifier` | A `pqch.verifier/1` verdict |
| `queue.enqueued`, `queue.drained` | `controller` | The work item and the tier it waits for; the items cleared |
| `engine.swapped` | `controller` | From, to, and the measured duration in milliseconds |
| `checkpoint.signed` | `controller` | A `pqch.checkpoint/1` object |
| `trace.completed` | `model` | The investigator's trace of one wire finding to a configuration line, in a run of kind `investigate` over a scan run: the finding (its run, event, fingerprint, subject and asset), the service, the files read (path and hash), the step and token budgets and what was used, the engine and its settings (tier, reasoning, model, the upstream that served it), every step with its latency and usage, the measured total time, the answer (file and line range, or `cause: default`) with the lines' text, and `key_check` when the answer key names the cause. A claim labelled the model's: no rule, link or verdict reads it |
| `package.issued` | `rule` | A change package for a migration item blocked on its supplier, in a run of kind `package` over a scan run (`package/supplier/1`): the item (scan run, service, function, queue, deadline, whether prioritized, the supplied owner); why no configuration change can do it (the blocker's event and basis, the software and library, what it lists, the capability snapshot and its evidence by path and hash); `unblock`, the services in the same snapshot running the same product that do list an algorithm for the function; the pack's replacement clause; the CBOM entries the item covers, by fingerprint, with the files they are served from; the verifier check that will count once replaced; `rollback: null` and `rehearsal: not rehearsed`. Nothing in it is applied |
| `import.completed` | `scanner` | In a run of kind `import`: the tool and version, each imported document (name, the image it describes, stored path, SHA-256, CycloneDX version), the assets by type, the findings placed by layer, the entries that could not be placed (count and names), and, when an answer key was committed, the score by layer. Each placed entry is a `finding.observed` whose `source.image_digest` is the document's hash and `source.profile` is `import:<tool>` |
| `run.closed` | `runner` | Nothing |

New types may be added without a major bump. A reader that does not know a
type still verifies its place in the chain.

Two rules bind types together, and a ledger that breaks either is invalid:

1. A `change.applied` event must have an `approval.granted` for the same change
   id earlier in the ledger. Approval and apply events must name a change id.
2. An entry is shown as verified only if a `verdict.issued` event says so. No
   other event type can set that state.

### Signing checkpoints — `pqch.checkpoint/1`

A checkpoint signs the chain up to a point. It is itself an event, so it is
chained like any other.

```json
{
  "schema": "pqch.checkpoint/1",
  "through_seq": 41,
  "head_hash": "…",
  "signed_at": "2026-10-04T12:37:04.902Z",
  "alg": "ML-DSA-65",
  "key_id": "…",
  "signature": "<base64>"
}
```

- `head_hash` is the `hash` of the event at `through_seq`.
- The signed message is the ASCII bytes of
  `pqch.checkpoint/1\n<through_seq>\n<head_hash>\n<signed_at>`.
- `signed_at` is the signer's own UTC time when it signed. A checkpoint written
  before 2026-10-04 has none; its message is the first three lines, and it is
  reported as giving no signer time.
- The signer's time brackets the ledger's: no event may be stamped later than
  a signature over it, and none after a checkpoint may be stamped earlier than
  that checkpoint's `signed_at`, each within 2000 ms. The signer refuses to
  sign a ledger that breaks either, and verification fails one.
- `key_id` is the SHA-256 of the public key in its standard encoding, DER
  SubjectPublicKeyInfo. The public key is kept beside the ledger as
  `ledger.pub` and shown in the UI.
- A checkpoint is written after every `approval.granted`, after every
  `verdict.issued`, and before `run.closed`: the event before `run.closed` is
  a checkpoint through the event before it.
- A checkpoint is also written immediately before `policy.changed` (over
  `run.started`) and immediately before each approval, and after the
  proposals. So each of the two events a person causes is written between two
  signatures: it is chained after the first, so it did not exist before that
  signature was made, and it is covered by the second. Before a run's first
  checkpoint nothing bounds a timestamp from below.
- Time-to-change on the signer's clock is an upper bound: from the last
  signature before the event was written to the first signature over the
  verdict. A run without the earlier signature reports only when the signer
  first saw each event, and says so. When the ledger's interval and the
  signer's differ by more than twice the tolerance, neither is shown as a
  time-to-change.
- The `checkpoint.signed` payload is the checkpoint object. It may also carry
  `signing_ms` and `hardware`: the measured signing time and the machine.

**Who signs.** A signer service holds the key on storage no other service can
read. It has no network and reads run ledgers read-only. It signs only after
it has verified the chain through `through_seq` itself, and only if every
checkpoint it signed before for that run is still in the ledger. It keeps its
own record of each checkpoint it signed (`through_seq`, `head_hash`,
`key_id`, `signed_at`), outside the ledger and out of reach of the service that
writes it. It refuses a ledger whose `run.started` names another run or no
run: a ledger copied to a new run id is not signed again. It signs only
forward — never through an event at or before one it has already signed
through — and its `signed_at` never runs backwards within a run: if its clock
stepped back, the new checkpoint carries the previous one's time. The services
that call it mount its socket read-only and cannot put another in its place.

To verify: verify the chain through `through_seq`, confirm `head_hash`, then
verify the signature with the public key. Then check every checkpoint recorded
outside the ledger — the signer's record, or values a reader wrote down — is
still there: a recorded checkpoint beyond the ledger's end, or one whose event
hash no longer matches, means events were removed or rewritten behind it.
Check the public key against the signer's, not only against `ledger.pub`,
which lives beside the ledger and can be replaced with it.

What this gives: alteration of any event at or before a checkpoint is detected
by anyone who holds the public key and recorded the checkpoint. What it does
not give: protection against the operator who holds the signing key, or for
events after the last checkpoint.

### The CBOM projection

The CycloneDX 1.6 CBOM is a pure function of the ledger. Fields CycloneDX does
not define are written as component properties under the `pqch:` namespace:
`pqch:owner`, `pqch:deadline`, `pqch:queue`, `pqch:state`, `pqch:evidence`
(event ids), `pqch:supplied`, `pqch:verifiable-by`, `pqch:conflict`. The
dependency chain is carried as components and `dependencies`: an `application`
component per service (`svc:<name>`, with the supplied facts as properties and
`pqch:supplied` naming each one with its event and author) depends on its
listeners and on a `container` component per image (`img:<repository>`), which
depends on the files found in it; a listener depends on the assets it
negotiates and serves, and a served certificate on the file holding its key.
The mapping is not part of this interface and may change as the standard's
minimum elements settle.

---

## 4. Inference seam — `pqch.inference/1`

**Frozen 2026-10-12.** A change to anything below is `pqch.inference/2`.

The only place that knows where a model lives. Code names a tier, or a role;
a config file maps tiers to endpoints and roles to tiers. No model name, and
no choice of model for a role, appears in code: which role runs on which tier,
with reasoning or without, is a measurement (spike S3) written into the file.

```yaml
schema: pqch.inference/1
profile: lab
tiers:
  fast:
    base_url: http://inference.example.internal:4000/v1
    api_key_env: LITELLM_API_KEY
    model: lab/flash
    hardware: lab-l4-fleet
    max_context: 32768
    timeout_s: 60
    residency: resident
    reasoning:                       # the same engine with reasoning on
      model: lab/reason-fast         #   another lane or model id, if that is how it is switched
      timeout_s: 600
      request: {}                    #   extra request fields, if that is how (vLLM: chat_template_kwargs)
  deliberate:
    base_url: http://inference.example.internal:4000/v1
    api_key_env: LITELLM_API_KEY
    model: lab/reason
    hardware: lab-gb10
    max_context: 131072
    timeout_s: 600
    residency: resident
  embed:
    base_url: http://inference.example.internal:4000/v1
    api_key_env: LITELLM_API_KEY
    model: lab/embed
    hardware: lab-gateway
    residency: resident
roles:
  call-site-read:     {tier: fast, reasoning: true}
  classify-algorithm: {tier: fast, reasoning: true}
  trace-to-cause:     {tier: deliberate, reasoning: false}
  change-plan:        {tier: deliberate, reasoning: false}
  normalize-name:     {tier: fast, reasoning: true}
```

| Field | Meaning |
|---|---|
| `base_url` | An OpenAI-compatible endpoint |
| `api_key_env` | The name of the environment variable holding the key. The key itself is never in the file |
| `model` | The model id sent to the endpoint |
| `hardware` | A label for what serves this tier. It is copied onto every timing so a number is never shown without the machine it came from |
| `residency` | `resident` — always loaded. `on-demand` — not loaded until asked for; a call raises at once and the caller queues the work |
| `reasoning` | Optional, on a completion tier: how the same engine is reached with reasoning on — `model` (another id or lane), `timeout_s`, and `request` (fields merged into the request body). Absent, a reasoning call goes to the tier as it is |
| `served_by_header` | Optional: the name of a response header in which the endpoint names the upstream that served a call (default `x-litellm-model-api-base`, which the lab's gateway sends). When present on a reply, its value is recorded as `served_by` beside the config's `hardware` label — the label is a claim, the header is what happened |
| `roles` | Optional: each role the pipeline names, bound to a `tier` (`fast` or `deliberate`) and a boolean `reasoning`. A role is bound here only on a measurement against a floor written before the run; a role no model reached is left unbound and is a rule's job. A file with no `roles` section binds every role to `fast` without reasoning; a file with one must name every role that is asked for |

The tiers are `fast`, `deliberate` and `embed`. A profile may omit `embed`.
The role names this project uses are spike S3's: `call-site-read`,
`normalize-name`, `classify-algorithm`, `resolve-conflict` (unbound),
`trace-to-cause`, `change-plan`.

The interface in code is three calls:

```python
complete(tier, messages, *, schema=None, max_tokens=None, purpose, reasoning=False) -> Completion
complete_role(role, messages, *, schema=None, max_tokens=None, purpose) -> Completion
embed(tier, texts) -> list[list[float]]
```

- `schema`, when given, is a JSON Schema the reply must satisfy; the seam
  validates and returns the parsed object or raises.
- `purpose` is a short label ("classify-finding", "trace-root") recorded with
  the call.
- `Completion` carries the text or parsed object, token usage, the model id
  the endpoint answered with, the tier, the hardware label, the latency in
  milliseconds, whether reasoning was on, the role if one was named, the
  upstream that served it when the endpoint says, and the endpoint's `finish_reason` — so a reply cut off at a token cap is never
  mistaken for a refusal.
- A call to an `on-demand` tier that is not loaded raises `TierUnavailable`
  immediately. It never blocks and never triggers a swap. The caller records
  a `queue.enqueued` event and moves on; the controller decides when to swap.
- Any event a model contributed to names the tier, model and hardware in its
  `actor`, with `reasoning: true` when it was on, `role` when one was named,
  and `served_by` when the endpoint said which upstream answered.

The seam has no knowledge of prompts or the ledger.

---

## 5. Verifier — `pqch.verifier/1`

A verifier decides whether a change landed. It runs no model. It takes a check
and a target, runs probes, and returns a verdict. The same check run twice on
an unchanged target returns the same status.

### The check

Carried in the `change.proposed` event, so what will count as verified is
fixed before anything is applied.

```json
{
  "schema": "pqch.verifier/1",
  "kind": "wire-kex",
  "intent": "require",
  "target": {"host": "172.16.106.10", "port": 443, "protocol": "tls", "sni": "portal.agency.test"},
  "must_accept": ["X25519MLKEM768"],
  "must_refuse": ["X25519", "secp256r1"]
}
```

| `kind` | What it probes |
|---|---|
| `wire-kex` | Which key-establishment groups a TLS or SSH listener accepts and refuses |
| `cert-parse` | The signature algorithm and chain of the certificate a listener serves |
| `compat-run` | A named client against the listener: does it still connect |

`intent` is `enable` or `require`, taken from the policy. `policy_intent`
records the policy's own word when it differs: a policy of `none` (classical
only) is checked as `require` with the classical group to accept and the hybrid
groups to refuse.

### The verdict

```json
{
  "schema": "pqch.verifier/1",
  "change_id": "01JD…",
  "status": "enabled-not-enforced",
  "probes": [
    {"name": "positive", "tool": "openssl s_client", "tool_digest": "sha256:…", "started_at": "…", "ended_at": "…", "result": "accepted", "negotiated": "X25519MLKEM768", "raw_sha256": "…", "container_id": "…", "image_digest": "sha256:…", "stable": true},
    {"name": "negative", "tool": "openssl s_client", "tool_digest": "sha256:…", "started_at": "…", "ended_at": "…", "result": "accepted", "negotiated": "X25519", "raw_sha256": "…", "container_id": "…", "image_digest": "sha256:…", "stable": true},
    {"name": "witness", "tool": "testssl.sh", "tool_digest": "sha256:…", "started_at": "…", "ended_at": "…", "result": "accepted", "negotiated": "X25519MLKEM768", "raw_sha256": "…", "container_id": "…", "image_digest": "sha256:…", "stable": true}
  ],
  "binding": {"address": "172.16.106.10:443", "container_id": "…", "image_digest": "sha256:…", "cert_fingerprint": "…"},
  "after_event": "01JD…",
  "durable": "untested",
  "meets_intent": true,
  "reasons": [],
  "hardware": "xr7620 (x86_64)"
}
```

`must_refuse` is every group of the other kind a client could offer, not only
the ones the listener was configured with: a listener that requires the hybrid
group must refuse a client offering any classical group.

A probe's `result` is judged by the group the server chose. A server that
sends its key share in an offered group has accepted it, even if the client
aborts later (in TLS 1.2, for instance, when the certificate's curve was not
offered). A handshake that completes on a group the client did not offer —
TLS 1.2 finite-field DHE, whose parameters the server chooses — is not
acceptance of an offered group; for the negative probe it is still a
classical exchange accepted.

The paired probes are single handshakes that offer only the named groups: the
positive probe offers `must_accept` over TLS 1.3; the negative probe offers
`must_refuse` with any protocol version, as a client that would downgrade. The
witness is a tool of a different kind whose own handshakes enumerate the
groups the listener accepts; it agrees when every group in `must_accept` is
among them. The pair samples and the witness enumerates: if the witness finds
the listener accepting any group outside `must_accept`, the status is at most
`enabled-not-enforced`, and the verdict lists those groups in `also_accepts`. Each probe records the container the runner found at the address
and whether it stayed the same through the probe.

### Checking a verdict against the runner's record

Each probe carries the runner's `job_id`. A reader checks every verdict
against the runner's own log of jobs and of applies, and the raw output the
runner wrote. A verdict is borne out when, for each probe:

- the runner logged that job with the same raw output hash, the same start
  and end and the same container, and no other verdict cites it;
- it is the job the check prescribes — the positive probe offered exactly
  `must_accept` over TLS 1.3, the negative exactly `must_refuse`, the witness
  the witness profile — against the check's address;
- it started after the runner's own record of the apply or recreate the
  verdict answers had ended, and reached the container that apply or recreate
  made;
- the runner's raw output, parsed again, gives the result the probe records,
  and the three results give the verdict's status.

A verdict whose probes name no job cannot be checked and is shown as
unchecked. A change is shown as verified, and its interval as a
time-to-change, only when every apply, recreate and verdict in it is borne
out.

`meets_intent` says whether the status meets the check's intent. `reasons`
lists why a verdict is `inconclusive`. `hardware` labels the machine. A
repeated verdict names the verdict it repeats in `repeats` and sets `durable`.
A verdict taken against another address than the check's — to show a wrong
container fails — records it in `target_override`, and is not counted in
time-to-change.

### Status

| Positive probe (offers only `must_accept`) | Negative probe (offers only `must_refuse`) | Status |
|---|---|---|
| accepted | refused | `enforced` |
| accepted | accepted | `enabled-not-enforced` |
| refused | either | `not-landed` |
| error or timeout on any probe | — | `inconclusive` |

- The witness is a second tool of a different kind repeating the positive
  probe. If it disagrees with the first, the status is `inconclusive`.
- A change with intent `enable` is met by `enabled-not-enforced` or `enforced`.
  A change with intent `require` is met only by `enforced`.
- `inconclusive` is never resolved by inference. The probe is run again or the
  change stays unverified.

### Rules a verifier must hold to

1. **No model.** No call through the inference seam, directly or indirectly.
2. **Fresh.** Every probe starts after the timestamp of `after_event` — the
   `change.applied` or `change.observed` event it answers. Output from an
   earlier scan is never reused.
3. **Bound.** The verdict records what was actually probed. If the address is
   not in the scope, or on an owned estate the container or image is not the
   one the change targeted, the status is `inconclusive`. On an estate the
   harness does not own, `container_id` and `image_digest` are null and the
   binding is the address and certificate fingerprint.
4. **Durable.** On an owned estate the check is repeated after the service is
   recreated, and `durable` becomes `true` or `false`. Elsewhere it stays
   `untested`.
5. **Scoped.** A verifier touches only endpoints in the scope.
6. **Honest about reach.** A finding whose fix no verifier can observe is
   marked `verifiable_by: none` in the answer key and counted in the receipts.
   No verdict is issued for it.
