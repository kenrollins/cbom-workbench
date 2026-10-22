# cbom-workbench

> A cryptography bill of materials, built from evidence, kept on a signed
> ledger, and put to work — with the role of AI in that work measured, not
> assumed.
>
> The import package and command are `pqch`.
>
> By **Ken Rollins**.

> [!IMPORTANT]
> **This is a personal exploration project, not an official Dell product,
> reference architecture, or supported offering.** Views and technical findings
> are the author's own.

---

## What this is

Federal agencies are required to inventory their cryptography and move it to
post-quantum algorithms on a published schedule. The inventory has a name — a
cryptography bill of materials, or CBOM — and a standard format. What it does
not yet have is a widely shared picture of what it is *for* once it exists.

cbom-workbench is that picture, running: a workbench that builds a CBOM
from three kinds of evidence — what endpoints negotiate on the wire, what sits on hosts and in
images, and what the source code and configuration say — and then uses it:

| Rung | The question the CBOM answers |
|---|---|
| Opaque | — |
| Enumerated | Where is quantum-vulnerable cryptography? |
| Structured | What depends on it, and how long must the data stay secret? |
| Managed | What first, what is blocked, and what changed since yesterday? |
| Agile | If policy changes, how fast can we respond — and did it land? |

Three ideas hold it together:

- **Agents propose, verifiers dispose.** A language model is used only where
  interpretation is needed. Whether a change worked is decided by re-scanning,
  with a pair of probes: a client offering only the new algorithm must
  succeed, and a client offering only the old one must be refused. Enabled is
  not enforced.
- **The ledger remembers.** Every finding, decision, approval and verification
  is an event in an append-only, hash-chained, signed log. The CBOM is built
  from it.
- **The models earn their place by measurement.** Six roles, a floor per role
  written before the run, every call repeated: two roles need the larger
  model, two run on the small one with reasoning on, two go back to rules.
  Each step up in models or hardware is a measured row, or marked not
  measured. And it all runs on infrastructure the organization holds: an
  inventory of where its cryptography is weakest is not something to send
  elsewhere.

It builds on [CBOMkit](https://github.com/cbomkit), the open-source scanner
set, as its first stage. It is measured against an answer key that includes
decoys and known misses, and against two baselines: CBOMkit alone, and all of
the open-source scanners run alone with no harness. The second is the bar.

## See it

**[The demo](https://kenrollins.github.io/cbom-workbench/)** — a snapshot of the workbench run against
the *mini-agency*, an eight-service test estate built with every cryptographic weakness planted and an
answer key: the overview on NIST's crypto-agility plan, the walkthrough from a stale spreadsheet to a
CBOM, the CBOM itself opened field by field, and the migration plan it makes possible, with what-ifs.
The snapshot is read-only; the live workbench scans, proposes and verifies on demand.

## Status

The workbench runs end to end on the mini-agency: discovery on the wire, in images and in code; the
CBOM on a signed ledger; dependency chains; policy queues from OMB M-26-15; a migration plan computed
from the CBOM; changes proposed, rehearsed on a copy, approved and proved on the wire. The model roles
are measured against floors written before the runs. What comes next is in [`ROADMAP.md`](ROADMAP.md).
The dates this runs against: the minimum elements of a federal CBOM are due from CISA and NIST by
2027-03-19; key establishment on prioritized systems by the end of 2030, signatures by the end of 2031
(`BRIEF.md`, "The clock").

## Read next

- [`BRIEF.md`](BRIEF.md) — the design, the claim, and what was ruled out
- [`ROADMAP.md`](ROADMAP.md) — what is built and what is next
- [`docs/adr/`](docs/adr/) — the decisions the rest depends on
- [`docs/journal/`](docs/journal/) — technical notes and lessons
- [`spec/`](spec/) — the interfaces, precise enough to rebuild the core from
- [Pointing it at your own network](https://kenrollins.github.io/cbom-workbench/site/your-own-network/) — what is involved, step by step, and what does not carry over

## License

[Apache License 2.0](LICENSE).

## The journal site

`docs/journal/` is published as a static site. To build it:

```sh
uv run --with mkdocs-material python tools/build_site.py   # copies the journal into site_src/
uv run --with mkdocs-material mkdocs build --strict         # writes site/
```

A deployment may mount `site/` into the UI service (`PQCH_SITE_DIR`, default
`/app/site`); it is then served at `/site/` behind the same door as the page.
