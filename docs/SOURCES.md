# Sources

Public references this project relies on, each with what it supports. A source
is added here before it is cited in a note. Items marked *verify* have not yet
been read first-hand for the specific claim.

## Policy and standards

| Source | Supports |
|---|---|
| Executive Order 14412, June 22, 2026 | The federal mandate and its deadlines |
| OMB M-26-15, *Execution of the Migration to Post-Quantum Cryptography* — https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf | Phases, plan deadline, automated inventory, prioritization criteria, the table of quantum-vulnerable algorithms, enforcement against downgrade, replacement of systems that cannot take PQC, TLS 1.3. Read first-hand 2026-10-03 and 2026-10-20; PDF sha256 `515af704…`, text in `policy/sources/m-26-15.txt`; carried as `policy/packs/m-26-15.yaml`, whose every quote the loader checks against that text |
| FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) | The algorithms |
| NIST IR 8547, *Transition to Post-Quantum Cryptography Standards* | Deprecation timeline (*verify* current revision) |
| NIST CSWP 39-upd1, *Considerations for Achieving Crypto Agility: Strategies and Practices* (Barker et al., December 19, 2025, updated June 29, 2026) — https://doi.org/10.6028/NIST.CSWP.39-upd1 | The definition of crypto agility; Fig. 3, the crypto-agility strategic plan, whose layout the overview page redraws with credit. Read first-hand 2026-10-21, PDF sha256 `e6b147d2…`. It supersedes CSWP 39 (withdrawn 2026-06-29); the update changes one paragraph of §2.3 and leaves Fig. 3 as it was |
| NIST SP 1800-38B, *Cryptographic Discovery* (NCCoE) | Discovery as practice |
| NSA CNSA 2.0 FAQ — https://media.defense.gov/2022/Sep/07/2003071836/-1/-1/0/CSI_CNSA_2.0_FAQ_.PDF | Requirements for national security systems. *Not read first-hand*: NSA's site refused it on 2026-10-05 and 2026-10-20 (HTTP 403). Dates from secondary summaries (Entrust, 2022; Encryption Consulting), carried `verified: false` in `policy/packs/cnsa-2.0.yaml` |
| OWASP CycloneDX, *Authoritative Guide to CBOM* — https://cyclonedx.org/capabilities/cbom/ | The CBOM model and format |
| NIST Cryptographic Module Validation Program — https://csrc.nist.gov/projects/cryptographic-module-validation-program | Why validation is a separate clock; which active certificates list ML-KEM or ML-DSA among their approved algorithms. Snapshot read 2026-10-20 by `tools/cmvp_snapshot.py`, every page's hash in `policy/snapshots/cmvp-2026-10-20.json` |

## Tools

| Source | Supports |
|---|---|
| CycloneDX, *bom-examples*, CBOM examples — https://github.com/CycloneDX/bom-examples (commit 7d9172d) | Public CBOM documents (CycloneDX 1.6 and 1.7) used to test the importer; they carry no locations |
| cdxgen — https://github.com/CycloneDX/cdxgen (11.11.0, image `ghcr.io/cyclonedx/cdxgen@sha256:bbe0ecfd…`) | Tried as a code-layer CBOM generator; needs a build and the network (note 15) |
| sonar-cryptography — https://github.com/cbomkit/sonar-cryptography (1.6.1, jar sha256 `de2f21ea…`) | CBOMkit's source scanner: library coverage and the SonarQube requirement (note 15) |
| sslyze — https://github.com/nabla-c0d3/sslyze (6.2.0, image `nablac0d3/sslyze@sha256:0224706d…`) | Tried as a second TLS scanner; lists no post-quantum group (note 15) |
| CISA, *Strategy for Migrating to Automated PQC Discovery and Inventory Tools* (2024) — https://www.cisa.gov/sites/default/files/2024-09/Strategy-for-Migrating-to-Automated-PQC-Discovery-and-Inventory-Tools.pdf; *Product Categories for Technologies That Use PQC Standards* — https://www.cisa.gov/resources-tools/resources/product-categories-technologies-use-post-quantum-cryptography-standards | Federal discovery tools are a workstream of their own, outside the product-category lists. *verify* the lists' current contents |
| NIST NCCoE SP 1800-38B (preliminary draft), *Quantum Readiness: Cryptographic Discovery* — https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38b-preliminary-draft.pdf | The commercial discovery tools demonstrated with NIST. *verify* the current collaborator list |
| CBOMkit — https://github.com/cbomkit | Baseline scanners: source (Java, Python, Go), images, CBOM storage and compliance |
| Opengrep — https://github.com/opengrep/opengrep | Rule-driven source matching for languages CBOMkit does not read; the Ruby rule pack is written in this project |
| PQCA, *CBOMkit architecture* — https://pqca.org/blog/2026/pqca-cbomkit-architecture/ | What CBOMkit covers and does not |
| testssl.sh, ssh-audit, Zeek | Wire evidence (*verify* ML-KEM reporting per tool, PLAN spike S2) |
| NVIDIA AI Blueprint, vulnerability analysis — https://github.com/NVIDIA-AI-Blueprints/vulnerability-analysis | Precedent for present / reachable / exploitable analysis |
| NVIDIA NeMo Agent Toolkit — https://docs.nvidia.com/nemo/agent-toolkit/latest/ | Orchestration and profiling option |
| NVIDIA cuPQC — https://github.com/NVIDIA/cuPQC | GPU-accelerated ML-KEM and ML-DSA (not planned; the one-GB10 target was withdrawn, ADR-0004) |

## Methods

| Source | Supports |
|---|---|
| *Recursive Language Models*, arXiv 2512.24601 | The investigator's code-writing, self-calling pattern |
| Intelligent Internet, *From RALPH to Zenith* — https://ii.inc/blog/post/zenith-research | Adaptive orchestration and cost-aware stopping |
| *Agentic Context Engineering*, arXiv 2510.04618 | Evolving playbooks |
| *Observability for Post-Quantum TLS Readiness*, arXiv 2605.02978 | Passive and active TLS evidence (*verify* the scanner blind-spot claim) |
