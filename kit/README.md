# The kit: the workbench on one box

Everything on one host: the mini-agency, the harness, the inference engines. Nothing leaves the box;
the page is on its loopback. First stood up on a DGX Spark (GB10, aarch64) on 2026-11-04 from the
offline bundle; the same steps hold for an x86_64 host.

## What the box needs

`kit/preflight.sh` checks it and says what is missing: Docker Engine with the Compose plugin and the
operator in the `docker` group; the NVIDIA Container Toolkit with a CDI spec (`nvidia.com/gpu=all`);
Python 3.12 and `uv`; about 20 GB of disk for the bundle and the harness, plus whatever the engines'
weights take; no root for anything in the kit.

## The steps

1. **Bring the tree and the bundle.** Clone the repository, or `rsync` it (without `.venv`, `var`,
   `site`). Then either build the bundle on the box, for its own architecture only:
   ```sh
   PQCH_BUNDLE_PLATFORMS=linux/arm64 uv run python bundle/build.py   # prints the SHA256SUMS hash
   ```
   or carry `bundle/out` from a build host on a disk, with its `SHA256SUMS` hash recorded separately
   from the bundle. Building needs the network; loading does not.
2. **The Python environment:** `uv sync --frozen --no-dev` in the tree (fetches wheels; the offline
   wheelhouse is M4's open item).
3. **The engines:** copy `kit/engines.env.example` to `kit/engines.env`, set the images and shares,
   then `kit/engines.sh up`. Shares are of the box's unified memory and must leave room for the
   harness and the estate. `kit/engines.sh status` shows each tier's `/v1/models`. A NIM needs
   `~/.config/nim/ngc.env` (mode 600) with `NGC_API_KEY` the first time, to fetch its weights.
4. **The stack, from the bundle:**
   ```sh
   export PQCH_AGENCY_DIR=$PWD/agency PQCH_VAR=$PWD/var PQCH_BUNDLE_DIR=$PWD/bundle/out \
          DOCKER_GID=$(getent group docker | cut -d: -f3) PQCH_UID=$(id -u) PQCH_GID=$(id -g) \
          PQCH_HARDWARE="DGX Spark GB10 (aarch64)" PQCH_OPERATOR="$USER"
   mkdir -p $PQCH_VAR/{scope,raw,runs}
   uv run python bundle/load.py --expect-sums <hash> --lab-overlay kit/compose.kit.yaml
   ```
   The loader checks every file and every registry blob against its hash, starts the bundle's registry
   read-only, pulls the thirteen images by digest, writes the estate's starting policy files from
   `agency/baseline/` where `agency/generated/` has none, starts the estate, regenerates the scope from
   what is running, and starts the harness. On the GB10 that took 8 s after the first load (29 s with the pulls).
5. **The page:** http://127.0.0.1:8080/ on the box. The walkthrough runs the scan; the CBOM, the plan,
   resolution and Ask the CBOM follow from it.

## Who approves

There is no front door on one box. The page is published on the loopback, the service accepts an
approval only from the bridge gateway (the box itself), and the person at the console is the operator
named in `PQCH_OPERATOR`. Every approval event records that the console vouched for the name, not a
sign-on. On a shared or remote machine, put the page behind a front door and set
`PQCH_TRUSTED_PROXIES` and `PQCH_IDENTITY_HEADER` instead.

## A real server, scanned elsewhere and shown here

The mini-agency is planted and scored. Beside it, the kit can show a real server scanned somewhere
else, as a recording: the scan's raw outputs with the server's identifiers replaced (ADR-0005; journal
note 20). Replaying it opens a new, signed run on this box with no access to the server; every page
says it was replayed and when the server was read.

On the host that scanned the server (the recording never goes in the repository):

```sh
pqch system export <run> --out <dir> --map <identifiers.yaml> --leaks <patterns.yaml> --scrub-hardware-ids
tar -C <dir>/.. -czf recording.tgz <dir-name> && sha256sum recording.tgz   # carry the hash separately
```

On the box, with the stack up:

```sh
tar -xzf recording.tgz -C $HOME
docker compose -f compose.yaml -f kit/compose.kit.yaml -f bundle/out/compose.harness.yaml \
  run --rm -v $HOME/<dir-name>:/recording:ro app pqch system replay /recording
```

Then: the plan page's "A server's plan" tab, and the CBOM page's "A server's CBOM".

## Leaving a box

`kit/cleanup.sh` takes off what the kit put on a machine. It lists everything first and changes
nothing without `--yes`:

```sh
kit/engines.sh down
kit/cleanup.sh                                       # read the list
kit/cleanup.sh --yes --images --caches --personal    # containers, volumes, images, caches, credentials
kit/cleanup.sh --yes --tree                          # last: the checkout, its ledgers and the bundle
```

`--personal` removes the NGC key file and the nvcr.io login, Hugging Face tokens, the GitHub CLI's
login and stored git credentials, Claude Code's sign-in and session transcripts, and shell history.
Caches outside the operator's home are left and named. Tokens made for the day are revoked at their
source as well: removing the file on the box does not.

## What the kit does not do

It scans the mini-agency it carries, and nothing else unless the operator writes a scope file naming
their own network (ADR-0003). It applies no change outside the mini-agency. It bundles no model: the
engines are the operator's, named in `kit/engines.env`, and which engine serves which role is decided
by measurement on that box (spike S3; `eval/ask`), never assumed.

## Measured on the GB10, 2026-11-04

Lab GB10: DGX Spark, aarch64, Ubuntu 24.04.4, kernel 6.17.0-1026-nvidia, Docker 29.2.1, NVIDIA
Container Toolkit 1.19.1 with CDI, driver 580.173.02, 121 GB unified memory.

| | |
|---|---|
| Bundle | 13 images, amd64 and arm64, 1.5 GB; 406 registry blobs checked at load |
| Load and start | 29 s with the pulls from the bundle's registry; 8 to 13 s on a reload |
| Live scan of the mini-agency | under 5 minutes; wire 38 of 40 (the 2 left are out of reach by design), host 20 of 20, posture 9 of 9, no false positives (run `01M6J41JHM771T1JA0AWZZDAPC`) |
| Engines resident | fast: Nemotron 3.5 Lightning 30B-A3B NVFP4 under vLLM (0.20 share, 40k window, reasoning parser on; thinks under the reply schema, about 2,300 tokens and 117 s a classification call with the 120B sharing the GPU); the Nemotron Nano 9B v2 NIM (DGX Spark build) ran in that slot first and was measured on the five roles, reaching no floor; deliberate: Nemotron 3.5 Super VL 120B-A12B NVFP4 under vLLM (0.55 share, 131k window, 88 shards in about 10 min); embed: ollama mxbai-embed-large |
| Memory with all three engines, the estate, the harness and two evaluations running | 101 GB used, 20 GB available; the engines' containers 4.0, 2.1 and 0.66 GiB of host memory beside their GPU shares |
| GPU power | 8.5 W idle; 31 W with two evaluations in flight (DCGM) |
| A step of the plan resolved on the box | change run `01M6J7MM0X9BJNZWWAEPC2R2PM`: proposed by rule, approved by the console operator (recorded as such), applied to the portal, verified on the wire (enabled-not-enforced for the `enable` intent), the service recreated and verified again, durable; 343 s from the policy change to the last verdict with the engines busy beside it |
| Engines that did not run, and why | journal lesson 49 |

Role results per engine (spike S3 on the box, `eval/ask`): journal, same date, and the BRIEF's table.
