---
title: Pointing it at your own network
---

# Pointing it at your own network

The demo runs against the *mini-agency*, a test estate built for it with every weakness planted. The
same workbench can look at a real network — it was built and measured that way on the author's own
lab — but it is not packaged for that. This page says what is involved, step by step, and what you
will have to wire up yourself. Expect an afternoon for the targeted scan and a day for passive capture,
for someone comfortable with Docker networking and a switch's mirror port.

!!! warning "Only a network you are authorized to scan"
    Scan only a network you own or have written permission to test. The workbench records that
    authorization as the first event of every run and refuses an external scan without it, but the
    permission is yours to obtain. It never changes anything on a network it did not build: an
    external estate gets findings and a plan, never an applied change.

## What you get

- **Every listed listener asked directly** (testssl.sh for TLS, ssh-audit for SSH): every key-exchange
  group, suite and protocol version it accepts, its certificate, its posture — classical, mixed or
  post-quantum.
- **Optionally, everything on the wire seen passively** (Zeek on a mirror port): what every client
  offers and what every server chooses in real handshakes, by VLAN, with the capture's loss beside
  every count. Nothing is sent.
- **One CBOM of the network** merging both, an entry per asset with both layers' evidence; the
  overview on NIST's crypto-agility plan; and a plan of who holds whom back — servers refusing what
  their clients offer, clients that can never offer a hybrid group, and the share of today's
  handshakes each change would refuse.

## What you need

- A Linux host with Docker and Docker Compose, Python 3.12 and [uv](https://docs.astral.sh/uv/), on
  a network that can reach the listeners you will scan.
- For passive capture: a switch that can mirror (SPAN) a port or VLAN, and a spare network interface
  on the host to receive it.
- No language model: the external path is scanners and rules only. (Models help with the code layer
  and with drafting changes, neither of which applies here.)

## 1. Run the workbench as for the demo

The stack expects the mini-agency beside it, so bring that up first; it also proves the scanners, the
signer and the ledger on your host before anything touches your network. From the repository root:

```sh
uv sync
uv run pqch scanners pull                                   # every scanner image, by its pinned digest
docker build -t pqch-agency/pki:m1 agency/pki               # the test estate's internal CA
uv run pqch policy render                                   # the portal's TLS settings, once
docker compose -f agency/compose.yaml up -d --build         # the mini-agency
uv run pqch scope generate agency/compose.yaml --out var/scope/scope.json
PQCH_AGENCY_DIR=$PWD/agency docker compose -f compose.yaml -f compose.local.yaml up -d --build
```

The base `compose.yaml` gives the web app no network at all, deliberately; a small overlay of your own
publishes it on the host only:

```yaml
# compose.local.yaml
services:
  app:
    network_mode: !reset null
    ports: ["127.0.0.1:8080:8080"]
```

Open `http://127.0.0.1:8080/`, run a scan from the walkthrough, and check the overview and the plan
fill in. `agency/README.md` has the details of the test estate.

!!! note "Not yet rehearsed on a clean machine"
    This sequence is the one the author's deployment uses, written out; it has not been run from an
    empty host by someone else. If a step fails, the error usually names the missing setting.

## 2. Write the scope

The scope is the list of what may be touched. It lives with your deployment, never in the
repository. A minimal one, with two listeners:

```json
{
  "schema": "pqch.scope/1",
  "id": "01JABCDEFGHJKMNPQRSTVWXYZ0",
  "estate": "external",
  "owned": false,
  "authorized_by": "Your Name, network owner, 2026-11-01: targeted TLS and SSH checks of the listeners listed here",
  "endpoints": [
    {"host": "192.0.2.10", "port": 443, "transport": "tcp", "protocol": "tls", "sni": "intranet.example.org"},
    {"host": "192.0.2.20", "port": 22, "transport": "tcp", "protocol": "ssh"}
  ],
  "images": [],
  "sources": [],
  "reach": {"kind": "local"}
}
```

- `id` is a ULID: `uv run python -c "from pqch.common import ulid; print(ulid())"`.
- `protocol` is `tls`, `ssh` or `postgres` (TLS after PostgreSQL's upgrade). A listener with a server
  name gets `sni`.
- `authorized_by` is a sentence, in your words: who authorized what, and when.
- To find listeners you did not know about, run passive capture first (step 5): its page lists every
  server that spoke, and you add the ones you are permitted to probe.

The schema with every field is in [the interfaces specification](https://github.com/kenrollins/cbom-workbench/blob/main/spec/interfaces.md).

## 3. Give a second runner a leg on your network

The demo's runner sits on the mini-agency's internal network and is bound to its scope. A second
runner, with your scope, needs an address on the network it will scan. A Compose overlay beside
`compose.yaml` — kept with your deployment, not in the repository — adds it. With a macvlan on a
VLAN interface, for example:

```sh
docker network create -d macvlan -o parent=eth0.100 \
  --subnet 192.0.2.0/24 --gateway 192.0.2.1 --ip-range 192.0.2.240/28 pqch_ext
```

```yaml
# compose.ext.yaml — docker compose -f compose.yaml -f compose.local.yaml -f compose.ext.yaml up -d
services:
  app:
    volumes:
      - ext-runner-sock:/run/pqch-lab:ro        # where `pqch scan-external` looks by default
  runner-ext:
    image: pqch/harness:m0
    restart: unless-stopped
    user: "${PQCH_UID:-1000}:${PQCH_GID:-1000}"
    command: ["uvicorn", "pqch.runner.service:app", "--uds", "/run/pqch-lab/runner.sock", "--log-level", "warning"]
    group_add: ["${DOCKER_GID:-999}"]
    environment:
      PQCH_SCOPE: /etc/pqch/scope.json
      PQCH_RAW: /var/pqch/raw
      PQCH_TARGET_NETWORK: pqch_ext                # scanners are started on this network
      PQCH_RUNS: /var/pqch/runs
      PQCH_RUNNER_LOG: /var/pqch-runner
      PQCH_SIGNER_SOCKET: /run/pqch-signer/signer.sock
      PQCH_AGENCY_DIR: ${PQCH_AGENCY_DIR}
      HOME: /tmp
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /path/to/your/scope.json:/etc/pqch/scope.json:ro
      - ${PQCH_VAR}/raw:/var/pqch/raw
      - ${PQCH_VAR}/runs:/var/pqch/runs:ro
      - ext-runner-sock:/run/pqch-lab
      - signer-sock:/run/pqch-signer:ro
      - ext-runner-log:/var/pqch-runner
      - ${PQCH_AGENCY_DIR}:${PQCH_AGENCY_DIR}:ro
    networks: [pqch_ext]
volumes:
  ext-runner-sock:
  ext-runner-log:
networks:
  pqch_ext:
    external: true
```

- Size the address range to the parallelism: each scanner takes an address for its run, and eight at
  once need more than a /29 ([lesson 25](lessons/25-size-the-scanner-network-to-the-parallelism.md)).
- The runner only ever starts the scanners its profiles name, against the endpoints the scope lists;
  anything else is refused before it starts.

## 4. Scan

```sh
docker compose -f compose.yaml -f compose.local.yaml -f compose.ext.yaml exec -T app pqch scan-external
```

Each listener gets one job; the run is a ledger of its own, signed, and the page's **A real network**
tab, the CBOM page's second estate and the plan's second estate read from it.

## 5. Optionally, capture passively

1. Mirror the traffic you want to see to a spare port on the host — the switch's own configuration
   is specific to the switch. A trunk carries every VLAN; mirror both directions.
2. Give the receiving interface no address, set it promiscuous, and turn generic receive offload
   off (`ethtool -K <iface> gro off`): with it on, merged segments are counted as loss and the loss
   figure reads many times too high.
3. Add the capture point to the scope:
   `"captures": [{"interface": "<iface>", "host": "<this host>", "vlans": [10, 20], "mirror": "switch port 1/2/1, both ways"}]`.
4. Run Zeek from the repository root, with the interface and a log directory set:

   ```sh
   PQCH_CAPTURE_IFACE=<iface> PQCH_CAPTURE_DIR=/path/to/capture-logs \
     docker compose --project-directory . -f capture/compose.yaml up -d
   ```

5. Ingest the rotated logs into a capture run, daily for instance, and prune what is ingested:

   ```sh
   PQCH_VAR=/path/to/var uv run pqch capture ingest --scope /path/to/scope.json --capture-dir /path/to/capture-logs
   PQCH_VAR=/path/to/var uv run pqch capture prune --capture-dir /path/to/capture-logs
   ```

What the capture can and cannot see is in [note 05](notes/05-what-can-be-seen-on-the-wire-host-and-code.md).
Capture logs hold addresses, names and certificates of a real network: keep them, and the `var/`
directory, out of any repository.

## What does not carry over

- **The wording.** The pages call the second estate "a real network" and "the owner's lab"; there is
  one such estate, not several.
- **Ranking.** The mini-agency's plan is ranked by the owner's facts (mission, how long the data must
  stay secret, impact). There is no such file for an external estate yet, so its plan orders by who
  holds whom back and by use, not by mission.
- **Images and code.** The external path reads the wire. Host and code evidence for your systems
  would need their own scope entries and their own authorization.
- **Changes.** None are applied to an estate the workbench did not build. A change package for an
  external estate is planned, not built.
- **Testing.** The path has been run on one network, the author's. Yours will find something it did
  not.

Questions and improvements are welcome as issues on [the repository](https://github.com/kenrollins/cbom-workbench).
