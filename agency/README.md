# The mini-agency

The estate the harness inventories. Every weakness in it is planted, so the
answer key (`answer-key.yaml`) can say exactly what a perfect inventory holds.

## M1: eight services

On `pqch-agency-net`, an internal-only bridge on `172.16.106.0/24`. Targets
take static addresses below `.128`; scan containers take dynamic ones above
it. No service has a route out or a VLAN address. Every weakness is planted
and keyed; the M0 slice is unchanged inside it.

| Service | Address | Listener | Posture |
|---|---|---|---|
| `portal` | 172.16.106.10 | 443/tls `portal.agency.test` | Classical: X25519 and P-256 key exchange, RSA-2048 certificate; TLS 1.2 and 1.3; policy-rendered |
| `api` | 172.16.106.11 | 443/tls `api.agency.test` | Mixed: X25519MLKEM768 hybrid key exchange, X25519 still accepted, ECDSA P-256 certificate; TLS 1.3 only |
| `api` | 172.16.106.11 | 8443/tls `api.agency.test` | The partner listener: as 443, and a client certificate from the partner CA (P-256) is required |
| `pq-gateway` | 172.16.106.12 | 443/tls `pq-gateway.agency.test` | Post-quantum: X25519MLKEM768 only, TLS 1.3 only, a self-signed ML-DSA-65 certificate |
| `sftp-legacy` | 172.16.106.20 | 22/ssh | Classical, old: OpenSSH 6.6 on Ubuntu 14.04; finite-field and elliptic-curve key exchange down to 1024-bit DH; RSA, DSA, ECDSA and Ed25519 host keys |
| `bastion` | 172.16.106.21 | 22/ssh | Mixed: OpenSSH 10.0 on Alpine 3.22; ML-KEM and sntrup761 hybrids first, X25519 still accepted; Ed25519 and RSA-3072 host keys |
| `records-db` | 172.16.106.30 | 5432/postgres | Mixed, with RSA key transport: PostgreSQL 18, TLS after the SSLRequest upgrade; X25519MLKEM768 first, X25519 accepted, and the default cipher list keeps TLS 1.2 `TLS_RSA_WITH_*`; RSA-2048 certificate from the internal CA |
| `queue` | 172.16.106.31 | 5671/tls | Classical: RabbitMQ 4, AMQP over TLS only; TLS 1.2, P-256 and P-384 named in `advanced.config`; ECDSA P-256 certificate from the internal CA |
| `legacy-app` | 172.16.106.32 | 8443/tls `legacy-app.agency.test` | Classical: Tomcat 8.5 on Java 8; TLS 1.2 only, two ECDHE-RSA suites, P-256 and P-384 pinned in `setenv.sh`; RSA-2048 certificate from the internal CA in a PKCS#12 keystore with its password in `server.xml` |

**The internal CA** (`pki/`) is a build-time image, never run: ECDSA P-384,
issuing the certificates of `records-db`, `queue` and `legacy-app`, each of
which copies its material out of the CA image at build. The ML-DSA-65
certificate is self-signed because the CA cannot issue it yet (the signature
track, M3).

**Plants beyond the M0 slice**, each keyed (`answer-key.yaml`): RSA key
transport real on `records-db` and a decoy on `legacy-app`, whose explicit
cipher list refuses it; a retired RSA-1024 certificate in the queue's image
named only by a file RabbitMQ does not load; a management listener and a
3DES connector that exist only in an unloaded file and an XML comment; a
commented hybrid-plus-classical fallback on the gateway; the partners' client
certificates, out of reach from the server side; the CA certificate as a file
in three images; a PKCS#12 keystore; an ML-DSA certificate file that
cbomkit-theia drops.

Memory: `records-db` 256 MB, `queue` 512 MB, `legacy-app` 256 MB (JVM
`-Xmx96m`), the rest 64 MB.

Certificates and host keys are generated when the images are built, so they
differ between builds. The answer key names them by path and algorithm, never
by fingerprint.

Base images are pinned by multi-arch index digest. `ubuntu:14.04` and
`alpine:3.22` both publish arm64 builds.

```sh
docker build -t pqch-agency/pki:m1 agency/pki   # the internal CA first; the services copy from it
uv run pqch policy render          # once, when building: portal's TLS settings from the policy
docker compose -f agency/compose.yaml up -d --build
```

Portal's protocol versions and key-exchange groups come from
`policy/crypto-policy.yaml`, rendered into `agency/generated/portal/tls.conf`
and mounted read-only; nginx includes it by exact name and will not start
without it. After the estate is built, a policy change goes through
`pqch change propose`, `pqch change approve`, and the runner's apply — never
another render.

After the estate is rebuilt, regenerate the scope and restart the runner; the
runner holds the scope it started with and will not pick up a new one:

```sh
uv run pqch scope generate agency/compose.yaml --out var/scope/scope.json
docker compose restart runner
```

Check the estate has no way out, and that the host holds no address on its
bridge:

```sh
agency/probe-egress.sh
```
