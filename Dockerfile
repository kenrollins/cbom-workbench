# The harness image: the UI service and the runner run from it, with different
# commands. Multi-arch bases, pinned by index digest.
FROM ghcr.io/astral-sh/uv:0.9.26@sha256:9a23023be68b2ed09750ae636228e903a54a05ea56ed03a934d00fe9fbeded4b AS uv
# The Docker CLI and Compose plugin, for the runner's apply job only.
FROM docker:29-cli@sha256:b1805116a6a86cc591b5d5f60a910a0715cdcc9d18d866ad68b1457ead25c35c AS dockercli

FROM python:3.12-slim@sha256:dddfd7e07f9d15aeeca61529320492139d21cac7f0070c00609243e51e4e0016
COPY --from=uv /uv /usr/local/bin/uv
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose
# The SSH client for the verifier's key-exchange probes (Debian 13: OpenSSH 10, which offers
# mlkem768x25519-sha256). The verifier's TLS probes use the base image's OpenSSL.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
 && rm -rf /var/lib/apt/lists/*
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev
# The runner's socket directory; the shared volume takes this mode when created.
RUN mkdir -p /run/pqch /run/pqch-signer /var/pqch-signer /var/pqch-runner \
 && chmod 1777 /run/pqch /run/pqch-signer /var/pqch-signer /var/pqch-runner
ENV PATH=/app/.venv/bin:$PATH PYTHONUNBUFFERED=1
