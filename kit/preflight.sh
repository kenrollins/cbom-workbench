#!/bin/sh
# What the kit needs from a box, checked before anything is loaded. Prints one line per check; exits
# non-zero if a hard requirement is missing. Run as the operator, not root.
set -u
ok=0; bad=0
say() { printf '%-34s %s\n' "$1" "$2"; }
need() { if [ "$2" = yes ]; then ok=$((ok+1)); say "$1" "ok  $3"; else bad=$((bad+1)); say "$1" "MISSING  $3"; fi; }
arch=$(uname -m); os=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")
say "machine" "$arch, $os, kernel $(uname -r)"
case $arch in x86_64|aarch64) need "architecture" yes "$arch (the bundle holds amd64 and arm64)";; *) need "architecture" no "$arch: the bundle holds amd64 and arm64 only";; esac
if command -v docker >/dev/null && docker info >/dev/null 2>&1; then need "docker, usable by this user" yes "$(docker --version | cut -d, -f1)"; else need "docker, usable by this user" no "install Docker Engine; add the operator to the docker group"; fi
docker compose version >/dev/null 2>&1 && need "compose plugin" yes "$(docker compose version --short)" || need "compose plugin" no "docker compose v2 plugin"
if docker info 2>/dev/null | grep -qE 'nvidia.com/gpu'; then need "GPU via CDI" yes "$(docker info 2>/dev/null | grep -oE 'cdi: nvidia.com/gpu=all' | head -1)"; elif command -v nvidia-ctk >/dev/null; then need "GPU via CDI" no "nvidia-ctk present; generate the CDI spec: sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml"; else need "GPU via CDI" no "NVIDIA Container Toolkit"; fi
command -v nvidia-smi >/dev/null && say "gpu" "$(nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader 2>/dev/null)" || say "gpu" "nvidia-smi not found"
for v in python3 uv git curl rsync; do command -v $v >/dev/null && say "$v" "$(command -v $v)" || say "$v" "not found$( [ $v = uv ] && echo ' (curl -LsSf https://astral.sh/uv/install.sh | sh)')"; done
py=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null || echo none); case $py in 3.12|3.13) need "python 3.12+" yes "$py";; *) need "python 3.12+" no "$py (uv can fetch one if the network allows)";; esac
mem=$(free -g | awk '/^Mem:/{print $2" GB total, "$7" GB available"}'); say "memory" "$mem"
say "disk, home" "$(df -h "$HOME" | awk 'NR==2{print $4" free of "$2}')"
for p in 8080 15000 8022 8023 8024; do ss -ltn 2>/dev/null | grep -qE ":$p " && say "port $p" "IN USE" || say "port $p" "free"; done
[ -r "$HOME/.config/nim/ngc.env" ] && need "NGC key file (600)" yes "$HOME/.config/nim/ngc.env" || need "NGC key file (600)" no "$HOME/.config/nim/ngc.env with NGC_API_KEY=... (only if a NIM is to be fetched)"
curl -s -m 5 -o /dev/null -w '%{http_code}' https://nvcr.io/v2/ 2>/dev/null | grep -qE '^(200|401)$' && say "nvcr.io reachable" "yes" || say "nvcr.io reachable" "no (fine once the images are on the box)"
sudo -n true 2>/dev/null && say "sudo without password" "yes" || say "sudo without password" "no (nothing in the kit needs root)"
echo; echo "$ok required checks passed, $bad missing"; [ $bad -eq 0 ]
