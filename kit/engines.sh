#!/bin/sh
# The kit's inference engines, on the same box as the harness: one container per tier, by name, on
# the bridge the UI service joins (kit/compose.kit.yaml). kit/inference.yaml reaches them by these
# names. Usage: kit/engines.sh up|down|status [fast|deliberate|embed ...]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/engines.env"
NET=pqch-kit-inference
cmd="${1:-status}"; [ $# -gt 0 ] && shift; tiers="${*:-fast deliberate embed}"

net_up() {
  docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 172.16.108.0/24 $NET >/dev/null
  # Made here, as the operator: a bind-mount source Docker creates is owned by root.
  mkdir -p "$HF_CACHE" "$VLLM_CACHE" "$HOME/.cache/nim"
}

up_fast() {
  if [ "${FAST_ENGINE:-nim}" = vllm ]; then
    docker run -d --name pqch-engine-fast --network $NET --device nvidia.com/gpu=all --shm-size=16g --restart unless-stopped \
      -v "$HF_CACHE:/root/.cache/huggingface" -v "$VLLM_CACHE:/root/.cache/vllm" -e HF_HOME=/root/.cache/huggingface \
      -p 127.0.0.1:8022:8000 --entrypoint vllm "$DELIBERATE_IMAGE" serve "$FAST_MODEL" \
      --served-model-name fast --host 0.0.0.0 --port 8000 --tensor-parallel-size 1 \
      --gpu-memory-utilization "$FAST_SHARE" --max-model-len "$FAST_WINDOW" --max-cudagraph-capture-size 64 \
      --max-num-seqs 32 --trust-remote-code --reasoning-parser nemotron_v3 >/dev/null
    return
  fi
  docker run -d --name pqch-engine-fast --network $NET --gpus all --shm-size=16g --restart unless-stopped \
    --env-file "$NGC_ENV_FILE" -e NIM_MAX_MODEL_LEN=$FAST_WINDOW -e NIM_MAX_GPU_MEMORY_UTILIZATION_STARTUP=$FAST_SHARE \
    -v "$HOME/.cache/nim:/opt/nim/.cache" -p 127.0.0.1:8022:8000 "$FAST_IMAGE" >/dev/null
}
up_deliberate() {
  # The same shape the lab's orchestrator uses for this model (CDI device, private shm, the HF cache
  # mounted); the model's own flags are its recipe's. Medium-effort thinking is asked per request
  # (kit/inference.yaml, the deliberate tier's reasoning block).
  docker run -d --name pqch-engine-deliberate --network $NET --device nvidia.com/gpu=all --shm-size=16g --restart unless-stopped \
    -v "$HF_CACHE:/root/.cache/huggingface" -v "$VLLM_CACHE:/root/.cache/vllm" -e HF_HOME=/root/.cache/huggingface \
    -p 127.0.0.1:8023:8000 --entrypoint vllm "$DELIBERATE_IMAGE" serve "$DELIBERATE_MODEL" \
    --served-model-name deliberate --host 0.0.0.0 --port 8000 --tensor-parallel-size 1 \
    --gpu-memory-utilization "$DELIBERATE_SHARE" --max-model-len "$DELIBERATE_WINDOW" \
    --max-cudagraph-capture-size 64 --max-num-seqs 32 --trust-remote-code \
    --reasoning-parser nemotron_v3 --mamba-backend flashinfer --mamba-ssm-cache-dtype float16 \
    --enable-mamba-cache-stochastic-rounding --mamba-cache-philox-rounds 5 --max-num-batched-tokens 8192 \
    --kv-cache-memory-bytes 2684354560 --limit-mm-per-prompt '{"image": 2, "video": 0}' >/dev/null
}
up_embed() {
  docker volume create pqch-engine-embed >/dev/null
  docker run -d --name pqch-engine-embed --network $NET --gpus all --restart unless-stopped \
    -v pqch-engine-embed:/root/.ollama -p 127.0.0.1:8024:11434 "$EMBED_IMAGE" >/dev/null
  sleep 3; docker exec pqch-engine-embed ollama pull "$EMBED_MODEL" >/dev/null 2>&1 || echo "pull of $EMBED_MODEL failed (offline? load it into the volume first)"
}

case "$cmd" in
  up) net_up; for t in $tiers; do docker rm -f pqch-engine-$t >/dev/null 2>&1 || true; up_$t; echo "pqch-engine-$t starting"; done ;;
  down) for t in $tiers; do docker rm -f pqch-engine-$t >/dev/null 2>&1 && echo "pqch-engine-$t removed"; done ;;
  status) for t in fast deliberate embed; do
            port=$(docker port pqch-engine-$t 2>/dev/null | head -1 | sed 's/.*://') || true
            if [ -n "$port" ]; then code=$(curl -s -m 3 -o /dev/null -w '%{http_code}' http://127.0.0.1:$port/v1/models || true); echo "$t: up, /v1/models http $code"; else echo "$t: not running"; fi; done ;;
  *) echo "usage: $0 up|down|status [tier ...]" >&2; exit 2 ;;
esac
