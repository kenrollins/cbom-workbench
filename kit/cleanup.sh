#!/bin/bash
# Leave a box as it was before the kit: everything the kit put there, and, when asked, the operator's
# own credentials and history. Prints what it would do and does nothing unless --yes is given.
#
#   kit/cleanup.sh                          # dry run: list it all
#   kit/cleanup.sh --yes                    # the kit's containers, volumes (the signer's key), networks, images
#   kit/cleanup.sh --yes --images           # also the engines' images (NIM, vLLM, ollama), from kit/engines.env
#   kit/cleanup.sh --yes --caches           # also model weights and build caches (public, but large)
#   kit/cleanup.sh --yes --personal         # also NGC, Hugging Face, GitHub and Claude Code credentials,
#                                           # Claude Code's session transcripts, and shell history
#   kit/cleanup.sh --yes --tree             # last: this repository checkout itself (source, ledgers, bundle)
#
# It touches only what carries the kit's names (pqch*, pqch-engine-*, the bundle's registry) and the
# files listed below. An image another container still uses is left, with a note. Run it as the
# operator who installed the kit, from inside the checkout.
set -u
HERE=$(cd "$(dirname "$0")" && pwd); TREE=$(cd "$HERE/.." && pwd)
YES=0 IMAGES=0 CACHES=0 PERSONAL=0 RMTREE=0
for a in "$@"; do case $a in
  --yes) YES=1;; --images) IMAGES=1;; --caches) CACHES=1;; --personal) PERSONAL=1;; --tree) RMTREE=1;;
  -h|--help) sed -n 2,16p "$0"; exit 0;; *) echo "unknown option $a" >&2; exit 2;; esac; done
[ -r "$HERE/engines.env" ] && . "$HERE/engines.env"
HF_CACHE=${HF_CACHE:-$HOME/.cache/huggingface}; VLLM_CACHE=${VLLM_CACHE:-$HOME/.cache/pqch-vllm}

run() { if [ $YES = 1 ]; then echo "+ $*"; "$@" || echo "  (did not complete: $?)"; else echo "would: $*"; fi; }
gone() { if [ -e "$1" ] || [ -L "$1" ]; then run rm -rf -- "$1"; fi; }
# A cache path from kit/engines.env is removed only under the operator's home: one that points
# elsewhere (a shared weight store) belongs to something else on the box.
cache() {
  case "$(realpath -m "$1")/" in
    "$(realpath -m "$HOME")"/*) gone "$1";;
    *) [ -e "$1" ] && echo "keep: $1 (outside $HOME; remove it by hand if it is the kit's)";;
  esac
}
hdr() { echo; echo "== $*"; }

hdr "the kit's containers and compose projects"
for proj in pqch pqch-agency; do
  if [ -n "$(docker ps -aq --filter label=com.docker.compose.project=$proj)" ]; then
    run docker compose -p $proj down --volumes --remove-orphans
  fi
done
for c in $(docker ps -a --format '{{.Names}}' | grep -E '^(pqch-|pqch_)' ); do run docker rm -f "$c"; done

hdr "the kit's volumes (the signer's ML-DSA key is one) and networks"
for v in $(docker volume ls -q | grep -E '^pqch'); do run docker volume rm "$v"; done
for n in $(docker network ls --format '{{.Name}}' | grep -E '^pqch'); do run docker network rm "$n"; done

hdr "the kit's images (they contain the workbench's source)"
for i in $(docker images --format '{{.Repository}}:{{.Tag}}' | grep -v ':<none>$' | grep -E '^(pqch/|pqch-agency/|127\.0\.0\.1:15000/)' | sort -u); do
  run docker image rm "$i"
done
for i in $(docker images --digests --format '{{.Repository}}@{{.Digest}}' | grep -E '^(pqch/|pqch-agency/|127\.0\.0\.1:15000/)' | sort -u); do
  run docker image rm "$i"
done
for i in "ghcr.io/distribution/distribution:3.0.0" "quay.io/skopeo/stable:v1.20"; do
  docker image inspect "$i" >/dev/null 2>&1 && run docker image rm "$i"
done
# The scanners the runner fetched (pinned by digest in src/pqch/runner/profiles.yaml).
for i in $(grep -hoE 'image: [^ ]+@sha256:[0-9a-f]+' "$TREE/src/pqch/runner/profiles.yaml" 2>/dev/null | cut -d' ' -f2 | sort -u); do
  docker image inspect "$i" >/dev/null 2>&1 && run docker image rm "$i"
done
if [ $YES = 1 ] && command -v docker >/dev/null; then echo "+ docker builder prune -af"; docker builder prune -af >/dev/null 2>&1 || true; else echo "would: docker builder prune -af"; fi

if [ $IMAGES = 1 ]; then
  hdr "the engines' images"
  for i in $(printf '%s\n' "${FAST_IMAGE:-}" "${DELIBERATE_IMAGE:-}" "${EMBED_IMAGE:-}" \
           nvcr.io/nim/nvidia/nvidia-nemotron-nano-9b-v2-dgx-spark:latest nvcr.io/nim/meta/llama-3.1-8b-instruct-dgx-spark:latest \
           nvcr.io/nim/nvidia/llama-3.2-nv-embedqa-1b-v2:latest nvcr.io/nim/nvidia/llm-nim:latest | awk 'NF && !seen[$0]++'); do
    [ -n "$i" ] || continue
    docker image inspect "$i" >/dev/null 2>&1 || continue
    users=$(docker ps -a --filter ancestor="$i" --format '{{.Names}}' | grep -vE '^pqch' | tr '\n' ' ')
    if [ -n "$users" ]; then echo "keep: $i (used by $users)"; else run docker image rm "$i"; fi
  done
fi

if [ $CACHES = 1 ]; then
  hdr "model weights and caches"
  gone "$HOME/.cache/nim"; cache "$HF_CACHE"; cache "$VLLM_CACHE"; gone "$HOME/.cache/uv"
fi

if [ $PERSONAL = 1 ]; then
  hdr "credentials, session transcripts and history"
  gone "$HOME/.config/nim/ngc.env"
  grep -q nvcr.io "$HOME/.docker/config.json" 2>/dev/null && run docker logout nvcr.io
  cache "$HF_CACHE/token"; gone "$HOME/.cache/huggingface/token"; gone "$HOME/.huggingface/token"
  command -v gh >/dev/null && gh auth status >/dev/null 2>&1 && run gh auth logout --hostname github.com
  gone "$HOME/.config/gh"; gone "$HOME/.git-credentials"
  # Claude Code: its sign-in and every session transcript (which hold whatever was read or typed).
  gone "$HOME/.claude"; gone "$HOME/.claude.json"; gone "$HOME/.claude.json.backup"
  gone "$HOME/.bash_history"; gone "$HOME/.python_history"; gone "$HOME/.lesshst"; gone "$HOME/.wget-hsts"
  echo "note: also run 'history -c' in each open shell, and sign out of any browser session on this box"
fi

if [ $RMTREE = 1 ]; then
  hdr "this checkout"
  echo "the repository at $TREE, with its var/ (ledgers, scope, raw scanner output) and bundle/out"
  if [ $YES = 1 ]; then cd / && run rm -rf -- "$TREE"; else echo "would: rm -rf -- $TREE"; fi
fi

echo
[ $YES = 1 ] && echo "done. Check: docker ps -a; docker images; docker volume ls; ls -a \$HOME" \
             || echo "dry run: nothing was changed. Add --yes to act."
