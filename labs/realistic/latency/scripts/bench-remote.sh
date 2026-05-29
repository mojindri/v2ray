#!/usr/bin/env bash
# bench-remote.sh — build Docker bench image locally (linux/amd64), push to VPS, run there
#
# Usage:
#   bench-remote.sh <ssh-host>
#   bench-remote.sh root@1.2.3.4
#
# Environment:
#   SSH_KEY         SSH key file (default: ssh-agent)
#   SSH_PORT        SSH port (default: 22)
#   BENCH_IMAGE     Docker image name (default: blackwire-bench)
#   BENCH_DURATION  Seconds per variant (default: 30)
#   BENCH_CONC      Concurrency (default: 32)
#   REPORT_DIR      Local dir to write pulled results (default: ./reports)
set -euo pipefail

HOST="${1:?Usage: bench-remote.sh <user@host>}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-}"
BENCH_IMAGE="${BENCH_IMAGE:-blackwire-bench}"
BENCH_DURATION="${BENCH_DURATION:-30}"
BENCH_CONC="${BENCH_CONC:-32}"

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPTS_DIR/../../../.." && pwd)"
REPORT_DIR="${REPORT_DIR:-$SCRIPTS_DIR/../reports}"

SSH_OPTS=(-p "$SSH_PORT" -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15)
[ -n "$SSH_KEY" ] && SSH_OPTS+=(-i "$SSH_KEY")

log() { echo "==> [bench-remote] $*"; }

# ── 1. Build image locally for linux/amd64 ────────────────────────────────────

log "building $BENCH_IMAGE for linux/amd64 (this compiles Blackwire — ~5 min first time)"
docker build \
    --platform linux/amd64 \
    -f "$REPO_ROOT/labs/realistic/latency/Dockerfile.bench" \
    -t "$BENCH_IMAGE" \
    "$REPO_ROOT"
log "build done"

# ── 2. Push image to VPS via docker save | docker load ────────────────────────

log "pushing $BENCH_IMAGE to $HOST (streaming via docker save | docker load)"
docker save "$BENCH_IMAGE" | gzip | \
    ssh "${SSH_OPTS[@]}" "$HOST" "gunzip | docker load"
log "image loaded on $HOST"

# ── 3. Run bench on VPS ───────────────────────────────────────────────────────

log "running benchmark on $HOST (${BENCH_DURATION}s × ${BENCH_CONC} conc)"
ssh "${SSH_OPTS[@]}" "$HOST" \
    docker run --rm \
        -e BENCH_DURATION="$BENCH_DURATION" \
        -e BENCH_CONC="$BENCH_CONC" \
        "$BENCH_IMAGE" compare-all

log "done — results printed above"
log "run 'make latency-report' locally if you pull the JSON files"
