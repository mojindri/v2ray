#!/usr/bin/env bash
# compare.sh — run multiple latency variants and collect results
#
# Usage:
#   compare.sh [scenario]
#
# Scenarios:
#   local-smoke    (default) direct + blackwire-socks-direct + blackwire-vless-loopback
#   local-full     all local variants, longer duration
#
# Environment:
#   BENCH_DURATION  seconds per variant (default 30)
#   BENCH_CONC      concurrency (default 32)
#   REPORT_DIR      output directory (default ./reports)
#   TARGET_URL      HTTP target (default http://127.0.0.1:18080/)
#   DRY_RUN         set to 1 for dry-run
#   BW_BIN          blackwire binary path
set -euo pipefail

SCENARIO="${1:-local-smoke}"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPTS_DIR/.." && pwd)"
CONFIGS_DIR="$LAB_DIR/configs"

BENCH_DURATION="${BENCH_DURATION:-30}"
BENCH_CONC="${BENCH_CONC:-32}"
REPORT_DIR="${REPORT_DIR:-$LAB_DIR/reports}"
TARGET_URL="${TARGET_URL:-http://127.0.0.1:18080/}"
DRY_RUN="${DRY_RUN:-0}"
BW_BIN="${BW_BIN:-blackwire}"

export BENCH_DURATION BENCH_CONC REPORT_DIR DRY_RUN BW_BIN

log() { echo "==> [compare] $*"; }

bench() {
    local variant="$1"; shift
    log "variant: $variant"
    bash "$SCRIPTS_DIR/run-bench.sh" "$variant" "$TARGET_URL" "$@"
}

case "$SCENARIO" in

  local-smoke)
    log "scenario: local-smoke (${BENCH_DURATION}s × ${BENCH_CONC} conc)"

    # 1. Direct — no proxy, pure target baseline
    bench "direct"

    # 2. Blackwire SOCKS5 → Freedom → target
    #    Measures SOCKS5 handshake + Freedom dial overhead
    PROXY_ADDR="127.0.0.1:1080" \
    CLIENT_CONFIG="$CONFIGS_DIR/blackwire-socks-direct.json" \
    CLIENT_PORT="1080" \
    bench "blackwire-socks-direct"

    # 3. Blackwire SOCKS5 → VLESS (no-TLS) → Freedom → target  (loopback)
    #    Measures full VLESS protocol overhead on loopback
    SERVER_CONFIG="$CONFIGS_DIR/blackwire-fast-lab-server.json" \
    SERVER_PORT="10080" \
    CLIENT_CONFIG="$CONFIGS_DIR/blackwire-fast-lab-client.json" \
    CLIENT_PORT="1081" \
    PROXY_ADDR="127.0.0.1:1081" \
    bench "blackwire-fast-lab"
    ;;

  local-full)
    log "scenario: local-full (${BENCH_DURATION}s × ${BENCH_CONC} conc)"
    BENCH_DURATION="${BENCH_DURATION:-60}" \
    BENCH_CONC="${BENCH_CONC:-256}" \
    bash "$0" local-smoke
    ;;

  *)
    echo "Unknown scenario: $SCENARIO"
    echo "Known: local-smoke, local-full"
    exit 1
    ;;
esac

log "all variants complete — run 'make latency-report' to render results"
