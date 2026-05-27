#!/usr/bin/env bash
# compare.sh — run multiple latency variants and collect results
#
# Usage:
#   compare.sh [scenario]
#
# Scenarios:
#   local-smoke       (default) direct + blackwire-socks-direct + blackwire-vless-loopback
#   local-full        all local variants, longer duration
#   xray-compare      Xray client vs Xray server, BW Compat, BW Fast (requires xray in PATH)
#   singbox-compare   sing-box client vs sing-box server, BW Compat, BW Fast (requires sing-box in PATH)
#   compare-all       local-smoke + xray-compare + singbox-compare
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

XRAY_BIN="${XRAY_BIN:-xray}"
SINGBOX_BIN="${SINGBOX_BIN:-sing-box}"

export BENCH_DURATION BENCH_CONC REPORT_DIR DRY_RUN BW_BIN XRAY_BIN SINGBOX_BIN

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

  xray-compare)
    log "scenario: xray-compare (${BENCH_DURATION}s × ${BENCH_CONC} conc)"
    command -v "$XRAY_BIN" >/dev/null 2>&1 || { echo "ERROR: '$XRAY_BIN' not found. Set XRAY_BIN or install xray."; exit 1; }
    XRAY_CMD="$XRAY_BIN run -config"

    # 1. Xray client → Xray server (same-tool TCP baseline)
    CONFIG_ENVSUBST=1 \
    SERVER_ADDR=127.0.0.1 SERVER_PORT=10081 \
    SERVER_CMD="$XRAY_CMD" CLIENT_CMD="$XRAY_CMD" \
    SERVER_CONFIG="$CONFIGS_DIR/xray-server-tcp.json" SERVER_PORT=10081 \
    CLIENT_CONFIG="$CONFIGS_DIR/xray-client-tcp.json" CLIENT_PORT=1082 \
    PROXY_ADDR="127.0.0.1:1082" \
    bench "xray-xray-tcp"

    # 2. Xray client → Blackwire Compat server (fairness: same client, different server)
    CONFIG_ENVSUBST=1 \
    SERVER_ADDR=127.0.0.1 SERVER_PORT=10083 \
    CLIENT_CMD="$XRAY_CMD" \
    SERVER_CONFIG="$CONFIGS_DIR/blackwire-compat-server-tcp.json" SERVER_PORT=10083 \
    CLIENT_CONFIG="$CONFIGS_DIR/xray-client-tcp.json" CLIENT_PORT=1082 \
    PROXY_ADDR="127.0.0.1:1082" \
    bench "xray-bw-compat-tcp"

    # 3. Xray client → Blackwire Fast server
    CONFIG_ENVSUBST=1 \
    SERVER_ADDR=127.0.0.1 SERVER_PORT=10080 \
    CLIENT_CMD="$XRAY_CMD" \
    SERVER_CONFIG="$CONFIGS_DIR/blackwire-fast-lab-server.json" SERVER_PORT=10080 \
    CLIENT_CONFIG="$CONFIGS_DIR/xray-client-tcp.json" CLIENT_PORT=1082 \
    PROXY_ADDR="127.0.0.1:1082" \
    bench "xray-bw-fast-tcp"
    ;;

  singbox-compare)
    log "scenario: singbox-compare (${BENCH_DURATION}s × ${BENCH_CONC} conc)"
    command -v "$SINGBOX_BIN" >/dev/null 2>&1 || { echo "ERROR: '$SINGBOX_BIN' not found. Set SINGBOX_BIN or install sing-box."; exit 1; }
    SB_CMD="$SINGBOX_BIN run -c"

    # 1. sing-box client → sing-box server (same-tool TCP baseline)
    CONFIG_ENVSUBST=1 \
    SERVER_ADDR=127.0.0.1 SERVER_PORT=10082 \
    SERVER_CMD="$SB_CMD" CLIENT_CMD="$SB_CMD" \
    SERVER_CONFIG="$CONFIGS_DIR/singbox-server-tcp.json" SERVER_PORT=10082 \
    CLIENT_CONFIG="$CONFIGS_DIR/singbox-client-tcp.json" CLIENT_PORT=1083 \
    PROXY_ADDR="127.0.0.1:1083" \
    bench "singbox-singbox-tcp"

    # 2. sing-box client → Blackwire Compat server
    CONFIG_ENVSUBST=1 \
    SERVER_ADDR=127.0.0.1 SERVER_PORT=10083 \
    CLIENT_CMD="$SB_CMD" \
    SERVER_CONFIG="$CONFIGS_DIR/blackwire-compat-server-tcp.json" SERVER_PORT=10083 \
    CLIENT_CONFIG="$CONFIGS_DIR/singbox-client-tcp.json" CLIENT_PORT=1083 \
    PROXY_ADDR="127.0.0.1:1083" \
    bench "singbox-bw-compat-tcp"

    # 3. sing-box client → Blackwire Fast server
    CONFIG_ENVSUBST=1 \
    SERVER_ADDR=127.0.0.1 SERVER_PORT=10080 \
    CLIENT_CMD="$SB_CMD" \
    SERVER_CONFIG="$CONFIGS_DIR/blackwire-fast-lab-server.json" SERVER_PORT=10080 \
    CLIENT_CONFIG="$CONFIGS_DIR/singbox-client-tcp.json" CLIENT_PORT=1083 \
    PROXY_ADDR="127.0.0.1:1083" \
    bench "singbox-bw-fast-tcp"
    ;;

  compare-all)
    log "scenario: compare-all"
    bash "$0" local-smoke
    bash "$0" xray-compare
    bash "$0" singbox-compare
    ;;

  *)
    echo "Unknown scenario: $SCENARIO"
    echo "Known: local-smoke, local-full, xray-compare, singbox-compare, compare-all"
    exit 1
    ;;
esac

log "all variants complete — run 'make latency-report' to render results"
