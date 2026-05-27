#!/usr/bin/env bash
# run-bench.sh — single-variant latency benchmark driver
#
# Usage:
#   run-bench.sh <variant> <target-url> [options]
#
# Environment (all optional):
#   PROXY_ADDR     SOCKS5 proxy address (host:port) — omit for direct
#   SERVER_CONFIG  Path to blackwire server config to start
#   SERVER_PORT    Port the server config listens on (for readiness poll)
#   CLIENT_CONFIG  Path to blackwire client config to start
#   CLIENT_PORT    SOCKS5 port the client exposes (for readiness poll)
#   BENCH_DURATION Duration in seconds (default 30)
#   BENCH_CONC     Concurrency (default 32)
#   BENCH_DISABLE_KEEPALIVE  Set to 1 to use a fresh conn per request
#   REPORT_DIR     Where to write <variant>.json (default ./reports)
#   DRY_RUN        Set to 1 to print commands without running them
#   BW_BIN         Path to blackwire binary (default: blackwire in PATH)
#   SERVER_CMD     Full command to start server, e.g. "xray run -config"
#                  (default: "$BW_BIN run -c")
#   CLIENT_CMD     Full command to start client (default: "$BW_BIN run -c")
#   CONFIG_ENVSUBST  Set to 1 to run envsubst on config files before use
#                    (for configs with ${SERVER_ADDR}, ${SERVER_PORT}, etc.)
set -euo pipefail

VARIANT="${1:?Usage: run-bench.sh <variant> <target-url>}"
TARGET="${2:?Usage: run-bench.sh <variant> <target-url>}"

BENCH_DURATION="${BENCH_DURATION:-30}"
BENCH_CONC="${BENCH_CONC:-32}"
REPORT_DIR="${REPORT_DIR:-$(dirname "$0")/../reports}"
DRY_RUN="${DRY_RUN:-0}"
BW_BIN="${BW_BIN:-blackwire}"
PROXY_ADDR="${PROXY_ADDR:-}"
SERVER_CONFIG="${SERVER_CONFIG:-}"
SERVER_PORT="${SERVER_PORT:-}"
CLIENT_CONFIG="${CLIENT_CONFIG:-}"
CLIENT_PORT="${CLIENT_PORT:-}"
BENCH_DISABLE_KEEPALIVE="${BENCH_DISABLE_KEEPALIVE:-0}"
CONFIG_ENVSUBST="${CONFIG_ENVSUBST:-0}"

_DEFAULT_CMD="${BW_BIN:-blackwire} run -c"
SERVER_CMD="${SERVER_CMD:-$_DEFAULT_CMD}"
CLIENT_CMD="${CLIENT_CMD:-$_DEFAULT_CMD}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_FILE="$REPORT_DIR/${VARIANT}-${TS}.json"
mkdir -p "$REPORT_DIR"

_run() {
    if [ "$DRY_RUN" = "1" ]; then
        echo "[DRY RUN] $*"
    else
        "$@"
    fi
}

log() { echo "  [run-bench] $*"; }

# ── Config preprocessing (envsubst) ───────────────────────────────────────────

_TMPFILES=()
cleanup_tmpfiles() { rm -f "${_TMPFILES[@]}" 2>/dev/null || true; }
trap cleanup_tmpfiles EXIT

maybe_envsubst() {
    local cfg="$1"
    if [ "$CONFIG_ENVSUBST" != "1" ]; then
        echo "$cfg"
        return
    fi
    command -v envsubst >/dev/null 2>&1 || { echo "ERROR: envsubst not found (install gettext)"; exit 1; }
    local tmp; tmp="$(mktemp /tmp/bw-cfg-XXXXXX.json)"
    _TMPFILES+=("$tmp")
    envsubst < "$cfg" > "$tmp"
    echo "$tmp"
}

# ── Tool check ────────────────────────────────────────────────────────────────

if [ "$DRY_RUN" != "1" ] && ! command -v hey >/dev/null 2>&1; then
    echo "ERROR: 'hey' not found."
    echo "  macOS:  brew install hey"
    echo "  Linux:  go install github.com/rakyll/hey@latest"
    exit 1
fi

# ── Start server process (optional) ──────────────────────────────────────────

SERVER_PID=
if [ -n "$SERVER_CONFIG" ]; then
    _SERVER_CFG="$(maybe_envsubst "$SERVER_CONFIG")"
    log "starting server: $SERVER_CMD $_SERVER_CFG"
    if [ "$DRY_RUN" != "1" ]; then
        $SERVER_CMD "$_SERVER_CFG" >/tmp/bw-server-$VARIANT.log 2>&1 &
        SERVER_PID=$!
        if [ -n "$SERVER_PORT" ]; then
            for i in $(seq 1 20); do
                nc -z 127.0.0.1 "$SERVER_PORT" 2>/dev/null && break
                sleep 0.3
                [ "$i" = "20" ] && { echo "ERROR: server port $SERVER_PORT never opened"; kill $SERVER_PID 2>/dev/null; exit 1; }
            done
        else
            sleep 1
        fi
        log "server up (pid $SERVER_PID)"
    fi
fi

# ── Start client process (optional) ──────────────────────────────────────────

CLIENT_PID=
if [ -n "$CLIENT_CONFIG" ]; then
    _CLIENT_CFG="$(maybe_envsubst "$CLIENT_CONFIG")"
    log "starting client: $CLIENT_CMD $_CLIENT_CFG"
    if [ "$DRY_RUN" != "1" ]; then
        $CLIENT_CMD "$_CLIENT_CFG" >/tmp/bw-client-$VARIANT.log 2>&1 &
        CLIENT_PID=$!
        POLL_PORT="${CLIENT_PORT:-${PROXY_ADDR##*:}}"
        if [ -n "$POLL_PORT" ]; then
            for i in $(seq 1 20); do
                nc -z 127.0.0.1 "$POLL_PORT" 2>/dev/null && break
                sleep 0.3
                [ "$i" = "20" ] && { echo "ERROR: client port $POLL_PORT never opened"; kill $CLIENT_PID $SERVER_PID 2>/dev/null; exit 1; }
            done
        else
            sleep 1
        fi
        log "client up (pid $CLIENT_PID)"
    fi
fi

# ── Build hey command ─────────────────────────────────────────────────────────

HEY_ARGS=(-z "${BENCH_DURATION}s" -c "$BENCH_CONC")
[ "$BENCH_DISABLE_KEEPALIVE" = "1" ] && HEY_ARGS+=(-disable-keepalive)
[ -n "$PROXY_ADDR" ] && HEY_ARGS+=(-x "socks5://$PROXY_ADDR")

log "running: hey ${HEY_ARGS[*]} $TARGET"

cleanup() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    cleanup_tmpfiles
}
trap cleanup EXIT

# ── Run benchmark ─────────────────────────────────────────────────────────────

if [ "$DRY_RUN" = "1" ]; then
    echo "[DRY RUN] hey ${HEY_ARGS[*]} $TARGET"
    cat > "$REPORT_FILE" <<EOF
{
  "variant": "$VARIANT",
  "timestamp": "$TS",
  "dry_run": true,
  "target": "$TARGET",
  "duration_s": $BENCH_DURATION,
  "concurrency": $BENCH_CONC
}
EOF
    echo "DRY RUN: would write $REPORT_FILE"
    exit 0
fi

RAW="$(hey "${HEY_ARGS[@]}" "$TARGET" 2>&1)"
echo "$RAW"

# ── Parse hey output → JSON ───────────────────────────────────────────────────

parse_secs() {
    # Extract "X.XXXX secs" after a label
    echo "$RAW" | grep -E "$1" | grep -oE '[0-9]+\.[0-9]+' | head -1
}

TOTAL_SECS=$(parse_secs "Total:")
RPS=$(echo "$RAW" | grep "Requests/sec:" | grep -oE '[0-9]+\.[0-9]+' | head -1)
P50=$(echo "$RAW" | grep "50% in" | grep -oE '[0-9]+\.[0-9]+' | head -1)
P90=$(echo "$RAW" | grep "90% in" | grep -oE '[0-9]+\.[0-9]+' | head -1)
P95=$(echo "$RAW" | grep "95% in" | grep -oE '[0-9]+\.[0-9]+' | head -1)
P99=$(echo "$RAW" | grep "99% in" | grep -oE '[0-9]+\.[0-9]+' | head -1)
FASTEST=$(parse_secs "Fastest:")
SLOWEST=$(parse_secs "Slowest:")
SUCCESS=$(echo "$RAW" | grep -E '^\s+\[200\]' | grep -oE '[0-9]+' | head -1)
ERRORS=$(echo "$RAW" | grep -E 'Error distribution:' -A 20 | grep -oE '\[([0-9]+)\]' | tr -d '[]' | paste -sd+ | bc 2>/dev/null || echo "0")

cat > "$REPORT_FILE" <<EOF
{
  "variant": "$VARIANT",
  "timestamp": "$TS",
  "target": "$TARGET",
  "duration_s": $BENCH_DURATION,
  "concurrency": $BENCH_CONC,
  "proxy": "${PROXY_ADDR:-null}",
  "requests_per_sec": ${RPS:-0},
  "total_duration_s": ${TOTAL_SECS:-0},
  "p50_s": ${P50:-0},
  "p90_s": ${P90:-0},
  "p95_s": ${P95:-0},
  "p99_s": ${P99:-0},
  "fastest_s": ${FASTEST:-0},
  "slowest_s": ${SLOWEST:-0},
  "successful_responses": ${SUCCESS:-0},
  "errors": ${ERRORS:-0}
}
EOF

log "wrote $REPORT_FILE"
