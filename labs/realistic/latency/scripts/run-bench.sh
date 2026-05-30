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
#   BENCH_WARMUP   Warmup seconds to run before measurement (default 0)
#   BENCH_CONC     Concurrency (default 32)
#   BENCH_PAYLOAD  Payload class label (1k, 4k, 16k, 64k, 1m)
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
BENCH_WARMUP="${BENCH_WARMUP:-0}"
BENCH_CONC="${BENCH_CONC:-32}"
BENCH_PAYLOAD="${BENCH_PAYLOAD:-unknown}"
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

json_file_or_null() {
    if [ -n "${1:-}" ]; then
        printf '"%s"' "$(basename "$1")"
    else
        printf 'null'
    fi
}

# Port readiness: prefer nc when installed (Docker bench image), else bash /dev/tcp.
port_open() {
    local host="$1" port="$2"
    if command -v nc >/dev/null 2>&1; then
        nc -z "$host" "$port" 2>/dev/null
        return $?
    fi
    (echo >/dev/tcp/"$host"/"$port") 2>/dev/null
}

# ── Config preprocessing (envsubst) ───────────────────────────────────────────

_TMPFILES=()
cleanup_tmpfiles() {
    [ "${#_TMPFILES[@]}" -gt 0 ] && rm -f "${_TMPFILES[@]}" 2>/dev/null || true
}
trap cleanup_tmpfiles EXIT

maybe_envsubst() {
    local cfg="$1"
    if [ "$CONFIG_ENVSUBST" != "1" ]; then
        echo "$cfg"
        return
    fi
    command -v envsubst >/dev/null 2>&1 || { echo "ERROR: envsubst not found (install gettext)"; exit 1; }
    local tmp; tmp="$(mktemp "${TMPDIR:-/tmp}/bw-cfg-XXXXXX").json"
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
                port_open 127.0.0.1 "$SERVER_PORT" && break
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
                port_open 127.0.0.1 "$POLL_PORT" && break
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
    if [ "$BENCH_WARMUP" != "0" ]; then
        echo "[DRY RUN] hey -z ${BENCH_WARMUP}s -c $BENCH_CONC ${PROXY_ADDR:+-x socks5://$PROXY_ADDR} $TARGET"
    fi
    echo "[DRY RUN] hey ${HEY_ARGS[*]} $TARGET"
    cat > "$REPORT_FILE" <<EOF
{
  "variant": "$VARIANT",
  "timestamp": "$TS",
  "dry_run": true,
  "target": "$TARGET",
  "payload": "$BENCH_PAYLOAD",
  "duration_s": $BENCH_DURATION,
  "warmup_s": $BENCH_WARMUP,
  "concurrency": $BENCH_CONC,
  "keepalive": $([ "$BENCH_DISABLE_KEEPALIVE" = "1" ] && echo false || echo true)
}
EOF
    echo "DRY RUN: would write $REPORT_FILE"
    exit 0
fi

if [ "$BENCH_WARMUP" != "0" ]; then
    WARMUP_ARGS=(-z "${BENCH_WARMUP}s" -c "$BENCH_CONC")
    [ "$BENCH_DISABLE_KEEPALIVE" = "1" ] && WARMUP_ARGS+=(-disable-keepalive)
    [ -n "$PROXY_ADDR" ] && WARMUP_ARGS+=(-x "socks5://$PROXY_ADDR")
    log "warmup: hey ${WARMUP_ARGS[*]} $TARGET"
    hey "${WARMUP_ARGS[@]}" "$TARGET" >/tmp/bw-warmup-$VARIANT.log 2>&1 || {
        echo "ERROR: warmup failed; see /tmp/bw-warmup-$VARIANT.log"
        cat /tmp/bw-warmup-$VARIANT.log
        exit 1
    }
fi

RAW="$(hey "${HEY_ARGS[@]}" "$TARGET" 2>&1)"
echo "$RAW"
RAW_FILE="$REPORT_DIR/${VARIANT}-${TS}.hey.txt"
printf '%s\n' "$RAW" > "$RAW_FILE"

SERVER_LOG_FILE=""
CLIENT_LOG_FILE=""
if [ -f "/tmp/bw-server-$VARIANT.log" ]; then
    SERVER_LOG_FILE="$REPORT_DIR/${VARIANT}-${TS}.server.log"
    tail -200 "/tmp/bw-server-$VARIANT.log" > "$SERVER_LOG_FILE" || true
fi
if [ -f "/tmp/bw-client-$VARIANT.log" ]; then
    CLIENT_LOG_FILE="$REPORT_DIR/${VARIANT}-${TS}.client.log"
    tail -200 "/tmp/bw-client-$VARIANT.log" > "$CLIENT_LOG_FILE" || true
fi
RAW_FILE_JSON="$(json_file_or_null "$RAW_FILE")"
SERVER_LOG_FILE_JSON="$(json_file_or_null "$SERVER_LOG_FILE")"
CLIENT_LOG_FILE_JSON="$(json_file_or_null "$CLIENT_LOG_FILE")"

# ── Parse hey output → JSON ───────────────────────────────────────────────────

parse_secs() {
    # Extract "X.XXXX secs" after a label; || true prevents set -e on no-match
    echo "$RAW" | grep -E "$1" | grep -oE '[0-9]+\.[0-9]+' | head -1 || true
}

# hey ≥0.1.5 prints "50%%" (double-%) in latency distribution; match both forms
pct_grep() { echo "$RAW" | grep -E "${1}%%? in" | grep -oE '[0-9]+\.[0-9]+' | head -1 || true; }

TOTAL_SECS=$(parse_secs "Total:")
RPS=$(echo "$RAW" | grep "Requests/sec:" | grep -oE '[0-9]+\.[0-9]+' | head -1 || true)
P50=$(pct_grep 50)
P90=$(pct_grep 90)
P95=$(pct_grep 95)
P99=$(pct_grep 99)
FASTEST=$(parse_secs "Fastest:")
SLOWEST=$(parse_secs "Slowest:")
SUCCESS=$(echo "$RAW" | awk '
    /Status code distribution:/ { in_status = 1; next }
    in_status && $1 == "[200]" { print $2; found = 1; exit }
    in_status && NF == 0 { in_status = 0 }
    END { if (!found) print 0 }
')
STATUS_TOTAL=$(echo "$RAW" | awk '
    /Status code distribution:/ { in_status = 1; next }
    in_status && $1 ~ /^\[[0-9]+\]$/ {
        gsub(/\[|\]/, "", $2)
        total += $2
        found = 1
        next
    }
    in_status && NF == 0 { in_status = 0 }
    END { print total + 0 }
')
NON_200=$(( ${STATUS_TOTAL:-0} - ${SUCCESS:-0} ))
ERRORS=$(echo "$RAW" | awk '
    /Error distribution:/ { in_errors = 1; next }
    in_errors && $1 ~ /^\[[0-9]+\]$/ {
        gsub(/\[|\]/, "", $1)
        total += $1
        found = 1
        next
    }
    in_errors && NF == 0 { in_errors = 0 }
    END { print total + 0 }
')
error_count_matching() {
    local pattern="$1"
    echo "$RAW" | awk -v pattern="$pattern" '
        BEGIN { total = 0 }
        /Error distribution:/ { in_errors = 1; next }
        in_errors && $1 ~ /^\[[0-9]+\]$/ {
            count = $1
            gsub(/\[|\]/, "", count)
            line = tolower($0)
            if (line ~ pattern) total += count
            next
        }
        in_errors && NF == 0 { in_errors = 0 }
        END { print total + 0 }
    '
}
TIMEOUT_ERRORS="$(error_count_matching "timeout|deadline exceeded|awaiting headers")"
EOF_ERRORS="$(error_count_matching "eof|unexpected end")"
RESET_ERRORS="$(error_count_matching "reset by peer|connection reset")"
REFUSED_ERRORS="$(error_count_matching "connection refused|connect: refused")"
OTHER_ERRORS=$(( ${ERRORS:-0} - ${TIMEOUT_ERRORS:-0} - ${EOF_ERRORS:-0} - ${RESET_ERRORS:-0} - ${REFUSED_ERRORS:-0} ))
[ "$OTHER_ERRORS" -lt 0 ] && OTHER_ERRORS=0
BENCH_FAILED=$(awk -v errors="${ERRORS:-0}" -v non200="${NON_200:-0}" -v total="${TOTAL_SECS:-0}" -v requested="$BENCH_DURATION" '
    BEGIN {
        failed = 0
        if (errors + 0 > 0) failed = 1
        if (non200 + 0 > 0) failed = 1
        if (total + 0 > requested * 1.25) failed = 1
        print failed ? "true" : "false"
    }
')

cat > "$REPORT_FILE" <<EOF
{
  "variant": "$VARIANT",
  "timestamp": "$TS",
  "target": "$TARGET",
  "payload": "$BENCH_PAYLOAD",
  "duration_s": $BENCH_DURATION,
  "warmup_s": $BENCH_WARMUP,
  "concurrency": $BENCH_CONC,
  "keepalive": $([ "$BENCH_DISABLE_KEEPALIVE" = "1" ] && echo false || echo true),
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
  "non_200_responses": ${NON_200:-0},
  "errors": ${ERRORS:-0},
  "timeout_errors": ${TIMEOUT_ERRORS:-0},
  "eof_errors": ${EOF_ERRORS:-0},
  "reset_errors": ${RESET_ERRORS:-0},
  "connection_refused_errors": ${REFUSED_ERRORS:-0},
  "other_errors": ${OTHER_ERRORS:-0},
  "raw_output_file": $RAW_FILE_JSON,
  "server_log_file": $SERVER_LOG_FILE_JSON,
  "client_log_file": $CLIENT_LOG_FILE_JSON,
  "benchmark_failed": ${BENCH_FAILED:-false}
}
EOF

log "wrote $REPORT_FILE"
