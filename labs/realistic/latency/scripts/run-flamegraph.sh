#!/usr/bin/env bash
# run-flamegraph.sh — profile blackwire under hey load using perf + FlameGraph
#
# Linux only. Requires:
#   - perf (linux-perf / linux-tools)
#   - FlameGraph scripts (stackcollapse-perf.pl + flamegraph.pl) in PATH or FLAMEGRAPH_DIR
#   - hey
#   - blackwire binary (BW_BIN)
#
# Usage:
#   run-flamegraph.sh <variant> <target-url>
#
# Environment (all optional):
#   BW_BIN            blackwire binary (default: blackwire)
#   SERVER_CONFIG     blackwire server config to start under perf
#   CLIENT_CONFIG     blackwire client config to start normally
#   CLIENT_PORT       SOCKS5 port the client exposes
#   PROXY_ADDR        SOCKS5 proxy for hey
#   BENCH_DURATION    hey duration in seconds (default: 30)
#   BENCH_CONC        hey concurrency (default: 32)
#   REPORT_DIR        output dir for flamegraph SVG (default: ./reports)
#   FLAMEGRAPH_DIR    dir containing stackcollapse-perf.pl and flamegraph.pl
#   PERF_FREQ         sampling frequency (default: 99)
set -euo pipefail

VARIANT="${1:?Usage: run-flamegraph.sh <variant> <target-url>}"
TARGET="${2:?Usage: run-flamegraph.sh <variant> <target-url>}"

BW_BIN="${BW_BIN:-blackwire}"
SERVER_CONFIG="${SERVER_CONFIG:-}"
CLIENT_CONFIG="${CLIENT_CONFIG:-}"
CLIENT_PORT="${CLIENT_PORT:-}"
PROXY_ADDR="${PROXY_ADDR:-}"
BENCH_DURATION="${BENCH_DURATION:-30}"
BENCH_CONC="${BENCH_CONC:-32}"
REPORT_DIR="${REPORT_DIR:-$(dirname "$0")/../reports}"
FLAMEGRAPH_DIR="${FLAMEGRAPH_DIR:-}"
PERF_FREQ="${PERF_FREQ:-99}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SVG_OUT="$REPORT_DIR/flamegraph-${VARIANT}-${TS}.svg"
PERF_DATA="$(mktemp /tmp/perf-bw-XXXXXX.data)"

log() { echo "  [flamegraph] $*"; }

# ── Prerequisites ─────────────────────────────────────────────────────────────

uname -s | grep -q Linux || { echo "ERROR: run-flamegraph.sh is Linux-only"; exit 1; }
command -v perf  >/dev/null 2>&1 || { echo "ERROR: 'perf' not found — install linux-perf or linux-tools"; exit 1; }
command -v hey   >/dev/null 2>&1 || { echo "ERROR: 'hey' not found"; exit 1; }
command -v perl  >/dev/null 2>&1 || { echo "ERROR: 'perl' not found"; exit 1; }

find_script() {
    local name="$1"
    if [ -n "$FLAMEGRAPH_DIR" ] && [ -x "$FLAMEGRAPH_DIR/$name" ]; then
        echo "$FLAMEGRAPH_DIR/$name"; return
    fi
    if command -v "$name" >/dev/null 2>&1; then
        command -v "$name"; return
    fi
    # Common install locations
    for d in /usr/share/flamegraph /opt/flamegraph "$HOME/FlameGraph" "$HOME/.local/share/FlameGraph"; do
        [ -x "$d/$name" ] && { echo "$d/$name"; return; }
    done
    echo "ERROR: '$name' not found. Clone https://github.com/brendangregg/FlameGraph and set FLAMEGRAPH_DIR" >&2
    exit 1
}

STACKCOLLAPSE="$(find_script stackcollapse-perf.pl)"
FLAMEGRAPH_PL="$(find_script flamegraph.pl)"

mkdir -p "$REPORT_DIR"

# ── Start optional client process ─────────────────────────────────────────────

CLIENT_PID=
if [ -n "$CLIENT_CONFIG" ]; then
    log "starting client: $BW_BIN run -c $CLIENT_CONFIG"
    $BW_BIN run -c "$CLIENT_CONFIG" >/tmp/bw-fg-client.log 2>&1 &
    CLIENT_PID=$!
    POLL_PORT="${CLIENT_PORT:-${PROXY_ADDR##*:}}"
    if [ -n "$POLL_PORT" ]; then
        for i in $(seq 1 20); do
            nc -z 127.0.0.1 "$POLL_PORT" 2>/dev/null && break
            sleep 0.3
            [ "$i" = "20" ] && { echo "ERROR: client port $POLL_PORT never opened"; kill $CLIENT_PID 2>/dev/null; exit 1; }
        done
    else
        sleep 1
    fi
    log "client up (pid $CLIENT_PID)"
fi

# ── Start server under perf record ────────────────────────────────────────────

SERVER_PID=
if [ -n "$SERVER_CONFIG" ]; then
    log "starting server under perf: $BW_BIN run -c $SERVER_CONFIG"
    perf record -g -F "$PERF_FREQ" -o "$PERF_DATA" -- \
        $BW_BIN run -c "$SERVER_CONFIG" >/tmp/bw-fg-server.log 2>&1 &
    SERVER_PID=$!
    sleep 1
    log "server up under perf (pid $SERVER_PID)"
else
    log "WARNING: no SERVER_CONFIG — profiling the client or running hey without a server"
fi

cleanup() {
    [ -n "$CLIENT_PID" ] && kill "$CLIENT_PID" 2>/dev/null || true
    [ -n "$SERVER_PID" ] && kill "$SERVER_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# ── Run load ──────────────────────────────────────────────────────────────────

HEY_ARGS=(-z "${BENCH_DURATION}s" -c "$BENCH_CONC")
[ -n "$PROXY_ADDR" ] && HEY_ARGS+=(-x "socks5://$PROXY_ADDR")

log "running: hey ${HEY_ARGS[*]} $TARGET"
hey "${HEY_ARGS[@]}" "$TARGET"

# Stop server so perf data is flushed
if [ -n "$SERVER_PID" ]; then
    log "stopping server (pid $SERVER_PID)"
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=
fi

# ── Generate flamegraph ────────────────────────────────────────────────────────

log "generating flamegraph → $SVG_OUT"
perf script -i "$PERF_DATA" \
    | perl "$STACKCOLLAPSE" \
    | perl "$FLAMEGRAPH_PL" --title "blackwire ${VARIANT} (${BENCH_DURATION}s @ ${BENCH_CONC}c)" \
    > "$SVG_OUT"
rm -f "$PERF_DATA"

log "wrote $SVG_OUT"
echo "Open in browser: file://$SVG_OUT"
