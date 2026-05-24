#!/usr/bin/env bash
# run-demo.sh — Start a local server + client proxy pair and test it with curl.
#
# This simulates a real proxy deployment entirely on localhost:
#
#   curl → SOCKS5:1080 → VLESS client → VLESS server:10443 → internet
#
# How to run:
#   1. Build: cargo build --release
#   2. Run:   bash examples/run-demo.sh
#
# The script starts the server and client in the background, waits for them
# to bind their ports, tests with curl, then cleans up.

set -euo pipefail

BINARY="${1:-./target/debug/blackwire}"

if [[ ! -x "$BINARY" ]]; then
    echo "Binary not found at '$BINARY'. Run 'cargo build' first."
    echo "Usage: bash examples/run-demo.sh [path/to/blackwire]"
    exit 1
fi

SERVER_PID=""
CLIENT_PID=""

cleanup() {
    echo ""
    echo "Stopping proxy processes..."
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    [[ -n "$CLIENT_PID" ]] && kill "$CLIENT_PID" 2>/dev/null || true
}
trap cleanup EXIT

# ── Start the server ──────────────────────────────────────────────────────────
echo "Starting VLESS server on 0.0.0.0:10443 ..."
"$BINARY" run -c examples/server.json &
SERVER_PID=$!

# ── Start the client ──────────────────────────────────────────────────────────
echo "Starting SOCKS5+VLESS client on 127.0.0.1:1080 ..."
"$BINARY" run -c examples/client.json &
CLIENT_PID=$!

# Give both processes time to bind their ports.
sleep 1

# ── Test with curl ────────────────────────────────────────────────────────────
echo ""
echo "Testing: curl --socks5 127.0.0.1:1080 http://example.com"
echo "------------------------------------------------------------"
curl --silent --max-time 10 --socks5 127.0.0.1:1080 http://example.com | head -5
echo ""
echo "------------------------------------------------------------"
echo "Success! Traffic flowed: curl → SOCKS5 → VLESS → Freedom → example.com"
