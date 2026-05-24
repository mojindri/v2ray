#!/usr/bin/env bash
# VPS matrix test runner. Run from the CLIENT VPS after client-setup.sh.
# Usage: bash run-matrix.sh /path/to/matrix.env
#
# For each protocol it:
#   1. Starts blackwire with the generated client config.
#   2. Waits for the SOCKS5 port to be ready.
#   3. Sends HTTP traffic through the proxy to a target on the server.
#   4. Records pass/fail.
#   5. Kills blackwire.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${1:-$LAB_DIR/configs/matrix.env}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: $ENV_FILE not found."
    exit 1
fi
# shellcheck source=/dev/null
source "$ENV_FILE"

PROXY_BIN="${PROXY_BIN:-/usr/local/bin/blackwire}"
SOCKS_PORT=1080
# target-http on the server VPS listens on 18080.
TARGET_URL="http://${SERVER_HOST}:18080"
REPORT_DIR="$LAB_DIR/reports"
REPORT_FILE="$REPORT_DIR/vps-matrix-$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "$REPORT_DIR"

PASS=0
FAIL=0
PROXY_PID=""

cleanup() {
    if [[ -n "$PROXY_PID" ]] && kill -0 "$PROXY_PID" 2>/dev/null; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    PROXY_PID=""
}
trap cleanup EXIT

wait_for_port() {
    local port="$1" timeout="${2:-10}" i
    for i in $(seq 1 "$timeout"); do
        if nc -z 127.0.0.1 "$port" 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    return 1
}

run_test() {
    local name="$1" cfg="$2"

    if [[ ! -f "$cfg" ]]; then
        echo "SKIP $name — config not found: $cfg"
        return
    fi

    cleanup

    "$PROXY_BIN" run -c "$cfg" >/tmp/blackwire-"$name".log 2>&1 &
    PROXY_PID=$!

    if ! wait_for_port "$SOCKS_PORT" 10; then
        echo "FAIL $name — proxy did not start (SOCKS port $SOCKS_PORT not up)"
        FAIL=$((FAIL+1))
        echo "FAIL $name" >> "$REPORT_FILE"
        cat /tmp/blackwire-"$name".log >> "$REPORT_FILE"
        cleanup
        return
    fi

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 10 \
        --socks5 "127.0.0.1:$SOCKS_PORT" \
        "$TARGET_URL" 2>/dev/null || echo "000")

    if [[ "$http_code" == "200" ]]; then
        echo "PASS $name"
        PASS=$((PASS+1))
        echo "PASS $name" >> "$REPORT_FILE"
    else
        echo "FAIL $name — HTTP $http_code"
        FAIL=$((FAIL+1))
        echo "FAIL $name (HTTP $http_code)" >> "$REPORT_FILE"
        cat /tmp/blackwire-"$name".log >> "$REPORT_FILE"
    fi

    cleanup
}

CFG=/etc/blackwire/generated

echo "==> VPS matrix run — $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$REPORT_FILE"
echo "    Server: $SERVER_HOST   Target: $TARGET_URL" | tee -a "$REPORT_FILE"
echo "" | tee -a "$REPORT_FILE"

run_test "vless-tcp"      "$CFG/client-vless-tcp.json"
run_test "vless-reality"  "$CFG/client-vless-reality.json"
run_test "vless-ws"       "$CFG/client-vless-ws.json"
run_test "vmess-grpc"     "$CFG/client-vmess-grpc.json"
run_test "trojan-tls"     "$CFG/client-trojan-tls.json"
run_test "ss2022"         "$CFG/client-ss2022.json"
run_test "hysteria2"      "$CFG/client-hysteria2.json"

echo "" | tee -a "$REPORT_FILE"
echo "==> Results: $PASS passed, $FAIL failed" | tee -a "$REPORT_FILE"
echo "    Report: $REPORT_FILE"

[[ $FAIL -eq 0 ]]
