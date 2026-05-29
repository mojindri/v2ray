#!/usr/bin/env bash
# bench-entrypoint.sh — Docker entrypoint for latency benchmark
#
# Starts a minimal upstream HTTP server on 127.0.0.1:18080,
# runs the requested comparison scenario, prints the report.
#
# Usage (via docker run):
#   docker run blackwire-bench [scenario]
#   scenario: compare-all (default), local-smoke, xray-compare, singbox-compare
set -euo pipefail

SCENARIO="${1:-compare-all}"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==> [bench] scenario: $SCENARIO"
echo "==> [bench] blackwire: $(blackwire --version 2>&1 | head -1 || echo n/a)"
echo "==> [bench] xray:      $(xray version 2>&1 | head -1 || echo n/a)"
echo "==> [bench] sing-box:  $(sing-box version 2>&1 | head -1 || echo n/a)"
echo "==> [bench] hey:       $(hey 2>&1 | head -1 || echo ok)"
echo ""

# ── Upstream HTTP server ───────────────────────────────────────────────────────

python3 "$SCRIPTS_DIR/upstream_static.py" --host 127.0.0.1 --port 18080 &

UPSTREAM_PID=$!
trap "kill $UPSTREAM_PID 2>/dev/null || true" EXIT

# Wait for upstream to be ready
for i in $(seq 1 20); do
    curl -sf http://127.0.0.1:18080/ >/dev/null 2>&1 && break
    sleep 0.1
done
echo "==> [bench] upstream HTTP ready on 127.0.0.1:18080"

# ── Run comparison ─────────────────────────────────────────────────────────────

REPORT_DIR="${REPORT_DIR:-/lab/reports}"
mkdir -p "$REPORT_DIR"

BENCH_DURATION="${BENCH_DURATION:-30}"
BENCH_CONC="${BENCH_CONC:-32}"
BENCH_PAYLOAD="${BENCH_PAYLOAD:-1k}"
TARGET_URL="${TARGET_URL:-http://127.0.0.1:18080/{payload}}"

export BW_BIN="${BW_BIN:-blackwire}"
export XRAY_BIN="${XRAY_BIN:-xray}"
export SINGBOX_BIN="${SINGBOX_BIN:-sing-box}"
export REPORT_DIR BENCH_DURATION BENCH_CONC BENCH_PAYLOAD TARGET_URL

bash "$SCRIPTS_DIR/compare.sh" "$SCENARIO"

# ── Render report ──────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════"
echo " Latency Results"
echo "════════════════════════════════════════════"
python3 "$SCRIPTS_DIR/report.py" --dir "$REPORT_DIR" 2>/dev/null || \
    echo "(no report.py output — check $REPORT_DIR for raw JSON)"
