#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
REPORT_DIR_ARG="${1:-labs/realistic/reports/production}"
case "$REPORT_DIR_ARG" in
  /*) REPORT_DIR="$REPORT_DIR_ARG" ;;
  *) REPORT_DIR="$PROJECT_ROOT/$REPORT_DIR_ARG" ;;
esac
mkdir -p "$REPORT_DIR"

cd "$PROJECT_ROOT"

PROXY_PORT="${PROXY_PORT:-1080}"
SLOW_CLIENTS="${SLOW_CLIENTS:-25}"
SLOW_INTERVAL="${SLOW_INTERVAL:-1.0}"
SLOW_DURATION="${SLOW_DURATION:-15}"
SLOW_EXPECT_CLOSE="${SLOW_EXPECT_CLOSE:-0}"

CONFIG="$REPORT_DIR/slowloris-socks-direct.json"

cat > "$CONFIG" <<JSON
{
  "log": { "level": "info" },
  "limits": {
    "maxConnections": 200,
    "maxConnectionsPerInbound": 100,
    "maxHandshakeSeconds": 10,
    "maxIdleSeconds": 300
  },
  "inbounds": [
    {
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": $PROXY_PORT,
      "limits": {
        "maxConnections": 100,
        "maxHandshakeSeconds": 10,
        "maxIdleSeconds": 300
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ]
}
JSON

cargo build --release --bin blackwire

RUST_LOG="${RUST_LOG:-info}" target/release/blackwire run -c "$CONFIG" > "$REPORT_DIR/slowloris-proxy.log" 2>&1 &
PROXY_PID=$!

cleanup() {
  kill "$PROXY_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 100); do
  if nc -z 127.0.0.1 "$PROXY_PORT" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

if ! nc -z 127.0.0.1 "$PROXY_PORT" >/dev/null 2>&1; then
  echo "proxy did not open 127.0.0.1:$PROXY_PORT"
  cat "$REPORT_DIR/slowloris-proxy.log" || true
  exit 1
fi

EXTRA=""
if [ "$SLOW_EXPECT_CLOSE" = "1" ]; then
  EXTRA="--expect-close"
fi

python3 "$SCRIPT_DIR/slowloris_probe.py" \
  --host 127.0.0.1 \
  --port "$PROXY_PORT" \
  --clients "$SLOW_CLIENTS" \
  --interval "$SLOW_INTERVAL" \
  --duration "$SLOW_DURATION" \
  $EXTRA \
  | tee "$REPORT_DIR/slowloris.json"

echo "slowloris diagnostic complete"
