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
TARGET_PORT="${TARGET_PORT:-18080}"
LOAD_REQUESTS="${LOAD_REQUESTS:-250}"
LOAD_CONCURRENCY="${LOAD_CONCURRENCY:-50}"
LOAD_TIMEOUT="${LOAD_TIMEOUT:-10}"
LOAD_MIN_SUCCESS_RATE="${LOAD_MIN_SUCCESS_RATE:-0.99}"

CONFIG="$REPORT_DIR/load-socks-direct.json"

cat > "$CONFIG" <<JSON
{
  "log": { "level": "info" },
  "limits": {
    "maxConnections": 2000,
    "maxConnectionsPerInbound": 1000,
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
        "maxConnections": 1000,
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

echo "==> building blackwire"
cargo build --release --bin blackwire

echo "==> starting local target HTTP server on 127.0.0.1:$TARGET_PORT"
python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1 > "$REPORT_DIR/load-target-http.log" 2>&1 &
HTTP_PID=$!

echo "==> starting blackwire on 127.0.0.1:$PROXY_PORT"
RUST_LOG="${RUST_LOG:-info}" target/release/blackwire run -c "$CONFIG" > "$REPORT_DIR/load-proxy.log" 2>&1 &
PROXY_PID=$!

cleanup() {
  kill "$PROXY_PID" "$HTTP_PID" >/dev/null 2>&1 || true
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
  cat "$REPORT_DIR/load-proxy.log" || true
  exit 1
fi

echo "==> running managed load"
python3 "$SCRIPT_DIR/local_curl_load.py" \
  --proxy "socks5h://127.0.0.1:$PROXY_PORT" \
  --url "http://127.0.0.1:$TARGET_PORT/" \
  --requests "$LOAD_REQUESTS" \
  --concurrency "$LOAD_CONCURRENCY" \
  --timeout "$LOAD_TIMEOUT" \
  --min-success-rate "$LOAD_MIN_SUCCESS_RATE" \
  | tee "$REPORT_DIR/local-load.json"

echo "managed local load complete"
