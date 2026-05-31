#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/reports/perf}"
mkdir -p "$OUT_DIR"

BW_BIN="${BW_BIN:-$ROOT/target/release/blackwire}"
HEY_BIN="${HEY_BIN:-hey}"

SERVER_PORT="${MEM_SERVER_PORT:-21080}"
CLIENT_PORT="${MEM_CLIENT_PORT:-21081}"
METRICS_PORT="${MEM_METRICS_PORT:-29091}"
UPSTREAM_HOST="${MEM_UPSTREAM_HOST:-127.0.0.1}"
UPSTREAM_PORT="${MEM_UPSTREAM_PORT:-18080}"
PAYLOAD="${MEM_PAYLOAD:-64k}"
URL="${MEM_URL:-http://${UPSTREAM_HOST}:${UPSTREAM_PORT}/${PAYLOAD}}"

DURATION="${MEM_DURATION:-15}"
CONCURRENCY="${MEM_CONCURRENCY:-32}"
SAMPLE_INTERVAL_SEC="${MEM_SAMPLE_INTERVAL_SEC:-0.25}"
SAMPLE_COUNT="${MEM_SAMPLE_COUNT:-60}"
START_NGINX="${PERF_START_NGINX:-0}"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
RAW_LOG="$OUT_DIR/memory-profile-nginx-${PAYLOAD}-${TS}.log"
OUT_JSON="$OUT_DIR/memory-profile-nginx-${PAYLOAD}-${TS}.json"
TMP_DIR="$(mktemp -d)"
SERVER_CFG="$TMP_DIR/server.json"
CLIENT_CFG="$TMP_DIR/client.json"
HEY_LOG="$TMP_DIR/hey.log"
SERVER_LOG="$TMP_DIR/server.log"
CLIENT_LOG="$TMP_DIR/client.log"
NGINX_CONF="$TMP_DIR/nginx.conf"
NGINX_DATA="$TMP_DIR/nginx-data"
NGINX_PID="$TMP_DIR/nginx.pid"

SERVER_PID=""
CLIENT_PID=""
SAMPLER_PID=""

cleanup() {
  if [ -n "$SAMPLER_PID" ]; then
    kill "$SAMPLER_PID" 2>/dev/null || true
  fi
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
  if [ -n "$CLIENT_PID" ]; then
    kill "$CLIENT_PID" 2>/dev/null || true
  fi
  if [ -f "$NGINX_PID" ]; then
    nginx -s quit -c "$NGINX_CONF" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

command -v "$HEY_BIN" >/dev/null 2>&1 || { echo "ERROR: hey not found"; exit 1; }
command -v nc >/dev/null 2>&1 || { echo "ERROR: nc not found"; exit 1; }
test -x "$BW_BIN" || { echo "ERROR: blackwire binary not executable at $BW_BIN"; exit 1; }

if [ "$START_NGINX" = "1" ]; then
  command -v nginx >/dev/null 2>&1 || { echo "ERROR: nginx not found"; exit 1; }
  mkdir -p "$NGINX_DATA"
  python3 - "$NGINX_DATA" <<'PY'
import pathlib
import sys
base = pathlib.Path(sys.argv[1])
for name, size in [("1k", 1024), ("4k", 4096), ("16k", 16384), ("64k", 65536)]:
    (base / name).write_bytes(b"a" * size)
PY
  cat >"$NGINX_CONF" <<EOF
worker_processes  1;
pid ${NGINX_PID};
events { worker_connections 1024; }
http {
  access_log off;
  server {
    listen ${UPSTREAM_HOST}:${UPSTREAM_PORT};
    server_name _;
    location /1k { alias ${NGINX_DATA}/1k; add_header Content-Type application/octet-stream; }
    location /4k { alias ${NGINX_DATA}/4k; add_header Content-Type application/octet-stream; }
    location /16k { alias ${NGINX_DATA}/16k; add_header Content-Type application/octet-stream; }
    location /64k { alias ${NGINX_DATA}/64k; add_header Content-Type application/octet-stream; }
  }
}
EOF
  nginx -t -c "$NGINX_CONF" >/dev/null
  nginx -c "$NGINX_CONF"
fi

cat >"$SERVER_CFG" <<EOF
{
  "profile": "fast",
  "fast": { "strictProduction": false, "pool": "disabled", "splice": "adaptive" },
  "log": { "level": "warn" },
  "metricsAddr": "127.0.0.1:${METRICS_PORT}",
  "inbounds": [
    {
      "tag": "vless-in",
      "protocol": "vless",
      "listen": "127.0.0.1",
      "port": ${SERVER_PORT},
      "settings": { "clients": [{ "id": "00000000-0000-4000-8000-000000000001" }] }
    }
  ],
  "outbounds": [
    { "tag": "freedom", "protocol": "freedom", "settings": { "pool": null } }
  ]
}
EOF

cat >"$CLIENT_CFG" <<EOF
{
  "log": { "level": "warn" },
  "inbounds": [
    { "tag": "socks-in", "protocol": "socks", "listen": "127.0.0.1", "port": ${CLIENT_PORT} }
  ],
  "outbounds": [
    {
      "tag": "vless-out",
      "protocol": "vless",
      "settings": {
        "address": "127.0.0.1",
        "port": ${SERVER_PORT},
        "users": [{ "id": "00000000-0000-4000-8000-000000000001", "flow": "" }]
      }
    }
  ]
}
EOF

"$BW_BIN" run -c "$CLIENT_CFG" >"$CLIENT_LOG" 2>&1 &
CLIENT_PID="$!"
"$BW_BIN" run -c "$SERVER_CFG" >"$SERVER_LOG" 2>&1 &
SERVER_PID="$!"

for _ in $(seq 1 100); do
  if nc -z 127.0.0.1 "$CLIENT_PORT" && nc -z 127.0.0.1 "$SERVER_PORT"; then
    break
  fi
  sleep 0.1
done

echo "timestamp=$TS"
echo "server_pid=$SERVER_PID client_pid=$CLIENT_PID"
echo "url=$URL duration_s=$DURATION concurrency=$CONCURRENCY"
echo "sample_interval_s=$SAMPLE_INTERVAL_SEC sample_count=$SAMPLE_COUNT"

{
  echo "timestamp=$TS"
  echo "server_pid=$SERVER_PID client_pid=$CLIENT_PID"
  echo "url=$URL duration_s=$DURATION concurrency=$CONCURRENCY"
} >"$RAW_LOG"

(
  for _ in $(seq 1 "$SAMPLE_COUNT"); do
    ts="$(date +%s.%N)"
    rss="$(awk '/VmRSS/ {print $2}' "/proc/$SERVER_PID/status" 2>/dev/null || echo 0)"
    vms="$(awk '/VmSize/ {print $2}' "/proc/$SERVER_PID/status" 2>/dev/null || echo 0)"
    thr="$(awk '/Threads/ {print $2}' "/proc/$SERVER_PID/status" 2>/dev/null || echo 0)"
    fd="$(ls "/proc/$SERVER_PID/fd" 2>/dev/null | wc -l | tr -d ' ')"
    echo "$ts rss_kb=$rss vmsize_kb=$vms threads=$thr fd=$fd"
    sleep "$SAMPLE_INTERVAL_SEC"
  done
) >>"$RAW_LOG" &
SAMPLER_PID="$!"

"$HEY_BIN" -z "${DURATION}s" -c "$CONCURRENCY" -x "socks5://127.0.0.1:${CLIENT_PORT}" "$URL" >"$HEY_LOG" 2>&1 || true
wait "$SAMPLER_PID" || true
SAMPLER_PID=""

rps="$(awk '/Requests\/sec:/ {print $2}' "$HEY_LOG" | tail -n1)"
p95_s="$(awk '/ 95% in / {print $3}' "$HEY_LOG" | tail -n1)"
p99_s="$(awk '/ 99% in / {print $3}' "$HEY_LOG" | tail -n1)"
ok_200="$(awk '/\[200\]/ {print $2}' "$HEY_LOG" | tail -n1)"
ok_200="${ok_200:-0}"
rps="${rps:-0}"
p95_s="${p95_s:-0}"
p99_s="${p99_s:-0}"

read -r peak_rss peak_vms peak_threads peak_fd <<EOF
$(awk '
  BEGIN { max_rss=0; max_vms=0; max_threads=0; max_fd=0 }
  /rss_kb=/ {
    split($2,a,"="); split($3,b,"="); split($4,c,"="); split($5,d,"=");
    if (a[2] > max_rss) max_rss=a[2];
    if (b[2] > max_vms) max_vms=b[2];
    if (c[2] > max_threads) max_threads=c[2];
    if (d[2] > max_fd) max_fd=d[2];
  }
  END { print max_rss, max_vms, max_threads, max_fd }
' "$RAW_LOG")
EOF

cat >"$OUT_JSON" <<EOF
{
  "timestamp": "$TS",
  "payload": "$PAYLOAD",
  "duration_s": $DURATION,
  "concurrency": $CONCURRENCY,
  "url": "$URL",
  "requests_per_second": $rps,
  "latency_ms": {
    "p95": $(awk -v s="$p95_s" 'BEGIN { printf "%.3f", s * 1000.0 }'),
    "p99": $(awk -v s="$p99_s" 'BEGIN { printf "%.3f", s * 1000.0 }')
  },
  "status_200_count": $ok_200,
  "memory": {
    "peak_rss_kb": ${peak_rss:-0},
    "peak_vmsize_kb": ${peak_vms:-0},
    "peak_threads": ${peak_threads:-0},
    "peak_fd": ${peak_fd:-0}
  },
  "raw_log": "$RAW_LOG"
}
EOF

echo "memory_profile_log=$RAW_LOG"
echo "memory_profile_json=$OUT_JSON"
