#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/reports/perf}"
mkdir -p "$OUT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_JSON="$OUT_DIR/perf-smoke-$TS.json"

python3 "$ROOT/labs/realistic/scripts/local_curl_load.py" \
  --proxy "${PERF_PROXY:-socks5h://127.0.0.1:1080}" \
  --url "${PERF_URL:-http://127.0.0.1:18080/}" \
  --requests "${PERF_REQUESTS:-200}" \
  --concurrency "${PERF_CONCURRENCY:-40}" \
  --timeout "${PERF_TIMEOUT:-5}" \
  > "$OUT_JSON"

echo "perf_smoke_json=$OUT_JSON"
