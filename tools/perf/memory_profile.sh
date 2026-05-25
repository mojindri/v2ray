#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/reports/perf}"
mkdir -p "$OUT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_DIR/memory-profile-$TS.log"

{
  echo "timestamp=$TS"
  echo "note=run with proxy already started; samples rss/fd and runs load smoke"
  pgrep -f "blackwire run" >/tmp/blackwire_pids.$$ || true
  if [ -s /tmp/blackwire_pids.$$ ]; then
    pid="$(head -n1 /tmp/blackwire_pids.$$)"
    echo "pid=$pid"
    if [ -r "/proc/$pid/status" ]; then
      awk '/VmRSS|VmSize|Threads/ {print}' "/proc/$pid/status"
    fi
    if [ -d "/proc/$pid/fd" ]; then
      echo "fd_count=$(ls "/proc/$pid/fd" | wc -l | tr -d ' ')"
    fi
  else
    echo "pid=not-found"
  fi
  python3 "$ROOT/labs/realistic/scripts/local_curl_load.py" --requests 150 --concurrency 30 || true
} | tee "$OUT"

rm -f /tmp/blackwire_pids.$$
echo "memory_profile_log=$OUT"
