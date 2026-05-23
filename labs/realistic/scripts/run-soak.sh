#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="${1:-configs/soak.env}"
REPORT_DIR="${2:-reports/production}"
mkdir -p "$REPORT_DIR"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE"
: "${DURATION_SECS:=60}"
: "${INTERVAL_SECS:=15}"
: "${LOAD_ENV:=configs/load.env}"
: "${HEALTH_URL:=http://127.0.0.1:18080/}"
: "${PROXY_PID_FILE:=}"
LOG="$REPORT_DIR/soak-$(date -u +%Y%m%dT%H%M%SZ).log"
CSV="$REPORT_DIR/soak-samples-$(date -u +%Y%m%dT%H%M%SZ).csv"
echo "ts,iter,curl_http_code,load_exit,rss_kb,fd_count" > "$CSV"
end=$((SECONDS + DURATION_SECS)); iter=0
while (( SECONDS < end )); do
  iter=$((iter + 1)); ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "=== soak iter $iter at $ts ===" | tee -a "$LOG"
  code="000"
  command -v curl >/dev/null 2>&1 && code="$(curl -m 5 -s -o /dev/null -w '%{http_code}' "$HEALTH_URL" || true)"
  set +e
  bash scripts/run-load.sh "$LOAD_ENV" "$REPORT_DIR" >> "$LOG" 2>&1
  load_exit=$?
  set -e
  rss=""; fds=""
  if [[ -n "$PROXY_PID_FILE" && -f "$PROXY_PID_FILE" ]]; then
    pid="$(cat "$PROXY_PID_FILE")"
    [[ -r "/proc/$pid/status" ]] && rss="$(awk '/VmRSS/ {print $2}' "/proc/$pid/status")"
    [[ -d "/proc/$pid/fd" ]] && fds="$(ls "/proc/$pid/fd" | wc -l | tr -d ' ')"
  fi
  echo "$ts,$iter,$code,$load_exit,$rss,$fds" >> "$CSV"
  (( load_exit == 0 )) || exit "$load_exit"
  sleep "$INTERVAL_SECS"
done
echo "Soak complete. Log: $LOG CSV: $CSV"
