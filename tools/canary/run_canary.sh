#!/usr/bin/env bash
set -euo pipefail

CANARY_PERCENT="${CANARY_PERCENT:-5}"
CANARY_MINUTES="${CANARY_MINUTES:-30}"
ALERT_ERROR_RATE="${ALERT_ERROR_RATE:-0.01}"
ALERT_P99_MS="${ALERT_P99_MS:-1000}"
ALERT_RSS_MB="${ALERT_RSS_MB:-1024}"
ALERT_FD="${ALERT_FD:-8192}"
ALERT_TASKS="${ALERT_TASKS:-50000}"

cat <<EOF
canary_plan:
  traffic_percent: ${CANARY_PERCENT}
  duration_minutes: ${CANARY_MINUTES}
  rollback_on:
    error_rate_gt: ${ALERT_ERROR_RATE}
    p99_latency_ms_gt: ${ALERT_P99_MS}
    rss_mb_gt: ${ALERT_RSS_MB}
    fd_count_gt: ${ALERT_FD}
    task_count_gt: ${ALERT_TASKS}
  required_checks:
    - auth_failure_rate
    - outbound_timeout_rate
    - dns_failure_rate
    - reload_failure_rate
    - session_evictions
EOF
