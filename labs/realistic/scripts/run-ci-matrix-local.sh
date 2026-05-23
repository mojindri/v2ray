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

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SUMMARY="$REPORT_DIR/ci-matrix-local-$TS.txt"
: > "$SUMMARY"

run_step() {
  name="$1"
  shift
  log="$REPORT_DIR/ci-matrix-$name-$TS.log"
  echo "==> [$name] $*" | tee -a "$SUMMARY"
  if "$@" > "$log" 2>&1; then
    echo "PASS $name" | tee -a "$SUMMARY"
  else
    echo "FAIL $name (see $log)" | tee -a "$SUMMARY"
    return 1
  fi
}

run_step local-fast make local-fast
run_step local-load make local-load
run_step local-slowloris make local-slowloris
run_step local-prod make local-prod
run_step pcap-local make local-pcap
run_step fingerprint-compare make local-fingerprint-compare
run_step netem-local make local-netem

echo "local CI matrix complete" | tee -a "$SUMMARY"
