#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
REPORT_DIR_ARG="${1:-labs/realistic/reports/production}"
case "$REPORT_DIR_ARG" in
  /*) REPORT_DIR="$REPORT_DIR_ARG" ;;
  *) REPORT_DIR="$PROJECT_ROOT/$REPORT_DIR_ARG" ;;
esac

ART="$REPORT_DIR/artifacts"
PCAP_DIR="$ART/pcaps"
LOG_DIR="$ART/logs"
CFG_DIR="$ART/configs"
mkdir -p "$PCAP_DIR" "$LOG_DIR" "$CFG_DIR"

cd "$PROJECT_ROOT"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$PCAP_DIR/local-interop-$TS.pcap"
SUMMARY="$REPORT_DIR/pcap-local-summary-$TS.txt"

{
  echo "pcap-local timestamp: $TS"
  echo "project: $PROJECT_ROOT"
  echo "output: $OUT"
} | tee "$SUMMARY"

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "SKIP: tcpdump not installed." | tee -a "$SUMMARY"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not installed." | tee -a "$SUMMARY"
  exit 0
fi

# Copy configs that define the run.
if [ -d tests/interop/configs ]; then
  mkdir -p "$CFG_DIR/tests-interop-$TS"
  cp -R tests/interop/configs/. "$CFG_DIR/tests-interop-$TS/" 2>/dev/null || true
fi

# Prefer loopback capture for local Docker Desktop/interop traffic.
IFACE="${PCAP_IFACE:-lo0}"
if ! tcpdump -D 2>/dev/null | grep -q "$IFACE"; then
  IFACE="${PCAP_IFACE_FALLBACK:-any}"
fi

echo "Starting tcpdump on interface: $IFACE" | tee -a "$SUMMARY"

set +e
sudo -n tcpdump -i "$IFACE" -w "$OUT" \
  'tcp port 443 or tcp port 8443 or tcp port 1080 or tcp port 18080 or udp port 443 or udp port 8443' \
  > "$LOG_DIR/tcpdump-local-$TS.log" 2>&1 &
TCPDUMP_PID=$!
sleep 2

# Run a short interop smoke if available. Do not make pcap helper responsible for correctness.
if [ -f tests/interop/Makefile ]; then
  make -C tests/interop up > "$LOG_DIR/interop-up-$TS.log" 2>&1 || true
  cargo test -p proxy-transport --test interop d1 -- --ignored --nocapture \
    > "$LOG_DIR/interop-d1-$TS.log" 2>&1 || true
fi

sleep 2
sudo -n kill "$TCPDUMP_PID" >/dev/null 2>&1 || kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
set -e

if [ -s "$OUT" ]; then
  echo "pcap saved: $OUT" | tee -a "$SUMMARY"
else
  echo "WARN: pcap is empty or not created: $OUT" | tee -a "$SUMMARY"
fi

echo "logs saved under: $LOG_DIR"
echo "configs saved under: $CFG_DIR"
