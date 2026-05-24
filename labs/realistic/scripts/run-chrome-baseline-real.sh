#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
REPORT_DIR_ARG="${1:-reports/production}"

case "$REPORT_DIR_ARG" in
  /*) REPORT_DIR="$REPORT_DIR_ARG" ;;
  *) REPORT_DIR="$PROJECT_ROOT/labs/realistic/$REPORT_DIR_ARG" ;;
esac

BASELINE_DIR="$REPORT_DIR/baselines"
LOG_DIR="$REPORT_DIR/artifacts/logs"
CFG_DIR="$REPORT_DIR/artifacts/configs"

mkdir -p "$BASELINE_DIR" "$LOG_DIR" "$CFG_DIR"

cd "$PROJECT_ROOT"

TS="$(date -u +%Y%m%dT%H%M%SZ)"

CHROME_TARGET_URL="${CHROME_TARGET_URL:-https://www.cloudflare.com}"
CHROME_TARGET_SLUG="${CHROME_TARGET_SLUG:-cloudflare}"
CHROME_PROFILE_DIR="${CHROME_PROFILE_DIR:-/tmp/blackwire-chrome-real-baseline-profile}"
CHROME_CAPTURE_SECONDS="${CHROME_CAPTURE_SECONDS:-12}"
CHROME_PCAP_IFACE="${CHROME_PCAP_IFACE:-en0}"
CHROME_TCPDUMP_FILTER="${CHROME_TCPDUMP_FILTER:-tcp port 443}"
CHROME_OPEN_BROWSER="${CHROME_OPEN_BROWSER:-0}"
CHROME_EXPECT_SNI="${CHROME_EXPECT_SNI:-www.cloudflare.com}"
CHROME_REQUIRE_CLIENT_HELLO="${CHROME_REQUIRE_CLIENT_HELLO:-1}"

PCAP="$BASELINE_DIR/chrome-real-$CHROME_TARGET_SLUG-$TS.pcap"
LATEST="$BASELINE_DIR/chrome-real-$CHROME_TARGET_SLUG-latest.pcap"
SUMMARY="$REPORT_DIR/chrome-baseline-real-summary-$TS.txt"

{
  echo "chrome-baseline-real timestamp: $TS"
  echo "target: $CHROME_TARGET_URL"
  echo "interface: $CHROME_PCAP_IFACE"
  echo "filter: $CHROME_TCPDUMP_FILTER"
  echo "pcap: $PCAP"
  echo "mode: real macOS Google Chrome"
  echo "sudo: requested immediately before capture"
  echo "open browser: $CHROME_OPEN_BROWSER"
  echo "expect SNI: $CHROME_EXPECT_SNI"
  echo "require ClientHello: $CHROME_REQUIRE_CLIENT_HELLO"
} | tee "$SUMMARY"

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "ERROR: tcpdump not installed." | tee -a "$SUMMARY"
  exit 1
fi

if ! command -v open >/dev/null 2>&1; then
  echo "ERROR: macOS open command not found." | tee -a "$SUMMARY"
  exit 1
fi

echo "==> requesting sudo now, before capture starts"
sudo -v

echo "==> starting host tcpdump" | tee -a "$SUMMARY"
sudo tcpdump -i "$CHROME_PCAP_IFACE" -w "$PCAP" "$CHROME_TCPDUMP_FILTER" \
  > "$LOG_DIR/chrome-real-tcpdump-$TS.log" 2>&1 &
TCPDUMP_PID=$!

cleanup() {
  kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

if [ "$CHROME_OPEN_BROWSER" = "1" ]; then
  echo "==> opening real Chrome: $CHROME_TARGET_URL" | tee -a "$SUMMARY"
  open -na "Google Chrome" --args \
    --user-data-dir="$CHROME_PROFILE_DIR" \
    --disable-quic \
    --disable-background-networking \
    --disable-component-update \
    --disable-sync \
    --disable-extensions \
    --new-window "$CHROME_TARGET_URL"
else
  echo "==> Chrome auto-open disabled." | tee -a "$SUMMARY"
  echo "Open this URL manually during the next $CHROME_CAPTURE_SECONDS seconds if you want a fresh real Chrome baseline:" | tee -a "$SUMMARY"
  echo "    $CHROME_TARGET_URL" | tee -a "$SUMMARY"
fi

sleep "$CHROME_CAPTURE_SECONDS"

cleanup
wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
trap - EXIT

if [ -s "$PCAP" ]; then
  cp "$PCAP" "$LATEST"
  echo "pcap saved: $PCAP" | tee -a "$SUMMARY"
  echo "latest copy: $LATEST" | tee -a "$SUMMARY"
else
  echo "ERROR: pcap is empty or not created: $PCAP" | tee -a "$SUMMARY"
  echo "tcpdump log: $LOG_DIR/chrome-real-tcpdump-$TS.log" | tee -a "$SUMMARY"
  exit 1
fi

if [ "$CHROME_REQUIRE_CLIENT_HELLO" = "1" ]; then
  if ! command -v tshark >/dev/null 2>&1; then
    echo "ERROR: tshark is required to verify Chrome baseline ClientHello." | tee -a "$SUMMARY"
    exit 1
  fi

  CLIENT_HELLO_COUNT="$(tshark -r "$PCAP" -Y 'tls.handshake.type == 1' -T fields -e frame.number 2>/dev/null | grep -c . || true)"
  TARGET_HELLO_COUNT="$(tshark -r "$PCAP" -Y "tls.handshake.type == 1 && tls.handshake.extensions_server_name == \"$CHROME_EXPECT_SNI\"" -T fields -e frame.number 2>/dev/null | grep -c . || true)"

  echo "ClientHello count: $CLIENT_HELLO_COUNT" | tee -a "$SUMMARY"
  echo "Target SNI ClientHello count for $CHROME_EXPECT_SNI: $TARGET_HELLO_COUNT" | tee -a "$SUMMARY"

  if [ "$CLIENT_HELLO_COUNT" -lt 1 ]; then
    echo "ERROR: Chrome baseline pcap has no TLS ClientHello records." | tee -a "$SUMMARY"
    exit 1
  fi

  if [ -n "$CHROME_EXPECT_SNI" ] && [ "$TARGET_HELLO_COUNT" -lt 1 ]; then
    echo "ERROR: Chrome baseline pcap has no ClientHello for expected SNI: $CHROME_EXPECT_SNI" | tee -a "$SUMMARY"
    echo "Open $CHROME_TARGET_URL manually during capture or set CHROME_OPEN_BROWSER=1." | tee -a "$SUMMARY"
    exit 1
  fi
fi


echo "==> running fingerprint compare" | tee -a "$SUMMARY"
make -C labs/realistic fingerprint-compare
