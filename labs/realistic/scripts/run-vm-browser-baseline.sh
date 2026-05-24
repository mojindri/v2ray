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

VM_HOST="${VM_HOST:-}"
VM_USER="${VM_USER:-lab}"
VM_SSH_PORT="${VM_SSH_PORT:-22}"
VM_REMOTE_DIR="${VM_REMOTE_DIR:-/tmp/blackwire-vm-browser-lab}"
VM_TARGET_URL="${VM_TARGET_URL:-https://www.cloudflare.com}"
VM_EXPECT_SNI="${VM_EXPECT_SNI:-www.cloudflare.com}"
VM_CAPTURE_SECONDS="${VM_CAPTURE_SECONDS:-15}"
VM_CAPTURE_IFACE="${VM_CAPTURE_IFACE:-any}"

if [ -z "$VM_HOST" ]; then
  echo "ERROR: VM_HOST is required. Example:"
  echo "  VM_HOST=192.168.64.10 VM_USER=lab make vm-browser-baseline"
  exit 1
fi

cd "$PROJECT_ROOT"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
SAFE_SNI="$(echo "$VM_EXPECT_SNI" | tr '/:' '__')"
REMOTE_PCAP="$VM_REMOTE_DIR/vm-browser-$SAFE_SNI-$TS.pcap"
LOCAL_PCAP="$BASELINE_DIR/vm-browser-$SAFE_SNI-$TS.pcap"
LATEST_PCAP="$BASELINE_DIR/vm-browser-$SAFE_SNI-latest.pcap"
SUMMARY="$REPORT_DIR/vm-browser-baseline-summary-$TS.txt"

SSH=(ssh -p "$VM_SSH_PORT" "$VM_USER@$VM_HOST")
SCP=(scp -P "$VM_SSH_PORT")

{
  echo "vm-browser-baseline timestamp: $TS"
  echo "vm: $VM_USER@$VM_HOST:$VM_SSH_PORT"
  echo "target: $VM_TARGET_URL"
  echo "expect SNI: $VM_EXPECT_SNI"
  echo "remote pcap: $REMOTE_PCAP"
  echo "local pcap: $LOCAL_PCAP"
  echo "capture iface: $VM_CAPTURE_IFACE"
  echo "capture seconds: $VM_CAPTURE_SECONDS"
} | tee "$SUMMARY"

echo "==> requesting sudo on VM now, before capture starts"
"${SSH[@]}" 'sudo -v'

echo "==> running VM browser capture"
"${SSH[@]}" \
  VM_REMOTE_DIR="$VM_REMOTE_DIR" \
  VM_TARGET_URL="$VM_TARGET_URL" \
  VM_EXPECT_SNI="$VM_EXPECT_SNI" \
  VM_CAPTURE_SECONDS="$VM_CAPTURE_SECONDS" \
  VM_CAPTURE_IFACE="$VM_CAPTURE_IFACE" \
  REMOTE_PCAP="$REMOTE_PCAP" \
  'bash -s' > "$LOG_DIR/vm-browser-capture-$TS.log" 2>&1 <<'REMOTE'
set -euo pipefail

mkdir -p "$VM_REMOTE_DIR"

if command -v apt-get >/dev/null 2>&1; then
  sudo -v

  BROWSER=""
  for candidate in google-chrome-stable google-chrome chromium chromium-browser; do
    if command -v "$candidate" >/dev/null 2>&1; then
      BROWSER="$candidate"
      break
    fi
  done

  missing=""
  for tool in tcpdump tshark xvfb-run; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      missing="$missing $tool"
    fi
  done

  if [ -n "$missing" ] || [ -z "$BROWSER" ]; then
    echo "Installing missing VM browser-lab dependencies..."
    sudo DEBIAN_FRONTEND=noninteractive apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates gnupg tcpdump tshark xvfb chromium || \
      sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates gnupg tcpdump tshark xvfb chromium-browser
  fi
fi

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "ERROR: tcpdump is not installed and automatic install failed."
  exit 1
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "ERROR: tshark is not installed and automatic install failed."
  exit 1
fi

if ! command -v xvfb-run >/dev/null 2>&1; then
  echo "ERROR: xvfb-run is not installed and automatic install failed."
  exit 1
fi

BROWSER=""
for candidate in google-chrome-stable google-chrome chromium chromium-browser; do
  if command -v "$candidate" >/dev/null 2>&1; then
    BROWSER="$candidate"
    break
  fi
done

if [ -z "$BROWSER" ]; then
  echo "ERROR: no Chrome/Chromium browser found after automatic install."
  exit 1
fi

PROFILE="$VM_REMOTE_DIR/profile-$RANDOM"
rm -rf "$PROFILE"
mkdir -p "$PROFILE"

sudo rm -f "$REMOTE_PCAP"

sudo tcpdump -i "$VM_CAPTURE_IFACE" -w "$REMOTE_PCAP" 'tcp port 443' &
TCPDUMP_PID=$!

cleanup() {
  sudo kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

echo "browser: $BROWSER"
echo "target: $VM_TARGET_URL"

BROWSER_ARGS=(
  --user-data-dir="$PROFILE"
  --disable-quic
  --disable-background-networking
  --disable-component-update
  --disable-sync
  --disable-extensions
  --no-first-run
  --disable-gpu
  --no-sandbox
  --headless=new
  --disable-dev-shm-usage
  --remote-debugging-port=0
  "$VM_TARGET_URL"
)

xvfb-run -a "$BROWSER" "${BROWSER_ARGS[@]}" >/tmp/blackwire-vm-browser.log 2>&1 &

BROWSER_PID=$!

sleep "$VM_CAPTURE_SECONDS"

kill "$BROWSER_PID" >/dev/null 2>&1 || true
cleanup
wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
trap - EXIT

if [ ! -s "$REMOTE_PCAP" ]; then
  echo "ERROR: VM pcap is empty or missing: $REMOTE_PCAP"
  exit 1
fi

CLIENT_HELLO_COUNT="$(tshark -r "$REMOTE_PCAP" -Y 'tls.handshake.type == 1' -T fields -e frame.number 2>/dev/null | grep -c . || true)"
TARGET_HELLO_COUNT="$(tshark -r "$REMOTE_PCAP" -Y "tls.handshake.type == 1 && tls.handshake.extensions_server_name == \"$VM_EXPECT_SNI\"" -T fields -e frame.number 2>/dev/null | grep -c . || true)"

echo "ClientHello count: $CLIENT_HELLO_COUNT"
echo "Target SNI ClientHello count for $VM_EXPECT_SNI: $TARGET_HELLO_COUNT"

if [ "$CLIENT_HELLO_COUNT" -lt 1 ]; then
  echo "ERROR: VM pcap has no TLS ClientHello records."
  exit 1
fi

if [ "$TARGET_HELLO_COUNT" -lt 1 ]; then
  echo "ERROR: VM pcap has no ClientHello for expected SNI: $VM_EXPECT_SNI"
  exit 1
fi

echo "VM browser baseline capture verified."
REMOTE

echo "==> copying pcap back"
"${SCP[@]}" "$VM_USER@$VM_HOST:$REMOTE_PCAP" "$LOCAL_PCAP"

if [ ! -s "$LOCAL_PCAP" ]; then
  echo "ERROR: copied VM pcap is empty or missing: $LOCAL_PCAP" | tee -a "$SUMMARY"
  exit 1
fi

cp "$LOCAL_PCAP" "$LATEST_PCAP"

echo "pcap saved: $LOCAL_PCAP" | tee -a "$SUMMARY"
echo "latest copy: $LATEST_PCAP" | tee -a "$SUMMARY"

echo "==> running strict fingerprint verify"
CHROME_EXPECT_SNI="$VM_EXPECT_SNI" make -C labs/realistic fingerprint-verify

echo "VM fingerprint total complete."
