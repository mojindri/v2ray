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
LIMA_INSTANCE="${LIMA_INSTANCE:-blackwire-browser}"
LIMA_TARGET_URL="${LIMA_TARGET_URL:-https://www.cloudflare.com}"
LIMA_EXPECT_SNI="${LIMA_EXPECT_SNI:-www.cloudflare.com}"
LIMA_CAPTURE_SECONDS="${LIMA_CAPTURE_SECONDS:-15}"
LIMA_REMOTE_DIR="${LIMA_REMOTE_DIR:-/tmp/blackwire-lima-browser-lab}"
SAFE_SNI="$(echo "$LIMA_EXPECT_SNI" | tr '/:' '__')"
REMOTE_PCAP="$LIMA_REMOTE_DIR/lima-browser-$SAFE_SNI-$TS.pcap"
LOCAL_PCAP="$BASELINE_DIR/lima-browser-$SAFE_SNI-$TS.pcap"
LATEST_PCAP="$BASELINE_DIR/lima-browser-$SAFE_SNI-latest.pcap"
SUMMARY="$REPORT_DIR/lima-browser-baseline-summary-$TS.txt"
YAML="$CFG_DIR/lima-$LIMA_INSTANCE.yaml"

{
  echo "lima-browser-baseline timestamp: $TS"
  echo "instance: $LIMA_INSTANCE"
  echo "target: $LIMA_TARGET_URL"
  echo "expect SNI: $LIMA_EXPECT_SNI"
  echo "local pcap: $LOCAL_PCAP"
  echo "capture seconds: $LIMA_CAPTURE_SECONDS"
} | tee "$SUMMARY"

if ! command -v limactl >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    echo "==> limactl not found; installing Lima with Homebrew" | tee -a "$SUMMARY"
    brew install lima
  else
    echo "ERROR: limactl not found and Homebrew is not installed." | tee -a "$SUMMARY"
    echo "Install Lima manually, then rerun: make lima-fingerprint-total" | tee -a "$SUMMARY"
    exit 1
  fi
fi

if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$LIMA_INSTANCE"; then
  echo "==> creating Lima VM: $LIMA_INSTANCE" | tee -a "$SUMMARY"
  cat > "$YAML" <<'YAML'
images:
- location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
  arch: "aarch64"
- location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
  arch: "x86_64"
cpus: 2
memory: "4GiB"
disk: "20GiB"
mounts:
- location: "~"
  writable: false
provision:
- mode: system
  script: |
    #!/bin/sh
    set -eux
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y curl ca-certificates gnupg tcpdump tshark xvfb chromium
YAML
  limactl start --name "$LIMA_INSTANCE" --tty=false "$YAML" 2>&1 | tee "$LOG_DIR/lima-create-$TS.log"
else
  echo "==> Lima VM already exists: $LIMA_INSTANCE" | tee -a "$SUMMARY"
  limactl start "$LIMA_INSTANCE" 2>&1 | tee "$LOG_DIR/lima-start-$TS.log" || true
fi

echo "==> waiting for Lima shell" | tee -a "$SUMMARY"
for _ in $(seq 1 80); do
  if limactl shell "$LIMA_INSTANCE" true >/dev/null 2>&1; then
    break
  fi
  sleep 3
done

if ! limactl shell "$LIMA_INSTANCE" true >/dev/null 2>&1; then
  echo "ERROR: Lima VM did not become ready: $LIMA_INSTANCE" | tee -a "$SUMMARY"
  exit 1
fi

echo "==> ensuring VM browser/capture tools are installed" | tee -a "$SUMMARY"
limactl shell "$LIMA_INSTANCE" sudo DEBIAN_FRONTEND=noninteractive apt-get update \
  2>&1 | tee "$LOG_DIR/lima-apt-update-$TS.log" >/dev/null
limactl shell "$LIMA_INSTANCE" sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  curl ca-certificates gnupg tcpdump tshark xvfb chromium \
  2>&1 | tee "$LOG_DIR/lima-apt-install-$TS.log" >/dev/null

echo "==> running browser capture inside Lima VM" | tee -a "$SUMMARY"
limactl shell "$LIMA_INSTANCE" env \
  LIMA_REMOTE_DIR="$LIMA_REMOTE_DIR" \
  LIMA_TARGET_URL="$LIMA_TARGET_URL" \
  LIMA_EXPECT_SNI="$LIMA_EXPECT_SNI" \
  LIMA_CAPTURE_SECONDS="$LIMA_CAPTURE_SECONDS" \
  REMOTE_PCAP="$REMOTE_PCAP" \
  bash -s > "$LOG_DIR/lima-browser-capture-$TS.log" 2>&1 <<'REMOTE'
set -euo pipefail

mkdir -p "$LIMA_REMOTE_DIR"

BROWSER=""
for candidate in chromium google-chrome-stable google-chrome chromium-browser; do
  if command -v "$candidate" >/dev/null 2>&1; then
    BROWSER="$candidate"
    break
  fi
done

if [ -z "$BROWSER" ]; then
  echo "ERROR: no Chrome/Chromium browser found."
  exit 1
fi

sudo rm -f "$REMOTE_PCAP"

PROFILE="$LIMA_REMOTE_DIR/profile-$RANDOM"
rm -rf "$PROFILE"
mkdir -p "$PROFILE"

sudo tcpdump -i any -w "$REMOTE_PCAP" 'tcp port 443' &
TCPDUMP_PID=$!

cleanup() {
  sudo kill "$TCPDUMP_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 2

xvfb-run -a "$BROWSER" \
  --user-data-dir="$PROFILE" \
  --disable-quic \
  --disable-background-networking \
  --disable-component-update \
  --disable-sync \
  --disable-extensions \
  --no-first-run \
  --disable-gpu \
  --no-sandbox \
  --headless=new \
  --disable-dev-shm-usage \
  --remote-debugging-port=0 \
  "$LIMA_TARGET_URL" >/tmp/blackwire-lima-browser.log 2>&1 &

BROWSER_PID=$!

sleep "$LIMA_CAPTURE_SECONDS"

kill "$BROWSER_PID" >/dev/null 2>&1 || true
cleanup
wait "$TCPDUMP_PID" >/dev/null 2>&1 || true
trap - EXIT

if [ ! -s "$REMOTE_PCAP" ]; then
  echo "ERROR: Lima pcap is empty or missing: $REMOTE_PCAP"
  exit 1
fi

CLIENT_HELLO_COUNT="$(tshark -r "$REMOTE_PCAP" -Y 'tls.handshake.type == 1' -T fields -e frame.number 2>/dev/null | grep -c . || true)"
TARGET_HELLO_COUNT="$(tshark -r "$REMOTE_PCAP" -Y "tls.handshake.type == 1 && tls.handshake.extensions_server_name == \"$LIMA_EXPECT_SNI\"" -T fields -e frame.number 2>/dev/null | grep -c . || true)"

echo "ClientHello count: $CLIENT_HELLO_COUNT"
echo "Target SNI ClientHello count for $LIMA_EXPECT_SNI: $TARGET_HELLO_COUNT"

if [ "$CLIENT_HELLO_COUNT" -lt 1 ]; then
  echo "ERROR: Lima pcap has no TLS ClientHello records."
  exit 1
fi

if [ "$TARGET_HELLO_COUNT" -lt 1 ]; then
  echo "ERROR: Lima pcap has no ClientHello for expected SNI: $LIMA_EXPECT_SNI"
  exit 1
fi

echo "Lima browser baseline capture verified."
REMOTE

echo "==> copying pcap back from Lima VM" | tee -a "$SUMMARY"
limactl copy "$LIMA_INSTANCE:$REMOTE_PCAP" "$LOCAL_PCAP" 2>&1 | tee "$LOG_DIR/lima-copy-$TS.log"

if [ ! -s "$LOCAL_PCAP" ]; then
  echo "ERROR: copied Lima pcap is empty or missing: $LOCAL_PCAP" | tee -a "$SUMMARY"
  exit 1
fi

cp "$LOCAL_PCAP" "$LATEST_PCAP"

echo "pcap saved: $LOCAL_PCAP" | tee -a "$SUMMARY"
echo "latest copy: $LATEST_PCAP" | tee -a "$SUMMARY"

echo "==> running strict fingerprint verify" | tee -a "$SUMMARY"
CHROME_EXPECT_SNI="$LIMA_EXPECT_SNI" make -C labs/realistic fingerprint-verify

echo "Lima fingerprint total complete." | tee -a "$SUMMARY"
