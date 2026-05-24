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

mkdir -p "$BASELINE_DIR" "$LOG_DIR"

cd "$PROJECT_ROOT"

TS="$(date -u +%Y%m%dT%H%M%SZ)"

CHROME_TARGET_URL="${CHROME_TARGET_URL:-https://www.cloudflare.com}"
CHROME_TARGET_SLUG="${CHROME_TARGET_SLUG:-cloudflare}"
CHROME_DOCKER_IMAGE="${CHROME_DOCKER_IMAGE:-browserless/chrome:latest}"
CHROME_CONTAINER="blackwire-chrome-baseline-$TS"
CAPTURE_CONTAINER="blackwire-chrome-pcap-$TS"

PCAP_NAME="chrome-docker-$CHROME_TARGET_SLUG-$TS.pcap"
PCAP="$BASELINE_DIR/$PCAP_NAME"
LATEST="$BASELINE_DIR/chrome-docker-$CHROME_TARGET_SLUG-latest.pcap"
SUMMARY="$REPORT_DIR/chrome-baseline-docker-summary-$TS.txt"

{
  echo "chrome-baseline-docker timestamp: $TS"
  echo "target: $CHROME_TARGET_URL"
  echo "image: $CHROME_DOCKER_IMAGE"
  echo "pcap: $PCAP"
  echo "mode: Docker Chromium/Chrome-family baseline"
  echo "host sudo: no"
} | tee "$SUMMARY"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not installed." | tee -a "$SUMMARY"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon unavailable." | tee -a "$SUMMARY"
  exit 0
fi

cleanup() {
  docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$CHROME_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> starting browser container" | tee -a "$SUMMARY"
docker run -d --name "$CHROME_CONTAINER" \
  --shm-size=1g \
  -e PREBOOT_CHROME=true \
  -p 127.0.0.1::3000 \
  "$CHROME_DOCKER_IMAGE" \
  > "$LOG_DIR/chrome-docker-container-$TS.id" 2> "$LOG_DIR/chrome-docker-container-$TS.log" || {
    echo "SKIP: failed to start Docker browser image. See $LOG_DIR/chrome-docker-container-$TS.log" | tee -a "$SUMMARY"
    exit 0
  }

sleep 5

echo "==> starting tcpdump sidecar" | tee -a "$SUMMARY"
docker run -d --name "$CAPTURE_CONTAINER" \
  --net=container:"$CHROME_CONTAINER" \
  -v "$BASELINE_DIR:/pcaps" \
  nicolaka/netshoot \
  tcpdump -i any -w "/pcaps/$PCAP_NAME" "tcp port 443" \
  > "$LOG_DIR/chrome-docker-tcpdump-$TS.id" 2> "$LOG_DIR/chrome-docker-tcpdump-$TS.log" || {
    echo "SKIP: failed to start tcpdump sidecar. See $LOG_DIR/chrome-docker-tcpdump-$TS.log" | tee -a "$SUMMARY"
    exit 0
  }

sleep 2

echo "==> triggering Docker browser best-effort navigation" | tee -a "$SUMMARY"

# browserless/chrome exposes a browser control API; this is best-effort because image APIs differ by version.
PORT="$(docker port "$CHROME_CONTAINER" 3000/tcp 2>/dev/null | sed 's/.*://g' | head -1 || true)"

if [ -n "$PORT" ]; then
  curl -fsS "http://127.0.0.1:$PORT/json/version" > "$LOG_DIR/chrome-docker-version-$TS.json" 2>&1 || true

  node - <<NODE > "$LOG_DIR/chrome-docker-trigger-$TS.log" 2>&1 || true
const http = require("http");
const target = process.env.CHROME_TARGET_URL || "$CHROME_TARGET_URL";
const port = "$PORT";

function req(path, cb) {
  http.get({ hostname: "127.0.0.1", port, path }, res => {
    let data = "";
    res.on("data", d => data += d);
    res.on("end", () => cb(null, data));
  }).on("error", err => cb(err));
}

req("/json/new?" + encodeURIComponent(target), (err, data) => {
  if (err) {
    console.error(err);
    process.exit(0);
  }
  console.log(data);
});
NODE
else
  echo "WARN: could not determine browserless mapped port; capture may be empty." | tee -a "$SUMMARY"
fi

sleep "${CHROME_CAPTURE_SECONDS:-12}"

docker rm -f "$CAPTURE_CONTAINER" >/dev/null 2>&1 || true
sleep 1

if [ -s "$PCAP" ]; then
  cp "$PCAP" "$LATEST"
  echo "pcap saved: $PCAP" | tee -a "$SUMMARY"
  echo "latest copy: $LATEST" | tee -a "$SUMMARY"
  echo "==> running fingerprint compare" | tee -a "$SUMMARY"
  make -C labs/realistic fingerprint-compare
else
  echo "WARN: Docker Chrome pcap is empty or not created: $PCAP" | tee -a "$SUMMARY"
  echo "This Docker path is reproducible/no-sudo, but less reliable than real macOS Chrome." | tee -a "$SUMMARY"
fi
