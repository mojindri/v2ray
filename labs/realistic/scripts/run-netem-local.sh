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
LOG="$REPORT_DIR/netem-local-$TS.log"

{
  echo "netem-local timestamp: $TS"
  echo "This is best-effort. On macOS Docker Desktop, real tc/netem behavior may be limited."
} | tee "$LOG"

if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not installed." | tee -a "$LOG"
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  echo "SKIP: docker daemon unavailable." | tee -a "$LOG"
  exit 0
fi

# Start local lab if compose exists.
if [ -f labs/realistic/docker-compose.yml ]; then
  docker compose -f labs/realistic/docker-compose.yml up -d >> "$LOG" 2>&1 || true
fi

CONTAINER="$(docker ps --format '{{.Names}}' | grep -E 'proxy|target|xray|server|client' | head -1 || true)"
if [ -z "$CONTAINER" ]; then
  echo "SKIP: no suitable running Docker container found for netem smoke." | tee -a "$LOG"
  exit 0
fi

echo "Using container: $CONTAINER" | tee -a "$LOG"

if ! docker exec "$CONTAINER" sh -c 'command -v tc >/dev/null 2>&1' ; then
  echo "SKIP: tc not available inside $CONTAINER." | tee -a "$LOG"
  exit 0
fi

if ! docker exec "$CONTAINER" sh -c 'id -u' | grep -q '^0$'; then
  echo "SKIP: container is not root; tc likely unavailable." | tee -a "$LOG"
  exit 0
fi

# Try applying and removing a tiny delay on eth0.
set +e
docker exec "$CONTAINER" sh -c 'tc qdisc del dev eth0 root 2>/dev/null || true'
docker exec "$CONTAINER" sh -c 'tc qdisc add dev eth0 root netem delay 50ms loss 1%'
ADD_RC=$?
docker exec "$CONTAINER" sh -c 'tc qdisc show dev eth0'
docker exec "$CONTAINER" sh -c 'tc qdisc del dev eth0 root 2>/dev/null || true'
set -e

if [ "$ADD_RC" -ne 0 ]; then
  echo "SKIP: Docker/container does not permit tc netem here." | tee -a "$LOG"
  exit 0
fi

echo "netem-local smoke passed: tc qdisc add/show/delete worked." | tee -a "$LOG"
