#!/usr/bin/env bash
# Production-like health/failover lab: Docker health + echo services, blackwire on host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB_DIR"

mkdir -p "$LAB_DIR/../reports"
LOG="$LAB_DIR/../reports/health-failover.log"
: > "$LOG"

echo "=== [health-failover] starting probe + echo services ===" | tee -a "$LOG"
docker compose -f docker-compose.yml up -d health-probe echo-target

cleanup() {
  docker compose -f docker-compose.yml down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "=== [health-failover] waiting for services ===" | tee -a "$LOG"
sleep 2

export HEALTH_PROBE_PORT=18081
export ECHO_PORT=19091

echo "=== [health-failover] running integration test ===" | tee -a "$LOG"
cd "$ROOT"
cargo test -p integration-tests --locked --test e2e_health_failover health_failover_docker_lab_services -- --ignored --nocapture 2>&1 | tee -a "$LOG"

echo "=== [health-failover] PASS ===" | tee -a "$LOG"
