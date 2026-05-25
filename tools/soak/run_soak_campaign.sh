#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${1:-$ROOT/reports/soak-campaign}"
PROFILE="${2:-24h}"

mkdir -p "$OUT_DIR"

case "$PROFILE" in
  24h) DURATION_SECS=$((24 * 3600)) ;;
  72h) DURATION_SECS=$((72 * 3600)) ;;
  7d) DURATION_SECS=$((7 * 24 * 3600)) ;;
  *)
    echo "Usage: $0 [out-dir] [24h|72h|7d]"
    exit 2
    ;;
esac

export DURATION_SECS
export INTERVAL_SECS="${INTERVAL_SECS:-30}"

echo "==> soak campaign profile=$PROFILE duration_secs=$DURATION_SECS"
echo "==> output=$OUT_DIR"

bash "$ROOT/labs/realistic/scripts/run-soak.sh" "$ROOT/labs/realistic/configs/soak.env" "$OUT_DIR"
