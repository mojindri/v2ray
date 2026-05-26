#!/usr/bin/env bash
# Profile one e2e protocol bench with cargo-flamegraph (Linux recommended).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PERF_DIR="${PERF_REPORT_DIR:-$PROJECT_ROOT/benches/reports/flamegraphs}"
PROTOCOL="${1:-vless_tcp}"
SCENARIO="${2:-bulk}" # bulk | short | mixed | handshake
TS="$(date -u +%Y%m%dT%H%M%SZ)"

mkdir -p "$PERF_DIR"

if ! command -v cargo-flamegraph >/dev/null 2>&1; then
  echo "Installing cargo-flamegraph..."
  cargo install flamegraph
fi

export BENCH_QUICK=1
export RUST_LOG=warn
export CARGO_PROFILE_BENCH_DEBUG="${CARGO_PROFILE_BENCH_DEBUG:-true}"

BENCH="e2e_${PROTOCOL}"
OUT="$PERF_DIR/${PROTOCOL}-${SCENARIO}-${TS}.svg"

# Narrow criterion to one group when possible.
FILTER="${PROTOCOL}/${SCENARIO}"
case "$SCENARIO" in
  bulk) FILTER="${PROTOCOL}/bulk_relay" ;;
  short) FILTER="${PROTOCOL}/short_lived" ;;
  mixed) FILTER="${PROTOCOL}/mixed_small_writes" ;;
  handshake) FILTER="${PROTOCOL}/handshake" ;;
esac

echo "Profiling bench=$BENCH filter=$FILTER -> $OUT"
cd "$PROJECT_ROOT"
rm -f cargo-flamegraph.trace
cargo flamegraph \
  --package blackwire-benches \
  --bench "$BENCH" \
  --output "$OUT" \
  -- \
  "$FILTER" \
  --bench

echo "flamegraph=$OUT"
