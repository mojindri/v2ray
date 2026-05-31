#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRIT_DIR="${1:-$ROOT_DIR/target/criterion}"
SCENARIO_FILE="${2:-$ROOT_DIR/ci/bench-gate-key-scenarios.txt}"
REGRESS_THRESHOLD="${3:-0.08}"

if [[ ! -d "$CRIT_DIR" ]]; then
  echo "criterion directory not found: $CRIT_DIR" >&2
  exit 1
fi

if [[ ! -f "$SCENARIO_FILE" ]]; then
  echo "scenario file not found: $SCENARIO_FILE" >&2
  exit 1
fi

fail=0
echo "Benchmark gate threshold: ${REGRESS_THRESHOLD} (mean CI lower bound)"
while IFS= read -r scenario; do
  [[ -z "$scenario" || "${scenario:0:1}" == "#" ]] && continue
  file="$CRIT_DIR/$scenario/change/estimates.json"
  if [[ ! -f "$file" ]]; then
    echo "MISSING: $scenario ($file)"
    fail=1
    continue
  fi

  lower="$(jq -r '.mean.confidence_interval.lower_bound' "$file")"
  point="$(jq -r '.mean.point_estimate' "$file")"
  upper="$(jq -r '.mean.confidence_interval.upper_bound' "$file")"

  if awk "BEGIN {exit !($lower > $REGRESS_THRESHOLD)}"; then
    echo "FAIL    $scenario  lower=$lower point=$point upper=$upper"
    fail=1
  else
    echo "PASS    $scenario  lower=$lower point=$point upper=$upper"
  fi
done < "$SCENARIO_FILE"

if [[ "$fail" -ne 0 ]]; then
  echo "Benchmark gate failed." >&2
  exit 1
fi

echo "Benchmark gate passed."

