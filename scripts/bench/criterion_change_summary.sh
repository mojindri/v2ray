#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRIT_DIR="${1:-$ROOT_DIR/target/criterion}"

if [[ ! -d "$CRIT_DIR" ]]; then
  echo "criterion directory not found: $CRIT_DIR" >&2
  exit 1
fi

printf "%-78s %-10s %-10s %-10s %-8s\n" "benchmark" "lower" "point" "upper" "class"
printf -- "%.0s-" {1..124}
printf "\n"

while IFS= read -r file; do
  bench="${file#"$CRIT_DIR"/}"
  bench="${bench%/change/estimates.json}"
  lower="$(jq -r '.mean.confidence_interval.lower_bound' "$file")"
  point="$(jq -r '.mean.point_estimate' "$file")"
  upper="$(jq -r '.mean.confidence_interval.upper_bound' "$file")"

  cls="noise"
  awk "BEGIN {exit !($lower > 0)}" && cls="regress"
  awk "BEGIN {exit !($upper < 0)}" && cls="improve"

  printf "%-78s %10.4f %10.4f %10.4f %8s\n" "$bench" "$lower" "$point" "$upper" "$cls"
done < <(find "$CRIT_DIR" -type f -path '*/change/estimates.json' | sort)

