#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CRIT_DIR="${1:-$ROOT_DIR/target/criterion}"
REGRESS_THRESHOLD="${2:-0.08}"

GATE_SCRIPT="$ROOT_DIR/scripts/bench/criterion_gate.sh"
SCENARIO_FILES=(
  "$ROOT_DIR/ci/bench-gate-vless.txt"
  "$ROOT_DIR/ci/bench-gate-trojan.txt"
  "$ROOT_DIR/ci/bench-gate-ss2022.txt"
  "$ROOT_DIR/ci/bench-gate-vmess-grpc.txt"
)

if [[ ! -x "$GATE_SCRIPT" ]]; then
  echo "gate script not executable: $GATE_SCRIPT" >&2
  exit 1
fi

for scenario_file in "${SCENARIO_FILES[@]}"; do
  echo
  echo "== Benchmark gate: $(basename "$scenario_file") =="
  "$GATE_SCRIPT" "$CRIT_DIR" "$scenario_file" "$REGRESS_THRESHOLD"
done

echo
echo "All protocol benchmark gates passed."

