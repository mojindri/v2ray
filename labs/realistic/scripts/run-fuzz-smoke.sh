#!/usr/bin/env bash
set -euo pipefail
REPORT_DIR="${1:-reports/production}"
mkdir -p "$REPORT_DIR"
LOG="$REPORT_DIR/fuzz-smoke-$(date -u +%Y%m%dT%H%M%SZ).log"
if [[ ! -d fuzz ]]; then
  echo "No fuzz/ directory found. Copy your fuzz.zip contents into project root first." | tee "$LOG"
  exit 0
fi
if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "cargo-fuzz not installed. Install with: cargo install cargo-fuzz" | tee "$LOG"
  exit 0
fi
mapfile -t targets < <(find fuzz/fuzz_targets -maxdepth 1 -name '*.rs' -not -name 'common.rs' -exec basename {} .rs \; | sort)
if [[ ${#targets[@]} -eq 0 ]]; then
  echo "No fuzz targets found." | tee "$LOG"
  exit 1
fi
for t in "${targets[@]}"; do
  echo "=== fuzz smoke: $t ===" | tee -a "$LOG"
  cargo fuzz run "$t" -- -runs=128 2>&1 | tee -a "$LOG"
done
