#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

cd "$PROJECT_ROOT"


REPORT_DIR="${1:-reports/production}"
mkdir -p "$REPORT_DIR"
LOG="$REPORT_DIR/security-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee "$LOG") 2>&1

echo "=== security checks at $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
echo "--- rust/cargo version ---"
rustc --version || true
cargo --version || true

echo "--- cargo check all features ---"
cargo check --workspace --all-features

echo "--- unsafe occurrences ---"
if command -v rg >/dev/null 2>&1; then
  rg -n "\bunsafe\b|unwrap\(|expect\(|todo!\(|unimplemented!\(|panic!\(" crates tests || true
else
  grep -RInE "\bunsafe\b|unwrap\(|expect\(|todo!\(|unimplemented!\(|panic!\(" crates tests || true
fi

echo "--- possible secrets in repo ---"
if command -v rg >/dev/null 2>&1; then
  rg -n --hidden \
    -g '!target/**' \
    -g '!reports/**' \
    -g '!labs/realistic/reports/**' \
    -g '!.git/**' \
    -g '!.idea/**' \
    -g '!*.lock' \
    '(PRIVATE KEY|BEGIN RSA|BEGIN OPENSSH|password\s*=|secret\s*=|token\s*=|api[_-]?key)' . || true
else
  grep -RInE \
    --exclude-dir=target \
    --exclude-dir=reports \
    --exclude-dir=.git \
    --exclude-dir=.idea \
    --exclude='*.lock' \
    '(PRIVATE KEY|BEGIN RSA|BEGIN OPENSSH|password[[:space:]]*=|secret[[:space:]]*=|token[[:space:]]*=|api[_-]?key)' . || true
fi

echo "--- duplicate dependencies ---"
cargo tree -d || true

echo "--- cargo audit if available ---"
if command -v cargo-audit >/dev/null 2>&1; then
  cargo audit
else
  echo "cargo-audit not installed. Install with: cargo install cargo-audit"
fi

echo "--- cargo deny if available ---"
if command -v cargo-deny >/dev/null 2>&1; then
  cargo deny check advisories licenses bans sources
else
  echo "cargo-deny not installed. Install with: cargo install cargo-deny"
fi

echo "Security hygiene checks complete. Review $LOG manually; grep output is not a proof of vulnerability."
