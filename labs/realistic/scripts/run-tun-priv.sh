#!/usr/bin/env bash
# Run TUN privileged integration tests on the server VPS (Linux + root required).
# Must be run from the v2ray project root with the Rust toolchain available.
# Usage: bash labs/realistic/scripts/run-tun-priv.sh
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "ERROR: TUN tests require Linux."
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "ERROR: TUN tests require root (CAP_NET_ADMIN)."
    echo "Re-run with: sudo -E bash $0"
    exit 1
fi

REPORT_DIR="labs/realistic/reports"
REPORT_FILE="$REPORT_DIR/vps-tun-$(date -u +%Y%m%dT%H%M%SZ).log"
mkdir -p "$REPORT_DIR"

echo "==> TUN privileged tests — $(date -u +%Y-%m-%dT%H:%M:%SZ)" | tee "$REPORT_FILE"

echo "--- unit + cross-platform TUN tests ---" | tee -a "$REPORT_FILE"
cargo test -p blackwire-transport --all-features 2>&1 | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"
echo "--- privileged TUN device tests ---" | tee -a "$REPORT_FILE"
cargo test -p blackwire-transport --features priv-test --test tun_priv \
    -- --include-ignored --nocapture 2>&1 | tee -a "$REPORT_FILE"

echo "" | tee -a "$REPORT_FILE"
echo "--- VPS interop: real DNS through TUN NAT ---" | tee -a "$REPORT_FILE"
TUN_INTEROP=1 cargo test -p blackwire-transport --features priv-test --test tun_priv \
    vps_udp_nat_real_dns_query -- --include-ignored --nocapture 2>&1 | tee -a "$REPORT_FILE"

echo ""
grep -E "^test result:" "$REPORT_FILE" | tail -5
echo "==> Report: $REPORT_FILE"
