#!/usr/bin/env bash
# run-netem.sh — Run integration tests under Linux tc netem traffic shaping.
#
# Requires: Linux, root (or CAP_NET_ADMIN), iproute2, tc, cargo in PATH.
# Usage: sudo bash run-netem.sh [REPORT_DIR]
#
# For each netem profile the script:
#   1. Installs a netem qdisc on the loopback interface.
#   2. Runs `cargo test -p integration-tests` (unit + integration).
#   3. Removes the qdisc unconditionally.
#   4. Writes a per-profile log to REPORT_DIR/vps-netem-<profile>.log.
#   5. Prints a PASS/FAIL summary at the end.
#
# Profiles run (matching the network-hostility checklist):
#   loss 1%          — 1% random packet loss
#   loss 5%          — 5% random packet loss
#   loss 10%         — 10% random packet loss
#   delay 100ms      — 100ms constant latency
#   delay 300ms      — 300ms constant latency
#   delay 50ms 20ms  — 50ms ± 20ms jitter (uniform distribution)
#   rate 1mbit       — 1 Mbit/s bandwidth cap

set -euo pipefail

REPORT_DIR="${1:-$(cd "$(dirname "$0")/../reports" && pwd)}"
mkdir -p "$REPORT_DIR"

IFACE="lo"
CARGO_ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"

# Netem profiles: each entry is a label and the tc qdisc parameters.
declare -a LABELS=(
    "loss-1pct"
    "loss-5pct"
    "loss-10pct"
    "latency-100ms"
    "latency-300ms"
    "jitter-50ms-20ms"
    "bandwidth-1mbit"
)

declare -a PARAMS=(
    "loss 1%"
    "loss 5%"
    "loss 10%"
    "delay 100ms"
    "delay 300ms"
    "delay 50ms 20ms"
    "rate 1mbit"
)

if [[ "${#LABELS[@]}" -ne "${#PARAMS[@]}" ]]; then
    echo "BUG: LABELS and PARAMS arrays must have the same length." >&2
    exit 1
fi

# ── helpers ───────────────────────────────────────────────────────────────────

netem_add() {
    # $1: tc netem parameters (e.g. "loss 1%" or "delay 100ms")
    # shellcheck disable=SC2086
    tc qdisc add dev "$IFACE" root netem $1
}

netem_del() {
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
}

run_tests() {
    local log="$1"
    cd "$CARGO_ROOT"
    cargo test -p integration-tests 2>&1 | tee "$log"
}

# ── guard: must be root / have CAP_NET_ADMIN ─────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: run-netem.sh must run as root (or with sudo) to manage tc qdiscs." >&2
    exit 1
fi

if ! command -v tc &>/dev/null; then
    echo "ERROR: 'tc' not found. Install iproute2: apt-get install iproute2" >&2
    exit 1
fi

# ── ensure loopback is clean before we start ─────────────────────────────────

netem_del

# ── main loop ────────────────────────────────────────────────────────────────

declare -a RESULTS=()
OVERALL=0

for i in "${!LABELS[@]}"; do
    label="${LABELS[$i]}"
    params="${PARAMS[$i]}"
    log="$REPORT_DIR/vps-netem-${label}.log"

    echo ""
    echo "════════════════════════════════════════════════════════"
    echo "  netem profile: ${label}  (tc: ${params})"
    echo "════════════════════════════════════════════════════════"

    netem_add "$params"

    set +e
    run_tests "$log"
    exit_code=$?
    set -e

    netem_del

    if [[ $exit_code -eq 0 ]]; then
        RESULTS+=("PASS  ${label}")
        echo "→ PASS"
    else
        RESULTS+=("FAIL  ${label}")
        OVERALL=1
        echo "→ FAIL (see ${log})"
    fi
done

# ── summary ──────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════════════════════"
echo "  netem test summary"
echo "════════════════════════════════════════════════════════"
for r in "${RESULTS[@]}"; do
    echo "  $r"
done
echo ""

if [[ $OVERALL -eq 0 ]]; then
    echo "All netem profiles PASSED."
else
    echo "One or more netem profiles FAILED."
fi

exit $OVERALL
