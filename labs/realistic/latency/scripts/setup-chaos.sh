#!/usr/bin/env bash
# setup-chaos.sh — tc-netem loopback chaos for latency lab
#
# Linux only. Requires root or CAP_NET_ADMIN.
# On Ubuntu/Debian: apt-get install iproute2
#
# Usage:
#   bash setup-chaos.sh add      # apply netem rules
#   bash setup-chaos.sh del      # remove netem rules (cleanup)
#   bash setup-chaos.sh status   # show current qdisc
#
# Environment:
#   CHAOS_IFACE   interface to emulate on (default: lo)
#   CHAOS_DELAY   base delay            (default: 50ms)
#   CHAOS_JITTER  delay variation       (default: 10ms)
#   CHAOS_LOSS    packet loss percent   (default: 5%)
set -euo pipefail

IFACE="${CHAOS_IFACE:-lo}"
DELAY="${CHAOS_DELAY:-50ms}"
JITTER="${CHAOS_JITTER:-10ms}"
LOSS="${CHAOS_LOSS:-5%}"

CMD="${1:-}"

require_linux() {
    uname -s | grep -q Linux || { echo "ERROR: setup-chaos.sh is Linux-only (tc-netem)"; exit 1; }
    command -v tc >/dev/null 2>&1 || { echo "ERROR: 'tc' not found — install iproute2"; exit 1; }
}

case "$CMD" in
  add)
    require_linux
    echo "==> chaos: adding netem on ${IFACE}: delay ${DELAY} ±${JITTER} loss ${LOSS}"
    tc qdisc add dev "$IFACE" root netem delay "$DELAY" "$JITTER" loss "$LOSS"
    echo "==> chaos: netem active"
    ;;
  del|rm|remove|cleanup)
    require_linux
    echo "==> chaos: removing netem from ${IFACE}"
    tc qdisc del dev "$IFACE" root 2>/dev/null || true
    echo "==> chaos: netem removed"
    ;;
  status)
    require_linux
    echo "==> chaos: qdisc on ${IFACE}:"
    tc qdisc show dev "$IFACE"
    ;;
  *)
    echo "Usage: setup-chaos.sh add|del|status"
    echo "  CHAOS_IFACE=${IFACE}  CHAOS_DELAY=${DELAY}  CHAOS_JITTER=${JITTER}  CHAOS_LOSS=${LOSS}"
    exit 1
    ;;
esac
