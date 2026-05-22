#!/usr/bin/env bash
# run_pcap.sh [output_pcap]
# Starts a tcpdump capture on port 8443.  Press Ctrl-C to stop.
# After stopping, run: make analyze
set -euo pipefail

PCAP="${1:-pcaps/capture.pcap}"
mkdir -p "$(dirname "$PCAP")"

echo "Starting capture → $PCAP"
echo "Run 'cargo test --test interop -- --ignored' in another terminal, then Ctrl-C here."
echo ""

# macOS uses lo0; Linux uses lo.
IFACE="lo0"
if [[ "$(uname)" == "Linux" ]]; then
    IFACE="lo"
fi

tcpdump -i "$IFACE" -w "$PCAP" "port 8443"
