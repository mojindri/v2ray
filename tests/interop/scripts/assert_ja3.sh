#!/usr/bin/env bash
# assert_ja3.sh <pcap_file> <expected_ja3_string>
# Extracts the JA3 fingerprint from the first ClientHello in the pcap and
# compares it against the expected value.
#
# Requires: tshark  (brew install wireshark  /  apt install tshark)
set -euo pipefail

PCAP="${1:?usage: $0 <pcap_file> <expected_ja3>}"
EXPECTED="${2:?usage: $0 <pcap_file> <expected_ja3>}"

if ! command -v tshark &>/dev/null; then
    echo "ERROR: tshark not found."
    echo "  macOS : brew install wireshark"
    echo "  Ubuntu: sudo apt install tshark"
    exit 1
fi

if [[ ! -f "$PCAP" ]]; then
    echo "ERROR: pcap file not found: $PCAP"
    exit 1
fi

echo "Analyzing: $PCAP"

ACTUAL=$(tshark -r "$PCAP" \
    -Y "tls.handshake.type == 1" \
    -T fields \
    -e tls.handshake.ja3 \
    2>/dev/null | head -1 | tr -d '\n\r')

if [[ -z "$ACTUAL" ]]; then
    echo "ERROR: no TLS ClientHello found in pcap."
    echo "       Did the test actually run while pcap was capturing?"
    exit 1
fi

echo "Expected : $EXPECTED"
echo "Actual   : $ACTUAL"

if [[ "$ACTUAL" == "$EXPECTED" ]]; then
    echo "✓ JA3 matches Chrome 131"
    exit 0
else
    echo "✗ JA3 mismatch — fingerprint drift detected"
    exit 1
fi
