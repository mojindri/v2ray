#!/usr/bin/env bash
set -euo pipefail
REPORT_DIR="${1:-reports/production}"
mkdir -p "$REPORT_DIR"
LOG="$REPORT_DIR/tls-fingerprint-$(date -u +%Y%m%dT%H%M%SZ).log"
exec > >(tee "$LOG") 2>&1

echo "=== TLS fingerprint helper ==="
echo "This script does not start blackwire. Start the client/server path you want to inspect, then capture traffic."
echo ""
echo "Useful commands:"
echo "  sudo tcpdump -i any -w $REPORT_DIR/clienthello.pcap 'tcp port 443 or tcp port 8443 or udp port 443'"
echo "  tshark -r $REPORT_DIR/clienthello.pcap -Y 'tls.handshake.type == 1' -V"
echo "  ja3 -a $REPORT_DIR/clienthello.pcap  # if ja3 tooling is installed"
echo ""
if command -v tshark >/dev/null 2>&1; then
  echo "tshark found. If $REPORT_DIR/clienthello.pcap exists, extracting ClientHello summary:"
  if [[ -f "$REPORT_DIR/clienthello.pcap" ]]; then
    tshark -r "$REPORT_DIR/clienthello.pcap" -Y 'tls.handshake.type == 1' \
      -T fields \
      -e frame.time_epoch \
      -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
      -e tls.handshake.extensions_server_name \
      -e tls.handshake.extensions_alpn_str \
      -e tls.handshake.ciphersuite \
      -e tls.handshake.extension.type || true
  else
    echo "No $REPORT_DIR/clienthello.pcap yet."
  fi
else
  echo "tshark not installed. Install Wireshark/tshark to parse captures."
fi

echo "Compare extension order, cipher order, ALPN, supported groups, SNI, GREASE, and record sizing against fingerprints/chrome-131.json or your intended target."
