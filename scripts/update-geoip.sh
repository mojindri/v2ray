#!/usr/bin/env bash
# update-geoip.sh — Download the latest GeoIP and GeoSite data files.
#
# These files are used by the router in Phase 4+ to match traffic by country
# (e.g. route traffic destined for Chinese IPs directly, and everything else
# through the proxy).
#
# Sources:
#   - geoip.dat:   https://github.com/v2fly/geoip (CC-BY-SA 4.0)
#   - geosite.dat: https://github.com/v2fly/domain-list-community (MIT)
#
# The files are placed in the current directory by default, or in the directory
# specified by the DATA_DIR environment variable.

set -euo pipefail

DATA_DIR="${DATA_DIR:-/usr/local/share/blackwire}"
GEOIP_URL="https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
GEOSITE_URL="https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat"

mkdir -p "$DATA_DIR"

echo "Downloading geoip.dat from v2fly/geoip..."
curl -L --progress-bar -o "$DATA_DIR/geoip.dat" "$GEOIP_URL"
echo "Saved to $DATA_DIR/geoip.dat"

echo "Downloading geosite.dat from v2fly/domain-list-community..."
curl -L --progress-bar -o "$DATA_DIR/geosite.dat" "$GEOSITE_URL"
echo "Saved to $DATA_DIR/geosite.dat"

echo ""
echo "Update complete. Add these to your config.json:"
echo '  "geoipPath":   "'"$DATA_DIR/geoip.dat"'"'
echo '  "geositePath": "'"$DATA_DIR/geosite.dat"'"'
