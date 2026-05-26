#!/usr/bin/env sh
# DNS A lookup via SOCKS5 UDP ASSOCIATE (proxychains + dig).
# Used by the external-client matrix for trojan-udp (Xray CMD 0x03 proof).
set -eu

PROXY_HOST="${1:?proxy host}"
PROXY_PORT="${2:-1080}"
QUERY_NAME="${3:-example.com}"
RESOLVER="${4:-8.8.8.8}"

if ! command -v dig >/dev/null 2>&1 || ! command -v proxychains4 >/dev/null 2>&1; then
    echo "udp-socks-probe: missing dig or proxychains4" >&2
    exit 1
fi

PROXYCHAINS_CONF="${TMPDIR:-/tmp}/proxychains-blackwire-matrix.conf"
cat >"$PROXYCHAINS_CONF" <<EOF
strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 5000
tcp_connect_time_out 3000
[ProxyList]
socks5 ${PROXY_HOST} ${PROXY_PORT}
EOF

export PROXYCHAINS_CONF_FILE="$PROXYCHAINS_CONF"
result=$(proxychains4 -q dig "@${RESOLVER}" "${QUERY_NAME}" A +short +time=2 +tries=1 +timeout=2 2>/dev/null | head -1)
case "$result" in
    [0-9]*.[0-9]*.[0-9]*.[0-9]*) exit 0 ;;
    *) echo "udp-socks-probe: unexpected dig result: ${result:-empty}" >&2; exit 1 ;;
esac
