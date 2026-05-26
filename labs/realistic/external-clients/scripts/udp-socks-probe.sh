#!/usr/bin/env sh
# SOCKS5 UDP ASSOCIATE probe: sends a DNS A query through the UDP relay.
# Exercises Trojan CMD 0x03 (trojan-udp) and VLESS XUDP (vless-udp) end-to-end.
#
# Requires python3 (alpine: apk add python3).
# proxychains4 cannot be used here: it rejects hostnames as the first entry in
# a strict chain and does not perform real SOCKS5 UDP ASSOCIATE for tools (like
# dig) that call sendto() without a prior connect() on the UDP socket.
set -eu

PROXY_HOST="${1:?proxy host}"
PROXY_PORT="${2:-1080}"
QUERY_NAME="${3:-example.com}"
RESOLVER="${4:-8.8.8.8}"

if ! command -v python3 >/dev/null 2>&1; then
    echo "udp-socks-probe: python3 not found" >&2
    exit 1
fi

python3 - "$PROXY_HOST" "$PROXY_PORT" "$RESOLVER" "$QUERY_NAME" <<'PY'
import socket, struct, sys

proxy_host = sys.argv[1]
proxy_port = int(sys.argv[2])
resolver   = sys.argv[3]
query_name = sys.argv[4]
TXID       = 0x1337

def build_dns_query(name, txid):
    buf = struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 0)
    for label in name.split('.'):
        buf += bytes([len(label)]) + label.encode()
    buf += b'\x00\x01\x00\x01'  # QTYPE=A, QCLASS=IN
    return buf

def socks5_udp_wrap(dest_ip, dest_port, data):
    # RSV(2) + FRAG(1) + ATYP=IPv4(1) + IP(4) + PORT(2) + data
    return b'\x00\x00\x00\x01' + socket.inet_aton(dest_ip) + struct.pack('>H', dest_port) + data

def unwrap_socks5_udp(resp):
    """Extract DNS payload from SOCKS5 UDP reply (IPv4 or IPv6 ATYP)."""
    if len(resp) < 4:
        return None
    atyp = resp[3]
    if atyp == 1 and len(resp) >= 10:   # IPv4: 4+4+2 = 10 byte header
        return resp[10:]
    if atyp == 4 and len(resp) >= 22:   # IPv6: 4+16+2 = 22 byte header
        return resp[22:]
    return None

try:
    # 1. TCP control channel: SOCKS5 greeting + UDP ASSOCIATE (RFC 1928 §6)
    tcp = socket.create_connection((proxy_host, proxy_port), timeout=5)
    tcp.sendall(b'\x05\x01\x00')            # VER=5, NMETHODS=1, METHOD=0 (no auth)
    if tcp.recv(2) != b'\x05\x00':
        print("udp-socks-probe: SOCKS5 greeting rejected", file=sys.stderr)
        sys.exit(1)
    # CMD=0x03 UDP ASSOCIATE, bind 0.0.0.0:0
    tcp.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
    reply = tcp.recv(32)
    if not reply or reply[1] != 0x00:
        rep = reply[1] if reply else -1
        print(f"udp-socks-probe: UDP ASSOCIATE failed REP=0x{rep:02x}", file=sys.stderr)
        sys.exit(1)
    relay_ip   = socket.inet_ntoa(reply[4:8])
    relay_port = struct.unpack('>H', reply[8:10])[0]

    # 2. UDP socket: send DNS A query wrapped in SOCKS5 UDP header
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    dns_pkt = build_dns_query(query_name, TXID)
    udp.sendto(socks5_udp_wrap(resolver, 53, dns_pkt), (relay_ip, relay_port))

    # 3. Receive response and match transaction ID
    resp, _ = udp.recvfrom(4096)
    dns_data = unwrap_socks5_udp(resp)
    if dns_data and len(dns_data) >= 2:
        resp_txid = struct.unpack('>H', dns_data[:2])[0]
        if resp_txid == TXID:
            sys.exit(0)
        print(f"udp-socks-probe: txid mismatch got=0x{resp_txid:04x} want=0x{TXID:04x}",
              file=sys.stderr)
    else:
        print(f"udp-socks-probe: malformed reply {(resp or b'').hex()[:40]}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"udp-socks-probe: {e}", file=sys.stderr)
    sys.exit(1)
PY
