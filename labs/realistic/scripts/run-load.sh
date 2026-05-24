#!/usr/bin/env bash
set -euo pipefail
ENV_FILE="${1:-configs/load.env}"
REPORT_DIR="${2:-reports/production}"
mkdir -p "$REPORT_DIR"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE"
: "${SOCKS_HOST:=127.0.0.1}"
: "${SOCKS_PORT:=1080}"
: "${TARGET_URL:=http://127.0.0.1:18080/}"
: "${CONCURRENCY:=50}"
: "${REQUESTS:=250}"
: "${CONNECT_TIMEOUT_SECS:=3}"
: "${READ_TIMEOUT_SECS:=8}"
OUT="$REPORT_DIR/load-$(date -u +%Y%m%dT%H%M%SZ).json"
python3 - <<PY
import socket, sys
host='$SOCKS_HOST'; port=int('$SOCKS_PORT')
s=socket.socket(); s.settimeout(0.5)
try:
    s.connect((host, port))
except OSError:
    print(f'SKIP: no local SOCKS proxy listening at {host}:{port}. Start blackwire first for a real load test.')
exit 0
    open('$OUT','w').write('{"status":"skipped","reason":"no local SOCKS proxy"}\n')
    sys.exit(0)
finally:
    s.close()
PY
python3 scripts/socks_http_load.py \
  --socks-host "$SOCKS_HOST" \
  --socks-port "$SOCKS_PORT" \
  --target-url "$TARGET_URL" \
  --concurrency "$CONCURRENCY" \
  --requests "$REQUESTS" \
  --connect-timeout "$CONNECT_TIMEOUT_SECS" \
  --read-timeout "$READ_TIMEOUT_SECS" \
  --json "$OUT"
echo "Wrote $OUT"
