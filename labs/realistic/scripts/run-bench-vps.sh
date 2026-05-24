#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-smoke}"
REPORT_ROOT="${2:-reports/production}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

REPORT_DIR="$PROJECT_ROOT/labs/realistic/$REPORT_ROOT/bench"
mkdir -p "$REPORT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT="$REPORT_DIR/bench-vps-$MODE-$TS.txt"

SSH_SERVER="${SSH_SERVER:-}"
SSH_CLIENT="${SSH_CLIENT:-}"
SSH_USER="${SSH_USER:-root}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-}"
SSH_EXTRA_OPTS="${SSH_EXTRA_OPTS:-}"
REMOTE_DIR="${VPS_REMOTE_BENCH_DIR:-/tmp/blackwire-bench}"

REQS_SMOKE="${BENCH_SMOKE_REQUESTS:-200}"
REQS_TOTAL="${BENCH_TOTAL_REQUESTS:-2000}"
CONC_SMOKE="${BENCH_SMOKE_CONCURRENCY:-10}"
CONC_TOTAL="${BENCH_TOTAL_CONCURRENCY:-50}"

if [ -z "$SSH_SERVER" ] || [ -z "$SSH_CLIENT" ]; then
  echo "ERROR: SSH_SERVER and SSH_CLIENT are required."
  echo "Example: SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 make bench-vps-smoke"
  exit 1
fi

if [ "$MODE" = "total" ]; then
  REQS="$REQS_TOTAL"
  CONC="$CONC_TOTAL"
else
  REQS="$REQS_SMOKE"
  CONC="$CONC_SMOKE"
fi

SSH_OPTS=(-o BatchMode=yes -o ConnectTimeout=8 -p "$SSH_PORT")
if [ -n "$SSH_KEY" ]; then
  SSH_OPTS+=(-i "$SSH_KEY")
fi
if [ -n "$SSH_EXTRA_OPTS" ]; then
  # shellcheck disable=SC2206
  EXTRA_SSH_OPTS=($SSH_EXTRA_OPTS)
  SSH_OPTS+=("${EXTRA_SSH_OPTS[@]}")
fi

{
  echo "bench-vps"
  echo "timestamp=$TS"
  echo "mode=$MODE"
  echo "server=$SSH_SERVER"
  echo "client=$SSH_CLIENT"
  echo "ssh_user=$SSH_USER"
  echo "ssh_port=$SSH_PORT"
  echo "ssh_key=$([ -n "$SSH_KEY" ] && echo "set" || echo "unset")"
  echo "requests=$REQS"
  echo "concurrency=$CONC"
  echo ""
} | tee "$REPORT"

echo "==> checking SSH" | tee -a "$REPORT"
ssh "${SSH_OPTS[@]}" "$SSH_USER@$SSH_SERVER" 'echo server_ssh_ok'
ssh "${SSH_OPTS[@]}" "$SSH_USER@$SSH_CLIENT" 'echo client_ssh_ok'

echo "==> preparing server" | tee -a "$REPORT"
ssh "${SSH_OPTS[@]}" "$SSH_USER@$SSH_SERVER" "bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y python3 procps curl >/dev/null
mkdir -p /tmp/blackwire-bench
cd /tmp/blackwire-bench
cat > server.py <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os

SMALL = b"ok\n"
LARGE = os.urandom(10 * 1024 * 1024)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = LARGE if self.path.startswith("/large") else SMALL
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return

ThreadingHTTPServer(("0.0.0.0", 18080), Handler).serve_forever()
PY
pkill -f '/tmp/blackwire-bench/server.py' >/dev/null 2>&1 || true
nohup python3 /tmp/blackwire-bench/server.py >/tmp/blackwire-bench/server.log 2>&1 &
sleep 1
REMOTE

echo "==> preparing client" | tee -a "$REPORT"
ssh "${SSH_OPTS[@]}" "$SSH_USER@$SSH_CLIENT" "bash -s" <<'REMOTE'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update >/dev/null
apt-get install -y curl python3 procps time golang-go >/dev/null
if ! command -v hey >/dev/null 2>&1; then
  GOBIN=/usr/local/bin go install github.com/rakyll/hey@latest
fi
REMOTE

echo "==> running client benchmark" | tee -a "$REPORT"
ssh "${SSH_OPTS[@]}" "$SSH_USER@$SSH_CLIENT" "bash -s" -- "$SSH_SERVER" "$MODE" "$REQS" "$CONC" <<'REMOTE' 2>&1 | tee -a "$REPORT"
set -euo pipefail

SERVER="$1"
MODE="$2"
REQS="$3"
CONC="$4"

echo ""
echo "client system:"
uname -a || true
nproc || true
free -m || true
echo ""

echo "server sanity:"
curl -fsS "http://$SERVER:18080/small" >/dev/null
curl -fsS "http://$SERVER:18080/large" -o /dev/null
echo "server_ok=1"
echo ""

echo "small request benchmark:"
hey -n "$REQS" -c "$CONC" "http://$SERVER:18080/small"
echo ""

echo "large transfer benchmark:"
/usr/bin/time -v curl -fsS "http://$SERVER:18080/large" -o /dev/null
echo ""

echo "connection churn benchmark:"
for i in $(seq 1 100); do
  curl -fsS --no-keepalive "http://$SERVER:18080/small" >/dev/null
done
echo "connection_churn_100=ok"
echo ""

if [ "$MODE" = "total" ]; then
  echo "total-mode extra concurrency sweep:"
  for c in 1 10 25 50 100; do
    echo "concurrency=$c"
    hey -n "$REQS" -c "$c" "http://$SERVER:18080/small"
  done
fi
REMOTE

echo "" | tee -a "$REPORT"
echo "bench-vps report: $REPORT" | tee -a "$REPORT"
