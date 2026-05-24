#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-smoke}"
REPORT_ROOT="${2:-reports/production}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

REPORT_DIR="$PROJECT_ROOT/labs/realistic/$REPORT_ROOT/bench"
mkdir -p "$REPORT_DIR"

TS="$(date -u +%Y%m%dT%H%M%SZ)"
LIMA_INSTANCE="${LIMA_INSTANCE:-blackwire-browser}"
REMOTE_DIR="${LIMA_REMOTE_BENCH_DIR:-/tmp/blackwire-bench}"
REPORT="$REPORT_DIR/bench-vm-$MODE-$TS.txt"

REQS_SMOKE="${BENCH_SMOKE_REQUESTS:-200}"
REQS_TOTAL="${BENCH_TOTAL_REQUESTS:-2000}"
CONC_SMOKE="${BENCH_SMOKE_CONCURRENCY:-10}"
CONC_TOTAL="${BENCH_TOTAL_CONCURRENCY:-50}"

if [ "$MODE" = "total" ]; then
  REQS="$REQS_TOTAL"
  CONC="$CONC_TOTAL"
else
  REQS="$REQS_SMOKE"
  CONC="$CONC_SMOKE"
fi

{
  echo "bench-vm"
  echo "timestamp=$TS"
  echo "mode=$MODE"
  echo "instance=$LIMA_INSTANCE"
  echo "requests=$REQS"
  echo "concurrency=$CONC"
  echo ""
} | tee "$REPORT"

if ! command -v limactl >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    echo "limactl missing; installing Lima..." | tee -a "$REPORT"
    brew install lima
  else
    echo "ERROR: limactl missing and Homebrew not found." | tee -a "$REPORT"
    exit 1
  fi
fi

if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$LIMA_INSTANCE"; then
  echo "ERROR: Lima instance does not exist: $LIMA_INSTANCE" | tee -a "$REPORT"
  echo "Run make check-browser first; it creates the Lima VM." | tee -a "$REPORT"
  exit 1
fi

limactl start "$LIMA_INSTANCE" >/dev/null 2>&1 || true

echo "==> preparing benchmark tools inside Lima" | tee -a "$REPORT"
limactl shell "$LIMA_INSTANCE" -- bash -lc '
set -euo pipefail
sudo DEBIAN_FRONTEND=noninteractive apt-get update >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y curl python3 procps time >/dev/null
if ! command -v hey >/dev/null 2>&1; then
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y golang-go >/dev/null
  GOBIN=/usr/local/bin sudo -E go install github.com/rakyll/hey@latest
fi
' 2>&1 | tee -a "$REPORT"

echo "==> running benchmark inside Lima" | tee -a "$REPORT"

limactl shell "$LIMA_INSTANCE" -- bash -s -- "$REMOTE_DIR" "$MODE" "$REQS" "$CONC" <<'REMOTE' 2>&1 | tee -a "$REPORT"
set -euo pipefail

REMOTE_DIR="$1"
MODE="$2"
REQS="$3"
CONC="$4"

mkdir -p "$REMOTE_DIR"
cd "$REMOTE_DIR"

cat > server.py <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os

SMALL = b"ok\n"
LARGE = os.urandom(10 * 1024 * 1024)

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/large"):
            body = LARGE
        else:
            body = SMALL
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return

ThreadingHTTPServer(("127.0.0.1", 18080), Handler).serve_forever()
PY

python3 server.py &
SERVER_PID=$!

cleanup() {
  kill "$SERVER_PID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

sleep 1

echo ""
echo "system:"
uname -a || true
nproc || true
free -m || true
echo ""

echo "tool versions:"
python3 --version || true
if hey --help >/dev/null 2>&1; then
  echo "hey=installed"
else
  echo "hey=missing"
fi
curl --version | head -1 || true
echo ""

echo "startup sanity:"
curl -fsS http://127.0.0.1:18080/small >/dev/null
curl -fsS http://127.0.0.1:18080/large -o /dev/null
echo "server_ok=1"
echo ""

echo "small request benchmark:"
hey -n "$REQS" -c "$CONC" http://127.0.0.1:18080/small
echo ""

echo "large transfer benchmark:"
/usr/bin/time -v curl -fsS http://127.0.0.1:18080/large -o /dev/null
echo ""

echo "connection churn benchmark:"
for i in $(seq 1 100); do
  curl -fsS --no-keepalive http://127.0.0.1:18080/small >/dev/null
done
echo "connection_churn_100=ok"
echo ""

echo "process snapshot:"
ps aux | head -20 || true
echo ""

if [ "$MODE" = "total" ]; then
  echo "total-mode extra concurrency sweep:"
  for c in 1 10 25 50 100; do
    echo "concurrency=$c"
    hey -n "$REQS" -c "$c" http://127.0.0.1:18080/small
  done
fi
REMOTE

echo "" | tee -a "$REPORT"
echo "bench-vm report: $REPORT" | tee -a "$REPORT"
