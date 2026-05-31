#!/usr/bin/env bash
# run-vps.sh — run latency comparison on a remote VPS client and pull results
#
# Requires SSH access to VPS_CLIENT_HOST. The remote host must have:
#   - blackwire binary in PATH (or BW_BIN set)
#   - hey in PATH
#   - curl in PATH
#   - This repo cloned at VPS_REPO_PATH
#
# Usage:
#   run-vps.sh [scenario]   (default: local-smoke)
#
# Environment (required):
#   VPS_CLIENT_HOST   SSH host for the client node (runs hey + blackwire client)
#   VPS_SERVER_HOST   Address the client uses to reach the server node (for VLESS)
#
# Environment (optional):
#   VPS_CLIENT_USER   SSH user on client (default: root)
#   VPS_CLIENT_PORT   SSH port on client (default: 22)
#   VPS_SSH_KEY       SSH key file (default: use ssh-agent)
#   VPS_REPO_PATH     Repo path on client (default: ~/Blackwire)
#   BENCH_DURATION    Duration per variant in seconds (default: 60)
#   BENCH_CONC        Concurrency (default: 32)
#   BENCH_CONCS       Concurrency matrix for server gate scenarios
#   REPORT_DIR        Local dir to write pulled results (default: ./reports)
#   BW_BIN            Remote blackwire binary path (default: blackwire)
set -euo pipefail

SCENARIO="${1:-local-smoke}"

VPS_CLIENT_HOST="${VPS_CLIENT_HOST:?ERROR: VPS_CLIENT_HOST is required}"
VPS_SERVER_HOST="${VPS_SERVER_HOST:-127.0.0.1}"
VPS_CLIENT_USER="${VPS_CLIENT_USER:-root}"
VPS_CLIENT_PORT="${VPS_CLIENT_PORT:-22}"
VPS_SSH_KEY="${VPS_SSH_KEY:-}"
VPS_REPO_PATH="${VPS_REPO_PATH:-~/Blackwire}"

BENCH_DURATION="${BENCH_DURATION:-60}"
BENCH_CONC="${BENCH_CONC:-32}"
BENCH_CONCS="${BENCH_CONCS:-}"
BENCH_PAYLOAD="${BENCH_PAYLOAD:-1k}"
BENCH_PAYLOADS="${BENCH_PAYLOADS:-}"
BENCH_KEEPALIVE_MODES="${BENCH_KEEPALIVE_MODES:-}"
REPORT_DIR="${REPORT_DIR:-$(dirname "$0")/../reports}"
BW_BIN="${BW_BIN:-blackwire}"

SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log() { echo "==> [run-vps] $*"; }

SSH_OPTS=(-p "$VPS_CLIENT_PORT" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new)
[ -n "$VPS_SSH_KEY" ] && SSH_OPTS+=(-i "$VPS_SSH_KEY")
SSH_TARGET="${VPS_CLIENT_USER}@${VPS_CLIENT_HOST}"

# ── Preflight ─────────────────────────────────────────────────────────────────

log "checking SSH to $SSH_TARGET"
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" 'echo "SSH OK"' || {
    echo "ERROR: cannot SSH to $SSH_TARGET"
    echo "  Set VPS_CLIENT_HOST, VPS_CLIENT_USER, VPS_SSH_KEY as needed"
    exit 1
}

log "checking remote tools"
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "
    command -v hey    >/dev/null 2>&1 || { echo 'ERROR: hey not found on remote'; exit 1; }
    command -v curl   >/dev/null 2>&1 || { echo 'ERROR: curl not found on remote'; exit 1; }
    test -d '$VPS_REPO_PATH' || { echo 'ERROR: VPS_REPO_PATH=$VPS_REPO_PATH not found'; exit 1; }
    echo 'remote: ok'
"

log "checking native nginx upstream on ${VPS_SERVER_HOST}:18080"
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "
    set -euo pipefail
    base='http://${VPS_SERVER_HOST}:18080'
    server_header=\"\$(curl -fsSI \"\$base/1k\" | tr -d '\r' | grep -i '^server:' | head -1 | tr '[:upper:]' '[:lower:]' || true)\"
    case \"\$server_header\" in
      *nginx*) ;;
      *) echo \"ERROR: upstream must be native nginx on :18080; got Server header: \${server_header:-<missing>}\"; exit 1 ;;
    esac
    for spec in 1k:1024 4k:4096 16k:16384 64k:65536; do
      payload=\"\${spec%%:*}\"
      expected=\"\${spec##*:}\"
      actual=\"\$(curl -fsS \"\$base/\$payload\" | wc -c | tr -d '[:space:]')\"
      if [ \"\$actual\" != \"\$expected\" ]; then
        echo \"ERROR: native nginx payload /\$payload expected \$expected bytes, got \$actual\"
        exit 1
      fi
    done
    echo 'upstream: native-nginx ok'
"

# ── Remote timestamp for result prefix ────────────────────────────────────────

REMOTE_TS="$(date -u +%Y%m%dT%H%M%SZ)"
REMOTE_REPORT_DIR="${VPS_REPO_PATH}/labs/realistic/latency/reports"

# ── Run compare.sh remotely ───────────────────────────────────────────────────

log "running scenario '$SCENARIO' on $VPS_CLIENT_HOST"
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "
    set -euo pipefail
    BENCH_DURATION=$BENCH_DURATION \
    BENCH_CONC=$BENCH_CONC \
    BENCH_CONCS='$BENCH_CONCS' \
    BENCH_PAYLOAD=$BENCH_PAYLOAD \
    BENCH_PAYLOADS='$BENCH_PAYLOADS' \
    BENCH_KEEPALIVE_MODES='$BENCH_KEEPALIVE_MODES' \
    REPORT_DIR=$REMOTE_REPORT_DIR \
    BW_BIN=$BW_BIN \
    BENCH_UPSTREAM=native-nginx \
    UPSTREAM_BASE_URL=http://${VPS_SERVER_HOST}:18080 \
    bash ${VPS_REPO_PATH}/labs/realistic/latency/scripts/compare.sh $SCENARIO
"

# ── Pull results ──────────────────────────────────────────────────────────────

mkdir -p "$REPORT_DIR"
log "pulling results from $VPS_CLIENT_HOST:$REMOTE_REPORT_DIR/*.json"

# Use scp with ssh options
SCP_OPTS=(-P "$VPS_CLIENT_PORT" -o BatchMode=yes)
[ -n "$VPS_SSH_KEY" ] && SCP_OPTS+=(-i "$VPS_SSH_KEY")

scp "${SCP_OPTS[@]}" \
    "${VPS_CLIENT_USER}@${VPS_CLIENT_HOST}:${REMOTE_REPORT_DIR}/*.json" \
    "$REPORT_DIR/" 2>/dev/null || {
    log "WARNING: no JSON files found or scp failed — results may already be local"
}

log "done — run 'make latency-report' to render results"
