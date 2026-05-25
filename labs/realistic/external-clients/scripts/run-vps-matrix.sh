#!/usr/bin/env bash
# VPS external-client matrix — same scenario set and sequencing as run-docker-matrix.sh:
# one blackwire server start per protocol, four client cases (xray, sing-box, negatives).
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REALISTIC_DIR="$(cd "$LAB_DIR/.." && pwd)"
REPORT_DIR="${1:-$REALISTIC_DIR/reports/external-clients-vps}"
ENV_FILE="${2:-$REALISTIC_DIR/configs/matrix.env}"

if [[ -z "${SSH_SERVER:-}" || -z "${SSH_CLIENT:-}" ]]; then
    echo "ERROR: SSH_SERVER and SSH_CLIENT must be set." >&2
    exit 1
fi
if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: matrix env not found: $ENV_FILE" >&2
    exit 1
fi

set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

SSH_USER="${SSH_USER:-root}"
SSH_PORT="${SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-}"
SSH_EXTRA_OPTS="${SSH_EXTRA_OPTS:-}"
TARGET_URL="http://${SERVER_HOST}:18080"
REMOTE_DIR="/root/lab/external-clients"
GENERATED_DIR="$LAB_DIR/generated-vps"
SUMMARY="$REPORT_DIR/summary.txt"

PORT_WAIT_TRIES="${MATRIX_PORT_WAIT_TRIES:-15}"
PORT_WAIT_SLEEP="${MATRIX_PORT_WAIT_SLEEP:-1}"
SOCKS_WAIT_TRIES="${MATRIX_SOCKS_WAIT_TRIES:-20}"
SOCKS_WAIT_SLEEP="${MATRIX_SOCKS_WAIT_SLEEP:-1}"

mkdir -p "$REPORT_DIR/logs"
: > "$SUMMARY"

LOCKDIR="$REPORT_DIR/.matrix.lock.d"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
    echo "ERROR: external-client VPS matrix already running (lock: $LOCKDIR)" >&2
    exit 1
fi

SSH_OPTS=(-p "$SSH_PORT")
SCP_OPTS=(-P "$SSH_PORT")
if [[ -n "$SSH_KEY" ]]; then
    SSH_OPTS+=(-i "$SSH_KEY")
    SCP_OPTS+=(-i "$SSH_KEY")
fi
if [[ -n "$SSH_EXTRA_OPTS" ]]; then
    # shellcheck disable=SC2206
    EXTRA=($SSH_EXTRA_OPTS)
    SSH_OPTS+=("${EXTRA[@]}")
    SCP_OPTS+=("${EXTRA[@]}")
fi

ssh_client() {
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${SSH_CLIENT}" "$@"
}

ssh_server() {
    ssh "${SSH_OPTS[@]}" "${SSH_USER}@${SSH_SERVER}" "$@"
}

copy_to_client() {
    scp "${SCP_OPTS[@]}" -r \
        "$GENERATED_DIR/xray" \
        "$GENERATED_DIR/sing-box" \
        "$GENERATED_DIR/xray-negative" \
        "$GENERATED_DIR/sing-box-negative" \
        "${SSH_USER}@${SSH_CLIENT}:${REMOTE_DIR}/generated/" \
        > "$REPORT_DIR/sync.log" 2>&1
}

port_for_protocol() {
    case "$1" in
        trojan-tls) echo 8445 ;;
        vless-tcp) echo 10080 ;;
        vless-vision) echo 10082 ;;
        vless-udp) echo 10081 ;;
        vless-ws) echo 8443 ;;
        vless-httpupgrade) echo 8446 ;;
        vless-quic) echo 8447 ;;
        vless-splithttp) echo 8448 ;;
        vmess-grpc) echo 8444 ;;
        ss2022) echo 8388 ;;
        hysteria2) echo 4433 ;;
        vless-reality) echo 10443 ;;
        vless-shadowtls) echo 8450 ;;
        vless-mkcp) echo 8451 ;;
        vless-sniff) echo 8452 ;;
        *) echo "" ;;
    esac
}

stop_client() {
    ssh_client 'docker rm -f external-xray-client external-sing-box-client >/dev/null 2>&1 || true' \
        >> "$REPORT_DIR/cleanup.log" 2>&1 || true
}

stop_server() {
    ssh_server 'if [ -f /tmp/blackwire-external.pid ]; then kill "$(cat /tmp/blackwire-external.pid)" >/dev/null 2>&1 || true; rm -f /tmp/blackwire-external.pid; fi' \
        >> "$REPORT_DIR/cleanup.log" 2>&1 || true
}

cleanup_all() {
    stop_client
    stop_server
    rmdir "$LOCKDIR" 2>/dev/null || true
}
trap cleanup_all EXIT

assert_single_client() {
    local n=0
    ssh_client 'docker ps --filter status=running --format "{{.Names}}" | grep -qx external-xray-client' \
        2>/dev/null && n=$((n + 1)) || true
    ssh_client 'docker ps --filter status=running --format "{{.Names}}" | grep -qx external-sing-box-client' \
        2>/dev/null && n=$((n + 1)) || true
    if [[ "${n:-0}" -gt 1 ]]; then
        echo "ERROR: multiple external clients on VPS (${n}); sequential matrix violated" >&2
        exit 1
    fi
}

append_logs() {
    local log="$1" protocol="$2" client="$3"
    ssh_server "cat '/tmp/blackwire-external-${protocol}.log'" >> "$log" 2>&1 || true
    if [[ -n "$client" ]]; then
        ssh_client "docker logs external-${client}-client" >> "$log" 2>&1 || true
    fi
}

wait_for_server_port() {
    local protocol="$1"
    local port
    port="$(port_for_protocol "$protocol")"

    if [[ "$protocol" == "vless-shadowtls" ]]; then
        ssh_client "for i in \$(seq 1 ${PORT_WAIT_TRIES}); do \
            nc -z '${SERVER_HOST}' 443 && sleep 1 && nc -z '${SERVER_HOST}' '${port}' && exit 0; \
            sleep ${PORT_WAIT_SLEEP}; done; exit 1" || return 1
        return 0
    fi
    if [[ "$protocol" == "hysteria2" || "$protocol" == "vless-quic" || "$protocol" == "vless-mkcp" ]]; then
        sleep 2
        return 0
    fi
    [[ -z "$port" ]] && return 0
    ssh_client "for i in \$(seq 1 ${PORT_WAIT_TRIES}); do \
        nc -z '${SERVER_HOST}' '${port}' && exit 0; sleep ${PORT_WAIT_SLEEP}; done; exit 1"
}

start_server() {
    local protocol="$1" server_cfg="$2"
    stop_server
    ssh_server "nohup /usr/local/bin/blackwire run -c '/etc/blackwire/generated/${server_cfg}' \
        > '/tmp/blackwire-external-${protocol}.log' 2>&1 & echo \$! > /tmp/blackwire-external.pid"
}

wait_for_socks() {
    ssh_client "for i in \$(seq 1 ${SOCKS_WAIT_TRIES}); do \
        curl -fsS --max-time 3 --socks5-hostname 127.0.0.1:1080 '${TARGET_URL}' >/dev/null && exit 0; \
        sleep ${SOCKS_WAIT_SLEEP}; done; exit 1"
}

start_client() {
    local client="$1" client_cfg="$2" root="${3:-}"
    stop_client
    if [[ "$client" == "xray" ]]; then
        if [[ -n "$root" ]]; then
            ssh_client "docker run -d --rm --name external-xray-client --network host \
                -v '${REMOTE_DIR}/generated:/generated:ro' ghcr.io/xtls/xray-core:latest \
                run -c '/generated/${root}/${client_cfg}'"
        else
            ssh_client "docker run -d --rm --name external-xray-client --network host \
                -v '${REMOTE_DIR}/generated/xray:/generated/xray:ro' ghcr.io/xtls/xray-core:latest \
                run -c '/generated/xray/${client_cfg}'"
        fi
    else
        if [[ -n "$root" ]]; then
            ssh_client "docker run -d --rm --name external-sing-box-client --network host \
                -v '${REMOTE_DIR}/generated:/generated:ro' ghcr.io/sagernet/sing-box:latest \
                run -c '/generated/${root}/${client_cfg}'"
        else
            ssh_client "docker run -d --rm --name external-sing-box-client --network host \
                -v '${REMOTE_DIR}/generated/sing-box:/generated/sing-box:ro' ghcr.io/sagernet/sing-box:latest \
                run -c '/generated/sing-box/${client_cfg}'"
        fi
    fi
}

run_client_case() {
    local expect_pass="$1" label="$2" client="$3" client_cfg="$4" log="$5" protocol="$6"
    local neg_root=""

    if [[ "$client_cfg" == "-" ]]; then
        echo "SKIP ${label}" | tee -a "$SUMMARY"
        return 0
    fi

    if [[ "$label" == negative-* ]]; then
        if [[ "$client" == "xray" ]]; then
            neg_root="xray-negative"
        else
            neg_root="sing-box-negative"
        fi
    fi

    assert_single_client
    start_client "$client" "$client_cfg" "$neg_root"
    assert_single_client

    if wait_for_socks >>"$log" 2>&1; then
        if [[ "$expect_pass" == "pass" ]]; then
            echo "PASS ${label}" | tee -a "$SUMMARY"
            stop_client
            return 0
        fi
        echo "FAIL ${label} accepted" | tee -a "$SUMMARY"
        append_logs "$log" "$protocol" "$client"
        stop_client
        return 1
    fi

    if [[ "$expect_pass" == "pass" ]]; then
        echo "FAIL ${label}" | tee -a "$SUMMARY"
        append_logs "$log" "$protocol" "$client"
        stop_client
        return 1
    fi

    echo "PASS ${label} rejected" | tee -a "$SUMMARY"
    stop_client
    return 0
}

run_protocol() {
    local protocol="$1" server_cfg="$2" xray_cfg="$3" sing_cfg="$4"
    local overall=0

    echo "==> protocol ${protocol}" >> "$REPORT_DIR/run.log"
    start_server "$protocol" "$server_cfg" >> "$REPORT_DIR/run.log" 2>&1

    if ! wait_for_server_port "$protocol" >>"$REPORT_DIR/run.log" 2>&1; then
        echo "FAIL xray-${protocol} (server not listening)" | tee -a "$SUMMARY"
        echo "FAIL sing-box-${protocol} (server not listening)" | tee -a "$SUMMARY"
        echo "FAIL negative-xray-${protocol} (server not listening)" | tee -a "$SUMMARY"
        echo "FAIL negative-sing-box-${protocol} (server not listening)" | tee -a "$SUMMARY"
        append_logs "$REPORT_DIR/logs/xray-${protocol}.log" "$protocol" ""
        stop_server
        return 1
    fi

    run_client_case pass "xray-${protocol}" xray "$xray_cfg" \
        "$REPORT_DIR/logs/xray-${protocol}.log" "$protocol" || overall=1
    run_client_case pass "sing-box-${protocol}" sing-box "$sing_cfg" \
        "$REPORT_DIR/logs/sing-box-${protocol}.log" "$protocol" || overall=1
    run_client_case reject "negative-xray-${protocol}" xray "$xray_cfg" \
        "$REPORT_DIR/logs/negative-xray-${protocol}.log" "$protocol" || overall=1
    run_client_case reject "negative-sing-box-${protocol}" sing-box "$sing_cfg" \
        "$REPORT_DIR/logs/negative-sing-box-${protocol}.log" "$protocol" || overall=1

    stop_server
    stop_client
    return "$overall"
}

echo "==> Rendering external-client VPS configs" > "$REPORT_DIR/render.log"
EXTERNAL_SERVER_ADDRESS="$SERVER_HOST" \
EXTERNAL_TLS_SERVER_NAME="$TEST_DOMAIN" \
SHADOWTLS_DEST="${SHADOWTLS_DEST:-${TEST_DOMAIN}:443}" \
    bash "$LAB_DIR/scripts/render-configs.sh" "$ENV_FILE" "$GENERATED_DIR" >> "$REPORT_DIR/render.log" 2>&1

echo "==> Preflight"
ssh_client 'command -v docker >/dev/null && command -v curl >/dev/null && command -v nc >/dev/null' \
    > "$REPORT_DIR/preflight-client.log" 2>&1 || {
    echo "ERROR: CLIENT VPS needs docker, curl, and nc." >&2
    exit 1
}
ssh_server 'test -x /usr/local/bin/blackwire && test -d /etc/blackwire/generated && test -f /etc/blackwire/certs/cert.pem' \
    > "$REPORT_DIR/preflight-server.log" 2>&1 || {
    echo "ERROR: SERVER VPS needs blackwire binary, generated configs, and certs." >&2
    exit 1
}
ssh_client "mkdir -p '$REMOTE_DIR/generated'" > "$REPORT_DIR/remote-mkdir.log" 2>&1
copy_to_client

overall=0
exec 3< "$LAB_DIR/scenarios.env"
while IFS='|' read -r protocol server_cfg xray_cfg sing_cfg <&3; do
    [[ -z "${protocol:-}" || "$protocol" =~ ^# ]] && continue
    run_protocol "$protocol" "$server_cfg" "$xray_cfg" "$sing_cfg" || overall=1
done
exec 3<&-

echo "External-client VPS report: $SUMMARY"
exit "$overall"
