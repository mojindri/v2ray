#!/usr/bin/env bash
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

mkdir -p "$REPORT_DIR/logs"
: > "$SUMMARY"

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
        vless-ws) echo 8443 ;;
        vmess-grpc) echo 8444 ;;
        ss2022) echo 8388 ;;
        hysteria2) echo 4433 ;;
        vless-reality) echo 10443 ;;
        *) echo "" ;;
    esac
}

cleanup_client() {
    ssh_client 'docker rm -f external-xray-client external-sing-box-client >/dev/null 2>&1 || true' \
        >> "$REPORT_DIR/cleanup.log" 2>&1 || true
}

cleanup_server() {
    ssh_server 'if [ -f /tmp/blackwire-external.pid ]; then kill "$(cat /tmp/blackwire-external.pid)" >/dev/null 2>&1 || true; rm -f /tmp/blackwire-external.pid; fi' \
        >> "$REPORT_DIR/cleanup.log" 2>&1 || true
}

cleanup_all() {
    cleanup_client
    cleanup_server
}
trap cleanup_all EXIT

echo "==> Rendering external-client VPS configs" > "$REPORT_DIR/render.log"
EXTERNAL_SERVER_ADDRESS="$SERVER_HOST" \
EXTERNAL_TLS_SERVER_NAME="$TEST_DOMAIN" \
    bash "$LAB_DIR/scripts/render-configs.sh" "$ENV_FILE" "$GENERATED_DIR" >> "$REPORT_DIR/render.log" 2>&1

echo "==> Preflight"
ssh_client 'command -v docker >/dev/null && command -v curl >/dev/null && command -v nc >/dev/null' \
    > "$REPORT_DIR/preflight-client.log" 2>&1 || {
    echo "ERROR: CLIENT VPS needs docker, curl, and nc. Run client setup or install Docker manually." >&2
    exit 1
}
ssh_server 'test -x /usr/local/bin/blackwire && test -d /etc/blackwire/generated && test -f /etc/blackwire/certs/cert.pem' \
    > "$REPORT_DIR/preflight-server.log" 2>&1 || {
    echo "ERROR: SERVER VPS needs /usr/local/bin/blackwire plus generated configs/certs." >&2
    exit 1
}
ssh_client "mkdir -p '$REMOTE_DIR/generated'" > "$REPORT_DIR/remote-mkdir.log" 2>&1
copy_to_client

run_one() {
    local protocol="$1" client="$2" server_cfg="$3" client_cfg="$4"
    local label="${client}-${protocol}"
    local log="$REPORT_DIR/logs/${label}.log"
    local port
    port="$(port_for_protocol "$protocol")"

    if [[ "$client_cfg" == "-" ]]; then
        echo "SKIP ${label}" | tee -a "$SUMMARY"
        return 0
    fi

    cleanup_all

    ssh_server "nohup /usr/local/bin/blackwire run -c '/etc/blackwire/generated/${server_cfg}' > '/tmp/blackwire-external-${protocol}.log' 2>&1 & echo \$! > /tmp/blackwire-external.pid" \
        >> "$log" 2>&1

    if [[ "$protocol" != "hysteria2" ]]; then
        ssh_client "for i in \$(seq 1 15); do nc -z '${SERVER_HOST}' '${port}' && exit 0; sleep 1; done; exit 1" \
            >> "$log" 2>&1 || {
            echo "FAIL ${label} server-port-${port}" | tee -a "$SUMMARY"
            ssh_server "cat '/tmp/blackwire-external-${protocol}.log'" >> "$log" 2>&1 || true
            return 1
        }
    fi

    if [[ "$client" == "xray" ]]; then
        ssh_client "docker run -d --rm --name external-xray-client --network host -v '${REMOTE_DIR}/generated/xray:/generated/xray:ro' ghcr.io/xtls/xray-core:latest run -c '/generated/xray/${client_cfg}'" \
            >> "$log" 2>&1
    else
        ssh_client "docker run -d --rm --name external-sing-box-client --network host -v '${REMOTE_DIR}/generated/sing-box:/generated/sing-box:ro' ghcr.io/sagernet/sing-box:latest run -c '/generated/sing-box/${client_cfg}'" \
            >> "$log" 2>&1
    fi

    if ssh_client "for i in \$(seq 1 20); do curl -fsS --max-time 3 --socks5-hostname 127.0.0.1:1080 '${TARGET_URL}' >/dev/null && exit 0; sleep 1; done; exit 1" \
        >> "$log" 2>&1; then
        echo "PASS ${label}" | tee -a "$SUMMARY"
        return 0
    fi

    echo "FAIL ${label}" | tee -a "$SUMMARY"
    ssh_server "cat '/tmp/blackwire-external-${protocol}.log'" >> "$log" 2>&1 || true
    ssh_client "docker logs external-${client}-client" >> "$log" 2>&1 || true
    return 1
}

run_negative() {
    local protocol="$1" client="$2" server_cfg="$3" client_cfg="$4"
    local label="negative-${client}-${protocol}"
    local log="$REPORT_DIR/logs/${label}.log"
    local root
    local port
    port="$(port_for_protocol "$protocol")"

    if [[ "$client_cfg" == "-" ]]; then
        echo "SKIP ${label}" | tee -a "$SUMMARY"
        return 0
    fi
    if [[ "$client" == "xray" ]]; then
        root="xray-negative"
    else
        root="sing-box-negative"
    fi

    cleanup_all

    ssh_server "nohup /usr/local/bin/blackwire run -c '/etc/blackwire/generated/${server_cfg}' > '/tmp/blackwire-external-${protocol}.log' 2>&1 & echo \$! > /tmp/blackwire-external.pid" \
        >> "$log" 2>&1

    if [[ "$protocol" != "hysteria2" ]]; then
        ssh_client "for i in \$(seq 1 15); do nc -z '${SERVER_HOST}' '${port}' && exit 0; sleep 1; done; exit 1" \
            >> "$log" 2>&1 || {
            echo "FAIL ${label} server-port-${port}" | tee -a "$SUMMARY"
            ssh_server "cat '/tmp/blackwire-external-${protocol}.log'" >> "$log" 2>&1 || true
            return 1
        }
    fi

    if [[ "$client" == "xray" ]]; then
        ssh_client "docker run -d --rm --name external-xray-client --network host -v '${REMOTE_DIR}/generated:/generated:ro' ghcr.io/xtls/xray-core:latest run -c '/generated/${root}/${client_cfg}'" \
            >> "$log" 2>&1
    else
        ssh_client "docker run -d --rm --name external-sing-box-client --network host -v '${REMOTE_DIR}/generated:/generated:ro' ghcr.io/sagernet/sing-box:latest run -c '/generated/${root}/${client_cfg}'" \
            >> "$log" 2>&1
    fi

    if ssh_client "for i in \$(seq 1 20); do curl -fsS --max-time 3 --socks5-hostname 127.0.0.1:1080 '${TARGET_URL}' >/dev/null && exit 0; sleep 1; done; exit 1" \
        >> "$log" 2>&1; then
        echo "FAIL ${label} accepted" | tee -a "$SUMMARY"
        ssh_server "cat '/tmp/blackwire-external-${protocol}.log'" >> "$log" 2>&1 || true
        ssh_client "docker logs external-${client}-client" >> "$log" 2>&1 || true
        return 1
    fi

    echo "PASS ${label} rejected" | tee -a "$SUMMARY"
    return 0
}

overall=0
while IFS='|' read -r protocol server_cfg xray_cfg sing_cfg; do
    [[ -z "${protocol:-}" || "$protocol" =~ ^# ]] && continue
    run_one "$protocol" xray "$server_cfg" "$xray_cfg" || overall=1
    run_one "$protocol" sing-box "$server_cfg" "$sing_cfg" || overall=1
    run_negative "$protocol" xray "$server_cfg" "$xray_cfg" || overall=1
    run_negative "$protocol" sing-box "$server_cfg" "$sing_cfg" || overall=1
done < "$LAB_DIR/scenarios.env"

echo "External-client VPS report: $SUMMARY"
exit "$overall"
