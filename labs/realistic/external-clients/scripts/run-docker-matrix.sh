#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REALISTIC_DIR="$(cd "$LAB_DIR/.." && pwd)"
REPORT_DIR="${1:-$REALISTIC_DIR/reports/external-clients}"
ENV_FILE="${2:-$REALISTIC_DIR/configs/matrix.env}"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-blackwire-external-clients}"
COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$LAB_DIR/docker-compose.yml")
TARGET_URL="http://target-http:8080"
NETWORK_NAME="${PROJECT_NAME}_default"

mkdir -p "$REPORT_DIR/logs"

# Only one matrix run at a time (no parallel Xray/sing-box or overlapping makes).
LOCKDIR="$REPORT_DIR/.matrix.lock.d"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
    echo "ERROR: external-client matrix already running (lock: $LOCKDIR)" >&2
    exit 1
fi

bash "$LAB_DIR/scripts/render-configs.sh" "$ENV_FILE" "$LAB_DIR/generated" > "$REPORT_DIR/render.log" 2>&1

"${COMPOSE[@]}" up -d target-http > "$REPORT_DIR/compose.log" 2>&1

cleanup_case() {
    "${COMPOSE[@]}" stop blackwire-server xray-client sing-box-client >/dev/null 2>&1 || true
    docker rm -f blackwire-server xray-client sing-box-client 2>/dev/null || true
    # Remove stale one-off server containers from prior matrix rows.
    while read -r cid; do
        [[ -n "$cid" ]] && docker rm -f "$cid" >/dev/null 2>&1 || true
    done < <(docker ps -aq --filter "name=blackwire-server" 2>/dev/null || true)
}

cleanup_all() {
    cleanup_case
    "${COMPOSE[@]}" down -v >> "$REPORT_DIR/compose.log" 2>&1 || true
    rmdir "$LOCKDIR" 2>/dev/null || true
}
trap cleanup_all EXIT

# Ensure at most one external client container is running (never Xray + sing-box together).
assert_single_client() {
    local n
    n="$(docker ps -q --filter "name=xray-client" --filter "name=sing-box-client" 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "${n:-0}" -gt 1 ]]; then
        echo "ERROR: multiple external clients running; sequential matrix violated" >&2
        exit 1
    fi
}

port_for_protocol() {
    case "$1" in
        trojan-tls) echo 8445 ;;
        vless-tcp) echo 10080 ;;
        vless-udp) echo 10081 ;;
        vless-ws) echo 8443 ;;
        vless-httpupgrade) echo 8446 ;;
        vmess-grpc) echo 8444 ;;
        ss2022) echo 8388 ;;
        hysteria2) echo 4433 ;;
        vless-reality) echo 10443 ;;
        *) echo "" ;;
    esac
}

wait_for_server_port() {
    local protocol="$1"
    local port
    port="$(port_for_protocol "$protocol")"
    [[ -z "$port" ]] && return 0
    # Hysteria2 binds QUIC/UDP; TCP nc -z never succeeds (same as run-vps-matrix.sh).
    if [[ "$protocol" == "hysteria2" ]]; then
        sleep 3
        return 0
    fi
    local i
    for i in $(seq 1 20); do
        if docker run --rm --network "$NETWORK_NAME" busybox:1.36 \
            nc -z blackwire-server "$port" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "server port $port not open for $protocol" >&2
    return 1
}

wait_for_socks() {
    local client="$1"
    local i
    for i in $(seq 1 20); do
        if docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.10.1 \
            -fsS --max-time 2 --socks5-hostname "${client}:1080" "$TARGET_URL" \
            >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

run_one() {
    local protocol="$1" client="$2" server_cfg="$3" client_cfg="$4"
    local config_root="${5:-$client}"
    local label="${client}-${protocol}"
    local log="$REPORT_DIR/logs/${label}.log"

    if [[ "$client_cfg" == "-" ]]; then
        echo "SKIP ${label}" | tee -a "$REPORT_DIR/summary.txt"
        return 0
    fi

    cleanup_case
    assert_single_client

    # --use-aliases: required so freedom outbound can resolve compose service "target-http".
    "${COMPOSE[@]}" run -d --no-deps --use-aliases --name blackwire-server blackwire-server \
        run -c "/generated/blackwire/${server_cfg}" >> "$log" 2>&1

    if ! wait_for_server_port "$protocol"; then
        echo "FAIL ${label} (server not listening)" | tee -a "$REPORT_DIR/summary.txt"
        docker logs blackwire-server >> "$log" 2>&1 || true
        echo "  triage: docs/external-client-failure-triage.md" >> "$log"
        return 1
    fi

    # One client only — never start Xray and sing-box concurrently.
    if [[ "$client" == "xray" ]]; then
        "${COMPOSE[@]}" run -d --no-deps --use-aliases --name xray-client xray-client \
            run -c "/generated/${config_root}/${client_cfg}" >> "$log" 2>&1
    else
        "${COMPOSE[@]}" run -d --no-deps --use-aliases --name sing-box-client sing-box-client \
            run -c "/generated/${config_root}/${client_cfg}" >> "$log" 2>&1
    fi
    assert_single_client

    if wait_for_socks "${client}-client"; then
        echo "PASS ${label}" | tee -a "$REPORT_DIR/summary.txt"
        return 0
    fi

    echo "FAIL ${label}" | tee -a "$REPORT_DIR/summary.txt"
    docker logs blackwire-server >> "$log" 2>&1 || true
    docker logs "${client}-client" >> "$log" 2>&1 || true
    {
        echo "--- triage ---"
        echo "See docs/external-client-failure-triage.md"
        echo "Xray VLESS: github.com/XTLS/Xray-core/tree/main/proxy/vless"
        echo "sing-box VLESS: sing-box.sagernet.org/configuration/outbound/vless/"
    } >> "$log"
    return 1
}

run_negative() {
    local protocol="$1" client="$2" server_cfg="$3" client_cfg="$4"
    local root
    local label="negative-${client}-${protocol}"
    local log="$REPORT_DIR/logs/${label}.log"

    if [[ "$client_cfg" == "-" ]]; then
        echo "SKIP ${label}" | tee -a "$REPORT_DIR/summary.txt"
        return 0
    fi

    if [[ "$client" == "xray" ]]; then
        root="xray-negative"
    else
        root="sing-box-negative"
    fi

    cleanup_case
    assert_single_client

    # --use-aliases: required so freedom outbound can resolve compose service "target-http".
    "${COMPOSE[@]}" run -d --no-deps --use-aliases --name blackwire-server blackwire-server \
        run -c "/generated/blackwire/${server_cfg}" >> "$log" 2>&1

    if ! wait_for_server_port "$protocol"; then
        echo "FAIL ${label} (server not listening)" | tee -a "$REPORT_DIR/summary.txt"
        docker logs blackwire-server >> "$log" 2>&1 || true
        return 1
    fi

    if [[ "$client" == "xray" ]]; then
        "${COMPOSE[@]}" run -d --no-deps --use-aliases --name xray-client xray-client \
            run -c "/generated/${root}/${client_cfg}" >> "$log" 2>&1
    else
        "${COMPOSE[@]}" run -d --no-deps --use-aliases --name sing-box-client sing-box-client \
            run -c "/generated/${root}/${client_cfg}" >> "$log" 2>&1
    fi
    assert_single_client

    if wait_for_socks "${client}-client"; then
        echo "FAIL ${label} accepted" | tee -a "$REPORT_DIR/summary.txt"
        docker logs blackwire-server >> "$log" 2>&1 || true
        docker logs "${client}-client" >> "$log" 2>&1 || true
        return 1
    fi

    echo "PASS ${label} rejected" | tee -a "$REPORT_DIR/summary.txt"
    return 0
}

: > "$REPORT_DIR/summary.txt"
overall=0

while IFS='|' read -r protocol server_cfg xray_cfg sing_cfg; do
    [[ -z "${protocol:-}" || "$protocol" =~ ^# ]] && continue
    run_one "$protocol" xray "$server_cfg" "$xray_cfg" || overall=1
    run_one "$protocol" sing-box "$server_cfg" "$sing_cfg" || overall=1
    run_negative "$protocol" xray "$server_cfg" "$xray_cfg" || overall=1
    run_negative "$protocol" sing-box "$server_cfg" "$sing_cfg" || overall=1
done < "$LAB_DIR/scenarios.env"

echo "External-client report: $REPORT_DIR/summary.txt"
exit "$overall"
