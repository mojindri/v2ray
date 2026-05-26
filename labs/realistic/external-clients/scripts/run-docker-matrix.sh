#!/usr/bin/env bash
# Fast external-client matrix: one `compose up`, long-lived containers, `compose exec`
# for probes and process restarts. One blackwire server start per protocol (not per case).
# Xray image is distroless (no shell) — uses `compose run` per xray case only.
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REALISTIC_DIR="$(cd "$LAB_DIR/.." && pwd)"
REPORT_DIR="${1:-$REALISTIC_DIR/reports/external-clients}"
ENV_FILE="${2:-$REALISTIC_DIR/configs/matrix.env}"
PROJECT_NAME="${COMPOSE_PROJECT_NAME:-blackwire-external-clients}"
COMPOSE=(docker compose -p "$PROJECT_NAME" -f "$LAB_DIR/docker-compose.yml")
TARGET_URL="http://target-http:8080"

PORT_WAIT_TRIES="${MATRIX_PORT_WAIT_TRIES:-40}"
PORT_WAIT_SLEEP="${MATRIX_PORT_WAIT_SLEEP:-0.15}"
SOCKS_WAIT_TRIES="${MATRIX_SOCKS_WAIT_TRIES:-20}"
SOCKS_WAIT_SLEEP="${MATRIX_SOCKS_WAIT_SLEEP:-0.25}"
CLIENT_WAIT_TRIES="${MATRIX_CLIENT_WAIT_TRIES:-20}"

mkdir -p "$REPORT_DIR/logs"

LOCKDIR="$REPORT_DIR/.matrix.lock.d"
if ! mkdir "$LOCKDIR" 2>/dev/null; then
    echo "ERROR: external-client matrix already running (lock: $LOCKDIR)" >&2
    exit 1
fi

bash "$LAB_DIR/scripts/render-configs.sh" "$ENV_FILE" "$LAB_DIR/generated" > "$REPORT_DIR/render.log" 2>&1

port_for_protocol() {
    case "$1" in
        trojan-tls|trojan-udp) echo 8445 ;;
        vless-tcp|vless-mux) echo 10080 ;;
        vless-vision) echo 10082 ;;
        vless-udp) echo 10081 ;;
        vless-ws) echo 8443 ;;
        vless-httpupgrade) echo 8446 ;;
        vless-quic) echo 8447 ;;
        vless-splithttp) echo 8448 ;;
        vmess-grpc) echo 8444 ;;
        ss2022) echo 8388 ;;
        ss2022-udp) echo 8389 ;;
        hysteria2) echo 4433 ;;
        vless-reality) echo 10443 ;;
        vless-shadowtls) echo 8450 ;;
        vless-mkcp) echo 8451 ;;
        vless-sniff) echo 8452 ;;
        *) echo "" ;;
    esac
}

client_container_running() {
    local name="$1"
    docker ps --filter "status=running" --format '{{.Names}}' | grep -qx "$name"
}

matrix_bootstrap() {
    echo "==> Starting long-lived matrix stack (compose up -d)" >> "$REPORT_DIR/compose.log"
    stop_xray
    docker rm -f blackwire-server xray-client 2>/dev/null || true
    "${COMPOSE[@]}" down -v >> "$REPORT_DIR/compose.log" 2>&1 || true
    # xray-client is defined for compose run only (distroless image).
    "${COMPOSE[@]}" up -d target-http tls-cover matrix-probe blackwire-server sing-box-client \
        >> "$REPORT_DIR/compose.log" 2>&1

    "${COMPOSE[@]}" exec -T matrix-probe sh -c \
        'command -v python3 >/dev/null 2>&1 || apk add --no-cache curl netcat-openbsd bind-tools python3 >/dev/null' \
        </dev/null >> "$REPORT_DIR/compose.log" 2>&1 || true

    local i
    for i in $(seq 1 30); do
        if "${COMPOSE[@]}" exec -T matrix-probe sh -c \
            'nc -z -w1 target-http 8080' </dev/null >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "ERROR: target-http not ready" >&2
    return 1
}

stop_blackwire() {
    "${COMPOSE[@]}" exec -T blackwire-server sh -c 'pkill -x blackwire 2>/dev/null || true' \
        </dev/null >/dev/null 2>&1 || true
    sleep 0.2
}

start_blackwire() {
    local server_cfg="$1"
    stop_blackwire
    "${COMPOSE[@]}" exec -d blackwire-server \
        blackwire run -c "/generated/blackwire/${server_cfg}" </dev/null >> "$REPORT_DIR/compose.log" 2>&1
}

stop_xray() {
    docker rm -f xray-client >/dev/null 2>&1 || true
    local cid
    while IFS= read -r cid; do
        [[ -n "$cid" ]] && docker rm -f "$cid" >/dev/null 2>&1 || true
    done < <(docker ps -aq --filter "name=xray-client" 2>/dev/null || true)
    local i
    for i in $(seq 1 30); do
        if ! docker ps -a --filter "name=xray-client" -q | grep -q .; then
            return 0
        fi
        sleep 0.1
    done
    echo "WARN: xray-client container still present after cleanup" >&2
    return 0
}

start_xray() {
    local client_cfg="$1"
    stop_xray
    if ! "${COMPOSE[@]}" run -d --no-deps --use-aliases --name xray-client xray-client \
        run -c "/generated/${client_cfg}" </dev/null >> "$REPORT_DIR/compose.log" 2>&1; then
        return 1
    fi
    local i
    for i in $(seq 1 "$CLIENT_WAIT_TRIES"); do
        if client_container_running xray-client; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

stop_sing_box() {
    "${COMPOSE[@]}" exec -T sing-box-client sh -c 'pkill -x sing-box 2>/dev/null || true' \
        </dev/null >/dev/null 2>&1 || true
    sleep 0.2
}

start_sing_box() {
    local client_cfg="$1"
    stop_sing_box
    "${COMPOSE[@]}" exec -d sing-box-client \
        sing-box run -c "/generated/${client_cfg}" </dev/null >> "$REPORT_DIR/compose.log" 2>&1
}

assert_single_client() {
    local n=0
    client_container_running xray-client && n=$((n + 1))
    if "${COMPOSE[@]}" exec -T sing-box-client sh -c 'pgrep -x sing-box >/dev/null' </dev/null 2>/dev/null; then
        n=$((n + 1))
    fi
    if [[ "$n" -gt 1 ]]; then
        echo "ERROR: multiple external clients running (${n}); sequential matrix violated" >&2
        exit 1
    fi
}

wait_for_server_port() {
    local protocol="$1"
    local port
    port="$(port_for_protocol "$protocol")"
    [[ -z "$port" ]] && return 0
    if [[ "$protocol" == "vless-shadowtls" ]]; then
        local i
        for i in $(seq 1 "$PORT_WAIT_TRIES"); do
            if "${COMPOSE[@]}" exec -T matrix-probe sh -c \
                "nc -z -w1 tls-cover 443" </dev/null >/dev/null 2>&1; then
                sleep 0.5
                if "${COMPOSE[@]}" exec -T matrix-probe sh -c \
                    "nc -z -w1 blackwire-server ${port}" </dev/null >/dev/null 2>&1; then
                    return 0
                fi
            fi
            sleep "$PORT_WAIT_SLEEP"
        done
        echo "tls-cover:443 or blackwire-server:${port} not ready for $protocol" >&2
        return 1
    fi
    if [[ "$protocol" == "hysteria2" || "$protocol" == "vless-quic" || "$protocol" == "vless-mkcp" ]]; then
        sleep 2
        return 0
    fi
    # SS2022 UDP inbound binds UDP only — TCP nc -z would always fail.
    if [[ "$protocol" == "ss2022-udp" ]]; then
        local i
        for i in $(seq 1 "$PORT_WAIT_TRIES"); do
            if "${COMPOSE[@]}" exec -T blackwire-server sh -c \
                "ss -H -uln 2>/dev/null | grep -qE ':${port}\\b'" \
                </dev/null >/dev/null 2>&1; then
                return 0
            fi
            if "${COMPOSE[@]}" exec -T matrix-probe sh -c \
                "nc -u -z -w1 blackwire-server ${port}" </dev/null >/dev/null 2>&1; then
                return 0
            fi
            sleep "$PORT_WAIT_SLEEP"
        done
        echo "server UDP port $port not open for $protocol" >&2
        return 1
    fi
    local i
    for i in $(seq 1 "$PORT_WAIT_TRIES"); do
        if "${COMPOSE[@]}" exec -T matrix-probe sh -c \
            "nc -z -w1 blackwire-server ${port}" </dev/null >/dev/null 2>&1; then
            return 0
        fi
        sleep "$PORT_WAIT_SLEEP"
    done
    echo "server port $port not open for $protocol" >&2
    return 1
}

requires_udp_probe() {
    case "$1" in
        trojan-udp|vless-udp|ss2022-udp) return 0 ;;
        *) return 1 ;;
    esac
}

# UDP-only inbounds have no TCP listener — skip curl and use the SOCKS5 UDP probe only.
udp_only_protocol() {
    case "$1" in
        ss2022-udp) return 0 ;;
        *) return 1 ;;
    esac
}

should_run_protocol() {
    local protocol="$1"
    local filter="${MATRIX_PROTOCOLS:-}"
    [[ -z "$filter" ]] && return 0
    local p
    IFS=',' read -ra _protos <<< "$filter"
    for p in "${_protos[@]}"; do
        p="${p#"${p%%[![:space:]]*}"}"
        p="${p%"${p##*[![:space:]]}"}"
        [[ "$p" == "$protocol" ]] && return 0
    done
    return 1
}

wait_for_socks() {
    local client_host="$1"
    local i
    for i in $(seq 1 "$SOCKS_WAIT_TRIES"); do
        if "${COMPOSE[@]}" exec -T matrix-probe \
            curl -fsS --max-time 2 --socks5-hostname "${client_host}:1080" "$TARGET_URL" \
            </dev/null >/dev/null 2>&1; then
            return 0
        fi
        sleep "$SOCKS_WAIT_SLEEP"
    done
    return 1
}

wait_for_socks_udp() {
    local client_host="$1"
    local i
    for i in $(seq 1 "$SOCKS_WAIT_TRIES"); do
        if "${COMPOSE[@]}" exec -T matrix-probe \
            sh /scripts/udp-socks-probe.sh "$client_host" 1080 \
            </dev/null >/dev/null 2>&1; then
            return 0
        fi
        sleep "$SOCKS_WAIT_SLEEP"
    done
    return 1
}

capture_pcap_on_fail() {
    local log="$1"
    [[ "${MATRIX_PCAP_ON_FAIL:-}" != "1" ]] && return 0
    mkdir -p "$REPORT_DIR/captures"
    local cap="$REPORT_DIR/captures/$(basename "$log" .log).pcap"
    "${COMPOSE[@]}" exec -T matrix-probe sh -c \
        'command -v tcpdump >/dev/null 2>&1 || apk add --no-cache tcpdump >/dev/null 2>&1; \
         timeout 8 tcpdump -i any -c 80 -w - 2>/dev/null' \
        </dev/null > "$cap" 2>/dev/null || true
    if [[ -s "$cap" ]]; then
        echo "pcap: $cap" >> "$log"
    fi
}

append_logs() {
    local log="$1"
    capture_pcap_on_fail "$log"
    "${COMPOSE[@]}" logs --no-color blackwire-server >> "$log" 2>&1 || true
    if [[ "${2:-}" == "xray-client" ]]; then
        docker logs xray-client >> "$log" 2>&1 || true
    elif [[ -n "${2:-}" ]]; then
        "${COMPOSE[@]}" logs --no-color "$2" >> "$log" 2>&1 || true
    fi
}

run_client_case() {
    local expect_pass="$1" label="$2" client="$3" client_cfg="$4" log="$5" protocol="${6:-}"

    if [[ "$client_cfg" == "-" ]]; then
        echo "SKIP ${label}" | tee -a "$REPORT_DIR/summary.txt"
        return 0
    fi

    assert_single_client

    local client_service="${client}-client"
    if [[ "$client" == "xray" ]]; then
        if [[ "$client_cfg" == */* ]]; then
            start_xray "$client_cfg" || {
                echo "FAIL ${label} (client start)" | tee -a "$REPORT_DIR/summary.txt"
                return 1
            }
        else
            start_xray "xray/${client_cfg}" || {
                echo "FAIL ${label} (client start)" | tee -a "$REPORT_DIR/summary.txt"
                return 1
            }
        fi
    else
        if [[ "$client_cfg" == */* ]]; then
            start_sing_box "$client_cfg"
        else
            start_sing_box "sing-box/${client_cfg}"
        fi
    fi
    assert_single_client

    if udp_only_protocol "$protocol"; then
        if wait_for_socks_udp "${client}-client"; then
            if [[ "$expect_pass" == "pass" ]]; then
                echo "PASS ${label}" | tee -a "$REPORT_DIR/summary.txt"
                if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
                return 0
            fi
            echo "FAIL ${label} accepted" | tee -a "$REPORT_DIR/summary.txt"
            append_logs "$log" "$client_service"
            if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
            return 1
        fi
        if [[ "$expect_pass" == "pass" ]]; then
            echo "FAIL ${label} (udp socks probe)" | tee -a "$REPORT_DIR/summary.txt"
            append_logs "$log" "$client_service"
            if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
            return 1
        fi
        echo "PASS ${label} rejected" | tee -a "$REPORT_DIR/summary.txt"
        if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
        return 0
    fi

    if wait_for_socks "${client}-client"; then
        if [[ "$expect_pass" == "pass" ]]; then
            if requires_udp_probe "$protocol" && ! wait_for_socks_udp "${client}-client"; then
                echo "FAIL ${label} (udp socks probe)" | tee -a "$REPORT_DIR/summary.txt"
                append_logs "$log" "$client_service"
                if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
                return 1
            fi
            echo "PASS ${label}" | tee -a "$REPORT_DIR/summary.txt"
            if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
            return 0
        fi
        echo "FAIL ${label} accepted" | tee -a "$REPORT_DIR/summary.txt"
        append_logs "$log" "$client_service"
        if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
        return 1
    fi

    if [[ "$expect_pass" == "pass" ]]; then
        echo "FAIL ${label}" | tee -a "$REPORT_DIR/summary.txt"
        append_logs "$log" "$client_service"
        {
            echo "--- triage ---"
            echo "See docs/external-client-failure-triage.md"
        } >> "$log"
        if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
        return 1
    fi

    echo "PASS ${label} rejected" | tee -a "$REPORT_DIR/summary.txt"
    if [[ "$client" == "xray" ]]; then stop_xray; else stop_sing_box; fi
    return 0
}

run_protocol() {
    local protocol="$1" server_cfg="$2" xray_cfg="$3" sing_cfg="$4"
    local overall=0

    echo "==> protocol ${protocol}" >> "$REPORT_DIR/compose.log"

    start_blackwire "$server_cfg"
    if ! wait_for_server_port "$protocol"; then
        echo "FAIL xray-${protocol} (server not listening)" | tee -a "$REPORT_DIR/summary.txt"
        echo "FAIL sing-box-${protocol} (server not listening)" | tee -a "$REPORT_DIR/summary.txt"
        echo "FAIL negative-xray-${protocol} (server not listening)" | tee -a "$REPORT_DIR/summary.txt"
        echo "FAIL negative-sing-box-${protocol} (server not listening)" | tee -a "$REPORT_DIR/summary.txt"
        append_logs "$REPORT_DIR/logs/xray-${protocol}.log"
        stop_blackwire
        return 1
    fi

    run_client_case pass "xray-${protocol}" xray "$xray_cfg" \
        "$REPORT_DIR/logs/xray-${protocol}.log" "$protocol" || overall=1
    run_client_case pass "sing-box-${protocol}" sing-box "$sing_cfg" \
        "$REPORT_DIR/logs/sing-box-${protocol}.log" "$protocol" || overall=1

    local xray_neg="xray-negative/${xray_cfg}"
    local sing_neg="sing-box-negative/${sing_cfg}"
    run_client_case reject "negative-xray-${protocol}" xray "$xray_neg" \
        "$REPORT_DIR/logs/negative-xray-${protocol}.log" "$protocol" || overall=1
    run_client_case reject "negative-sing-box-${protocol}" sing-box "$sing_neg" \
        "$REPORT_DIR/logs/negative-sing-box-${protocol}.log" "$protocol" || overall=1

    stop_blackwire
    stop_xray
    stop_sing_box
    return "$overall"
}

cleanup_all() {
    stop_blackwire
    stop_xray
    stop_sing_box
    "${COMPOSE[@]}" down -v >> "$REPORT_DIR/compose.log" 2>&1 || true
    rmdir "$LOCKDIR" 2>/dev/null || true
}
trap cleanup_all EXIT

matrix_bootstrap || exit 1

: > "$REPORT_DIR/summary.txt"
overall=0

exec 3< "$LAB_DIR/scenarios.env"
while IFS='|' read -r protocol server_cfg xray_cfg sing_cfg <&3; do
    [[ -z "${protocol:-}" || "$protocol" =~ ^# ]] && continue
    if ! should_run_protocol "$protocol"; then
        echo "SKIP ${protocol} (MATRIX_PROTOCOLS filter)" | tee -a "$REPORT_DIR/summary.txt"
        continue
    fi
    run_protocol "$protocol" "$server_cfg" "$xray_cfg" "$sing_cfg" || overall=1
done
exec 3<&-

echo "External-client report: $REPORT_DIR/summary.txt"
exit "$overall"
