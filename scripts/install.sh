#!/usr/bin/env bash
set -euo pipefail

REPO="${BLACKWIRE_REPO:-mojindri/v2ray}"
VERSION="${VERSION:-latest}"
DOWNLOAD_BASE="${BLACKWIRE_DOWNLOAD_BASE:-}"
ACTION="${ACTION:-install}"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/blackwire}"
STATE_DIR="${STATE_DIR:-/var/lib/blackwire}"
RUN_DIR="${RUN_DIR:-/run/blackwire}"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-auto}"
START_SERVICE="${START_SERVICE:-0}"
CONFIG_PATH="${CONFIG_PATH:-}"
CONFIG_URL="${CONFIG_URL:-}"
INIT_SERVER="${INIT_SERVER:-}"
SERVER_PORT="${SERVER_PORT:-443}"
SERVER_LISTEN="${SERVER_LISTEN:-0.0.0.0}"
REALITY_DEST="${REALITY_DEST:-www.microsoft.com:443}"
REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-www.microsoft.com}"
PUBLIC_HOST="${PUBLIC_HOST:-<server-ip-or-domain>}"
OPEN_FIREWALL="${OPEN_FIREWALL:-0}"
SERVICE_USER="${SERVICE_USER:-nobody}"
SERVICE_GROUP="${SERVICE_GROUP:-}"

log() {
    printf 'blackwire-install: %s\n' "$*"
}

die() {
    printf 'blackwire-install: ERROR: %s\n' "$*" >&2
    exit 1
}

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

sudo_cmd() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

uninstall_blackwire() {
    if command -v systemctl >/dev/null 2>&1; then
        sudo_cmd systemctl disable --now blackwire >/dev/null 2>&1 || true
    fi
    sudo_cmd rm -f /etc/systemd/system/blackwire.service "$PREFIX/bin/blackwire"
    if command -v systemctl >/dev/null 2>&1; then
        sudo_cmd systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    if [ "${REMOVE_CONFIG:-0}" = "1" ]; then
        sudo_cmd rm -rf "$CONFIG_DIR" "$STATE_DIR" "$RUN_DIR"
        log "removed binary, systemd unit, config, state, and run directories"
    else
        log "removed binary and systemd unit; kept $CONFIG_DIR and $STATE_DIR"
    fi
}

detect_asset() {
    os="$(uname -s)"
    arch="$(uname -m)"

    [ "$os" = "Linux" ] || die "this installer supports Linux only; download release assets manually for $os"

    case "$arch" in
        x86_64|amd64) echo "blackwire-linux-x86_64.tar.gz" ;;
        aarch64|arm64) echo "blackwire-linux-arm64.tar.gz" ;;
        *) die "unsupported Linux architecture: $arch" ;;
    esac
}

validate_port() {
    case "$SERVER_PORT" in
        ''|*[!0-9]*) die "SERVER_PORT must be numeric" ;;
    esac
    [ "$SERVER_PORT" -ge 1 ] && [ "$SERVER_PORT" -le 65535 ] || die "SERVER_PORT must be between 1 and 65535"
}

short_id() {
    od -An -N8 -tx1 /dev/urandom | tr -d ' \n'
}

service_group() {
    if [ -n "$SERVICE_GROUP" ]; then
        echo "$SERVICE_GROUP"
    elif getent group nobody >/dev/null 2>&1; then
        echo "nobody"
    else
        echo "nogroup"
    fi
}

protect_config_for_service() {
    path="$1"
    group="$(service_group)"
    if getent group "$group" >/dev/null 2>&1; then
        sudo_cmd chown "root:$group" "$path"
        sudo_cmd chmod 0640 "$path"
    else
        sudo_cmd chmod 0644 "$path"
        log "group '$group' not found; left $path world-readable so the service can read it"
    fi
}

generate_server_config() {
    [ -z "$CONFIG_PATH" ] && [ -z "$CONFIG_URL" ] || die "INIT_SERVER cannot be combined with CONFIG_PATH or CONFIG_URL"
    validate_port

    uuid="$("$PREFIX/bin/blackwire" uuid)"
    info_file="$CONFIG_DIR/client-info.txt"

    case "$INIT_SERVER" in
        vless-tcp)
            sudo_cmd sh -c "cat > '$CONFIG_DIR/config.json'" <<JSON
{
  "log": {
    "level": "info",
    "json": false
  },
  "inbounds": [
    {
      "tag": "vless-in",
      "protocol": "vless",
      "listen": "$SERVER_LISTEN",
      "port": $SERVER_PORT,
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "email": "vps@example.local"
          }
        ]
      }
    }
  ],
  "outbounds": [
    {
      "tag": "freedom",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "outboundTag": "freedom"
      }
    ]
  }
}
JSON
            protect_config_for_service "$CONFIG_DIR/config.json"
            sudo_cmd sh -c "cat > '$info_file'" <<INFO
Generated VLESS TCP server config

Address: $PUBLIC_HOST
Port: $SERVER_PORT
UUID: $uuid
Network: tcp
Security: none
INFO
            ;;
        vless-reality)
            x25519="$("$PREFIX/bin/blackwire" x25519)"
            private_key="$(printf '%s\n' "$x25519" | awk -F': ' '/Private key/ { print $2 }')"
            public_key="$(printf '%s\n' "$x25519" | awk -F': ' '/Public key/ { print $2 }')"
            [ -n "$private_key" ] && [ -n "$public_key" ] || die "failed to generate REALITY key pair"
            sid="$(short_id)"
            sudo_cmd sh -c "cat > '$CONFIG_DIR/config.json'" <<JSON
{
  "log": {
    "level": "info",
    "json": false
  },
  "inbounds": [
    {
      "tag": "vless-reality-in",
      "protocol": "vless",
      "listen": "$SERVER_LISTEN",
      "port": $SERVER_PORT,
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "email": "reality@example.local",
            "flow": ""
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "dest": "$REALITY_DEST",
          "privateKey": "$private_key",
          "shortIds": ["$sid"],
          "serverName": "$REALITY_SERVER_NAME",
          "maxTimeDiff": 120
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "freedom",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "outboundTag": "freedom"
      }
    ]
  }
}
JSON
            protect_config_for_service "$CONFIG_DIR/config.json"
            sudo_cmd sh -c "cat > '$info_file'" <<INFO
Generated VLESS REALITY server config

Address: $PUBLIC_HOST
Port: $SERVER_PORT
UUID: $uuid
Network: tcp
Security: reality
REALITY public key: $public_key
REALITY short ID: $sid
REALITY server name: $REALITY_SERVER_NAME
REALITY destination: $REALITY_DEST
INFO
            ;;
        *) die "unsupported INIT_SERVER value: $INIT_SERVER (use vless-tcp or vless-reality)" ;;
    esac

    sudo_cmd chmod 0600 "$info_file"
    log "generated $INIT_SERVER config at $CONFIG_DIR/config.json"
    log "wrote client connection hints to $info_file"
}

download_url() {
    asset="$1"
    if [ -n "$DOWNLOAD_BASE" ]; then
        echo "${DOWNLOAD_BASE%/}/${asset}"
    elif [ "$VERSION" = "latest" ]; then
        echo "https://github.com/${REPO}/releases/latest/download/${asset}"
    else
        echo "https://github.com/${REPO}/releases/download/${VERSION}/${asset}"
    fi
}

install_systemd_unit() {
    command -v systemctl >/dev/null 2>&1 || return 0
    [ -d /run/systemd/system ] || return 0

    unit_path="/etc/systemd/system/blackwire.service"
    tmp_unit="$(mktemp)"
    group="$(service_group)"
    cat > "$tmp_unit" <<UNIT
[Unit]
Description=blackwire proxy runtime
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
User=${SERVICE_USER}
Group=${group}
ExecStart=${PREFIX}/bin/blackwire run -c ${CONFIG_DIR}/config.json
ExecReload=/bin/kill -HUP \$MAINPID
WorkingDirectory=${STATE_DIR}
Restart=on-failure
RestartSec=5s
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${STATE_DIR} ${RUN_DIR}
PrivateTmp=true
NoNewPrivileges=true
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
UNIT

    sudo_cmd install -m 0644 "$tmp_unit" "$unit_path"
    rm -f "$tmp_unit"
    sudo_cmd systemctl daemon-reload
    log "installed systemd unit: $unit_path"

    if [ "$START_SERVICE" = "1" ]; then
        sudo_cmd systemctl enable --now blackwire
        log "enabled and started blackwire.service"
    elif [ -f "$CONFIG_DIR/config.json" ]; then
        log "service not started; run: systemctl enable --now blackwire"
    else
        log "service not started; create ${CONFIG_DIR}/config.json, then run: systemctl enable --now blackwire"
    fi
}

install_config() {
    if [ -n "$CONFIG_PATH" ] && [ -n "$CONFIG_URL" ]; then
        die "set only one of CONFIG_PATH or CONFIG_URL"
    fi

    if [ -n "$CONFIG_PATH" ]; then
        [ -f "$CONFIG_PATH" ] || die "CONFIG_PATH does not exist: $CONFIG_PATH"
        sudo_cmd install -m 0640 "$CONFIG_PATH" "$CONFIG_DIR/config.json"
        protect_config_for_service "$CONFIG_DIR/config.json"
        log "installed config from CONFIG_PATH to $CONFIG_DIR/config.json"
    elif [ -n "$CONFIG_URL" ]; then
        tmp_config="$(mktemp)"
        curl -fsSL "$CONFIG_URL" -o "$tmp_config"
        sudo_cmd install -m 0640 "$tmp_config" "$CONFIG_DIR/config.json"
        protect_config_for_service "$CONFIG_DIR/config.json"
        rm -f "$tmp_config"
        log "installed config from CONFIG_URL to $CONFIG_DIR/config.json"
    elif [ -n "$INIT_SERVER" ]; then
        generate_server_config
    fi

    if [ -f "$CONFIG_DIR/config.json" ]; then
        "$PREFIX/bin/blackwire" test -c "$CONFIG_DIR/config.json"
        log "config validation passed: $CONFIG_DIR/config.json"
    fi
}

configure_firewall() {
    [ "$OPEN_FIREWALL" = "1" ] || return 0
    validate_port

    if command -v ufw >/dev/null 2>&1; then
        sudo_cmd ufw allow "${SERVER_PORT}/tcp"
        log "opened tcp/${SERVER_PORT} with ufw"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        sudo_cmd firewall-cmd --add-port="${SERVER_PORT}/tcp" --permanent
        sudo_cmd firewall-cmd --reload
        log "opened tcp/${SERVER_PORT} with firewalld"
    else
        log "OPEN_FIREWALL=1 requested, but ufw/firewalld was not found"
        log "open tcp/${SERVER_PORT} in your cloud firewall and host firewall"
    fi
}

print_next_steps() {
    if [ "$START_SERVICE" = "1" ]; then
        log "next: service is enabled and running"
    elif [ -f "$CONFIG_DIR/config.json" ]; then
        log "next: start with 'systemctl enable --now blackwire' or run '$PREFIX/bin/blackwire run -c $CONFIG_DIR/config.json'"
    else
        log "next: create $CONFIG_DIR/config.json"
        log "next: validate with '$PREFIX/bin/blackwire test -c $CONFIG_DIR/config.json'"
        log "next: start with 'systemctl enable --now blackwire'"
    fi
    if [ -f "$CONFIG_DIR/client-info.txt" ]; then
        log "next: read client connection hints from '$CONFIG_DIR/client-info.txt'"
    fi
    log "next: ensure tcp/${SERVER_PORT} is open in your VPS/cloud firewall"
    log "next: view logs with 'journalctl -u blackwire -f'"
}

main() {
    case "$ACTION" in
        install|upgrade) ;;
        uninstall)
            if [ "$(id -u)" -ne 0 ]; then
                need_cmd sudo
            fi
            uninstall_blackwire
            exit 0
            ;;
        *) die "invalid ACTION value: $ACTION (use install, upgrade, or uninstall)" ;;
    esac

    need_cmd curl
    need_cmd tar
    need_cmd install
    need_cmd sha256sum
    need_cmd od
    if [ "$(id -u)" -ne 0 ]; then
        need_cmd sudo
    fi

    asset="$(detect_asset)"
    base_url="$(download_url "$asset")"
    workdir="$(mktemp -d)"
    trap 'rm -rf "$workdir"' EXIT

    log "downloading ${asset} from ${REPO} (${VERSION})"
    curl -fsSL "$base_url" -o "$workdir/$asset"
    curl -fsSL "$base_url.sha256" -o "$workdir/$asset.sha256"

    (
        cd "$workdir"
        awk -v asset="$asset" '{ print $1 "  " asset }' "$asset.sha256" > "$asset.sha256.local"
        sha256sum -c "$asset.sha256.local"
        tar -xzf "$asset"
    )

    binary="$(find "$workdir" -type f -name blackwire -perm -111 | head -n 1)"
    [ -n "$binary" ] || die "blackwire binary not found in $asset"

    sudo_cmd install -d -m 0755 "$PREFIX/bin" "$CONFIG_DIR" "$STATE_DIR" "$RUN_DIR"
    sudo_cmd install -m 0755 "$binary" "$PREFIX/bin/blackwire"

    if [ ! -f "$CONFIG_DIR/config.json" ]; then
        sudo_cmd sh -c "cat > '$CONFIG_DIR/README'" <<README
Place your blackwire JSON config at:

  ${CONFIG_DIR}/config.json

Validate it with:

  ${PREFIX}/bin/blackwire test -c ${CONFIG_DIR}/config.json
README
    fi

    install_config

    if [ "$START_SERVICE" = "1" ] && [ ! -f "$CONFIG_DIR/config.json" ]; then
        die "START_SERVICE=1 requires $CONFIG_DIR/config.json; set CONFIG_PATH or CONFIG_URL, or create the config first"
    fi

    configure_firewall

    case "$INSTALL_SYSTEMD" in
        1|true|yes) install_systemd_unit ;;
        0|false|no) ;;
        auto) install_systemd_unit ;;
        *) die "invalid INSTALL_SYSTEMD value: $INSTALL_SYSTEMD" ;;
    esac

    log "installed: $("$PREFIX/bin/blackwire" version 2>/dev/null || "$PREFIX/bin/blackwire" --version 2>/dev/null || echo "$PREFIX/bin/blackwire")"
    print_next_steps
}

main "$@"
