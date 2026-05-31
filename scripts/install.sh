#!/usr/bin/env bash
set -euo pipefail

REPO="${BLACKWIRE_REPO:-mojindri/Blackwire}"
VERSION="${VERSION:-latest}"
DOWNLOAD_BASE="${BLACKWIRE_DOWNLOAD_BASE:-}"
ACTION="${ACTION:-install}"
SETUP="${SETUP:-}"
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
DOMAIN="${DOMAIN:-}"
TLS_CERT_FILE="${TLS_CERT_FILE:-}"
TLS_KEY_FILE="${TLS_KEY_FILE:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
ACME_STAGING="${ACME_STAGING:-0}"
INSTALL_CERTBOT="${INSTALL_CERTBOT:-0}"
INSTALL_NGINX="${INSTALL_NGINX:-0}"
WS_PATH="${WS_PATH:-/blackwire}"
PROXY_PATH="${PROXY_PATH:-$WS_PATH}"
INTERNAL_PORT="${INTERNAL_PORT:-10080}"
REALITY_DEST="${REALITY_DEST:-www.microsoft.com:443}"
REALITY_SERVER_NAME="${REALITY_SERVER_NAME:-www.microsoft.com}"
PUBLIC_HOST="${PUBLIC_HOST:-<server-ip-or-domain>}"
OPEN_FIREWALL="${OPEN_FIREWALL:-0}"
SERVICE_USER="${SERVICE_USER:-nobody}"
SERVICE_GROUP="${SERVICE_GROUP:-}"
INSTALL_BLACK_UI="${INSTALL_BLACK_UI:-0}"
BLACK_UI_LISTEN="${BLACK_UI_LISTEN:-127.0.0.1:18080}"
BLACK_UI_DATA_DIR="${BLACK_UI_DATA_DIR:-/var/lib/black-ui}"
BLACK_UI_STATIC_DIR="${BLACK_UI_STATIC_DIR:-/usr/local/share/black-ui/frontend/dist}"
BLACK_UI_PUBLIC_BASE_URL="${BLACK_UI_PUBLIC_BASE_URL:-}"
BLACK_UI_PANEL_PATH="${BLACK_UI_PANEL_PATH:-/panel}"
BLACK_UI_COOKIE_SECURE="${BLACK_UI_COOKIE_SECURE:-}"

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
        if [ -f "$CONFIG_DIR/nginx-site" ]; then
            nginx_site="$(cat "$CONFIG_DIR/nginx-site" 2>/dev/null || true)"
            if [ -n "$nginx_site" ]; then
                sudo_cmd rm -f "/etc/nginx/sites-enabled/${nginx_site}" "/etc/nginx/sites-available/${nginx_site}"
            fi
        fi
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

detect_black_ui_asset() {
    os="$(uname -s)"
    arch="$(uname -m)"

    [ "$os" = "Linux" ] || die "black-ui installer supports Linux only"

    case "$arch" in
        x86_64|amd64) echo "black-ui-linux-x86_64.tar.gz" ;;
        aarch64|arm64) echo "black-ui-linux-arm64.tar.gz" ;;
        *) die "unsupported Linux architecture for black-ui: $arch" ;;
    esac
}

validate_port() {
    port="$1"
    name="$2"
    case "$port" in
        ''|*[!0-9]*) die "$name must be numeric" ;;
    esac
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || die "$name must be between 1 and 65535"
}

validate_server_port() {
    validate_port "$SERVER_PORT" SERVER_PORT
}

validate_ws_path() {
    WS_PATH="$PROXY_PATH"
    case "$WS_PATH" in
        /*) ;;
        *) die "WS_PATH must start with '/'" ;;
    esac
    [ "$WS_PATH" != "/" ] || die "WS_PATH must not be '/'"
    case "$WS_PATH" in
        *' '*|*'?'*|*'#'*|*'%'*) die "WS_PATH must not contain spaces, '?', '#', or '%'" ;;
    esac
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
    validate_server_port

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
        vless-ws-nginx)
            validate_port "$INTERNAL_PORT" INTERNAL_PORT
            validate_ws_path
            [ -n "$DOMAIN" ] || die "INIT_SERVER=vless-ws-nginx requires DOMAIN"
            sudo_cmd sh -c "cat > '$CONFIG_DIR/config.json'" <<JSON
{
  "log": {
    "level": "info",
    "json": false
  },
  "inbounds": [
    {
      "tag": "vless-ws-in",
      "protocol": "vless",
      "listen": "127.0.0.1",
      "port": $INTERNAL_PORT,
      "settings": {
        "clients": [
          {
            "id": "$uuid",
            "email": "ws@example.local"
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "none",
        "wsSettings": {
          "path": "$WS_PATH"
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
            setup_nginx_ws_proxy
            sudo_cmd sh -c "cat > '$info_file'" <<INFO
Generated VLESS WebSocket over nginx TLS server config

Address: $DOMAIN
Port: 443
UUID: $uuid
Network: ws
Security: tls
WebSocket path: $WS_PATH
Internal Blackwire listen: 127.0.0.1:$INTERNAL_PORT
INFO
            ;;
        trojan-tls)
            prepare_tls_certificate
            if [ "$SERVICE_USER" = "nobody" ] && [ "$SERVICE_GROUP" = "" ]; then
                SERVICE_USER="root"
                SERVICE_GROUP="root"
                log "using root service user for TLS so certificate private key is readable"
            fi
            password="$(short_id)$(short_id)$(short_id)$(short_id)"
            sudo_cmd sh -c "cat > '$CONFIG_DIR/config.json'" <<JSON
{
  "log": {
    "level": "info",
    "json": false
  },
  "inbounds": [
    {
      "tag": "trojan-tls-in",
      "protocol": "trojan",
      "listen": "$SERVER_LISTEN",
      "port": $SERVER_PORT,
      "settings": {
        "clients": [
          {
            "password": "$password"
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "certificateFile": "$TLS_CERT_FILE",
          "keyFile": "$TLS_KEY_FILE"
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
Generated Trojan TLS server config

Address: ${DOMAIN:-$PUBLIC_HOST}
Port: $SERVER_PORT
Password: $password
Network: tcp
Security: tls
TLS certificate: $TLS_CERT_FILE
TLS key: $TLS_KEY_FILE
INFO
            ;;
        *) die "unsupported INIT_SERVER value: $INIT_SERVER (use vless-tcp, vless-reality, vless-ws-nginx, or trojan-tls)" ;;
    esac

    sudo_cmd chmod 0600 "$info_file"
    log "generated $INIT_SERVER config at $CONFIG_DIR/config.json"
    log "wrote client connection hints to $info_file"
}

resolve_setup() {
    if [ -n "$SETUP" ] && [ -n "$INIT_SERVER" ]; then
        die "set only one of SETUP or INIT_SERVER"
    fi

    case "$SETUP" in
        "")
            ;;
        domain)
            INIT_SERVER="vless-ws-nginx"
            SERVER_PORT=443
            INSTALL_NGINX="${INSTALL_NGINX:-1}"
            INSTALL_CERTBOT="${INSTALL_CERTBOT:-1}"
            ;;
        reality)
            INIT_SERVER="vless-reality"
            ;;
        direct)
            INIT_SERVER="vless-tcp"
            ;;
        custom)
            [ -n "$CONFIG_PATH" ] || [ -n "$CONFIG_URL" ] || die "SETUP=custom requires CONFIG_PATH or CONFIG_URL"
            ;;
        *) die "unsupported SETUP value: $SETUP (use domain, reality, direct, or custom)" ;;
    esac
}

check_domain_preflight() {
    [ "$SETUP" = "domain" ] || [ "$INIT_SERVER" = "vless-ws-nginx" ] || return 0
    [ -n "$DOMAIN" ] || die "SETUP=domain requires DOMAIN"
    validate_ws_path
    validate_port "$INTERNAL_PORT" INTERNAL_PORT

    if command -v ss >/dev/null 2>&1; then
        for port in 80 443; do
            if ss -ltnp 2>/dev/null | grep -Eq "[:.]${port}[[:space:]]"; then
                if ! ss -ltnp 2>/dev/null | grep -E "[:.]${port}[[:space:]]" | grep -q 'nginx'; then
                    holder="$(ss -ltnp 2>/dev/null | grep -E "[:.]${port}[[:space:]]" | head -n 1)"
                    die "SETUP=domain needs tcp/${port} for nginx, but it is already in use: $holder"
                fi
            fi
        done
    else
        log "ss not found; skipping tcp/80 and tcp/443 ownership preflight"
    fi
}

install_package_if_possible() {
    package="$1"
    if command -v apt-get >/dev/null 2>&1; then
        sudo_cmd apt-get update
        sudo_cmd apt-get install -y "$package"
    elif command -v dnf >/dev/null 2>&1; then
        sudo_cmd dnf install -y "$package"
    elif command -v yum >/dev/null 2>&1; then
        sudo_cmd yum install -y "$package"
    else
        die "cannot install $package automatically; install it manually and rerun"
    fi
}

prepare_tls_certificate() {
    if [ -n "$TLS_CERT_FILE" ] || [ -n "$TLS_KEY_FILE" ]; then
        [ -n "$TLS_CERT_FILE" ] && [ -n "$TLS_KEY_FILE" ] || die "set both TLS_CERT_FILE and TLS_KEY_FILE"
        [ -f "$TLS_CERT_FILE" ] || die "TLS_CERT_FILE does not exist: $TLS_CERT_FILE"
        [ -f "$TLS_KEY_FILE" ] || die "TLS_KEY_FILE does not exist: $TLS_KEY_FILE"
        return 0
    fi

    [ -n "$DOMAIN" ] || die "INIT_SERVER=trojan-tls requires DOMAIN, or set TLS_CERT_FILE and TLS_KEY_FILE"

    if ! command -v certbot >/dev/null 2>&1; then
        if [ "$INSTALL_CERTBOT" = "1" ]; then
            install_package_if_possible certbot
        else
            die "certbot not found; install certbot, set INSTALL_CERTBOT=1, or provide TLS_CERT_FILE/TLS_KEY_FILE"
        fi
    fi

    certbot_args=(certonly --standalone --non-interactive --agree-tos --domain "$DOMAIN")
    if [ -n "$ACME_EMAIL" ]; then
        certbot_args+=(--email "$ACME_EMAIL")
    else
        certbot_args+=(--register-unsafely-without-email)
    fi
    if [ "$ACME_STAGING" = "1" ]; then
        certbot_args+=(--staging)
    fi

    log "requesting Let's Encrypt certificate for $DOMAIN with certbot standalone"
    log "ensure DNS points to this VPS and tcp/80 is open before this step"
    sudo_cmd certbot "${certbot_args[@]}"

    TLS_CERT_FILE="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    TLS_KEY_FILE="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
    [ -f "$TLS_CERT_FILE" ] || die "certbot did not create $TLS_CERT_FILE"
    [ -f "$TLS_KEY_FILE" ] || die "certbot did not create $TLS_KEY_FILE"
}

setup_nginx_ws_proxy() {
    if ! command -v nginx >/dev/null 2>&1; then
        if [ "$INSTALL_NGINX" = "1" ]; then
            install_package_if_possible nginx
        else
            die "nginx not found; install nginx or set INSTALL_NGINX=1"
        fi
    fi

    for port in 80 443; do
        if ss -ltnp 2>/dev/null | grep -Eq "[:.]${port}[[:space:]]"; then
            if ! ss -ltnp 2>/dev/null | grep -E "[:.]${port}[[:space:]]" | grep -q 'nginx'; then
                holder="$(ss -ltnp 2>/dev/null | grep -E "[:.]${port}[[:space:]]" | head -n 1)"
                die "tcp/${port} is already in use by another service: $holder"
            fi
        fi
    done

    if [ -n "$TLS_CERT_FILE" ] || [ -n "$TLS_KEY_FILE" ]; then
        [ -n "$TLS_CERT_FILE" ] && [ -n "$TLS_KEY_FILE" ] || die "set both TLS_CERT_FILE and TLS_KEY_FILE"
        [ -f "$TLS_CERT_FILE" ] || die "TLS_CERT_FILE does not exist: $TLS_CERT_FILE"
        [ -f "$TLS_KEY_FILE" ] || die "TLS_KEY_FILE does not exist: $TLS_KEY_FILE"
        use_existing_cert=1
    else
        use_existing_cert=0
        if [ "$INSTALL_CERTBOT" = "1" ] && command -v apt-get >/dev/null 2>&1; then
            install_package_if_possible python3-certbot-nginx
        elif ! command -v certbot >/dev/null 2>&1; then
            if [ "$INSTALL_CERTBOT" != "1" ]; then
                die "certbot not found; install certbot or set INSTALL_CERTBOT=1"
            fi
            install_package_if_possible certbot
        fi
        if ! certbot plugins 2>/dev/null | grep -Eq '^[*][[:space:]]+nginx$'; then
            die "certbot nginx plugin not found; install python3-certbot-nginx or provide TLS_CERT_FILE/TLS_KEY_FILE"
        fi
    fi

    webroot="/var/www/blackwire-${DOMAIN}"
    sudo_cmd install -d -m 0755 "$webroot"
    sudo_cmd sh -c "cat > '$webroot/index.html'" <<HTML
blackwire
HTML

    nginx_available="/etc/nginx/sites-available/blackwire-${DOMAIN}.conf"
    nginx_enabled="/etc/nginx/sites-enabled/blackwire-${DOMAIN}.conf"
    sudo_cmd sh -c "cat > '$nginx_available'" <<NGINX
server {
    listen 80;
    server_name $DOMAIN;
    root $webroot;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINX
    sudo_cmd ln -sf "$nginx_available" "$nginx_enabled"
    sudo_cmd nginx -t
    sudo_cmd systemctl enable --now nginx
    sudo_cmd systemctl reload nginx

    if [ "$use_existing_cert" = "1" ]; then
        cert_file="$TLS_CERT_FILE"
        key_file="$TLS_KEY_FILE"
        log "using provided TLS certificate for nginx"
    else
        certbot_args=(--nginx --non-interactive --agree-tos --domain "$DOMAIN")
        if [ -n "$ACME_EMAIL" ]; then
            certbot_args+=(--email "$ACME_EMAIL")
        else
            certbot_args+=(--register-unsafely-without-email)
        fi
        if [ "$ACME_STAGING" = "1" ]; then
            certbot_args+=(--staging)
        fi

        log "requesting nginx-managed Let's Encrypt certificate for $DOMAIN"
        sudo_cmd certbot "${certbot_args[@]}"
        cert_file="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
        key_file="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
    fi

    ui_nginx_location=""
    if [ "$INSTALL_BLACK_UI" = "1" ]; then
        case "$BLACK_UI_PANEL_PATH" in
            /*) ;;
            *) die "BLACK_UI_PANEL_PATH must start with '/'" ;;
        esac
        ui_nginx_location="
    location ${BLACK_UI_PANEL_PATH}/ {
        proxy_http_version 1.1;
        proxy_set_header Host \\$host;
        proxy_set_header X-Real-IP \\$remote_addr;
        proxy_set_header X-Forwarded-For \\$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://${BLACK_UI_LISTEN}/;
    }

    location = ${BLACK_UI_PANEL_PATH} {
        return 301 ${BLACK_UI_PANEL_PATH}/;
    }"
    fi

    sudo_cmd sh -c "cat > '$nginx_available'" <<NGINX
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $DOMAIN;

    ssl_certificate $cert_file;
    ssl_certificate_key $key_file;

    root $webroot;
    index index.html;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location $WS_PATH {
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 300s;
        proxy_pass http://127.0.0.1:$INTERNAL_PORT;
    }
${ui_nginx_location}
}
NGINX
    sudo_cmd sh -c "printf '%s\n' 'blackwire-${DOMAIN}.conf' > '$CONFIG_DIR/nginx-site'"
    sudo_cmd nginx -t
    sudo_cmd systemctl reload nginx
    log "installed nginx TLS reverse proxy for https://$DOMAIN$WS_PATH"
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

install_black_ui_systemd_unit() {
    command -v systemctl >/dev/null 2>&1 || return 0
    [ -d /run/systemd/system ] || return 0

    unit_path="/etc/systemd/system/black-ui.service"
    tmp_unit="$(mktemp)"
    group="$(service_group)"
    cookie_secure="$BLACK_UI_COOKIE_SECURE"
    if [ -z "$cookie_secure" ]; then
        if [ "$SETUP" = "domain" ]; then
            cookie_secure=1
        else
            cookie_secure=0
        fi
    fi
    cat > "$tmp_unit" <<UNIT
[Unit]
Description=black-ui Blackwire control panel
Documentation=https://github.com/${REPO}
After=network-online.target blackwire.service
Wants=network-online.target

[Service]
User=${SERVICE_USER}
Group=${group}
ExecStart=${PREFIX}/bin/black-ui
WorkingDirectory=${BLACK_UI_DATA_DIR}
Environment=BLACK_UI_DATA_DIR=${BLACK_UI_DATA_DIR}
Environment=BLACK_UI_LISTEN=${BLACK_UI_LISTEN}
Environment=BLACK_UI_STATIC_DIR=${BLACK_UI_STATIC_DIR}
Environment=BLACK_UI_COOKIE_SECURE=${cookie_secure}
Restart=on-failure
RestartSec=5s
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${BLACK_UI_DATA_DIR} ${CONFIG_DIR}
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

    sudo_cmd install -m 0644 "$tmp_unit" "$unit_path"
    rm -f "$tmp_unit"
    sudo_cmd systemctl daemon-reload
    sudo_cmd systemctl enable --now black-ui
    log "installed and started black-ui.service at ${BLACK_UI_LISTEN}"
}

install_black_ui() {
    [ "$INSTALL_BLACK_UI" = "1" ] || return 0
    ui_asset="$(detect_black_ui_asset)"
    ui_url="$(download_url "$ui_asset")"
    ui_workdir="$(mktemp -d)"
    log "downloading ${ui_asset} from ${REPO} (${VERSION})"
    curl -fsSL "$ui_url" -o "$ui_workdir/$ui_asset"
    curl -fsSL "$ui_url.sha256" -o "$ui_workdir/$ui_asset.sha256"
    (
        cd "$ui_workdir"
        awk -v asset="$ui_asset" '{ print $1 "  " asset }' "$ui_asset.sha256" > "$ui_asset.sha256.local"
        sha256sum -c "$ui_asset.sha256.local"
        tar -xzf "$ui_asset"
    )
    ui_binary="$(find "$ui_workdir" -type f -name black-ui -perm -111 | head -n 1)"
    [ -n "$ui_binary" ] || die "black-ui binary not found in $ui_asset"
    sudo_cmd install -d -m 0755 "$PREFIX/bin" "$BLACK_UI_DATA_DIR" "$BLACK_UI_STATIC_DIR"
    sudo_cmd install -m 0755 "$ui_binary" "$PREFIX/bin/black-ui"
    ui_dist="$(find "$ui_workdir" -type d -path '*/frontend/dist' | head -n 1)"
    if [ -n "$ui_dist" ]; then
        sudo_cmd cp -a "$ui_dist"/. "$BLACK_UI_STATIC_DIR"/
    else
        log "black-ui frontend dist not found in asset; API will run but browser UI may be unavailable"
    fi
    rm -rf "$ui_workdir"
    install_black_ui_systemd_unit
    if [ -n "$BLACK_UI_PUBLIC_BASE_URL" ]; then
        log "black-ui public base URL: $BLACK_UI_PUBLIC_BASE_URL"
    elif [ -n "$DOMAIN" ]; then
        log "black-ui can be reverse-proxied at https://${DOMAIN}${BLACK_UI_PANEL_PATH}"
    else
        log "black-ui listens locally at http://${BLACK_UI_LISTEN}"
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
    validate_server_port

    if [ "$SETUP" = "domain" ] || [ "$INIT_SERVER" = "vless-ws-nginx" ]; then
        firewall_ports="80/tcp 443/tcp"
    else
        firewall_ports="${SERVER_PORT}/tcp"
    fi

    if command -v ufw >/dev/null 2>&1; then
        for port in $firewall_ports; do
            sudo_cmd ufw allow "$port"
        done
        log "opened $firewall_ports with ufw"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        for port in $firewall_ports; do
            sudo_cmd firewall-cmd --add-port="$port" --permanent
        done
        sudo_cmd firewall-cmd --reload
        log "opened $firewall_ports with firewalld"
    else
        log "OPEN_FIREWALL=1 requested, but ufw/firewalld was not found"
        log "open $firewall_ports in your cloud firewall and host firewall"
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
    if [ "$SETUP" = "domain" ] || [ "$INIT_SERVER" = "vless-ws-nginx" ]; then
        log "next: ensure tcp/80 and tcp/443 are open in your VPS/cloud firewall"
    else
        log "next: ensure tcp/${SERVER_PORT} is open in your VPS/cloud firewall"
    fi
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
    resolve_setup
    check_domain_preflight

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

    install_black_ui

    log "installed: $("$PREFIX/bin/blackwire" version 2>/dev/null || "$PREFIX/bin/blackwire" --version 2>/dev/null || echo "$PREFIX/bin/blackwire")"
    print_next_steps
}

main "$@"
