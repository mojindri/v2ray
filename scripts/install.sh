#!/usr/bin/env bash
set -euo pipefail

REPO="${BLACKWIRE_REPO:-mojindri/v2ray}"
VERSION="${VERSION:-latest}"
DOWNLOAD_BASE="${BLACKWIRE_DOWNLOAD_BASE:-}"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="${CONFIG_DIR:-/etc/blackwire}"
STATE_DIR="${STATE_DIR:-/var/lib/blackwire}"
RUN_DIR="${RUN_DIR:-/run/blackwire}"
INSTALL_SYSTEMD="${INSTALL_SYSTEMD:-auto}"
START_SERVICE="${START_SERVICE:-0}"

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
    cat > "$tmp_unit" <<UNIT
[Unit]
Description=blackwire proxy runtime
Documentation=https://github.com/${REPO}
After=network-online.target
Wants=network-online.target

[Service]
User=nobody
Group=nobody
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
    else
        log "service not started; create ${CONFIG_DIR}/config.json, then run: systemctl enable --now blackwire"
    fi
}

main() {
    need_cmd curl
    need_cmd tar
    need_cmd install
    need_cmd sha256sum
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

    case "$INSTALL_SYSTEMD" in
        1|true|yes) install_systemd_unit ;;
        0|false|no) ;;
        auto) install_systemd_unit ;;
        *) die "invalid INSTALL_SYSTEMD value: $INSTALL_SYSTEMD" ;;
    esac

    log "installed: $("$PREFIX/bin/blackwire" version 2>/dev/null || "$PREFIX/bin/blackwire" --version 2>/dev/null || echo "$PREFIX/bin/blackwire")"
}

main "$@"
