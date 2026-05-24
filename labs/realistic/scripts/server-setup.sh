#!/usr/bin/env bash
# Server VPS provisioning script.
# Run as root on Ubuntu 24.04 after copying the labs/realistic directory.
# Usage: bash server-setup.sh /path/to/labs/realistic/configs/matrix.env
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${1:-$LAB_DIR/configs/matrix.env}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: $ENV_FILE not found. Copy matrix.env.example and fill in values."
    exit 1
fi
# Export sourced values so envsubst sees them.
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

echo "==> Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y --no-install-recommends -qq \
    curl ca-certificates socat gettext-base ufw iproute2 rustc cargo >/dev/null

echo "==> Installing Caddy"
if ! command -v caddy &>/dev/null; then
    curl -fsSL https://dl.cloudsmith.io/public/caddy/stable/gpg.key \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/caddy-stable-archive-keyring.gpg] \
https://dl.cloudsmith.io/public/caddy/stable/deb/debian any-version main" \
        > /etc/apt/sources.list.d/caddy-stable.list
    apt-get update -qq >/dev/null
    apt-get install -y -qq caddy >/dev/null
fi

echo "==> Checking blackwire binary"
if [[ ! -x /usr/local/bin/blackwire ]]; then
    echo "ERROR: /usr/local/bin/blackwire not found."
    echo "Build with: cargo build --release  then  scp target/release/blackwire server:/usr/local/bin/"
    exit 1
fi

echo "==> Creating blackwire user and directories"
useradd --system --home /var/lib/blackwire --shell /usr/sbin/nologin blackwire 2>/dev/null || true
mkdir -p /etc/blackwire/certs /etc/blackwire/generated /var/lib/blackwire
chown -R blackwire:blackwire /var/lib/blackwire

echo "==> Configuring Caddy"
TEST_DOMAIN="$TEST_DOMAIN" envsubst < "$LAB_DIR/configs/caddy/Caddyfile" > /etc/caddy/Caddyfile
systemctl enable --now caddy
systemctl reload caddy || systemctl restart caddy

echo "==> Waiting for Caddy to obtain TLS certificate (up to 120s)"
CERT_READY=0
for i in $(seq 1 24); do
    if caddy list-certificates 2>/dev/null | grep -q "$TEST_DOMAIN"; then
        CERT_READY=1
        break
    fi
    sleep 5
done
if [[ "$CERT_READY" -eq 1 ]]; then
    echo "Certificate obtained."
else
    echo "Certificate not reported yet; continuing with cert sync attempt."
fi

echo "==> Syncing certificates to /etc/blackwire/certs/"
bash "$SCRIPT_DIR/cert-sync.sh" "$TEST_DOMAIN"

echo "==> Generating blackwire server configs"
for tpl in "$LAB_DIR/configs/server"/*.json; do
    name="$(basename "$tpl")"
    envsubst < "$tpl" > "/etc/blackwire/generated/server-$name"
done
chown -R blackwire:blackwire /etc/blackwire

echo "==> Starting target HTTP echo service on :18080"
# Simple HTTP echo on port 18080 for the client-side matrix test.
if ! systemctl is-active --quiet blackwire-target 2>/dev/null; then
    cat > /etc/systemd/system/blackwire-target.service << 'EOF'
[Unit]
Description=blackwire lab HTTP target
After=network.target

[Service]
ExecStart=/usr/bin/python3 -m http.server 18080 --directory /var/lib/blackwire
Restart=always
User=blackwire

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable --now blackwire-target
fi

echo "==> Configuring UFW firewall"
ufw allow OpenSSH
ufw allow 80/tcp    # Caddy ACME + fallback
ufw allow 443/tcp   # Caddy HTTPS
ufw allow 10080/tcp # VLESS TCP
ufw allow 10443/tcp # VLESS REALITY
ufw allow 8443/tcp  # VLESS WS+TLS
ufw allow 8444/tcp  # VMess gRPC+TLS
ufw allow 8445/tcp  # Trojan TLS
ufw allow 8388/tcp  # SS2022
ufw allow 4433/udp  # Hysteria2 QUIC
ufw --force enable

echo "==> Setting up weekly cert renewal sync"
cat > /etc/cron.weekly/blackwire-cert-sync << EOF
#!/bin/sh
bash $SCRIPT_DIR/cert-sync.sh "$TEST_DOMAIN"
for cfg in /etc/blackwire/generated/server-*.json; do
    systemctl restart "blackwire-\$(basename \$cfg .json)" 2>/dev/null || true
done
EOF
chmod +x /etc/cron.weekly/blackwire-cert-sync

echo ""
echo "==> Server setup complete."
echo "    Configs: /etc/blackwire/generated/server-*.json"
echo "    Certs:   /etc/blackwire/certs/cert.pem  key.pem"
echo "    Next: run the individual protocol services or use run-matrix.sh from the client VPS."
