#!/usr/bin/env bash
# Client VPS provisioning script.
# Run as root on Ubuntu 24.04 after copying the labs/realistic directory.
# Usage: bash client-setup.sh /path/to/labs/realistic/configs/matrix.env
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ENV_FILE="${1:-$LAB_DIR/configs/matrix.env}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: $ENV_FILE not found. Copy matrix.env.example and fill in values."
    exit 1
fi
# shellcheck source=/dev/null
source "$ENV_FILE"

echo "==> Installing system packages"
apt-get update -q
apt-get install -y --no-install-recommends curl ca-certificates gettext-base netcat-openbsd

echo "==> Checking proxy-rs binary"
if [[ ! -x /usr/local/bin/proxy-rs ]]; then
    echo "ERROR: /usr/local/bin/proxy-rs not found."
    echo "Build with: cargo build --release  then  scp target/release/proxy-rs client:/usr/local/bin/"
    exit 1
fi

echo "==> Creating proxy-rs user and directories"
useradd --system --home /var/lib/proxy-rs --shell /usr/sbin/nologin proxy-rs 2>/dev/null || true
mkdir -p /etc/proxy-rs/generated /var/lib/proxy-rs
chown -R proxy-rs:proxy-rs /var/lib/proxy-rs

echo "==> Generating proxy-rs client configs"
for tpl in "$LAB_DIR/configs/client"/*.json; do
    name="$(basename "$tpl")"
    envsubst < "$tpl" > "/etc/proxy-rs/generated/client-$name"
done
chown -R proxy-rs:proxy-rs /etc/proxy-rs

echo ""
echo "==> Client setup complete."
echo "    Configs: /etc/proxy-rs/generated/client-*.json"
echo "    Next: run  bash scripts/run-matrix.sh $ENV_FILE"
