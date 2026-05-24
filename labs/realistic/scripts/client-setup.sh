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
# Export sourced values so envsubst sees them.
set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

echo "==> Installing system packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -y --no-install-recommends -qq \
    curl ca-certificates gettext-base netcat-openbsd >/dev/null

echo "==> Checking blackwire binary"
if [[ ! -x /usr/local/bin/blackwire ]]; then
    echo "ERROR: /usr/local/bin/blackwire not found."
    echo "Build with: cargo build --release  then  scp target/release/blackwire client:/usr/local/bin/"
    exit 1
fi

echo "==> Creating blackwire user and directories"
useradd --system --home /var/lib/blackwire --shell /usr/sbin/nologin blackwire 2>/dev/null || true
mkdir -p /etc/blackwire/generated /var/lib/blackwire
chown -R blackwire:blackwire /var/lib/blackwire

echo "==> Generating blackwire client configs"
for tpl in "$LAB_DIR/configs/client"/*.json; do
    name="$(basename "$tpl")"
    envsubst < "$tpl" > "/etc/blackwire/generated/client-$name"
done
chown -R blackwire:blackwire /etc/blackwire

echo ""
echo "==> Client setup complete."
echo "    Configs: /etc/blackwire/generated/client-*.json"
echo "    Next: run  bash scripts/run-matrix.sh $ENV_FILE"
