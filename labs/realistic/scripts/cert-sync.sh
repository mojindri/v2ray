#!/usr/bin/env bash
# Copy Caddy-managed cert+key to /etc/proxy-rs/certs/ so proxy-rs inbounds can read them.
# Run as root after Caddy has obtained the certificate.
set -euo pipefail

DOMAIN="${1:?Usage: cert-sync.sh <domain>}"
DEST=/etc/proxy-rs/certs

# Caddy stores certs under the home directory of the caddy user.
CADDY_DATA="${CADDY_DATA_DIR:-/var/lib/caddy/.local/share/caddy}"
ACME_DIR="$CADDY_DATA/certificates/acme-v02.api.letsencrypt.org-directory/$DOMAIN"

if [[ ! -f "$ACME_DIR/$DOMAIN.crt" ]]; then
    # Try the alternate acme.sh-style path (Caddy < 2.7 or custom storage).
    ACME_DIR="$CADDY_DATA/certificates/acme-v02.api.letsencrypt.org-directory/$DOMAIN"
fi

if [[ ! -f "$ACME_DIR/$DOMAIN.crt" ]]; then
    echo "ERROR: certificate not found under $ACME_DIR"
    echo "Check: caddy list-certificates"
    exit 1
fi

mkdir -p "$DEST"
cp "$ACME_DIR/$DOMAIN.crt" "$DEST/cert.pem"
cp "$ACME_DIR/$DOMAIN.key" "$DEST/key.pem"
chown -R proxy-rs:proxy-rs "$DEST"
chmod 640 "$DEST/key.pem"

echo "Certs synced to $DEST ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
