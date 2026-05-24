#!/usr/bin/env bash
# Copy Caddy-managed cert+key to /etc/blackwire/certs/ so blackwire inbounds can read them.
# Run as root after Caddy has obtained the certificate.
set -euo pipefail

DOMAIN="${1:?Usage: cert-sync.sh <domain>}"
DEST=/etc/blackwire/certs

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
# Convert to PKCS#8 to maximize parser compatibility across TLS stacks.
openssl pkcs8 -topk8 -nocrypt -in "$ACME_DIR/$DOMAIN.key" -out "$DEST/key.pem"
chown -R blackwire:blackwire "$DEST"
chmod 640 "$DEST/key.pem"

echo "Certs synced to $DEST ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
