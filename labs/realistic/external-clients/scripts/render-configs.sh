#!/usr/bin/env bash
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REALISTIC_DIR="$(cd "$LAB_DIR/.." && pwd)"
ENV_FILE="${1:-$REALISTIC_DIR/configs/matrix.env}"
OUT_DIR="${2:-$LAB_DIR/generated}"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "ERROR: matrix env not found: $ENV_FILE" >&2
    exit 1
fi

set -a
# shellcheck source=/dev/null
source "$ENV_FILE"
set +a

export EXTERNAL_SERVER_ADDRESS="${EXTERNAL_SERVER_ADDRESS:-blackwire-server}"
export EXTERNAL_TLS_SERVER_NAME="${EXTERNAL_TLS_SERVER_NAME:-blackwire.local}"

REALITY_PUBLIC_KEY_XRAY="$REALITY_PUBLIC_KEY"
if [[ "$REALITY_PUBLIC_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
    REALITY_PUBLIC_KEY_XRAY="$(python3 - "$REALITY_PUBLIC_KEY" <<'PY'
import base64
import sys
print(base64.urlsafe_b64encode(bytes.fromhex(sys.argv[1])).decode().rstrip("="))
PY
)"
fi
export REALITY_PUBLIC_KEY_XRAY

rm -rf "$OUT_DIR"
mkdir -p \
    "$OUT_DIR/blackwire" \
    "$OUT_DIR/xray" \
    "$OUT_DIR/sing-box" \
    "$OUT_DIR/xray-negative" \
    "$OUT_DIR/sing-box-negative" \
    "$OUT_DIR/certs" \
    "$OUT_DIR/hiddify"

for tpl in "$REALISTIC_DIR/configs/server"/*.json; do
    envsubst < "$tpl" > "$OUT_DIR/blackwire/server-$(basename "$tpl")"
done

for tpl in "$LAB_DIR/configs/xray"/*.json.tmpl; do
    envsubst < "$tpl" > "$OUT_DIR/xray/$(basename "$tpl" .tmpl)"
done

for tpl in "$LAB_DIR/configs/sing-box"/*.json.tmpl; do
    envsubst < "$tpl" > "$OUT_DIR/sing-box/$(basename "$tpl" .tmpl)"
done

(
    export VLESS_UUID="00000000-0000-4000-8000-000000000001"
    export VMESS_UUID="00000000-0000-4000-8000-000000000002"
    export TROJAN_PASSWORD="wrong-${TROJAN_PASSWORD}"
    # Use a valid base64 32-byte key that differs from the real key — xray/sing-box
    # reject non-base64 strings at startup, which would mask server-side rejection.
    export SS2022_PASSWORD="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    export HYSTERIA2_PASSWORD="wrong-${HYSTERIA2_PASSWORD}"
    export REALITY_SHORT_ID="0000000000000000"
    for tpl in "$LAB_DIR/configs/xray"/*.json.tmpl; do
        envsubst < "$tpl" > "$OUT_DIR/xray-negative/$(basename "$tpl" .tmpl)"
    done
    for tpl in "$LAB_DIR/configs/sing-box"/*.json.tmpl; do
        envsubst < "$tpl" > "$OUT_DIR/sing-box-negative/$(basename "$tpl" .tmpl)"
    done
)

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -nodes -days 2 \
    -keyout "$OUT_DIR/certs/key.pem" \
    -out "$OUT_DIR/certs/cert.pem" \
    -subj "/CN=blackwire.local" \
    -addext "subjectAltName=DNS:blackwire.local,DNS:blackwire-server" \
    >/dev/null 2>&1

cat > "$OUT_DIR/hiddify/vless-reality.txt" <<EOF
vless://${VLESS_UUID}@${SERVER_HOST}:10443?encryption=none&security=reality&type=tcp&sni=${REALITY_SERVER_NAME}&fp=chrome&pbk=${REALITY_PUBLIC_KEY_XRAY}&sid=${REALITY_SHORT_ID}#blackwire-vless-reality
EOF

cat > "$OUT_DIR/hiddify/trojan-tls.txt" <<EOF
trojan://${TROJAN_PASSWORD}@${SERVER_HOST}:8445?security=tls&sni=${TEST_DOMAIN}&type=tcp#blackwire-trojan-tls
EOF

cat > "$OUT_DIR/hiddify/ss2022.txt" <<EOF
ss://$(printf '2022-blake3-aes-256-gcm:%s' "$SS2022_PASSWORD" | base64 | tr -d '\n')@${SERVER_HOST}:8388#blackwire-ss2022
EOF

echo "Rendered external-client configs under $OUT_DIR"
