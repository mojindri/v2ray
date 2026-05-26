#!/usr/bin/env bash
# REALITY key generation and setup guide.
#
# REALITY uses X25519 key pairs. The server has a private key and the client
# has the corresponding public key. Run this on your server to generate the keys.
#
# Usage:
#   1. Run this script:  bash examples/reality-keygen.sh
#   2. Copy the output into examples/reality-server.json (privateKey)
#      and examples/reality-client.json (publicKey).
#   3. Edit SERVER_IP in reality-client.json to your server's IP address.
#   4. Edit the UUID (you can run: blackwire uuid  to generate a fresh one).
#   5. Start the server: blackwire run -c examples/reality-server.json
#   6. Start the client: blackwire run -c examples/reality-client.json
#   7. Test:  curl --socks5 127.0.0.1:1080 https://example.com
set -euo pipefail

echo "=== REALITY Key Generation ==="
echo ""

# Generate a key pair using the built CLI tool.
# Output format: "Private key: <base64>  Public key: <base64>"
OUTPUT=$(cargo run -q --bin blackwire -- x25519 2>/dev/null)
echo "$OUTPUT"
echo ""

PRIVATE=$(echo "$OUTPUT" | grep "Private key:" | awk '{print $3}')
PUBLIC=$(echo "$OUTPUT" | grep "Public key:"  | awk '{print $3}')

echo "=== Add to reality-server.json ==="
echo "  \"privateKey\": \"$PRIVATE\","
echo ""
echo "=== Add to reality-client.json ==="
echo "  \"publicKey\": \"$PUBLIC\","
echo ""
echo "=== Also generate a UUID for the user list ==="
cargo run -q --bin blackwire -- uuid 2>/dev/null
echo ""
echo "Done. Edit the JSON files with the values above, then run the demo."
