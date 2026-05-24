# Phase 7 ShadowTLS v3 + VLESS Example

This example shows the current Phase 7 ShadowTLS v3 transport shape:

```text
client app
  -> local SOCKS5 inbound
  -> VLESS outbound
  -> ShadowTLS v3 layer
  -> server ShadowTLS v3 layer
  -> VLESS inbound
  -> Freedom outbound
  -> target site
```

The runtime signs the ClientHello SessionID, relays the camouflage TLS handshake
to `shadowTlsSettings.dest`, verifies the tainted backend ApplicationData proof,
then switches to ShadowTLS v3 rolling-HMAC ApplicationData frames before passing
bytes to the inner VLESS protocol.

Current caveat: local e2e coverage exists, but external interop against
sing-box/shadow-tls deployments still needs production-realistic lab proof
before this feature is promoted into the mandatory Docker/VPS matrix.

Validate:

```sh
cargo run -q -p blackwire -- test -c examples/phase7-shadowtls-vless/client.json
cargo run -q -p blackwire -- test -c examples/phase7-shadowtls-vless/server.json
cargo test -p integration-tests phase7_vless_over_shadowtls_v3_transfers_data
```
