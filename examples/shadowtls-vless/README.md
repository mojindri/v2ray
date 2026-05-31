# ShadowTLS v3 + VLESS Example

This example shows the current ShadowTLS v3 + VLESS transport shape:

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

Current caveat: the server path is supported with local e2e proof. External
client matrix rows intentionally SKIP because upstream clients do not expose a
compatible VLESS-over-ShadowTLS client model.

Validate:

```sh
cargo run -q -p blackwire -- test -c examples/shadowtls-vless/client.json
cargo run -q -p blackwire -- test -c examples/shadowtls-vless/server.json
cargo test -p integration-tests vless_over_shadowtls_v3_transfers_data
```
