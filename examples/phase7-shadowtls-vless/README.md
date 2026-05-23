# Phase 7 ShadowTLS Marker + VLESS Example

This example shows the current Phase 7 ShadowTLS marker transport shape:

```text
client app
  -> local SOCKS5 inbound
  -> VLESS outbound
  -> ShadowTLS marker layer
  -> server ShadowTLS marker layer
  -> VLESS inbound
  -> Freedom outbound
  -> target site
```

The current runtime wiring validates a shared marker before passing bytes to the
inner VLESS protocol. This is useful for local Phase 7 plumbing tests.

Current caveat: this is not full upstream ShadowTLS v3 interop yet. The real v3
handshake relay still needs production-realistic validation before this feature
is promoted into the mandatory Docker/VPS lab matrix.

Validate:

```sh
cargo run -q -p proxy-rs -- test -c examples/phase7-shadowtls-vless/client.json
cargo run -q -p proxy-rs -- test -c examples/phase7-shadowtls-vless/server.json
cargo test -p integration-tests phase7_vless_over_shadowtls_marker_transfers_data
```
