# Phase 7 ShadowTLS v3 + VLESS Example

This example shows the intended Phase 7 ShadowTLS v3 shape:

```text
client app
  -> local SOCKS5 inbound
  -> VLESS outbound
  -> ShadowTLS v3 camouflage layer
  -> server ShadowTLS v3 layer
  -> VLESS inbound
  -> Freedom outbound
  -> target site
```

ShadowTLS makes the connection begin like a real TLS session to a legitimate
backend such as `www.apple.com:443`, then switches to proxy traffic after the
shared marker is accepted.

Current caveat: the Phase 7 schema and transport primitives are present, but the
main instance transport stack does not yet fully apply `security: "shadowtls"` to
VLESS/Trojan/VMess outbounds and inbounds. Treat these files as validated config
templates for the intended wiring.

Validate:

```sh
cargo run -q -p proxy-rs -- test -c examples/phase7-shadowtls-vless/client.json
cargo run -q -p proxy-rs -- test -c examples/phase7-shadowtls-vless/server.json
```
