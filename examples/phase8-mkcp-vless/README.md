# Phase 8 mKCP + VLESS Example

This example shows the current mKCP transport shape:

```text
client app
  -> local SOCKS5 inbound
  -> VLESS outbound
  -> mKCP over UDP
  -> server mKCP listener
  -> VLESS inbound
  -> Freedom outbound
  -> target site
```

mKCP is useful when the link is UDP-friendly but TCP performs badly because of
loss or unstable latency. The example keeps the protocol as VLESS and swaps the
transport from plain TCP/WebSocket/gRPC to `network: "kcp"`.

Current status: the runtime path accepts multiple peers on one UDP listener and
cleans up idle sessions. Loss/latency behavior and packet capture validation
still belong in the realistic Docker/VPS lab before this is promoted to the
mandatory production matrix.

Validate:

```sh
cargo run -q -p blackwire -- test -c examples/phase8-mkcp-vless/client.json
cargo run -q -p blackwire -- test -c examples/phase8-mkcp-vless/server.json
cargo test -p integration-tests phase8_vless_over_mkcp
```

Author: @moji.ndr
