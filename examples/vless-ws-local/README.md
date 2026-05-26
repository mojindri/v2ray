# VLESS over WebSocket Local Example

This example shows a local VLESS-over-WebSocket data path:

```text
test client
  -> client proxy SOCKS5 inbound
  -> client proxy VLESS outbound
  -> WebSocket transport
  -> server proxy WebSocket inbound
  -> server proxy VLESS inbound
  -> server proxy Freedom outbound
  -> target TCP service
```

`client.json` listens for SOCKS5 on `127.0.0.1:13080` and forwards every
connection to the VLESS-over-WebSocket server at `127.0.0.1:13443`.

`server.json` listens for VLESS over plain WebSocket on `127.0.0.1:13443` with
path `/vless-ws`, authenticates the shared UUID, then uses `freedom` to connect to
the requested target.

This is intentionally a local plain-WS example. Production deployments should put
WebSocket behind TLS (`wss`) or a reverse proxy.

The automated proof that bytes transfer through this chain is:

```sh
cargo test -p integration-tests vless_over_ws_to_freedom_transfers_data
```

The test starts both proxy instances plus a TCP echo server, sends
`HELLO PHASE4 VLESS WS` through the SOCKS5 listener, and verifies the same bytes
come back from the echo server.
