# Phase 2 REALITY Client/Server Example

This example shows the Phase 2 data path:

```text
test client
  -> client proxy SOCKS5 inbound
  -> client proxy VLESS outbound
  -> REALITY client handshake
  -> REALITY server authentication
  -> server proxy VLESS inbound
  -> server proxy Freedom outbound
  -> target TCP or HTTP service
```

The example is intentionally local so it can be tested without a VPS:

- `client.json` listens for SOCKS5 on `127.0.0.1:11080`.
- `server.json` listens for REALITY-protected VLESS on `127.0.0.1:11443`.
- The server uses `freedom` to connect to the target requested through SOCKS5.

Important caveat: this is the current Phase 2 direct REALITY mode. It
authenticates a Chrome-like ClientHello and then hands the stream directly to
VLESS. Full TLS completion with certificates is still not implemented.

The automated proof that bytes transfer through this chain is:

```sh
cargo test -p integration-tests phase2_reality_vless_to_freedom_transfers_data
```

The test starts both proxy instances plus a TCP echo server, sends
`HELLO PHASE2 REALITY` through the SOCKS5 listener, and verifies that the same
bytes come back from the echo server.

The key pair in these files is disposable and only for localhost examples.
Generate real deployment keys with:

```sh
cargo run -p proxy-rs -- x25519
```
