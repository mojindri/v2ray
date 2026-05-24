# Phase 3 Hysteria2 Client/Server Example

This example shows the Phase 3 QUIC data path:

```text
test client
  -> client proxy SOCKS5 inbound
  -> client proxy Hysteria2 outbound
  -> QUIC UDP connection with Hysteria2 auth
  -> server proxy Hysteria2 inbound
  -> server proxy Freedom outbound
  -> target TCP service
```

`client.json` runs the local client-side proxy. It listens for SOCKS5 traffic on
`127.0.0.1:12080` and forwards every connection to the Hysteria2 server at
`127.0.0.1:12443`.

`server.json` runs the server-side proxy. It accepts Hysteria2 over QUIC/UDP on
`127.0.0.1:12443`, authenticates the shared password, then uses `freedom` to
connect directly to the requested target.

This example includes a throwaway self-signed certificate for localhost. The
client sets `skipCertVerify: true` so it can connect to that dev certificate.
Do not use these certs or `skipCertVerify` in production.

The automated proof that bytes transfer through this chain is:

```sh
cargo test -p integration-tests phase3_hysteria2_to_freedom_transfers_data
```

The test starts both proxy instances plus a TCP echo server, sends
`HELLO PHASE3 HYSTERIA2` through the SOCKS5 listener, and verifies the same
bytes come back from the echo server.

You can validate the example config files with:

```sh
cargo run -p blackwire -- test -c examples/phase3-hysteria2-client-server/server.json
cargo run -p blackwire -- test -c examples/phase3-hysteria2-client-server/client.json
```
