# VLESS Client/Server Example

This example shows the currently implemented basic VLESS client/server data path:

```text
test client
  -> client proxy SOCKS5 inbound
  -> client proxy VLESS outbound
  -> server proxy VLESS inbound
  -> server proxy Freedom outbound
  -> target TCP service
```

`client.json` runs the local client-side proxy. It listens for SOCKS5 traffic on
`127.0.0.1:10080` and forwards every connection to the VLESS server at
`127.0.0.1:10443`.

`server.json` runs the server-side proxy. It accepts VLESS on
`127.0.0.1:10443`, authenticates the shared UUID, then uses `freedom` to connect
directly to the requested target.

The automated proof that bytes transfer through this chain is:

```sh
cargo test -p integration-tests e2e_socks5_to_vless_to_freedom_transfers_data
cargo test -p integration-tests e2e_socks5_to_vless_to_freedom_transfers_http
```

The first test starts both proxy instances plus a TCP echo server, sends
`HELLO PHASE1` through the SOCKS5 listener, and verifies the same bytes come
back from the echo server.

The second test starts both proxy instances plus a tiny HTTP/1.1 server, sends:

```http
GET /demo HTTP/1.1
Host: example.test
Connection: close
```

and verifies that the response comes back through the same SOCKS5 -> VLESS ->
Freedom chain.
