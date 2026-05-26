# REALITY Client/Server Example

This example shows the REALITY client/server data path:

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

Important caveat: this example no longer uses the old "direct REALITY" shortcut.
The REALITY client now completes the TLS handshake, and the local server side
unwraps that TLS session before handing application bytes to VLESS.

For the localhost example, the server uses an internal throwaway certificate to
finish TLS after REALITY authentication. This is enough for local end-to-end
tests, but it is not the same thing as live Xray REALITY camouflage against a
real cover origin.

The automated proof that bytes transfer through this chain is:

```sh
cargo test -p integration-tests reality_vless_to_freedom_transfers_data
```

The test starts both proxy instances plus a TCP echo server, sends
`HELLO PHASE2 REALITY` through the SOCKS5 listener, and verifies that the same
bytes come back from the echo server.

The key pair in these files is disposable and only for localhost examples.
Generate real deployment keys with:

```sh
cargo run -p blackwire -- x25519
```
