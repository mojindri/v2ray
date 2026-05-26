# Shadowsocks 2022 Local Example

This example shows a local Shadowsocks 2022 data path:

```text
test client
  -> client proxy SOCKS5 or HTTP CONNECT inbound
  -> client proxy Shadowsocks 2022 outbound
  -> encrypted SS2022 TCP tunnel
  -> server proxy Shadowsocks 2022 inbound
  -> server proxy Freedom outbound
  -> target TCP service
```

`client.json` listens on:

- SOCKS5: `127.0.0.1:16080`
- HTTP CONNECT: `127.0.0.1:16118`
- metrics: `127.0.0.1:16090`

`server.json` listens on:

- Shadowsocks 2022: `127.0.0.1:16388`
- metrics: `127.0.0.1:16091`

Both configs use `2022-blake3-aes-256-gcm` and the same local test password.
Use a strong random password for real deployments.

The automated proof that bytes transfer through this chain is:

```sh
cargo test -p integration-tests ss2022_local_example_transfers_data
```
