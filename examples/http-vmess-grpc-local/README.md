# HTTP CONNECT to VMess over gRPC Local Example

This example shows a local HTTP CONNECT → VMess → gRPC data path:

```text
test client
  -> client proxy HTTP CONNECT inbound
  -> client proxy VMess outbound
  -> gRPC transport
  -> server proxy gRPC inbound
  -> server proxy VMess inbound
  -> server proxy Freedom outbound
  -> target TCP service
```

`client.json` listens for HTTP CONNECT on `127.0.0.1:15080` and forwards every
tunnel to the VMess-over-gRPC server at `127.0.0.1:15443`.

`server.json` listens for VMess over plain gRPC on `127.0.0.1:15443`, using the
service name `demo.Gun`, authenticates the shared UUID, then uses `freedom` to
connect to the requested target.

This is intentionally a local plaintext gRPC example. Production deployments
should put gRPC behind TLS or a trusted reverse proxy.

The automated proof that bytes transfer through this chain is:

```sh
cargo test -p integration-tests http_connect_vmess_grpc_transfers_data
```
