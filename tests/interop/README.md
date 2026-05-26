# Xray REALITY Interop

This directory contains the differential interop harness for REALITY.

The point of these tests is not just "did TCP connect" and not just "did the
REALITY token look valid". The point is to verify that our Rust client behaves
the way a real Xray REALITY peer expects.

## Why TLS matters here

TLS is doing more than camouflage.

A valid TLS 1.3 connection must:

1. Exchange `ClientHello` / `ServerHello`.
2. Negotiate a shared key agreement group.
3. Derive the same handshake traffic secrets on both sides.
4. Verify `Finished`.
5. Only then start application data.

REALITY hides authentication inside a browser-like TLS `ClientHello`, but Xray
still expects the rest of the TLS handshake to complete. If our client only
sent a believable `ClientHello` and stopped there, Xray would reject the
connection because its TLS state never became fully established.

That is what the TLS 1.3 completion tests are checking.

## Test tiers

### `d0` self-interop

Run:

```sh
cargo test -p blackwire-transport --test interop d0 -- --ignored --nocapture
```

What it proves:

- Our `RealityClient` and `RealityServer` agree on REALITY token parsing.
- The authenticated path can finish TLS 1.3 locally.
- Application bytes can flow after the handshake.
- Invalid auth still goes to fallback.

This is an internal consistency check against our own implementation.

### `d1` live Xray interop (client-compat leg)

Run:

```sh
make -C labs/realistic interop-client-reality
# or: cd tests/interop && make up && cargo test -p blackwire-transport --test interop d1 -- --ignored --nocapture
```

What it proves:

- Our `RealityClient` can authenticate to a real `xray-core` REALITY server.
- The TLS 1.3 handshake completes the way Xray expects.
- Wrong short IDs and wrong SNI values hit the fallback path instead.
- A bare active-probe style `ClientHello` does not trigger a TCP reset.

This is the real compatibility check.

## Local test environment

`make up` renders the Xray configs and starts the Docker Compose stack:

- `xray-server`: `ghcr.io/xtls/xray-core:latest`
- `nginx-fallback`: plain HTTP fallback service

The Rust tests connect to `127.0.0.1:8443`.

The Xray config template is:

- [configs/xray-server.json.tmpl](/Users/mojnader/RustroverProjects/v2ray/tests/interop/configs/xray-server.json.tmpl)

Important settings:

- `dest` is `microsoft.com:443`
- `serverNames` includes `example.com`
- `shortIds` is rendered from `keys/short_id.txt`

The fallback nginx config is:

- [configs/nginx.conf](/Users/mojnader/RustroverProjects/v2ray/tests/interop/configs/nginx.conf)

It listens on plain HTTP intentionally so fallback is easy to detect in tests.

## Why `dest` must be HTTPS on port 443

`dest` is not just an arbitrary upstream.

For the valid REALITY path, Xray relays a real TLS handshake from the cover
destination. That means `dest` must itself speak TLS. If it points at plain
HTTP on port 80, there is no real certificate or `ServerHello` to relay, so
the client cannot finish TLS 1.3.

That is why the interop config uses `microsoft.com:443` instead of the local
nginx fallback.

## Known live-Xray behavior we had to match

When tested against live Xray, the cover origin selected `secp256r1` for the
TLS key agreement. If the client offered only `x25519`, Xray relayed a real
TLS `HelloRetryRequest`.

To interoperate cleanly, the Rust client now offers both:

- `x25519` for REALITY auth and normal TLS
- `secp256r1` for TLS servers that prefer P-256

That first-flight dual offer is what made the `d1` TLS 1.3 handshake pass.

## CI gates

Pull requests run `.github/workflows/interop-smoke.yml`:

- `cargo test -p integration-tests --locked` (parity unit tests, production readiness)
- `make -C labs/realistic advanced-features-smoke` (ShadowTLS + mKCP)

Scheduled / `workflow_dispatch` runs also execute `make -C labs/realistic interop-server-docker`
(external Xray/sing-box clients against a blackwire server). On failure, interop logs are
uploaded from `labs/realistic/reports/`.

Wire parity exit criteria are defined in `docs/xray-parity-source-of-truth.md`.
