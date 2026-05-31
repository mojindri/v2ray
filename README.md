# Blackwire

Blackwire is a Rust-native proxy runtime for server and local proxy use cases.
It targets wire compatibility with selected Xray-core and sing-box client paths,
but uses its own JSON config schema rather than accepting Xray/sing-box configs
as a drop-in format.

Compatibility is proved with real upstream clients, not only in-process Rust
tests. The realistic lab under `labs/realistic/` drives the configured
external-client matrix from `labs/realistic/external-clients/scenarios.env`,
with Docker, Lima fingerprint checks, and optional two-VPS validation.

For exact support status, use [docs/release.md](docs/release.md) and
[docs/feature-matrix.md](docs/feature-matrix.md) as the source of truth.

## Release Status

This is a pre-1.0 project with an explicit support contract. The canonical
release contract lives in [docs/release.md](docs/release.md); the detailed
feature evidence table lives in [docs/feature-matrix.md](docs/feature-matrix.md).

High-level summary:

- Supported: core proxy runtime, server mode, local SOCKS/HTTP proxy mode, the documented protocol/transport matrix, Handler API structural operations, and TUN runtime on Linux/macOS/Windows.
- Experimental: Stats API (gRPC) runtime stats until soak and observability validation are complete.
- Unsupported: V2Ray/Xray JSON import, VMess legacy alterId/non-AEAD, Xray endpoint protobuf decoding for Handler structural RPCs, OpenWrt/Android/iOS, and a standalone desktop/mobile client app.

## Local Quickstart

Prerequisites:

- Rust toolchain from `rust-toolchain.toml`
- `make`
- Docker, only if you want the realistic interop lab
- Lima, only if you want VM fingerprint/performance checks

Build and run the local Rust gate:

```sh
make verify-local
```

Run the CLI directly from source:

```sh
cargo run -q -p blackwire -- --help
cargo run -q -p blackwire -- test -c examples/vless-client-server/server.json
cargo run -q -p blackwire -- run -c examples/vless-client-server/server.json
```

Run a local client/server example in two terminals:

```sh
cargo run -q -p blackwire -- run -c examples/vless-client-server/server.json
cargo run -q -p blackwire -- run -c examples/vless-client-server/client.json
```

The example client exposes SOCKS5 on `127.0.0.1:10080`:

```sh
curl --socks5-hostname 127.0.0.1:10080 https://example.com/
```

More examples live under [examples/](examples/), and command/environment details
live in [docs/16-environment-cheatsheet.md](docs/16-environment-cheatsheet.md).

## Fast Profile

Blackwire also has a latency-first `fast` operating profile for a narrower
production path. It keeps the same auth, TLS, REALITY validation, timeouts, and
parser strictness as compatibility mode, but rejects features that add hot-path
complexity.

Use it with:

```sh
blackwire run -c config.json --profile fast
```

Read [docs/fast-profile.md](docs/fast-profile.md) before enabling it; that doc
owns the exact constraints, defaults, and benchmark policy.

## Start Here

If you are new to the repo, read in this order:

1. [Project Map](docs/00-project-map.md)
2. [Request Lifecycle](docs/01-request-lifecycle.md)
3. [Crate Guide](docs/02-crate-guide.md)
4. [Protocols And Transports](docs/03-protocols-and-transports.md)

The full beginner-oriented doc index is at [docs/README.md](docs/README.md).

## Interop validation

One **public gate** per environment. Sub-steps inside a gate are implementation
detail — you normally run the gate, not each sub-step.

| Environment | Run this | What it checks |
| --- | --- | --- |
| **Docker (local)** | `make verify-lab-docker` | Xray REALITY interop plus the configured external-client scenarios against your server |
| **Lima VM (local)** | `make verify-lab-lima` | Browser-like TLS fingerprint (Chrome baseline) |
| **Two VPS (remote)** | `make verify-remote` | Full protocol matrix plus the configured external-client scenarios over real public network |

**Both** in one shot (no VPS):

```sh
make verify-lab    # verify-lab-docker + verify-lab-lima
```

### What runs inside `verify-lab-docker`

Interop is one block with **two legs** (you normally run `interop-docker`, not each leg):

| Leg | Target (debug only) | Direction | What it proves |
| --- | --- | --- | --- |
| **server-compat** | `interop-server-docker` | Xray/sing-box **client → your server** | Real apps can connect; scenarios from `external-clients/scenarios.env` |
| **client-compat** | `interop-client-reality` | **Your Rust client → Xray server** | REALITY/TLS client implementation matches live Xray-core (d1) |

Other internal steps:

| Step | Purpose |
| --- | --- |
| `stable` | In-process Rust integration matrix |
| `interop-docker` | Both interop legs above |
| `health-failover` | Balancer failover e2e (+ Docker probe/echo when available) |
| `negative-auth` | Wrong creds rejected / REALITY fallback |

On VPS, `verify-remote` runs **`interop-server-vps`** (server-compat only — same scenarios over real network).

Legacy aliases: `make xray` → `interop-client-reality`; `external-clients-docker` still works as an atom.

Details: [tests/interop/README.md](tests/interop/README.md),
[labs/realistic/external-clients/README.md](labs/realistic/external-clients/README.md).

## Current Status

The support contract above is the current status. The detailed feature table is
maintained in [docs/feature-matrix.md](docs/feature-matrix.md), and the
external-client PASS/SKIP rationale is maintained in
[docs/parity-status.md](docs/parity-status.md).

Some external-client matrix rows intentionally SKIP an upstream client because
that client no longer exposes a compatible model for the scenario. Those SKIPs
are documented exceptions, not automatic evidence that the blackwire server path
is unsupported.

## Fastest Useful Commands

Canonical verification (run from your local checkout):

```sh
make verify-local
make verify-lab
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make verify-remote
make verify-sweep          # broad gate; includes remote when SSH_* is set
make perf
```

| Command | Runs where | Purpose |
| --- | --- | --- |
| `make verify-local` | local machine | host-only Rust gate (fmt, check, clippy, test) |
| `make verify-lab` | local + Docker + Lima | production-like lab (no VPS) |
| `make verify-remote` | local orchestrating two VPS | closest production network validation |
| `make verify-sweep` | mixed | local + lab + security + fuzz-smoke (+ remote if configured) |
| `make verify-release` | mixed | slow pre-release gate (sweep + perf + soak + long fuzz) |
| `make perf` | Lima VM | performance benchmark |

Discovery:

```sh
make help
make help-compat
```

Workflow guide: [docs/test-workflows.md](docs/test-workflows.md). Full target map:
[docs/15-make-command-guide.md](docs/15-make-command-guide.md) and
[docs/make-target-inventory.md](docs/make-target-inventory.md).

**Compatibility aliases** (`make check`, `make check-browser`, `make check-vps`,
`make ci`, `make ci-all`, …) still work and print a deprecation hint. Prefer
`verify-*` in new docs and scripts.

```sh
# legacy aliases (still work)
make check
make check-browser
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make check-vps
```

## Test Environments

Three main tiers:

1. **Host Rust:** `make verify-local`
2. **Local lab (Docker + Lima):** `make verify-lab`
3. **Real VPS:** `SSH_SERVER=… SSH_CLIENT=… make verify-remote`

Full testing details: [docs/11-testing.md](docs/11-testing.md).
Make organization: [docs/15-make-command-guide.md](docs/15-make-command-guide.md).

Environment rule:

- local-only work: run from your local checkout
- Docker work: still run from your local checkout
- Lima VM work: still run from your local checkout; the scripts drive the VM
- VPS work: still run from your local checkout; the scripts SSH into the VPS machines
- if you use a key file, pass `SSH_KEY=~/.ssh/id_hetzner` (and optionally `SSH_USER` / `SSH_PORT`)

If you need a strict command-by-command separation, use:

- [docs/15-make-command-guide.md](docs/15-make-command-guide.md)
- [docs/11-testing.md](docs/11-testing.md)
- [docs/16-environment-cheatsheet.md](docs/16-environment-cheatsheet.md)

## Protocol Interop Notes

REALITY and Xray-specific notes are documented separately in
[tests/interop/README.md](tests/interop/README.md).

That guide explains:

- what `d0` and `d1` are actually proving
- why REALITY still needs a full TLS 1.3 handshake
- how the local Xray harness is wired
- why Xray `dest` must be a real HTTPS endpoint on port `443`

## Realistic Lab

The realistic Docker/VM/VPS lab starts at
[labs/realistic/README.md](labs/realistic/README.md).

Use it when you want:

- Docker-based realistic scenarios
- Lima VM browser and fingerprint validation
- two-VPS production-style validation
- benchmark and evidence collection flows

Performance-specific commands are documented in the realistic lab, testing docs,
and Make command guide:

- [labs/realistic/README.md](labs/realistic/README.md)
- [docs/11-testing.md](docs/11-testing.md)
- [docs/15-make-command-guide.md](docs/15-make-command-guide.md)

## Examples

If you learn better from runnable examples, start here:

- [VLESS Client/Server](examples/vless-client-server/README.md)
- [REALITY Client/Server](examples/reality-client-server/README.md)
- [Hysteria2 Client/Server](examples/hysteria2-client-server/README.md)
- [VLESS + WebSocket Local](examples/vless-ws-local/README.md)
- [HTTP + VMess + gRPC Local](examples/http-vmess-grpc-local/README.md)
- [SS2022 Local](examples/ss2022-local/README.md)
- [DNS + FakeIP Routing](examples/dns-fakeip-routing/README.md)
- [ShadowTLS + VLESS](examples/shadowtls-vless/README.md)
- [Health + Failover](examples/health-failover/README.md)
- [mKCP + VLESS](examples/mkcp-vless/README.md)
- [TUN Local](examples/tun-local/README.md)

## Deeper Reading

Useful follow-up docs after the first four:

- [REALITY For Dummies](docs/04-reality-for-dummies.md)
- [VLESS, VMess, And Trojan Comparison](docs/05-vless-vmess-trojan-comparison.md)
- [How To Debug This Repo](docs/06-how-to-debug.md)
- [How To Add A New Protocol Or Transport](docs/07-how-to-add-a-new-protocol-or-transport.md)
- [Config For Dummies](docs/08-config-for-dummies.md)
- [Trace One Connection In Code](docs/09-trace-one-connection-in-code.md)
- [Glossary](docs/10-glossary.md)
- [Production Readiness Notes](docs/12-production-readiness.md)
- [Real Device Test Plan](docs/13-real-device-test-plan.md)
- [Security Audit Checklist](docs/14-security-audit-checklist.md)
