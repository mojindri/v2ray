# Realistic Test Lab

This lab is the production-realism layer for `proxy-rs`.

It has two jobs:

1. Run the stable protocol matrix in a repeatable local environment.
2. Provide a two-VPS checklist for the same scenarios over real public networking.

## What Is Mandatory Green

The mandatory matrix is limited to paths that are wired end-to-end today:

- VLESS TCP
- VLESS REALITY
- VLESS over WebSocket
- VMess over gRPC
- Trojan over TLS
- Shadowsocks 2022
- Hysteria2
- Xray REALITY interop

Phase 7/8 features are not mandatory green until they have realistic-lab proof:

- ShadowTLS marker mode has local e2e coverage, but full upstream v3 interop still needs VPS proof.
- mKCP multi-peer mode has local e2e coverage, but loss/latency behavior still needs VPS proof.
- TUN config/device helpers exist, but packet runtime is intentionally rejected until TCP/UDP stack and NAT are implemented.
- health/failover realistic failover scenarios
- geo/FakeIP production routing scenarios

## Local Docker Baseline

Run the full local baseline:

```sh
make -C labs/realistic docker-full
```

This does three things:

1. Starts deterministic target services for manual probing.
2. Runs the stable Rust integration matrix.
3. Starts Xray and runs the live REALITY interop tests.

Reports are written under `labs/realistic/reports/`.

Clean up:

```sh
make -C labs/realistic docker-down
```

## Two-VPS Gate

The closest-to-production gate uses two Ubuntu 24.04 VPS machines:

- client VPS: runs the client-side `proxy-rs` instance and traffic generator.
- server VPS: runs public protocol inbounds, target services, Caddy ACME, and firewall rules.

Start with:

```sh
make -C labs/realistic vm-pack
```

Then follow [vps/README.md](vps/README.md).

## Why This Lab Reuses Existing Tests

The existing integration tests already exercise real `proxy-core::Instance`
objects with the stable protocol stack. This lab deliberately wraps those tests
instead of duplicating protocol logic in shell scripts.

The Docker services here provide realistic targets and Xray compatibility
coverage. Full client/server process orchestration is added per feature only
after that feature has a passing local e2e test.
