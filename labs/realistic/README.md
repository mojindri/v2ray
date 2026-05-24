# Realistic Test Lab

This lab is the production-realism layer for `blackwire`.

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

**Advanced features** (ShadowTLS, mKCP, health/failover, DNS/geo routing) have local smoke
tests via `make -C labs/realistic advanced-features-smoke` but are not mandatory green yet.
See the table above and [labs/realistic/README.md](labs/realistic/README.md).

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

Run advanced-feature smoke tests (ShadowTLS, mKCP, health/failover, DNS/routing guards):

```sh
make -C labs/realistic advanced-features-smoke
```

Writes `reports/advanced-features-smoke.log`.

Run negative-auth scenarios:

```sh
make -C labs/realistic negative-auth
```

Run restart smoke checks:

```sh
make -C labs/realistic restart-smoke
```

Run repeat stress loop:

```sh
make -C labs/realistic stress
```

Build a compact report summary:

```sh
make -C labs/realistic report-summary
```

Run the whole realistic bundle:

```sh
make -C labs/realistic realistic-all
```

Clean up:

```sh
make -C labs/realistic docker-down
```

## External Client Compatibility

The external-client lab checks the scenarios currently configured under
`external-clients/scenarios.env` against a `blackwire` server inbound. This is
different from `vps-test`, which checks `blackwire` client to `blackwire` server.

```sh
make -C labs/realistic external-clients-docker
make -C labs/realistic external-clients-report
```

After Docker passes, promote the same external-client check to the two-VPS lab:

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_hetzner make -C labs/realistic external-clients-vps
```

Generated configs and Hiddify import artifacts are written under
`labs/realistic/external-clients/generated/`. Reports are written under
`labs/realistic/reports/external-clients/`.

Run this before claiming GUI-client compatibility for a specific scenario set. A
passing `blackwire` client matrix does not prove Xray, sing-box, or Hiddify
inbound compatibility on paths that are not in the current external-client
scenario file.

## Two-VPS Gate

The closest-to-production gate uses two Ubuntu 24.04 VPS machines:

- client VPS: runs the client-side `blackwire` instance and traffic generator.
- server VPS: runs public protocol inbounds, target services, Caddy ACME, and firewall rules.

See [docs/11-testing.md](../../docs/11-testing.md) for the full step-by-step VPS workflow.

Quick start:

```sh
# Fill in your server IP, domain, keys, and passwords
cp configs/matrix.env.example configs/matrix.env

# Provision server VPS
SSH_SERVER=1.2.3.4 SSH_KEY=~/.ssh/id_hetzner make vps-server-setup

# Provision client VPS
SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_hetzner make vps-client-setup

# Run the 7-protocol matrix from the client
SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_hetzner make vps-test

# Run TUN privileged tests on the server (Linux + root)
SSH_SERVER=1.2.3.4 SSH_KEY=~/.ssh/id_hetzner make vps-tun
```

Optional SSH overrides:

- `SSH_USER`
- `SSH_PORT`
- `SSH_EXTRA_OPTS`

Or pack everything into a tarball and transfer manually:

```sh
make vm-pack
# Then follow vps/README.md on each machine
```

## Why This Lab Reuses Existing Tests

The existing integration tests already exercise real `proxy-core::Instance`
objects with the stable protocol stack. This lab deliberately wraps those tests
instead of duplicating protocol logic in shell scripts.

The Docker services here provide realistic targets and Xray compatibility
coverage. Full client/server process orchestration is added per feature only
after that feature has a passing local e2e test.
