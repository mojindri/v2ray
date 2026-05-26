# Testing Guide

This document is the single reference for running every test tier in this project — from fast unit tests through to two-VPS production validation. Run them in order; each tier builds on the previous one.

---

## Overview

| Tier | What it covers | Time | Requires |
|------|---------------|------|----------|
| 1. Unit tests | Per-crate logic | ~5s | Rust toolchain |
| 2. Integration tests | End-to-end protocol matrix | ~30s | Rust toolchain |
| 3. Production readiness | Config validation, guard checks | ~10s | Rust toolchain |
| 4. Docker baseline | Stable matrix + interop-docker (server + client legs) | ~5 min | Docker |
| 5. Advanced features smoke | ShadowTLS, mKCP, health, geo/FakeIP guards | ~30s | Rust toolchain |
| 6. Stress loop | Flakiness detection on high-signal tests | ~2 min | Rust toolchain |
| 7. Interop d0 self-consistency | REALITY token + TLS self-consistency (Rust only) | ~5s | Rust toolchain |
| 8. Interop server-compat | Xray/sing-box clients → our server | ~5 min | Docker |
| 9. Interop client-compat | Our Rust client → Xray REALITY server (d1) | ~30s | Docker |
| 10. VPS external-client matrix | Same 16 rows as Docker (`scenarios.env`) over public network | ~10 min | Two Ubuntu 24.04 VPS |
| 11. TUN privileged | TUN device, iptables, SO_MARK on Linux | ~1 min | Linux VPS + root |

## Where You Run Things

This repo has two different meanings of "run":

1. where you invoke the command from
2. where the actual workload executes

Use this split:

| Tier / Command | Invoke from | Executes on | Needs real VPS? |
|---|---|---|---|
| `cargo test --workspace` | local checkout | local machine | no |
| `cargo test -p integration-tests` | local checkout | local machine | no |
| production-readiness tests | local checkout | local machine | no |
| `make -C labs/realistic docker-full` | local checkout | local machine + Docker | no |
| `make -C labs/realistic interop-docker` | local checkout | local machine + Docker | no |
| `make -C labs/realistic interop-server-docker` | local checkout | local machine + Docker | no |
| `make -C labs/realistic interop-client-reality` | local checkout | local machine + Docker | no |
| `make verify-lab-lima` | local checkout | local machine + Lima VM | no |
| `make perf` | local checkout | Lima VM | no |
| `make verify-remote` | local checkout | local machine + remote VPS over SSH | yes |
| `make perf-remote` | local checkout | remote VPS over SSH | yes |
| `make -C labs/realistic vps-server-setup` | local checkout | server VPS over SSH | yes |
| `make -C labs/realistic vps-client-setup` | local checkout | client VPS over SSH | yes |
| `make -C labs/realistic vps-test` | local checkout | client VPS over SSH | yes |
| `make -C labs/realistic interop-server-vps` | local checkout | both VPS machines over SSH | yes |
| `make -C labs/realistic vps-tun` | local checkout | server VPS over SSH | yes |

Important:

- For normal usage, invoke commands from your local repo checkout.
- **Canonical gates:** `verify-local`, `verify-lab`, `verify-remote`, `verify-sweep`, `verify-release` — see [test-workflows.md](test-workflows.md).
- Legacy `make check`, `make check-browser`, `make check-vps` remain as compatibility aliases.
- VPS commands are launched locally; they SSH into remote machines.
- Pass `SSH_KEY=~/.ssh/id_ed25519` (and optionally `SSH_USER` / `SSH_PORT`) for VPS work.
- SSH directly into a VPS only for debugging, service inspection, or manual recovery.

The external-client lab (Docker and VPS) is the first gate for GUI/app compatibility.
The automated scenario set is **16 protocol rows** in `labs/realistic/external-clients/scenarios.env`.
Each row runs up to 4 cases: Xray positive + negative, and sing-box (or hiddify-sing-box where
upstream sing-box lacks the feature) positive + negative.
Eight cases are expected **SKIP** when upstream clients lack that transport (QUIC on Xray 26+,
ShadowTLS, mKCP) — see [parity-status.md](parity-status.md).
The `vless-splithttp-packet-up` row uses **Xray** as the matrix gate. Stock **sing-box** is
**SKIP** (`scenarios.env` sing-box column `-`) because upstream sing-box has no xHTTP
`packet-up` mode. Optional manual validation: [hiddify-sing-box](https://github.com/hiddify/hiddify-sing-box)
`transport/v2rayxhttp` (fork).

---

## Tier 1 — Unit tests

Runs all unit and doc tests across every crate. No network required.

```sh
cargo test --workspace
```

To include feature-gated tests:

```sh
cargo test --workspace --all-features
```

Per-crate if you want faster feedback:

```sh
cargo test -p blackwire-transport
cargo test -p blackwire-protocol
cargo test -p blackwire-core
```

---

## Tier 2 — Integration tests

Full end-to-end protocol suite. Each test spins up a real `blackwire-core::Instance` pair in-process over loopback. No Docker required.

```sh
cargo test -p integration-tests
```

Protocols covered:

- VLESS TCP, VLESS REALITY, VLESS over WebSocket
- VMess over gRPC
- Trojan over TLS (self-signed)
- Shadowsocks 2022
- Hysteria2 over QUIC
- ShadowTLS v3 (local fake TLS backend)
- mKCP single-session and concurrent-session

---

## Tier 3 — Production readiness tests

Validates config parsing, startup guards, and protocol-level invariants. Runs across all three crates.

```sh
cargo test -p blackwire-core     --test production_readiness --all-features
cargo test -p blackwire-protocol --test production_readiness --all-features
cargo test -p blackwire-transport --test production_readiness --all-features
```

These are part of the fast local confidence gate before broader lab and VPS
validation.

---

## Tier 4 — Docker baseline

Runs the full stable protocol matrix plus live Xray REALITY interop in a local Docker environment. Docker must be running.

```sh
make -C labs/realistic docker-full
```

This does three things in order:

1. Builds the `blackwire:latest` Docker image.
2. Starts `target-http` (hashicorp/http-echo) and `target-echo` (socat) as deterministic targets.
3. Runs `cargo test -p integration-tests` (Tier 2).
4. Starts `xray-server` and `nginx-fallback` via Docker Compose.
5. Runs the live Xray d1 tests (see Tier 8).

Reports land in `labs/realistic/reports/`.

To run only the Docker target services without tests:

```sh
make -C labs/realistic docker-up
```

To tear everything down:

```sh
make -C labs/realistic docker-down
```

---

## Tier 5 — Advanced features smoke

Local smoke tests for ShadowTLS v3, mKCP, health/failover config guards, failover
runtime e2e, and DNS/geo/FakeIP startup guards.

```sh
make -C labs/realistic advanced-features-smoke
```

Writes `labs/realistic/reports/advanced-features-smoke.log`.

### Tier 5b — Health-check failover lab

Proves balancer traffic continues when a member outbound fails health probes.

```sh
make -C labs/realistic health-failover
# or: make verify-health-failover
```

In-process only (no Docker):

```sh
cargo test -p integration-tests --test e2e_health_failover health_failover_routes_to_backup_when_primary_unhealthy
```

Writes `labs/realistic/reports/health-failover.log`.

---

## Tier 6 — Stress loop

Repeats the three highest-signal data-plane tests five times each to catch timing-sensitive failures.

```sh
make -C labs/realistic stress
```

Writes `reports/stress.log`. A clean run means no flakiness under consecutive scheduling.

---

## Tier 7 — Xray d0 self-interop

Tests our REALITY implementation against itself: RealityClient talks to RealityServer over loopback. No Xray binary needed.

```sh
cargo test -p blackwire-transport --test interop d0 -- --ignored --nocapture
```

What it proves:

- REALITY token parsing round-trips correctly.
- The authenticated path completes TLS 1.3 locally.
- Invalid auth (wrong short ID, zero max-time) hits the fallback path.

---

## Tier 7 — Interop server-compat

Xray/sing-box **clients** connect to **your server** (scenarios in `external-clients/scenarios.env`).

```sh
make -C labs/realistic interop-server-docker
```

Or both interop legs together:

```sh
make -C labs/realistic interop-docker
```

---

## Tier 8 — Interop client-compat (REALITY d1)

Your Rust REALITY **client** connects to a live **Xray-core server** in Docker.

```sh
make -C labs/realistic interop-client-reality
```

What it proves:

- Our client authenticates to real xray-core REALITY.
- TLS 1.3 handshake completes the way Xray expects (including `secp256r1` / `x25519` dual offer).
- Wrong short IDs and wrong SNI go to fallback, not error.
- Bare active-probe ClientHello does not trigger a TCP reset.

Legacy alias: `make -C labs/realistic xray`.

See [tests/interop/README.md](../tests/interop/README.md) for the full protocol notes.

---

## Tier 9 — VPS external-client matrix

Runs the **same 16 protocol rows** as Tier 8 (`external-clients/scenarios.env`) over a
real public network between two Ubuntu 24.04 VPS machines. One blackwire server config
is started per row on the server VPS; Xray, sing-box, and hiddify-sing-box clients run
on the client VPS (see [external-clients/README.md](../labs/realistic/external-clients/README.md)).

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_ed25519 \
  make -C labs/realistic interop-server-vps
```

Reports land in `labs/realistic/reports/external-clients-vps/`. A green promotion run
matches Docker: **56 PASS, 8 SKIP, 0 FAIL** (SKIPs are upstream client limits, not
missing server transports).

Preflight (optional):

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 make -C labs/realistic vps-preflight
```

### Prerequisites

### Prerequisites

- Two Ubuntu 24.04 VPS machines (one server, one client).
- Root SSH access to both.
- A real domain name pointing at the server VPS (for TLS certs).
- `blackwire` binary built for Linux x86_64.

### Step 1 — Build the binary

On your dev machine:

```sh
cargo build --release --target x86_64-unknown-linux-gnu
# Binary at: target/x86_64-unknown-linux-gnu/release/blackwire
```

If you don't have the cross-compile target installed:

```sh
rustup target add x86_64-unknown-linux-gnu
```

Or build directly on each VPS if it has Rust installed.

### Step 2 — Fill in matrix.env

```sh
cp labs/realistic/configs/matrix.env.example labs/realistic/configs/matrix.env
```

Edit `matrix.env`:

```env
SERVER_HOST=1.2.3.4          # server VPS public IP
TEST_DOMAIN=proxy.example.com # domain pointing at server VPS

VLESS_UUID=<generate with: blackwire uuid>
VMESS_UUID=<generate with: blackwire uuid>
TROJAN_PASSWORD=<strong random string>
SS2022_PASSWORD=<strong random string>
HYSTERIA2_PASSWORD=<strong random string>

# Generate with: blackwire x25519
REALITY_PRIVATE_KEY=<server private key>
REALITY_PUBLIC_KEY=<client public key>
REALITY_SHORT_ID=<8-byte hex, e.g. aabbccdd00000001>
REALITY_SERVER_NAME=www.microsoft.com
REALITY_DEST=www.microsoft.com:443
```

### Step 3 — Provision the server VPS

```sh
SSH_SERVER=1.2.3.4 make -C labs/realistic vps-server-setup
```

This will:
- Install Caddy and obtain a TLS cert for `TEST_DOMAIN`.
- Create the `blackwire` system user and directory layout.
- Generate server configs from templates into `/etc/blackwire/generated/` (base matrix plus advanced rows: QUIC, SplitHTTP, ShadowTLS, mKCP, sniffing).
- Sync the Caddy cert to `/etc/blackwire/certs/`.
- Start a simple HTTP target on port 18080 for the matrix tests.
- Open the required UFW firewall ports.

Port layout after setup:

| Port | Protocol | Service |
|------|----------|---------|
| 80/tcp | HTTP | Caddy (ACME + fallback) |
| 443/tcp | HTTPS | Caddy |
| 10080/tcp | TCP | VLESS TCP |
| 10443/tcp | TCP | VLESS REALITY |
| 8443/tcp | TLS | VLESS WebSocket |
| 8444/tcp | TLS | VMess gRPC |
| 8445/tcp | TLS | Trojan |
| 8388/tcp | TCP | Shadowsocks 2022 |
| 4433/udp | QUIC | Hysteria2 |
| 8446–8448/tcp | TLS | Advanced VLESS rows (QUIC/SplitHTTP/ShadowTLS lab) |
| 8450–8452/tcp | TCP/TLS | Sniffing and extended matrix ports |
| 10081–10082/tcp | TCP | mKCP / auxiliary |

### Step 4 — Run the external-client matrix

From your dev machine (after server + client VPS are provisioned):

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_ed25519 \
  make -C labs/realistic interop-server-vps
```

`run-vps-matrix.sh` starts one server config per `scenarios.env` row, runs Xray/sing-box
clients where configured, and records PASS/FAIL/SKIP like Docker.

---

## Tier 9b — Legacy VPS blackwire client matrix (optional)

Separate from the external-client lab: proves **blackwire as client** over SOCKS to the
server VPS using seven standalone server configs.

### Provision client VPS

```sh
SSH_CLIENT=5.6.7.8 make -C labs/realistic vps-client-setup
```

### Run

```sh
SSH_CLIENT=5.6.7.8 make -C labs/realistic vps-test
```

This runs `scripts/run-matrix.sh` on the client VPS (SOCKS5 on `127.0.0.1:1080`,
`curl` to `http://<SERVER_HOST>:18080`). Reports go to `labs/realistic/reports/`.

On the server VPS you still start each legacy inbound manually when using only Tier 9b:

```sh
blackwire run -c /etc/blackwire/generated/server-vless-tcp.json &
blackwire run -c /etc/blackwire/generated/server-vless-reality.json &
# ... remaining base protocols
```

---

## Tier 10 — TUN privileged tests

Runs the TUN subsystem tests on Linux with root. Requires the Rust toolchain on the server VPS (or run from source if the VPS has the repo checked out).

```sh
SSH_SERVER=1.2.3.4 make -C labs/realistic vps-tun
```

Or directly on the Linux host:

```sh
sudo -E bash labs/realistic/scripts/run-tun-priv.sh
```

Three test groups run in sequence:

1. **Cross-platform unit tests** — packet parsing, NAT table logic, UDP response synthesis. No root needed.
2. **Privileged device tests** — creates a real TUN device, checks `ip link show`, installs and removes iptables rules, verifies symmetry.
3. **VPS interop** — sends a real UDP DNS query to `8.8.8.8:53` through the TUN NAT table and verifies the response arrives as a synthesized TUN packet.

The third group requires real internet access on the server.

---

## Running everything at once

Local (no VPS, no Docker for Tier 1–3):

```sh
cargo test --workspace --all-features
```

Local full baseline including Docker:

```sh
make -C labs/realistic realistic-all
```

This runs in order: `docker-full` → `advanced-features-smoke` → `negative-auth` → `restart-smoke` → `stress` → `report-summary`.

Full report summary after any run:

```sh
make -C labs/realistic report-summary
cat labs/realistic/reports/summary.txt
```

Full local ship gate (no VPS):

```sh
make -C labs/realistic finalize
```

VPS external-client matrix + TUN (requires provisioned VPS):

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_ed25519 \
    make -C labs/realistic interop-server-vps vps-tun
```

---

## What each tier proves

| Tier | What a green run means |
|------|----------------------|
| 1–3 | Code is internally consistent and config validation works |
| 4 | Stable matrix + full Docker interop (server + client legs) |
| 5 | Advanced features (ShadowTLS, mKCP, health, DNS/routing) pass smoke tests |
| 6 | No timing-sensitive flakiness in the data plane |
| 7 | REALITY implementation is self-consistent (d0) |
| 8 | Xray/sing-box/hiddify clients can use our server (configured scenarios) |
| 9 | Our REALITY client interoperates with live xray-core (d1) |
| 10 | External-client matrix (16 rows) passes over real public network; SKIPs documented |
| 11 | TUN device, iptables routing, and UDP NAT work on real Linux |

Tiers 1–9 are the mandatory green gate before any merge to main. Tiers 10–11 are required before a protocol or subsystem is marked production-ready.
