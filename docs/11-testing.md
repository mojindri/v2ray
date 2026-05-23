# Testing Guide

This document is the single reference for running every test tier in this project — from fast unit tests through to two-VPS production validation. Run them in order; each tier builds on the previous one.

---

## Overview

| Tier | What it covers | Time | Requires |
|------|---------------|------|----------|
| 1. Unit tests | Per-crate logic | ~5s | Rust toolchain |
| 2. Integration tests | End-to-end protocol matrix | ~30s | Rust toolchain |
| 3. Production readiness | Config validation, guard checks | ~10s | Rust toolchain |
| 4. Docker baseline | Full matrix + Xray REALITY interop | ~3 min | Docker |
| 5. Phase 7/8 bundle | ShadowTLS, mKCP, health, geo/FakeIP | ~30s | Rust toolchain |
| 6. Stress loop | Flakiness detection on high-signal tests | ~2 min | Rust toolchain |
| 7. Xray d0 self-interop | REALITY token + TLS self-consistency | ~5s | Rust toolchain |
| 8. Xray d1 live interop | REALITY against real xray-core binary | ~30s | Docker |
| 9. VPS matrix | All protocols over real public network | ~5 min | Two Ubuntu 24.04 VPS |
| 10. TUN privileged | TUN device, iptables, SO_MARK on Linux | ~1 min | Linux VPS + root |

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
cargo test -p proxy-transport
cargo test -p proxy-protocol
cargo test -p proxy-core
```

---

## Tier 2 — Integration tests

Full end-to-end protocol suite. Each test spins up a real `proxy-core::Instance` pair in-process over loopback. No Docker required.

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
cargo test -p proxy-core     --test production_readiness --all-features
cargo test -p proxy-protocol --test production_readiness --all-features
cargo test -p proxy-transport --test production_readiness --all-features
```

These are the mandatory-green gate before any release.

---

## Tier 4 — Docker baseline

Runs the full stable protocol matrix plus live Xray REALITY interop in a local Docker environment. Docker must be running.

```sh
make -C labs/realistic docker-full
```

This does three things in order:

1. Builds the `proxy-rs:latest` Docker image.
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

## Tier 5 — Phase 7/8 bundle

Local validation for the Phase 7/8 features: ShadowTLS v3, mKCP multi-peer, health/failover config guards, geo/FakeIP startup guards.

```sh
make -C labs/realistic phase78
```

Writes four report files:

- `reports/phase78-shadowtls.log`
- `reports/phase78-mkcp.log`
- `reports/phase78-health.log`
- `reports/phase78-geo-fakeip.log`

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
cargo test -p proxy-transport --test interop d0 -- --ignored --nocapture
```

What it proves:

- REALITY token parsing round-trips correctly.
- The authenticated path completes TLS 1.3 locally.
- Invalid auth (wrong short ID, zero max-time) hits the fallback path.

---

## Tier 8 — Xray d1 live interop

Tests our REALITY client against a real `xray-core` binary running in Docker. This is the actual compatibility gate.

```sh
# Start Xray and nginx fallback
cd tests/interop && docker compose up -d nginx-fallback xray-server && cd ../..

# Run the live tests
cargo test -p proxy-transport --test interop d1 -- --ignored --nocapture

# Tear down
cd tests/interop && docker compose down -v
```

Or via the Makefile shortcut:

```sh
make -C labs/realistic xray
```

What it proves:

- Our client authenticates to real xray-core REALITY.
- TLS 1.3 handshake completes the way Xray expects (including `secp256r1` / `x25519` dual offer).
- Wrong short IDs and wrong SNI go to fallback, not error.
- Bare active-probe ClientHello does not trigger a TCP reset.

See [tests/interop/README.md](../tests/interop/README.md) for the full protocol notes.

---

## Tier 9 — VPS matrix

Runs all seven protocols over a real public network between two Ubuntu 24.04 VPS machines. This is the production-realism gate.

### Prerequisites

- Two Ubuntu 24.04 VPS machines (one server, one client).
- Root SSH access to both.
- A real domain name pointing at the server VPS (for TLS certs).
- `proxy-rs` binary built for Linux x86_64.

### Step 1 — Build the binary

On your dev machine:

```sh
cargo build --release --target x86_64-unknown-linux-gnu
# Binary at: target/x86_64-unknown-linux-gnu/release/proxy-rs
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

VLESS_UUID=<generate with: proxy-rs uuid>
VMESS_UUID=<generate with: proxy-rs uuid>
TROJAN_PASSWORD=<strong random string>
SS2022_PASSWORD=<strong random string>
HYSTERIA2_PASSWORD=<strong random string>

# Generate with: proxy-rs x25519
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
- Create the `proxy-rs` system user and directory layout.
- Generate all seven server configs from templates into `/etc/proxy-rs/generated/`.
- Sync the Caddy cert to `/etc/proxy-rs/certs/`.
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

### Step 4 — Start server-side proxy-rs instances

On the server VPS, start each protocol inbound:

```sh
# Run one or all — each config is standalone
proxy-rs run -c /etc/proxy-rs/generated/server-vless-tcp.json &
proxy-rs run -c /etc/proxy-rs/generated/server-vless-reality.json &
proxy-rs run -c /etc/proxy-rs/generated/server-vless-ws.json &
proxy-rs run -c /etc/proxy-rs/generated/server-vmess-grpc.json &
proxy-rs run -c /etc/proxy-rs/generated/server-trojan-tls.json &
proxy-rs run -c /etc/proxy-rs/generated/server-ss2022.json &
proxy-rs run -c /etc/proxy-rs/generated/server-hysteria2.json &
```

Or use the systemd service for a long-running deployment:

```sh
cp labs/realistic/vps/proxy-rs-server.service /etc/systemd/system/
# Edit ExecStart to point at the config you want
systemctl daemon-reload && systemctl enable --now proxy-rs-server
```

### Step 5 — Provision the client VPS

```sh
SSH_CLIENT=5.6.7.8 make -C labs/realistic vps-client-setup
```

This generates all seven client configs into `/etc/proxy-rs/generated/` on the client VPS.

### Step 6 — Run the matrix

```sh
SSH_CLIENT=5.6.7.8 make -C labs/realistic vps-test
```

This runs `scripts/run-matrix.sh` on the client VPS. For each protocol it:

1. Starts `proxy-rs` with the client config (SOCKS5 on 127.0.0.1:1080).
2. Sends `curl` traffic through the SOCKS5 proxy to `http://<SERVER_HOST>:18080`.
3. Records PASS/FAIL.
4. Copies the report back to `labs/realistic/reports/`.

Expected output:

```
PASS vless-tcp
PASS vless-reality
PASS vless-ws
PASS vmess-grpc
PASS trojan-tls
PASS ss2022
PASS hysteria2

==> Results: 7 passed, 0 failed
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

This runs in order: `docker-full` → `phase78` → `negative-auth` → `restart-smoke` → `stress` → `report-summary`.

Full report summary after any run:

```sh
make -C labs/realistic report-summary
cat labs/realistic/reports/summary.txt
```

VPS matrix + TUN (requires provisioned VPS):

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 \
    make -C labs/realistic vps-test vps-tun
```

---

## What each tier proves

| Tier | What a green run means |
|------|----------------------|
| 1–3 | Code is internally consistent and config validation works |
| 4 | Stable protocol matrix passes in a repeatable Docker environment |
| 5 | Phase 7/8 features are wired and startup guards work |
| 6 | No timing-sensitive flakiness in the data plane |
| 7 | REALITY implementation is self-consistent |
| 8 | REALITY interoperates with real xray-core |
| 9 | All protocols work over a real public network with real TLS certs |
| 10 | TUN device, iptables routing, and UDP NAT work on real Linux |

Tiers 1–8 are the mandatory green gate before any merge to main. Tiers 9–10 are required before a protocol or subsystem is marked production-ready.
