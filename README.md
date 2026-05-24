# v2ray

Rust-native proxy project inspired by V2Ray/Xray.

This repository is organized around two goals:

- implement a practical protocol/runtime matrix in Rust
- verify behavior with local tests, Xray interop, and realistic Linux environments

It is not a drop-in V2Ray-core or Xray-core reimplementation, and it does not
claim JSON config compatibility with either project. For the exact scope, see
[docs/feature-matrix.md](docs/feature-matrix.md).

## Start Here

If you are new to the repo, read in this order:

1. [Project Map](docs/00-project-map.md)
2. [Request Lifecycle](docs/01-request-lifecycle.md)
3. [Crate Guide](docs/02-crate-guide.md)
4. [Protocols And Transports](docs/03-protocols-and-transports.md)

The full beginner-oriented doc index is at [docs/README.md](docs/README.md).

## Current Status

Stable validation focus today:

- VLESS over TCP
- VLESS over REALITY
- VLESS over WebSocket
- VMess over gRPC
- Trojan over TLS
- Shadowsocks 2022
- Hysteria2
- required Xray REALITY interop

Phase 7/8 status:

- health/failover: wired for runtime testing
- geo/FakeIP routing: wired for runtime testing
- ShadowTLS: local marker-mode coverage, still needs broader interop hardening
- mKCP: local multi-peer coverage, still needs hostile-network validation
- TUN: not production-ready until real packet runtime coverage exists

For exact support levels, see [docs/feature-matrix.md](docs/feature-matrix.md).

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

- [Phase 1 Client/Server](examples/phase1-client-server/README.md)
- [Phase 2 REALITY Client/Server](examples/phase2-reality-client-server/README.md)
- [Phase 3 Hysteria2 Client/Server](examples/phase3-hysteria2-client-server/README.md)
- [Phase 4 VLESS + WebSocket Local](examples/phase4-vless-ws-local/README.md)
- [Phase 5 HTTP + VMess + gRPC Local](examples/phase5-http-vmess-grpc-local/README.md)
- [Phase 6 SS2022 Local](examples/phase6-ss2022-local/README.md)
- [Phase 7 DNS + FakeIP Routing](examples/phase7-dns-fakeip-routing/README.md)
- [Phase 7 ShadowTLS + VLESS](examples/phase7-shadowtls-vless/README.md)
- [Phase 8 Health + Failover](examples/phase8-health-failover/README.md)
- [Phase 8 mKCP + VLESS](examples/phase8-mkcp-vless/README.md)
- [Phase 8 TUN Local](examples/phase8-tun-local/README.md)

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
