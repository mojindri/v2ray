# blackwire

Rust-native proxy **server** aimed at **wire compatibility** with the Xray and
sing-box client ecosystem.

This repository is organized around two goals:

- implement a practical protocol/transport matrix as an Xray/sing-box-compatible server
- prove compatibility with **real upstream clients** — Xray-core and sing-box in
  Docker labs, Lima fingerprint checks, and two-VPS production-style runs

Supported paths are validated against original clients, not only in-process Rust
tests. External-client automation lives under `labs/realistic/` and currently
starts with a VLESS REALITY scenario that can be expanded through
`labs/realistic/external-clients/scenarios.env`.

The project uses its **own JSON config schema** (not a byte-for-byte Xray config
drop-in). Wire behavior and client interop are the compatibility contract. For
per-protocol status, see [docs/feature-matrix.md](docs/feature-matrix.md).

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

You normally do **not** need to run sub-steps separately:

| Step (internal) | Client tested |
| --- | --- |
| `stable` | In-process Rust integration matrix |
| `xray` | **Xray-core** REALITY d1 (live binary in Docker) |
| `external-clients-docker` | The scenarios currently listed in `external-clients/scenarios.env` |
| `advanced-features-smoke` | ShadowTLS, mKCP, health, DNS guards |
| `negative-auth` | Wrong creds rejected / REALITY fallback |

Sub-steps exist for debugging only, e.g.
`make -C labs/realistic xray` or `make -C labs/realistic external-clients-docker`.

On VPS, `verify-remote` also runs `external-clients-vps` for the same configured
scenario set.

Details: [tests/interop/README.md](tests/interop/README.md),
[labs/realistic/external-clients/README.md](labs/realistic/external-clients/README.md).

## Current Status

**Best-covered server paths today** (Xray/sing-box interop + lab gates):

- VLESS over TCP, REALITY, WebSocket
- VMess over gRPC
- Trojan over TLS
- Shadowsocks 2022
- Hysteria2

**Advanced features — implemented, not fully proven in production-like labs:**

| Feature | What works today | What is still missing |
| --- | --- | --- |
| **Health checks + outbound failover** | Config, startup, basic runtime wiring | Real multi-outbound failure scenarios under load |
| **GeoIP / GeoSite + FakeIP routing** | Config, DNS pool, routing rules load and run in tests | Edge cases in long-running production traffic |
| **ShadowTLS v3** | Local end-to-end tests (VLESS over ShadowTLS) | Interop against external sing-box / shadow-tls deployments |
| **mKCP** | Local multi-session tests | Loss, jitter, and hostile-network lab validation |
| **TUN mode** | Linux TUN runtime, route setup/cleanup, UDP NAT, privileged tests | Broad production validation and cross-platform support — **do not use in production yet** |

See [docs/feature-matrix.md](docs/feature-matrix.md) for the full support table.

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
