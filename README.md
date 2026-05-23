# v2ray

## Running the tests

**No VPS, no Docker — just Rust:**
```sh
make ci
```

**Everything local including Docker and Xray interop:**
```sh
make ci-all
```

**Absolute everything including two VPS machines:**
```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 make ci-vps
```

That's it. Full details in [docs/11-testing.md](docs/11-testing.md).

---

Beginner-friendly docs live in [docs/README.md](docs/README.md).

Recommended starting path:

1. [Project Map](docs/00-project-map.md)
2. [Request Lifecycle](docs/01-request-lifecycle.md)
3. [Crate Guide](docs/02-crate-guide.md)
4. [Protocols And Transports](docs/03-protocols-and-transports.md)

Deep dives:

- [REALITY For Dummies](docs/04-reality-for-dummies.md)
- [VLESS, VMess, And Trojan Comparison](docs/05-vless-vmess-trojan-comparison.md)
- [How To Debug This Repo](docs/06-how-to-debug.md)
- [How To Add A New Protocol Or Transport](docs/07-how-to-add-a-new-protocol-or-transport.md)

Practical docs:

- [Config For Dummies](docs/08-config-for-dummies.md)
- [Trace One Connection In Code](docs/09-trace-one-connection-in-code.md)
- [Glossary](docs/10-glossary.md)

Example configs and local demos live under `examples/`.

Good entry points:

- [Phase 1 Client/Server](examples/phase1-client-server/README.md)
- [Phase 2 REALITY Client/Server](examples/phase2-reality-client-server/README.md)
- [Phase 4 VLESS + WebSocket Local](examples/phase4-vless-ws-local/README.md)
- [Phase 5 HTTP + VMess + gRPC Local](examples/phase5-http-vmess-grpc-local/README.md)
- [Phase 6 SS2022 Local](examples/phase6-ss2022-local/README.md)

REALITY and Xray interop notes live in [tests/interop/README.md](tests/interop/README.md).

That guide explains:

- what `d0` vs `d1` are proving
- why REALITY still needs a full TLS 1.3 handshake
- how the local Xray Docker harness is wired
- why the Xray `dest` must be a real HTTPS endpoint on port 443

Realistic environment testing starts at [labs/realistic/README.md](labs/realistic/README.md).

The full testing guide — unit tests through two-VPS production validation — is at [docs/11-testing.md](docs/11-testing.md).

That lab is the production-realism gate for the stable matrix:

- VLESS TCP, REALITY, and WebSocket
- VMess over gRPC
- Trojan over TLS
- Shadowsocks 2022
- Hysteria2
- required Xray REALITY interop

Phase 7/8 status is intentionally stricter: health/failover and geo/FakeIP are
wired for runtime testing, ShadowTLS has marker-mode local coverage, mKCP has
multi-peer local coverage, and TUN remains rejected until a real packet-to-proxy
TCP/UDP runtime exists.

## Runtime / Test Quick Start

The Makefile has many targets because this project has multiple test environments. Use the short aliases first. The detailed targets are kept for debugging, evidence collection, or specific environments.

### Main commands

```sh
make check
make check-browser
make check-all-local
make check-vps
```

| Command | Equivalent target | Runs where | Purpose |
| --- | --- | --- | --- |
| `make check` | `make local-total` | Mac/local checkout | Strongest normal local gate, including fuzz smoke. |
| `make check-browser` | `make lima-fingerprint-total` | Lima Ubuntu VM | Automated isolated browser/TLS fingerprint capture and strict verification. |
| `make check-all-local` | `make local-total-with-lima` | Mac + Lima VM | Runs local checks, then isolated browser/fingerprint verification. |
| `make check-vps` | `make vps-total` | Mac + VPS | Runs local non-fuzz gates, then real VPS SSH/network gate. Requires VPS env vars. |

### Recommended flow

Daily local confidence:

```sh
make check
```

Isolated browser/fingerprint confidence:

```sh
make check-browser
```

Strongest local-only flow:

```sh
make check-all-local
```

Real VPS later:

```sh
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make check-vps
```

### Sequential run

Use this when you want explicit step-by-step logs instead of one compact target:

```sh
make check-sequence
```

This runs:

```text
1. make check
2. make check-browser
3. make check-all-local
```

For VPS later:

```sh
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make check-sequence-with-vps
```

`check-sequence` intentionally repeats some work because `check-all-local` already includes `local-total` again. For the fastest local + Lima run, use:

```sh
make check-all-local
```

Use `check-sequence` when you want explicit evidence/log separation.

## Full Make Command Map

This section is for running every command group intentionally. Do not run the whole list blindly unless you want a long, noisy validation pass.

### 1. Local project checks

These run on the Mac/project checkout only.

Requirements:

- Rust toolchain
- Docker for interop/realistic helpers
- `cargo-fuzz` for fuzz targets

Run order:

```sh
make local-fast
make local
make local-prod
make local-fuzz
make local-fuzz-total
make local-total
```

| Command | Purpose |
| --- | --- |
| `make local-fast` | Fast Rust-only gate. |
| `make local` | Full normal local gate without fuzz. |
| `make local-prod` | Production-readiness helper gate. |
| `make local-fuzz` | Quick fuzz smoke. |
| `make local-fuzz-total` | Heavier fuzz pass. Override with `FUZZ_RUNS=10000`. |
| `make local-total` | Main local all-in-one target. Equivalent to `make check`. |

### 2. Advanced local diagnostics

These are local debug/evidence helpers. They are not all included in `make local`.

Run order:

```sh
make local-load
make local-slowloris
make local-netem
make local-hostility
make local-ci-matrix
```

| Command | Purpose |
| --- | --- |
| `make local-load` | Managed local load test. |
| `make local-slowloris` | Slow-client diagnostic. |
| `make local-netem` | Docker/local network-hostility smoke. |
| `make local-hostility` | Local netem + slow-client diagnostics. |
| `make local-ci-matrix` | Local Makefile-only CI matrix. |

### 3. Local pcap and fingerprint debugging

These are separate because they may need sudo, Docker, Chrome, `tcpdump`, or `tshark`.

Host/macOS capture path:

```sh
sudo -v
PCAP_ALLOW_SUDO=1 make local-pcap
make local-fingerprint-verify
```

Docker capture path:

```sh
make local-pcap-docker
make local-fingerprint-compare
```

Real Mac Chrome baseline path:

```sh
make local-chrome-baseline-real
make local-fingerprint-verify
```

Docker Chromium baseline path:

```sh
make local-chrome-baseline-docker
make local-fingerprint-compare
```

All-in-one real Mac Chrome fingerprint path:

```sh
make local-fingerprint-total
```

| Command | Purpose |
| --- | --- |
| `make local-pcap` | Host tcpdump capture. May require sudo. |
| `make local-pcap-docker` | Docker-isolated pcap capture. No host sudo. |
| `make local-chrome-baseline-real` | Real macOS Chrome baseline. Most realistic locally; may require sudo. |
| `make local-chrome-baseline-docker` | Docker Chromium baseline. Easier, less realistic than real Mac Chrome. |
| `make local-fingerprint-compare` | Non-strict fingerprint report. |
| `make local-fingerprint-verify` | Strict fingerprint verification from existing captures. |
| `make local-fingerprint-total` | Real Mac Chrome baseline + strict verify. |

### 4. Lima automated VM browser path

This is the recommended isolated browser/fingerprint path. It creates or starts a Lima Ubuntu VM, installs tools, captures Chromium TLS traffic, copies the pcap back, and runs strict verification.

Requirements:

- Homebrew or `limactl`
- Internet on first run
- Enough disk/RAM for an Ubuntu VM

Run order:

```sh
make lima-browser-baseline
make lima-fingerprint-total
make local-total-with-lima
```

Shortcut commands:

```sh
make check-browser
make check-all-local
```

| Command | Purpose |
| --- | --- |
| `make lima-browser-baseline` | Only capture the Lima browser baseline. |
| `make lima-fingerprint-total` | Lima browser baseline + strict verify. Equivalent to `make check-browser`. |
| `make local-total-with-lima` | `local-total` + Lima fingerprint check. Equivalent to `make check-all-local`. |

Important: `local-total-with-lima` runs Rust/local checks on the Mac, then browser/fingerprint inside Lima. It does not run the full Rust suite inside Lima yet.

### 5. Manual SSH VM path

This is for an existing UTM, VirtualBox, Parallels, or other VM that you manage yourself. Prefer Lima unless you specifically need a manual VM.

Requirements:

- Existing VM
- Real VM IP
- SSH user
- sudo inside the VM
- `.env.vm` configured

Setup/run order:

```sh
make vm-print-defaults
make vm-start-default
make vm-wait-default
make vm-browser-setup
make vm-browser-baseline
make vm-fingerprint-total
make vm-fingerprint-default
make local-total-with-vm
```

| Command | Purpose |
| --- | --- |
| `make vm-print-defaults` | Show `.env.vm` values and detected launchers. |
| `make vm-start-default` | Start configured UTM/VirtualBox/Parallels VM if it exists. |
| `make vm-wait-default` | Wait until configured VM SSH is reachable. |
| `make vm-browser-setup` | Install browser/tcpdump/tshark on the SSH VM. |
| `make vm-browser-baseline` | Capture browser baseline inside the SSH VM. |
| `make vm-fingerprint-total` | SSH VM browser baseline + strict verify. |
| `make vm-fingerprint-default` | Start/wait configured VM, then run VM fingerprint. |
| `make local-total-with-vm` | `local-total` + configured manual SSH VM fingerprint. |

### 6. VPS path

This is for real remote Linux servers. Use it later when you have VPS machines ready.

Requirements:

- Real server and client VPS machines
- SSH access
- `SSH_SERVER` and `SSH_CLIENT` environment variables
- Linux networking tools on the VPS side

Setup/run order:

```sh
SSH_SERVER=<server-ip> make -C labs/realistic vps-server-setup
SSH_CLIENT=<client-ip> make -C labs/realistic vps-client-setup
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make vps
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make vps-total
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make vps-total-with-fuzz
```

| Command | Purpose |
| --- | --- |
| `make vps` | VPS-only SSH/network gate. |
| `make vps-total` | Local non-fuzz gates, then VPS gate. Equivalent to `make check-vps`. |
| `make vps-total-with-fuzz` | All local gates including fuzz, then VPS gate. |
| `make check-sequence-with-vps` | `check-sequence`, then `check-vps`. Requires `SSH_SERVER` and `SSH_CLIENT`. |

Important: `vps-total` runs local checks on the Mac, then VPS network tests. It does not run the full Rust suite on the VPS yet.

### 7. Practical full sweep

These sweeps are for evidence collection. They intentionally repeat work and are slower than the normal aliases.

#### Non-VPS full sweep

Use this when you want the strongest local + Lima + Docker diagnostic pass without real remote servers:

```sh
make check-sequence
make local-load
make local-slowloris
make local-hostility
make local-pcap-docker
make local-fingerprint-compare
make local-fingerprint-verify
```

This covers:

- local gates and fuzz smoke through `make check`
- Lima browser/fingerprint verification through `make check-browser`
- combined local + Lima flow through `make check-all-local`
- managed local load diagnostics
- slow-client diagnostics
- local netem/hostility diagnostics
- Docker-isolated pcap capture
- fingerprint report and strict fingerprint verification

This does not cover:

- real VPS testing
- real Mac Chrome host capture path
- manual SSH VM path
- heavier fuzz beyond the configured fuzz targets/runs

If you also want real Mac Chrome host-capture evidence, run this separately because it may require sudo and real browser behavior:

```sh
make local-fingerprint-total
```

#### VPS full sweep

Use this only when real VPS machines are ready and reachable by SSH:

```sh
make check-sequence
make local-load
make local-slowloris
make local-hostility
make local-pcap-docker
make local-fingerprint-compare
make local-fingerprint-verify
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make check-sequence-with-vps
```

This covers everything in the non-VPS sweep, then adds the real VPS SSH/network gate.

For a shorter VPS path, run only:

```sh
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make check-vps
```

Important: the VPS commands run local checks on the Mac first, then VPS network tests. They do not run the full Rust test suite on the VPS yet.

### More help

```sh
make test-help
```

This prints the compact command help from the Makefile.