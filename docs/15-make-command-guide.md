# Make Command Guide

This file explains the Make targets without dumping the whole Makefile into the
root README.

Rule of thumb:

- use the public commands first
- use compatibility aliases only when you need a specific older flow

If you only want discovery from the terminal, run:

```sh
make help
make test-help
```

## Recommended Commands

These are the public commands most people should use first:

| Command | When to use it |
| --- | --- |
| `make check` | Main local validation gate |
| `make check-browser` | Browser/TLS fingerprint validation inside Lima Ubuntu VM |
| `make check-vps` | Closest production-style validation with two VPS machines |
| `make perf` | Performance benchmark inside Lima VM |
| `make lima-stop` | Stop the default Lima VM instance |
| `make clean-generated` | Remove generated reports/logs/pcaps/bench outputs |

## Environment Separation

This is the practical rule:

- run top-level `make ...` commands from your local checkout on your Mac/Linux dev machine
- let those commands orchestrate Docker, Lima VM, or VPS work for you
- only SSH into a VPS directly when you are debugging the VPS itself

### Run From Local Checkout

These are invoked from the repository root on your own machine:

| Command | Invoke from | Actually runs on | Needs real VPS? |
| --- | --- | --- | --- |
| `make check` | local checkout | local machine only | no |
| `make check-browser` | local checkout | local machine + Lima VM | no |
| `make check-vps` | local checkout | local machine + remote VPS machines over SSH | yes |
| `make perf` | local checkout | Lima VM | no |
| `make lima-stop` | local checkout | local Lima VM control plane | no |
| `make perf-vps` | local checkout | remote VPS machines over SSH | yes |
| `make clean-generated` | local checkout | local checkout only | no |

### Run Directly On A Real VPS

Usually not needed for the normal workflow. Do this only for debugging,
inspection, or manual setup verification.

Examples:

- `ssh root@<server>` then inspect `systemctl status proxy-rs-*`
- `ssh root@<server>` then inspect `/etc/proxy-rs/generated/`
- `ssh root@<server>` then run `journalctl -u proxy-rs-*`
- `ssh root@<client>` then inspect client-side logs or traffic tools

Do not treat the VPS shell as the normal place to run repo-level `make check-*`
commands. Those are designed to be launched from the local checkout and use SSH
to drive the remote machines.

### Docker vs VM vs VPS

| Environment | Trigger from | Typical commands | Notes |
| --- | --- | --- | --- |
| local-only | local checkout | `make check` | fastest normal gate |
| Docker | local checkout | `make -C labs/realistic docker-full` | local containers, no real VPS |
| Lima VM | local checkout | `make check-browser`, `make perf` | Linux-like local realism |
| manual SSH VM | local checkout | `make vm-fingerprint-default` | optional, mostly for custom VM setups |
| real VPS | local checkout | `make check-vps`, `make perf-vps` | closest production signal |

## Compatibility Aliases

These still work, but they are not the preferred front-door names anymore:

| Alias | Preferred public command |
| --- | --- |
| `make check-all-local` | `make check-browser` for the VM/browser path, or `make check` for the main local gate |
| `make ci-all` | `make check` |
| `make ci-vps` | `make check-vps` |
| `make check-perf-vm` | `make perf` |
| `make check-perf-vps` | `make perf-vps` |
| `make check-perf-total` | `make perf-all` |

## Command Families

### Build and quality

| Command | Purpose |
| --- | --- |
| `make` | Release build |
| `make dev` | Debug build |
| `make fmt` | Format source |
| `make fmt-check` | Check formatting |
| `make lint` | Run clippy with CI-level denies |
| `make test` | Run workspace unit and integration tests |
| `make audit` | Run `cargo audit` when installed |
| `make deny` | Run `cargo deny` |

### CI-style shortcuts

| Command | Purpose |
| --- | --- |
| `make ci` | Fast Rust-only quality gate |
| `make ci-all` | Local realistic lab plus production-readiness helpers |
| `make ci-prod-readiness` | Production-readiness helpers only |
| `make ci-vps` | Local + VPS gate |

### Local validation

| Command | Purpose |
| --- | --- |
| `make local-fast` | Fast Rust-only local gate |
| `make local` | Full local gate, excluding fuzz and VPS |
| `make local-prod` | Production-readiness helpers only |
| `make local-fuzz` | Quick fuzz smoke |
| `make local-fuzz-total` | Heavier fuzz pass |
| `make local-total` | Everything local, including fuzz smoke |

### Browser / fingerprint / VM validation

| Command | Purpose |
| --- | --- |
| `make check-browser` | Alias for the Lima fingerprint flow |
| `make lima-stop` | Stop the default Lima instance (`proxy-rs-browser`) |
| `make check-all-local` | Compatibility alias: local suite plus Lima fingerprint validation |
| `make check-sequence` | Run `check`, `check-browser`, `check-all-local` in sequence |
| `make check-sequence-with-vps` | Same as above, then VPS |

### VPS validation

| Command | Purpose |
| --- | --- |
| `make vps` | VPS-only SSH/network gate |
| `make vps-total` | Non-fuzz local gates, then VPS |
| `make vps-total-with-fuzz` | All local gates including fuzz, then VPS |
| `make check-vps` | Alias for `vps-total` |

### Performance

| Command | Purpose |
| --- | --- |
| `make bench-vm-smoke` | Quick Lima VM benchmark |
| `make bench-vm-total` | Full Lima VM benchmark |
| `make bench-vps-smoke` | Quick VPS benchmark |
| `make bench-vps-total` | Full VPS benchmark |
| `make perf` | Recommended public entrypoint for the Lima benchmark |
| `make perf-vps` | Public VPS benchmark alias |
| `make perf-all` | Run VM perf, then VPS perf |
| `make check-perf-vm` | Compatibility alias for `perf` |
| `make check-perf-vps` | Compatibility alias for `perf-vps` |
| `make check-perf-total` | Compatibility alias for `perf-all` |

### Cleanup

| Command | Purpose |
| --- | --- |
| `make clean-generated` | Remove generated reports/logs/pcaps/bench outputs |
| `make clean-pcaps` | Remove only pcap and fingerprint outputs |
| `make clean-all-generated` | Remove generated outputs and Rust build outputs |
| `make clean` | `cargo clean` |

## Where Detailed Flows Live

- Full testing tiers: [11-testing.md](11-testing.md)
- Realistic lab and Docker/VPS flows: [../labs/realistic/README.md](../labs/realistic/README.md)
- REALITY/Xray interop details: [../tests/interop/README.md](../tests/interop/README.md)
