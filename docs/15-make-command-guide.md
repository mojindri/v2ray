# Make Command Guide

This file explains Make targets without dumping the whole Makefile into the root
README.

**Public surface:** `verify-*` targets separate host, lab, and remote validation.
Legacy `check-*` / `ci-*` names remain as compatibility aliases (they print a
deprecation hint when run).

Terminal discovery:

```sh
make help           # canonical commands only
make help-compat    # deprecated alias map
make help-internal  # atomic targets
```

See also: [test-workflows.md](test-workflows.md), [make-target-inventory.md](make-target-inventory.md).

## Recommended Commands

| Command | When to use it |
| --- | --- |
| `make verify-local` | Everyday Rust development (no Docker/Lima/VPS) |
| `make verify-lab` | Protocol/transport changes needing Docker + Lima |
| `make verify-remote` | Production-style validation on two VPS hosts |
| `make verify-sweep` | Broad quick gate before a larger change |
| `make verify-release` | Slow pre-release gate |
| `make perf` | Lima VM performance benchmark |
| `make perf-remote` | VPS performance benchmark (`SSH_SERVER`, `SSH_CLIENT`) |
| `make security` | Audit/deny + lab security helpers |
| `make fuzz-smoke` | Short nightly fuzz pass |
| `make clean-generated` | Remove generated reports/logs/pcaps/bench |

### Subtargets (lab / remote)

| Command | Purpose |
| --- | --- |
| `make verify-lab-docker` | Docker stable + Xray + external clients + advanced-features-smoke |
| `make verify-lab-lima` | Lima browser TLS fingerprint baseline |
| `make lab-docker-preflight` / `lab-docker-down` | Docker preflight / teardown |
| `make lab-lima-preflight` / `lab-lima-down` | Lima preflight / stop VM |
| `make remote-preflight` / `remote-deploy` | VPS SSH checks / rsync + setup |
| `make remote-test-protocols` | Full protocol matrix from client VPS |
| `make remote-test-fingerprint` | Xray/sing-box external clients on VPS |

## Environment Separation

Run top-level `make …` from your **local checkout**. Commands orchestrate
Docker, Lima, or VPS over SSH — do not SSH into a VPS to run repo-level gates.

| Command | Invoke from | Executes on | Needs VPS? |
| --- | --- | --- | --- |
| `make verify-local` | local checkout | local machine | no |
| `make verify-lab-docker` | local checkout | local + Docker | no |
| `make verify-lab-lima` | local checkout | local + Lima VM | no |
| `make verify-remote` | local checkout | local + two VPS over SSH | yes |
| `make perf` | local checkout | Lima VM | no |
| `make perf-remote` | local checkout | two VPS over SSH | yes |

VPS variables: `SSH_SERVER`, `SSH_CLIENT`, optional `SSH_KEY`, `SSH_USER`,
`SSH_PORT`, `SSH_EXTRA_OPTS`.

Example:

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_ed25519 make verify-remote
```

### Docker vs Lima vs VPS

| Environment | Typical command | Notes |
| --- | --- | --- |
| Host Rust | `make verify-local` | fastest feedback |
| Docker lab | `make verify-lab-docker` | Xray/sing-box external clients |
| Lima VM | `make verify-lab-lima` | browser TLS fingerprint |
| Real VPS | `make verify-remote` | protocol matrix, TUN, netem |

Lower-level lab atoms: `make -C labs/realistic docker-full`, `external-clients-docker`, `vps-test`, etc. See [make-target-inventory.md](make-target-inventory.md).

## Compatibility Aliases

Still work; each prints `Deprecated alias: use make …`.

| Alias | Canonical replacement |
| --- | --- |
| `make check` / `make local-total` | `make verify-check-compat` |
| `make check-browser` | `make verify-lab-lima` |
| `make check-vps` | `verify-check-compat` + `verify-remote` |
| `make check-all-local` | `verify-check-compat` + `verify-lab-lima` |
| `make ci` / `make local-fast` | `make verify-local` |
| `make ci-all` / `make local` | `make -C labs/realistic ci` + `prod-readiness` |
| `make ci-vps` / `make vps` | `make verify-remote` |
| `make local-fuzz` | `make fuzz-smoke` |
| `make local-fuzz-total` | `make fuzz-long` |
| `make check-perf-vm` | `make perf` |
| `make perf-vps` / `make check-perf-vps` | `make perf-remote` |

Full mapping: `make help-compat`.

## Command Families

### Build and quality atoms

| Command | Purpose |
| --- | --- |
| `make build` / `make dev` | Release / debug build |
| `make fmt` / `make fmt-check` | rustfmt |
| `make lint` | clippy with `-D warnings` (same as `verify-local`) |
| `make lint-strict` | clippy + unwrap/expect denies (optional hygiene gate) |
| `make test` | `cargo test --workspace` |
| `make audit` / `make deny` | cargo-audit / cargo-deny |

### Production-readiness helpers (`labs/realistic`)

| Command | Purpose |
| --- | --- |
| `make -C labs/realistic prod-readiness` | load, soak, fingerprint, dns-chaos, security bundle |
| `make -C labs/realistic load` | managed local load smoke |
| `make -C labs/realistic soak` | bounded soak loop |
| `make -C labs/realistic security` | lab security script |
| `make -C labs/realistic real-devices` | manual device checklist template |
| `make security` | root wrapper: audit + deny + lab security |

### Fuzz

| Command | Purpose |
| --- | --- |
| `make fuzz-smoke` | 100 runs × 6 targets (nightly) |
| `make fuzz-long` | heavier pass (`FUZZ_RUNS`, default 100k via lab) |

### Realistic external clients

| Command | Purpose |
| --- | --- |
| `make -C labs/realistic external-clients-docker` | Xray/sing-box vs proxy-rs in Docker |
| `make -C labs/realistic external-clients-vps` | same from client VPS |
| `make -C labs/realistic external-clients-report` | print summary |

### Cleanup

| Command | Purpose |
| --- | --- |
| `make clean-generated` | reports, pcaps, bench outputs |
| `make clean-pcaps` | fingerprint/pcap outputs only |
| `make clean-all-generated` | generated + `cargo clean` |

## Where Detailed Flows Live

- Workflows by change type: [test-workflows.md](test-workflows.md)
- Full testing tiers: [11-testing.md](11-testing.md)
- Realistic lab: [../labs/realistic/README.md](../labs/realistic/README.md)
- REALITY/Xray interop: [../tests/interop/README.md](../tests/interop/README.md)
