# Test workflows

This repo uses **`verify-*`** as the canonical Make surface. Run commands from
your **local checkout** (not from inside a VPS shell).

Legacy names (`check`, `check-browser`, `check-vps`, `ci-all`, …) still work —
see `make help-compat`.

## Canonical commands

| Command | When to use |
|---------|-------------|
| `make verify-local` | Everyday Rust development |
| `make verify-lab` | Protocol/transport changes needing Docker + Lima |
| `make verify-remote` | Pre-merge production signal on real VPS hosts |
| `make verify-sweep` | Broad quick gate before a larger change |
| `make verify-release` | Pre-release / slow full gate |

See also: `make help`, `make help-compat`, `docs/make-target-inventory.md`.

## 1. Everyday development

```sh
make verify-local
```

Host-only: `fmt-check`, `cargo check`, `clippy`, `cargo test`. No Docker, Lima, VPS, root, or nightly.

## 2. Protocol / transport changes

```sh
make verify-local
make verify-lab
```

`verify-lab` runs the Docker matrix (stable tests, **interop-docker** with
server-compat + client-compat legs) and Lima browser/fingerprint checks.

Debug one interop leg only:

```sh
make -C labs/realistic interop-server-docker    # Xray/sing-box -> our server
make -C labs/realistic interop-client-reality   # our client -> Xray server
```

Subtargets:

```sh
make verify-lab-docker      # Docker only
make verify-lab-lima        # Lima fingerprint only
```

## 3. REALITY / TLS / fingerprint changes

```sh
make verify-lab
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make verify-remote
```

Docker external clients write `labs/realistic/reports/external-clients/summary.txt`.  
Lima artifacts live under `labs/realistic/reports/production/`.

## 4. VPS validation

**Required environment:**

- `SSH_SERVER` — server VPS (proxy inbounds, TUN/netem)
- `SSH_CLIENT` — client VPS (runs protocol matrix)
- Optional: `SSH_KEY`, `SSH_USER` (default `root`), `SSH_PORT`, `SSH_EXTRA_OPTS`

**Example:**

```sh
export SSH_SERVER=1.2.3.4
export SSH_CLIENT=5.6.7.8
export SSH_KEY=~/.ssh/id_ed25519

make remote-preflight          # connectivity + remote layout
make remote-deploy             # rsync lab + setup (mutates both VPS)
make verify-remote             # full remote gate
```

Remote targets **mutate VPS hosts** (install packages, run tests, load). Logs are copied into `labs/realistic/reports/`.

First-time setup only:

```sh
make remote-deploy
```

## 5. Pre-release

```sh
make verify-release
```

Runs `verify-sweep`, Lima `perf`, optional `perf-remote`, `soak`, and `fuzz-long` (`FUZZ_RUNS` configurable).

Expect **tens of minutes to hours** depending on fuzz/soak settings.

## 6. Requirements matrix

| Capability | Commands | Needs |
|------------|----------|-------|
| Rust only | `verify-local` | `cargo`, stable toolchain |
| Docker lab | `verify-lab-docker`, `lab-docker-*` | Docker daemon |
| Lima lab | `verify-lab-lima`, `lab-lima-*` | `limactl`, Homebrew Lima on macOS |
| VPS | `verify-remote`, `remote-*`, `perf-remote` | `SSH_SERVER`, `SSH_CLIENT`, SSH key |
| Privileged TUN | `remote-test-fallback` → `vps-tun` | Linux server VPS, `sudo` |
| netem | `remote-collect` → `vps-netem` | server VPS, `tc`, root |
| Fuzz smoke | `fuzz-smoke` | `cargo +nightly`, `cargo-fuzz` |
| Fuzz long | `fuzz-long` | nightly, time |
| Security extras | `security` | optional `cargo-audit`, `cargo-deny` |

## 7. Deprecated aliases

Old names (`check`, `ci-all`, `check-vps`, …) still work and print:

`Deprecated alias: use make <canonical-target>`

List: `make help-compat`.

## 8. Cleanup

```sh
make clean-generated    # reports, pcaps, bench outputs (keeps build cache)
make lab-docker-down    # stop lab Docker compose stacks
make lab-lima-down      # stop default Lima instance
```

Remote VPS cleanup is manual (`make remote-clean` only prints guidance).
