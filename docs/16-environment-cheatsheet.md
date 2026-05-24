# Environment Cheatsheet

Short answer: **what do I run locally, in Docker, in Lima, or on real VPS?**

Canonical commands use the `verify-*` prefix. Legacy `check-*` aliases still work
(`make help-compat`).

## Core Rule

Start from your **local repo checkout**. Repo-level `make` commands orchestrate
Docker, Lima, or VPS over SSH. SSH into a VPS only for debugging.

## 1. Host only (no Docker / Lima / VPS)

Use when changing Rust code and you want the fastest feedback.

```sh
make verify-local
```

Equivalent atoms if you need finer control:

```sh
cargo test --workspace --all-targets
cargo test -p integration-tests
cargo test -p proxy-core --test production_readiness --all-features
```

## 2. Local + Docker

Use when you need Xray interop, configured external-client checks, or containerized targets.

```sh
make verify-lab-docker
# or lower-level:
make -C labs/realistic docker-full
make -C labs/realistic external-clients-docker
make -C labs/realistic external-clients-report
make -C labs/realistic docker-down
```

## 3. Local + Lima VM

Use for Linux browser/TLS fingerprint capture and VM benchmarks.

```sh
make verify-lab-lima
make perf
make lab-lima-down    # or: make lima-stop
```

Full lab gate (Docker + Lima):

```sh
make verify-lab
```

## 4. Local + real VPS

Use for closest production signal (public network, two-VPS matrix, TUN/netem).

```sh
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> SSH_KEY=~/.ssh/id_ed25519 \
  make verify-remote
```

First-time setup:

```sh
make remote-deploy    # rsync lab + server/client setup (mutates both VPS)
```

Lower-level atoms:

```sh
make -C labs/realistic vps-preflight
make -C labs/realistic vps-test
make -C labs/realistic vps-tun
make -C labs/realistic external-clients-vps
make perf-remote      # VPS benchmark
```

Optional: `SSH_USER`, `SSH_PORT`, `SSH_EXTRA_OPTS`.

## 5. Directly on a VPS

Only for debugging — not the normal workflow.

```sh
ssh root@<server>
systemctl status blackwire-*
journalctl -u blackwire-* --no-pager | tail -200
```

Do **not** run `make verify-*` or legacy `make check-*` from inside a VPS shell.

## Quick Decision Guide

1. `make verify-local`
2. `make verify-lab` (or `verify-lab-docker` only)
3. `SSH_SERVER=… SSH_CLIENT=… make verify-remote`

Broad gate before a large change:

```sh
make verify-sweep    # skips remote unless SSH_* is set
```

Pre-release:

```sh
make verify-release  # slow
```

Performance:

1. `make perf`
2. `SSH_SERVER=… SSH_CLIENT=… make perf-remote`

## Legacy aliases (still work)

| Old | Prefer |
| --- | --- |
| `make check` | `make verify-check-compat` |
| `make check-browser` | `make verify-lab-lima` |
| `make check-vps` | `verify-check-compat` + `verify-remote` |

## Related Docs

- [test-workflows.md](test-workflows.md)
- [15-make-command-guide.md](15-make-command-guide.md)
- [make-target-inventory.md](make-target-inventory.md)
- [11-testing.md](11-testing.md)
- [../labs/realistic/README.md](../labs/realistic/README.md)
