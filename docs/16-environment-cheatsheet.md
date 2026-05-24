# Environment Cheatsheet

This is the shortest answer to "what do I run locally, in Docker, in a VM, or
with real VPS machines?"

## Core Rule

Almost everything starts from your local repo checkout.

You normally do **not** SSH into a VPS and start running repo-level `make`
commands there. The local commands orchestrate Docker, Lima, or VPS work for
you.

## 1. Local Only

Run these from your local checkout. They execute only on your machine.

Use when:

- you want the fastest feedback
- you are changing Rust code and want to catch regressions quickly
- you do not need Linux/browser/public-network realism yet

Commands:

```sh
make check
cargo test --workspace
cargo test -p integration-tests
cargo test -p proxy-core --test production_readiness --all-features
cargo test -p proxy-protocol --test production_readiness --all-features
cargo test -p proxy-transport --test production_readiness --all-features
```

## 2. Local + Docker

Run these from your local checkout. They execute on your machine and in local
Docker containers.

Use when:

- you want Xray interop
- you want deterministic target services
- you want a realistic local container environment without real VPS machines

Commands:

```sh
make -C labs/realistic docker-full
make -C labs/realistic docker-up
make -C labs/realistic docker-down
make -C labs/realistic xray
make -C labs/realistic negative-auth
make -C labs/realistic restart-smoke
```

## 3. Local + Lima VM

Run these from your local checkout. They execute partly on your machine and
partly inside the Lima Ubuntu VM.

Use when:

- you want Linux-like browser/TLS behavior
- you want isolated browser fingerprint capture
- you want VM benchmarking without renting VPS machines

Commands:

```sh
make check-browser
make perf
make lima-stop
make check-all-local
make check-sequence
```

Notes:

- `make check-browser` is the main Lima validation entrypoint.
- `make perf` is the main Lima benchmark entrypoint.
- `make check-all-local` is a compatibility alias that combines local checks and
  the Lima browser path.
- `make lima-stop` stops the default Lima VM instance.
- Raw equivalent if you want it directly:

```sh
limactl stop proxy-rs-browser
```

## 4. Local + Real VPS

Run these from your local checkout. They use SSH to drive the real VPS machines.

Use when:

- you want the closest production signal
- you need public-network behavior
- you want the two-VPS matrix
- you need Linux-root-only checks like TUN validation

Commands:

```sh
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make check-vps
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make perf-vps
SSH_SERVER=<server-ip> make -C labs/realistic vps-server-setup
SSH_CLIENT=<client-ip> make -C labs/realistic vps-client-setup
SSH_CLIENT=<client-ip> make -C labs/realistic vps-test
SSH_SERVER=<server-ip> make -C labs/realistic vps-tun
```

Notes:

- `make check-vps` is the main top-level VPS validation entrypoint.
- `make perf-vps` is the VPS benchmark entrypoint.
- `vps-server-setup`, `vps-client-setup`, `vps-test`, and `vps-tun` are
  lower-level realistic-lab commands.

## 5. Directly On A VPS

Do this only for debugging, inspection, or recovery.

Use when:

- a remote service failed and you need logs
- you need to inspect generated configs
- you need to confirm system state on the server or client VPS

Typical direct VPS commands:

```sh
ssh root@<server>
systemctl status proxy-rs-*
journalctl -u proxy-rs-* --no-pager | tail -200
ls /etc/proxy-rs/generated/

ssh root@<client>
journalctl --no-pager | tail -200
```

Do **not** treat the VPS shell as the normal place to run `make check`, `make
check-vps`, or other repo-level orchestration commands.

## Quick Decision Guide

If you are unsure, use this order:

1. `make check`
2. `make -C labs/realistic docker-full`
3. `make check-browser`
4. `SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make check-vps`

For performance:

1. `make perf`
2. `SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make perf-vps`

## Related Docs

- [11-testing.md](11-testing.md)
- [15-make-command-guide.md](15-make-command-guide.md)
- [../labs/realistic/README.md](../labs/realistic/README.md)
- [../tests/interop/README.md](../tests/interop/README.md)
