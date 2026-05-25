# External Client Compatibility Lab

This lab checks real external clients against `blackwire` server inbounds:

```text
Xray or sing-box client -> blackwire server -> target-http
```

It is intentionally separate from `vps-test`, which checks `blackwire` client to
`blackwire` server. Passing this lab is evidence that the currently configured
external-client scenarios are compatible with the server side.

## Sequential execution (required)

**Do not run two matrix invocations in parallel.**

Within one run, the Docker harness (`run-docker-matrix.sh`) keeps long-lived
containers and still runs **one external client at a time** (Xray, then sing-box,
then negatives). Only one of `xray-client` / `sing-box-client` may run a proxy
process at once. A lock under the report directory prevents overlapping matrix
invocations.

### Fast harness (default)

- `docker compose up -d` once (target, probe, server, clients).
- Reused `matrix-probe` container for `nc` / `curl` (no `docker run --rm` per check).
- `compose exec` to start/stop `blackwire` and sing-box per case.
- **Xray** uses `compose run` per case (distroless image has no `/bin/sh` for idle holders).
- **One server start per protocol** (four client cases reuse the same listener).
- `target-http` compose healthcheck instead of blind sleep loops.

Tune waits: `MATRIX_PORT_WAIT_TRIES`, `MATRIX_PORT_WAIT_SLEEP`, `MATRIX_SOCKS_WAIT_TRIES`, `MATRIX_SOCKS_WAIT_SLEEP`.

**12 protocols** in `scenarios.env` (48 matrix rows). Some rows **SKIP** Xray when upstream removed a transport (e.g. legacy QUIC in Xray 26+) or client framing differs (SplitHTTP).

## Commands

From `labs/realistic`:

```sh
make interop-server-docker    # server-compat: Xray/sing-box -> our server (Docker)
make interop-client-reality   # client-compat: our Rust client -> Xray server (d1)
make interop-docker           # both legs (used by verify-lab-docker)
make interop-server-vps       # server-compat on two VPS hosts
```

Atoms (debugging only):

```sh
make external-clients-docker
make external-clients-report
```

For the two-VPS promotion gate:

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_ed25519 make interop-server-vps
```

The VPS runner assumes the normal server/client setup already ran. It does not
install Docker or packages. It starts one `/usr/local/bin/blackwire` inbound at a
time on the server VPS, runs Xray/sing-box Docker clients on the client VPS, and
writes full logs under `labs/realistic/reports/external-clients-vps/`.

The runner keeps console output compact and writes full logs under:

```text
labs/realistic/reports/external-clients/
```

## Scenario Set

The automated matrix is driven by `external-clients/scenarios.env`.

`scenarios.env` drives the matrix (VLESS REALITY/TCP/WS, VMess gRPC, Trojan TLS,
SS-2022, Hysteria2). Add or comment out rows there to change coverage; both Docker
and VPS runners read the same file.

Hiddify remains a manual validation target using generated import artifacts
after the automated scenarios pass.

When a case **FAIL**s, follow [docs/external-client-failure-triage.md](../../docs/external-client-failure-triage.md):
read `reports/external-clients/logs/*.log`, then compare behavior with
[Xray-core](https://github.com/XTLS/Xray-core) / [sing-box](https://github.com/SagerNet/sing-box) source — not blackwire comments alone.

For every supported positive case, the lab also renders a negative-auth variant
with the wrong UUID/password/shortId. Those cases must fail to fetch the target;
otherwise the report marks them as accepted and fails the run.
