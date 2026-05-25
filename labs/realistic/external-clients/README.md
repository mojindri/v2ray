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

**15 protocols** in `scenarios.env` (60 matrix rows). Some rows **SKIP** when upstream cannot run the client transport (Xray legacy QUIC, SplitHTTP positives, sing-box ShadowTLS on VLESS stream).

Optional failure capture: `MATRIX_PCAP_ON_FAIL=1 make interop-server-docker`.

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

The VPS runner assumes server/client setup already ran (`server-setup.sh` /
`client-setup.sh`). It mirrors the Docker harness: **one blackwire start per
protocol**, four sequential client cases (xray, sing-box, negatives), same
`scenarios.env` and port-wait rules (including ShadowTLS cover on server `:443`).
Reports: `labs/realistic/reports/external-clients-vps/`.

The runner keeps console output compact and writes full logs under:

```text
labs/realistic/reports/external-clients/
```

## Scenario Set

The automated matrix is driven by `external-clients/scenarios.env`.

`scenarios.env` drives the matrix (15 protocols including ShadowTLS, mKCP, sniffing).
Both Docker and VPS runners read the same file; tune waits with `MATRIX_PORT_WAIT_*`
and `MATRIX_SOCKS_WAIT_*`.

**SKIP lines** mean that client is not run for the row (upstream config limits), not that
blackwire lacks the server transport. See [docs/parity-status.md](../../../docs/parity-status.md).

| Row | Typical SKIP reason |
|-----|---------------------|
| `vless-quic` | Xray 26+ removed QUIC client transport (sing-box proves row) |
| `vless-splithttp` | Full xHTTP client framing not in matrix |
| `vless-shadowtls` | Xray/sing-box client models differ from VLESS+`shadowtls` stream |
| `vless-mkcp` | sing-box has no mKCP; Xray uses new finalmask — server proven in e2e |

Hiddify remains a manual validation target using generated import artifacts
after the automated scenarios pass.

When a case **FAIL**s, follow [docs/external-client-failure-triage.md](../../docs/external-client-failure-triage.md):
read `reports/external-clients/logs/*.log`, then compare behavior with
[Xray-core](https://github.com/XTLS/Xray-core) / [sing-box](https://github.com/SagerNet/sing-box) source — not blackwire comments alone.

For every supported positive case, the lab also renders a negative-auth variant
with the wrong UUID/password/shortId. Those cases must fail to fetch the target;
otherwise the report marks them as accepted and fails the run.
