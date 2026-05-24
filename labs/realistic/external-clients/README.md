# External Client Compatibility Lab

This lab checks real external clients against `blackwire` server inbounds:

```text
Xray or sing-box client -> blackwire server -> target-http
```

It is intentionally separate from `vps-test`, which checks `blackwire` client to
`blackwire` server. Passing this lab is evidence that the currently configured
external-client scenarios are compatible with the server side.

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

At the moment that file contains one scenario:

1. VLESS REALITY

As more scenarios are added to `scenarios.env`, the same runner will pick them
up automatically for both Docker and VPS execution.

Hiddify remains a manual validation target using generated import artifacts
after the automated scenarios pass.

For every supported positive case, the lab also renders a negative-auth variant
with the wrong UUID/password/shortId. Those cases must fail to fetch the target;
otherwise the report marks them as accepted and fails the run.
