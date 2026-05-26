# Health-check outbound failover lab

Black-box scenario for balancer + HTTP health probes under the real `Instance` stack.

## What it proves

1. SOCKS traffic enters a balancer with two member outbounds.
2. `primary-vless` points at a dead upstream and fails health probes.
3. `backup-freedom` probes the live Docker `health-probe` service.
4. After probe rounds, user traffic still reaches the TCP echo target.

## Run

From repo root:

```sh
make -C labs/realistic health-failover
```

Or directly:

```sh
bash labs/realistic/health-failover/run.sh
```

Fast in-process proof (no Docker):

```sh
cargo test -p integration-tests --test e2e_health_failover health_failover_routes_to_backup_when_primary_unhealthy
```

## Services

| Service | Host port | Role |
|---------|-----------|------|
| `health-probe` | `18081` | HTTP 200/204 target for freedom health probes |
| `echo-target` | `19091` | TCP echo for SOCKS user traffic |

Logs: `labs/realistic/reports/health-failover.log`
