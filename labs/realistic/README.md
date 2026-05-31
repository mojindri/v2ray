# Realistic Test Lab

This lab is the production-realism layer for `blackwire`.

It has two jobs:

1. Run the stable protocol matrix in a repeatable local environment.
2. Provide a two-VPS checklist for the same scenarios over real public networking.

## Gates (what to run)

| Goal | Command |
|------|---------|
| Everyday Rust confidence | `make -C labs/realistic stable` |
| ShadowTLS, mKCP, QUIC/SplitHTTP e2e, health/DNS guards + failover runtime | `make -C labs/realistic advanced-features-smoke` |
| Health-check outbound failover (e2e + optional Docker) | `make -C labs/realistic health-failover` |
| Xray/sing-box clients → our server (Docker) | `make -C labs/realistic interop-server-docker` |
| All local pre-push checks | `make -C labs/realistic finalize` |
| Same matrix on two VPS hosts | `SSH_SERVER=… SSH_CLIENT=… make -C labs/realistic interop-server-vps` |

**External-client matrix (Docker):** `external-clients/scenarios.env` is the source of truth. It currently defines 19 scenario rows; each row runs the configured Xray and/or sing-box positive and negative cases. Rows with `-` in a client column are **SKIP** because of upstream client/config limits, not missing blackwire server transports — see [docs/parity-status.md](../../docs/parity-status.md).

Source of truth: [docs/xray-parity-source-of-truth.md](../../docs/xray-parity-source-of-truth.md).

## Local Docker baseline

```sh
make -C labs/realistic docker-full
```

1. Starts deterministic target services.
2. Runs the stable Rust integration matrix.
3. Runs Xray REALITY interop tests.

Reports: `labs/realistic/reports/`.

```sh
make -C labs/realistic advanced-features-smoke   # ShadowTLS, mKCP, QUIC/SplitHTTP, guards
make -C labs/realistic negative-auth
make -C labs/realistic restart-smoke
make -C labs/realistic stress
make -C labs/realistic report-summary
make -C labs/realistic realistic-all
make -C labs/realistic docker-down
```

## External client compatibility (server-compat)

Scenarios in `external-clients/scenarios.env`: real **Xray** or **sing-box** client → **blackwire** server → `target-http`.

```sh
make -C labs/realistic interop-server-docker
make -C labs/realistic interop-docker   # + client-compat REALITY leg
```

VPS:

```sh
SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_ed25519 make -C labs/realistic interop-server-vps
```

Configs: `external-clients/generated/`. Reports: `reports/external-clients/`.

Details: [external-clients/README.md](external-clients/README.md).

## Two-VPS gate

- **Client VPS:** runs matrix probes (Docker Xray/sing-box + curl).
- **Server VPS:** blackwire inbounds, Caddy ACME, target on `:18080`.

Full steps: [docs/11-testing.md](../../docs/11-testing.md).

```sh
cp configs/matrix.env.example configs/matrix.env
SSH_SERVER=1.2.3.4 SSH_KEY=~/.ssh/id_hetzner make vps-server-setup
SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_hetzner make vps-client-setup
SSH_CLIENT=5.6.7.8 SSH_KEY=~/.ssh/id_hetzner make vps-test
SSH_SERVER=1.2.3.4 SSH_KEY=~/.ssh/id_hetzner make vps-tun
```

### Sensitive host values

Keep `configs/matrix.env` generic in git (no real IPs or hostnames).
Use shell overrides or a private local env file for real VPS values:

```sh
source ./configs/matrix.private.env
SSH_SERVER="$MY_SERVER_HOST" SSH_CLIENT="$MY_CLIENT_HOST" \
  make -C labs/realistic interop-server-vps
```

`configs/matrix.private.env` should stay untracked and contain values like
`SERVER_HOST`, `TEST_DOMAIN`, and `SHADOWTLS_DEST`.

Optional: `SSH_USER`, `SSH_PORT`, `SSH_EXTRA_OPTS`, or `make vm-pack`.

## Why this lab reuses existing tests

Integration tests already exercise real `blackwire-core::Instance` objects. This lab wraps them with Docker targets and external clients instead of duplicating protocol logic in shell scripts.
