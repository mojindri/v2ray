# Release Canary Plan

## Canary Scope

- Start with 5% traffic for 30 minutes.
- Use real traffic with normal auth mix and background bad-auth noise.
- Keep periodic config reload enabled during canary.

Helper:

```bash
bash tools/canary/run_canary.sh
```

## Required Dashboards / Alerts

Monitor:

- error rate
- p99 latency
- RSS
- fd count
- task count
- auth failures
- outbound timeout rate
- DNS failure rate
- session evictions

## Rollback

Rollback helper:

```bash
bash tools/canary/rollback.sh <previous-release-tag>
```

Rollback path:

1. shift traffic back to stable
2. redeploy previous release tag
3. restore last-known-good config snapshot
4. verify health and synthetic probes
5. verify memory/fd/task counters converge to baseline
