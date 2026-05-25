# Soak Tests

`tests/soak/` is reserved for short soak smoke checks that are safe for CI runtime budgets.

Long campaigns (24h/72h/7d) are run via:

- `tools/soak/run_soak_campaign.sh`
- scheduled CI workflow `perf-and-soak.yml`
