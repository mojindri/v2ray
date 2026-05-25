# Performance And Soak Testing

Short CI-safe checks:

- `bash tools/perf/run_perf_smoke.sh`
- `python3 ci/scripts/check_perf_regression.py ci/perf-baselines/smoke.json <result.json>`

Long scheduled checks:

- `.github/workflows/perf-and-soak.yml` (scheduled)
- `bash tools/soak/run_soak_campaign.sh <out-dir> 24h|72h|7d`

Cross-platform coverage:

- `.github/workflows/cross-platform.yml`

Dependency/security audit coverage:

- `.github/workflows/security-audit.yml`
- `bash ci/security/run_dependency_audit.sh`
