# Task C Coverage Report (Performance + Release Infrastructure)

Date: 2026-05-25

Policy used: implement only missing coverage; do not duplicate existing implementation.

## 15) Long soak tests
- Status: **partially covered**
- Existing: `labs/realistic/scripts/run-soak.sh`, `labs/realistic/configs/soak.env`, `make soak`
- Added missing:
  - `tools/soak/run_soak_campaign.sh` (24h/72h/7d profiles)
  - `tests/soak/README.md` (short-smoke location contract)
  - scheduled hook in `.github/workflows/perf-and-soak.yml`
- Remaining gap:
  - fully automated real xray/sing-box orchestration over 24h+ in CI infra

## 16) Performance benchmarks
- Status: **partially covered**
- Existing: lab throughput scripts (`run-bench-vm.sh`, `run-bench-vps.sh`)
- Added missing:
  - criterion benchmark crate `benches/` with groups for throughput, handshake, routing/dns/fakeip, framing overhead
  - workflow job `criterion-benches`
- Remaining gap:
  - direct bench coverage wired to production parser/relay internals beyond synthetic microbench paths

## 17) Memory/allocation profiling
- Status: **partially covered**
- Existing: soak script samples RSS/fd
- Added missing:
  - `tools/perf/memory_profile.sh`
  - `tests/perf/README.md`
- Remaining gap:
  - allocator-level per-connection counters and automated heap profiling snapshots

## 18) Latency percentile tracking
- Status: **covered**
- Existing: `labs/realistic/scripts/local_curl_load.py` and `socks_http_load.py` emit p50/p95/p99/max
- Added:
  - `tools/perf/run_perf_smoke.sh` standardized JSON artifact path

## 19) CI performance regression gates
- Status: **covered**
- Added:
  - `ci/perf-baselines/smoke.json`
  - `ci/scripts/check_perf_regression.py`
  - workflow `perf-and-soak.yml` gate step

## 20) Lock contention profiling
- Status: **partially covered**
- Added:
  - `tools/perf/check_lock_contention.sh` (tokio-console/perf/flamegraph workflow)
  - `docs/performance.md`
- Remaining gap:
  - automated contention threshold gating

## 23) Cross-platform matrix
- Status: **covered**
- Added:
  - `.github/workflows/cross-platform.yml` for Linux x86_64, Linux ARM64, macOS, Docker tooling check

## 24) Dependency/security audit
- Status: **covered**
- Existing: `deny.toml`, optional audit/deny in make/lab scripts
- Added:
  - `ci/security/run_dependency_audit.sh`
  - `.github/workflows/security-audit.yml` with cargo audit/deny/outdated/geiger/udeps

## 25) Release canary plan
- Status: **covered**
- Added:
  - `tools/canary/run_canary.sh`
  - `tools/canary/rollback.sh`
  - `docs/release.md`
  - `docs/testing.md` linkage
