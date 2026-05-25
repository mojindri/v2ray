# Performance And Contention

This repository has two performance layers:

1. Lab-style performance and soak (`labs/realistic/scripts/run-bench-*.sh`, `run-soak.sh`).
2. Criterion microbenchmarks (`cargo bench -p blackwire-benches`).

## Benchmarks

Run:

```bash
cargo bench -p blackwire-benches
```

Covered benchmark groups:

- TCP relay throughput
- Protocol handshake latency (synthetic handshake path cost)
- Routing/DNS cache/FakeIP lookup-allocation latency
- WebSocket/gRPC framing overhead

## Regression Gates

CI baseline thresholds live in:

- `ci/perf-baselines/smoke.json`

Gate script:

- `ci/scripts/check_perf_regression.py`

## Lock Contention Profiling

Use:

```bash
bash tools/perf/check_lock_contention.sh
```

This documents workflow for:

- `tokio-console`
- `perf record/report`
- `cargo flamegraph`
