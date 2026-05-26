# E2E protocol perf baseline

First local run on **macOS** (loopback, in-process server+client `Instance`s). Harness: `benches/` Criterion suite. Quick mode: `BENCH_QUICK=1`, `sample-size 10`.

Reproduce:

```bash
make bench-protocol-quick
# or one path:
BENCH_QUICK=1 cargo bench -p blackwire-benches --bench e2e_vmess_grpc
```

Allocation counters (local only):

```bash
cargo bench -p blackwire-benches --bench e2e_vmess_grpc --features bench-alloc
```

Flamegraphs (Linux recommended):

```bash
make bench-flamegraph PROTO=vmess_grpc SCENARIO=bulk
# -> benches/reports/flamegraphs/vmess_grpc-bulk-<ts>.svg
```

## Bulk relay — steady state 64 KiB (median wall time)

| Path | Median time | ~MiB/s (128 KiB round-trip) | Notes |
|------|-------------|-------------------------------|--------|
| Trojan TCP | 176 µs | ~695 | Plain TCP + trojan framing |
| VLESS TCP | 222 µs | ~551 | Baseline proxy path |
| VLESS WebSocket | 330 µs | ~371 | ~1.5× TCP; WS framing |
| VMess gRPC | 2.25 ms | ~54 | ~10× TCP; H2/gRPC bridge |
| SS2022 | 2.36 ms | ~52 | Crypto + SIP022 framing |

Higher is better for MiB/s column (less time per 64 KiB echo).

## Setup / handshake

Measure with:

```bash
cargo bench -p blackwire-benches --bench e2e_<path> -- handshake --sample-size 50
```

Groups: `{path}/handshake/connect`. Optional sniffing overhead: `BENCH_SNIFF=1` (SOCKS paths only).

## Short-lived / mixed / concurrency

| Group | What it measures |
|-------|------------------|
| `{path}/short_lived/{64,256,1024}` | Connect + small payload + close per iter |
| `{path}/mixed_small_writes/chunk_x64/*` | 64 rounds of small write/read on one connection |
| `{path}/concurrency/short_lived_fanout/{1,8,32}` | Parallel short sessions |

## Cost breakdown (hypothesis → validate on Linux flamegraphs)

| Layer | Likely dominant on |
|-------|-------------------|
| Transport (WS, gRPC/H2) | VLESS WS, VMess gRPC |
| Crypto + packet framing | SS2022, especially small writes |
| Routing / sniffing / orchestration | Short-lived + `BENCH_SNIFF=1` |
| Relay bridge copies | Compare alloc counts with `bench-alloc` before/after copy work |

## Recommended next hotspot

**VMess over gRPC** — largest gap vs VLESS TCP on bulk 64 KiB (~10×). Profile `bulk` and `short` scenarios on Linux; look for gRPC/H2 bridge, buffer churn, and extra copies in the relay path.

Secondary: **SS2022** (similar bulk cost to VMess; likely crypto + framing on small writes).

## Before/after protocol changes

1. Run the same `cargo bench` filters and save `target/criterion/` or `benches/reports/`.
2. Re-run flamegraph script for the changed path.
3. Do not treat microbenches (`tcp_relay_throughput`, synthetic `protocol_handshake_latency`) as e2e proof.

## Machine / env

Record when updating this file:

- OS / CPU / `rustc -V`
- `BENCH_QUICK`, `BENCH_SNIFF`, `bench-alloc` on/off
- Commit SHA

_Current snapshot: informal dev machine, not a regression gate._

## Latest serial quick verification (2026-05-26)

Command shape:

```bash
BENCH_QUICK=1 BENCH_BULK_ONLY=1 BENCH_ITER_TIMEOUT_MS=20000 BENCH_IO_TIMEOUT_MS=3000 \
  cargo bench -p blackwire-benches --bench e2e_<path> -- bulk_relay/steady_state/chunk_65536/65536 --quick
```

- `ss2022`: time `[2.2002 ms 2.2964 ms 2.3204 ms]`, thrpt `[26.935 MiB/s 27.217 MiB/s 28.406 MiB/s]`
- `vmess_grpc`: time `[2.3214 ms 2.3412 ms 2.3461 ms]`, thrpt `[26.639 MiB/s 26.696 MiB/s 26.924 MiB/s]`

Both paths completed without relay stalls after stream progress fixes.
