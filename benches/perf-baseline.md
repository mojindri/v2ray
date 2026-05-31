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

## Shared-path local gate (2026-05-30)

Purpose: fast local filter for the shared-path optimization plan. This is not
the final acceptance gate; VPS competitor runs remain required before making
claims against Xray or sing-box.

Environment:

- Host: local macOS/Darwin arm64
- `rustc`: `rustc 1.95.0 (59807616e 2026-04-14)`
- Commit at run start: `354c566`
- Private host/IP values: not used in local reports

Commands and logs:

```bash
cargo test --workspace --all-targets
BENCH_QUICK=1 make bench-protocol-quick
BENCH_FEATURES=bench-alloc BENCH_QUICK=1 make bench-protocol-quick
make bench-flamegraph PROTO=vless_tcp SCENARIO=bulk
```

- Workspace tests: PASS, log `benches/reports/test-workspace-shared-path-20260530.log`
- Quick bench baseline: PASS, report `benches/reports/protocol-matrix-20260530T002407Z.log`
- Allocation quick bench: PASS, report `benches/reports/protocol-matrix-20260530T003107Z.log`
- macOS flamegraph attempt: BLOCKED, log `benches/reports/flamegraph-vless-tcp-bulk-20260530.log`

Flamegraph blocker:

- Darwin flamegraph collection reached profile collapse and failed with
  `IllFormed(MismatchedEndTag { expected: "binary", found: "frame" })`.
- Treat local macOS flamegraphs as non-authoritative for this phase.
- Required next proof: run the four requested flamegraphs on Linux/VPS.

Allocation observation:

- `vless_tcp/bulk` steady samples repeatedly reached `2 allocs, 131072 bytes`
  after setup, while setup/initial samples showed roughly `48-49 allocs` and
  `205-221 KiB`.
- Decision: shared bulk relay buffers already look allocation-minimal in steady
  state; prioritize TCP pool setup/stale behavior, scheduler boundaries, and
  Linux relay policy validation before broad allocation cleanup.

Rejected experiment:

- Candidate: replace the Fast Profile pooled first-write guard's per-connection
  `Vec<u8>` with the shared `BufferPool`.
- Target: reduce one 16 KiB allocation on pooled TCP hits.
- Correctness: focused unit test and `cargo test --workspace --all-targets`
  passed.
- Local quick bench after candidate: `benches/reports/protocol-matrix-20260530T004558Z.log`.
- Result: rejected locally. Criterion flagged several Trojan TCP short/mixed
  samples as slower, including `trojan_tcp/short_lived/256`
  `+4.2832% +7.3792% +10.598%` and
  `trojan_tcp/mixed_small_writes/chunk_x64/1024`
  `+4.4832% +11.373% +17.586%`.
- Final state: candidate reverted; do not reapply without a targeted pooled-hit
  benchmark showing a clear allocation and latency win.

Quiet local gate helper:

```bash
tools/perf/shared_path_local_gate.sh
```

The helper writes full command output under `benches/reports/shared-path-local-*`
and prints only short status lines plus failure tails.

## Native VPS nginx payload gate (2026-05-30)

Purpose: corrected native VPS acceptance filter for shared-path pool tuning.
This run used native `blackwire`, Xray, sing-box, `hey`, and nginx upstream on
`:18080`. Docker and Python upstream were not used. Private host/IP values are
intentionally omitted.

Harness fix:

- `labs/realistic/latency/scripts/run-vps.sh` now passes `BENCH_PAYLOAD` and
  `UPSTREAM_BASE_URL` instead of forcing `TARGET_URL` to `/`.
- This makes `BENCH_PAYLOAD=1k` actually benchmark `/1k` rather than the nginx
  `/` response.

Corrected adaptive baseline (`BENCH_PAYLOAD=1k`, 15s, concurrency 32):

| Variant | req/s | Decision |
|---|---:|---|
| `xray-bw-fast-tcp` | 15,794 | baseline |
| `singbox-bw-fast-tcp` | 15,872 | baseline |

Rejected experiments:

| Candidate | Result | Decision |
|---|---|---|
| Skip stale probe for pooled sockets younger than 50ms | `xray-bw-fast-tcp` 16,044; `singbox-bw-fast-tcp` 15,765 | rejected; mixed and below threshold |
| Fixed pool `maxPerDest=8` | run 1: 17,296 / 18,299; repeat: 15,308 / 17,741 | rejected as broad default; Xray repeat did not hold |

Pool threshold sweep:

| Candidate | Result | Decision |
|---|---|---|
| Adaptive pool with `minHotnessForPool=1` | Won 10/16 rows at 15s x 32, but only 7/16 at 10s x 128 | rejected as balanced default; too concurrency-sensitive |
| Adaptive pool with `minHotnessForPool=4` | Won 11/16 rows vs `min=1` at 15s x 32 and 11/16 rows vs `min=1` at 10s x 128 | accepted for fast lab profile |

Post-tuning competitor checkpoint (`BENCH_PAYLOAD=1k`, 15s, concurrency 32):

| Variant | req/s | p90 | p95 | p99 | Errors |
|---|---:|---:|---:|---:|---:|
| `xray-xray-tcp` | 17,564 | 0.0027 | 0.0031 | 0.0041 | 0 |
| `xray-bw-compat-tcp` | 11,816 | 0.0038 | 0.0043 | 0.0055 | 0 |
| `xray-bw-fast-tcp` | 14,586 | 0.0032 | 0.0036 | 0.0046 | 0 |
| `singbox-singbox-tcp` | 17,569 | 0.0027 | 0.0030 | 0.0039 | 0 |
| `singbox-bw-compat-tcp` | 11,756 | 0.0038 | 0.0043 | 0.0056 | 0 |
| `singbox-bw-fast-tcp` | 16,965 | 0.0028 | 0.0031 | 0.0041 | 0 |

Validation:

- `cargo run -q -p blackwire -- test -c labs/realistic/latency/configs/blackwire-fast-lab-server.json`: PASS.
- Native VPS runs showed no timeout/error distribution blocks for the accepted
  tuning.

Linux/VPS flamegraphs:

```bash
make bench-flamegraph PROTO=vless_tcp SCENARIO=bulk
make bench-flamegraph PROTO=trojan_tcp SCENARIO=bulk
make bench-flamegraph PROTO=vless_ws SCENARIO=bulk
make bench-flamegraph PROTO=vless_tcp SCENARIO=short
```

Artifacts were pulled to `benches/reports/flamegraphs/vps-20260530/`.

| Scenario | Main signal | Decision |
|---|---|---|
| `vless_tcp bulk` | syscall/splice/io worker path dominates; dispatch marker below 0.1% | keep relay/splice as primary target |
| `trojan_tcp bulk` | syscall/splice/io worker path dominates; dispatch marker below 0.1% | same as VLESS TCP |
| `vless_ws bulk` | socket send path dominates; splice is irrelevant because WS is wrapped | future WS work should target write/framing behavior, not raw splice |
| `vless_tcp short` | scheduler/syscall cost dominates short-session profile | investigate task/connect setup with concurrency data before changing boundaries |

Scheduler/task-boundary audit:

- TCP accepts still require one per-connection task so a slow connection cannot
  block the accept loop. Existing SO_REUSEPORT accept sharding remains the safer
  high-connection-rate scaling mechanism.
- No task-boundary rewrite was accepted in this pass. Flamegraphs did not show a
  standalone spawn/dispatch frame large enough to justify merging accept,
  dispatch, connect, or relay setup boundaries.

Dispatch abstraction audit:

- `async_trait` and dynamic dispatch remain in the shared dispatcher and handler
  interfaces, but the Linux profiles show dispatch markers below 1% in the
  checked paths.
- Decision: do not refactor protocol/handler traits in this phase. Revisit only
  if a focused dispatch benchmark or future flamegraph makes it a shared
  hotspot.

Observability audit:

- Fast Profile already demotes per-connection relay lifecycle logs to `debug`
  through `relay_log!`, while Compat keeps `info` logs for operator visibility.
- Metrics for connect, route, relay path, pool, and errors are intentionally
  kept. They did not appear as a dominant flamegraph cost in the checked paths.
- Decision: no metrics/logging removal in this pass; keep observability intact
  until a dedicated disabled-recorder benchmark proves a material cost.

## VLESS WebSocket direct-frame candidate (2026-05-30)

Linux flamegraph signal: `vless_ws bulk` is dominated by socket send/write
work, while raw TCP splice is irrelevant because WebSocket streams are wrapped.

Candidate: keep the existing 4 KiB WebSocket coalescing buffer for small writes,
but bypass it for writes of 16 KiB or larger and emit those writes as one
WebSocket binary frame. This targets the relay fallback's 16 KiB copy chunks
without increasing the per-stream buffer used by short-lived/small flows.

Local evidence:

| Variant | Bulk median | Bulk throughput | Small/concurrency signal | Decision |
|---|---:|---:|---|---|
| 4 KiB baseline | 329.58 us | 189.64 MiB/s | fanout 1/8/32: 6.67 ms / 4.79 ms / 5.67 ms | baseline |
| Fixed 16 KiB buffer | 187.62 us | 333.12 MiB/s | larger buffer for every stream; fanout 8/32 showed slower ranges in the full quick run | rejected as broad default |
| Fixed 8 KiB buffer | 238.20 us | 262.39 MiB/s | fanout 8/32 stayed within noise vs baseline; still grows every stream | rejected in favor of direct-frame candidate |
| Direct large frame, 4 KiB buffer | 244.87 us; repeat 289.76 us | 255.24 MiB/s; repeat 215.69 MiB/s | mixed/short/concurrency repeats stayed within Criterion noise; no test failures | locally promoted |

Commands/logs:

```bash
BENCH_QUICK=1 BENCH_BULK_ONLY=1 cargo bench -p blackwire-benches --bench e2e_vless_ws -- bulk_relay/steady_state/chunk_65536/65536 --quick
BENCH_QUICK=1 cargo bench -p blackwire-benches --bench e2e_vless_ws -- concurrency --quick
BENCH_QUICK=1 cargo bench -p blackwire-benches --bench e2e_vless_ws -- mixed_small_writes --quick
BENCH_QUICK=1 cargo bench -p blackwire-benches --bench e2e_vless_ws -- short_lived --quick
cargo test -p blackwire-transport ws_ --quiet
cargo test -p blackwire-transport --test production_readiness websocket --quiet
```

- 4 KiB repeat logs: `benches/reports/ws-buffer-4k-repeat-bulk-20260530.log`,
  `benches/reports/ws-buffer-4k-repeat-concurrency-20260530.log`
- 8 KiB logs: `benches/reports/ws-buffer-8k-bulk-20260530.log`,
  `benches/reports/ws-buffer-8k-concurrency-20260530.log`
- 16 KiB logs: `benches/reports/ws-buffer-after-20260530.log`,
  `benches/reports/ws-buffer-full-after-20260530.log`
- direct-frame logs: `benches/reports/ws-direct-frame-bulk-20260530.log`,
  `benches/reports/ws-direct-frame-bulk-repeat-20260530.log`,
  `benches/reports/ws-direct-frame-concurrency-20260530.log`,
  `benches/reports/ws-direct-frame-mixed-20260530.log`,
  `benches/reports/ws-direct-frame-mixed-repeat-20260530.log`,
  `benches/reports/ws-direct-frame-short-20260530.log`

Status: accepted for local promotion only. Final acceptance still requires a
native VPS WebSocket comparison row because the current latency lab matrix is
TCP-only.

Native VPS WebSocket gate:

- Added `ws-compare` and `ws-matrix` latency lab scenarios with Xray and
  sing-box same-client WebSocket baselines plus Blackwire WS server rows.
- Blackwire WS rows use Compat profile because Fast Profile intentionally
  rejects WebSocket as a production fast-profile transport. The freedom outbound
  still uses explicit adaptive pool settings for lab parity.
- Fixed `run-bench.sh` envsubst temp-file creation on macOS/BSD `mktemp`; the
  previous template could fail during dry runs before any benchmark started.

VPS smoke (`64k`, keepalive on, 5s x 8, native nginx upstream):

| Variant | req/s | p90 | p95 | p99 | Errors |
|---|---:|---:|---:|---:|---:|
| `xray-xray-ws` | 4,123 | 0.0028 | 0.0031 | 0.0040 | 0 |
| `xray-bw-ws` | 4,526 | 0.0025 | 0.0029 | 0.0037 | 0 |
| `singbox-singbox-ws` | 7,343 | 0.0016 | 0.0018 | 0.0023 | 0 |
| `singbox-bw-ws` | 6,222 | 0.0019 | 0.0021 | 0.0028 | 0 |

VPS matrix (`1k`, `4k`, `16k`, `64k`; keepalive on/off; 10s x 32):

- All rows completed with `0` errors and `0` non-200 responses.
- Blackwire WS beat Xray WS on req/s for `1k` no-keepalive, `16k`
  keepalive/no-keepalive, and `64k` keepalive/no-keepalive.
- Blackwire WS trailed sing-box WS on larger keepalive rows, especially `16k`
  and `64k`, so WS bulk still has room for a deeper framed relay path.

Focused before/after control (`16k`, `64k`; keepalive on/off; 5s x 32):

| Row | req/s change | p99 change | Decision |
|---|---:|---:|---|
| `xray-bw-ws 16k ka` | +1.1% | -1.0% | neutral/slightly better |
| `xray-bw-ws 16k noka` | -1.4% | +2.6% | neutral/slightly worse |
| `xray-bw-ws 64k ka` | +1.3% | -1.3% | neutral/slightly better |
| `xray-bw-ws 64k noka` | +1.0% | -4.5% | neutral/slightly better |
| `singbox-bw-ws 16k ka` | +3.4% | -4.4% | better |
| `singbox-bw-ws 16k noka` | -1.9% | +1.5% | neutral/slightly worse |
| `singbox-bw-ws 64k ka` | +3.0% | -3.0% | better |
| `singbox-bw-ws 64k noka` | +18.8% | -13.6% | accepted win |

Decision: keep the direct-large-frame candidate. It has one clear VPS win,
several small positive rows, two small negative no-keepalive rows, and no
errors/non-200s. Do not claim broad WS victory over sing-box; use this as a
low-risk transport improvement and continue with a WS-aware relay/framing
investigation if larger WS gains are required.

Additional VPS confidence checks:

| Gate | Variant | req/s | p90 | p95 | p99 | Errors |
|---|---|---:|---:|---:|---:|---:|
| `64k`, 10s x 128, ka | `xray-xray-ws` | 4,047 | 0.0455 | 0.0517 | 0.0731 | 0 |
| `64k`, 10s x 128, ka | `xray-bw-ws` | 2,794 | 0.0616 | 0.0667 | 0.0784 | 0 |
| `64k`, 10s x 128, noka | `xray-xray-ws` | 1,482 | 0.1169 | 0.1280 | 0.1481 | 0 |
| `64k`, 10s x 128, noka | `xray-bw-ws` | 1,507 | 0.1108 | 0.1198 | 0.1379 | 0 |
| `64k`, 10s x 128, ka | `singbox-singbox-ws` | 8,107 | 0.0244 | 0.0280 | 0.0379 | 0 |
| `64k`, 10s x 128, ka | `singbox-bw-ws` | 3,351 | 0.0509 | 0.0560 | 0.0676 | 0 |
| `64k`, 10s x 128, noka | `singbox-singbox-ws` | 2,105 | 0.0823 | 0.0900 | 0.1045 | 0 |
| `64k`, 10s x 128, noka | `singbox-bw-ws` | 1,421 | 0.1178 | 0.1278 | 0.1489 | 0 |
| `64k`, 30s x 32, ka | `xray-xray-ws` | 4,123 | 0.0117 | 0.0133 | 0.0168 | 0 |
| `64k`, 30s x 32, ka | `xray-bw-ws` | 2,764 | 0.0175 | 0.0198 | 0.0245 | 0 |
| `64k`, 30s x 32, noka | `xray-xray-ws` | 1,404 | 0.0316 | 0.0351 | 0.0423 | 0 |
| `64k`, 30s x 32, noka | `xray-bw-ws` | 1,492 | 0.0290 | 0.0318 | 0.0375 | 0 |
| `64k`, 30s x 32, ka | `singbox-singbox-ws` | 7,973 | 0.0059 | 0.0066 | 0.0084 | 0 |
| `64k`, 30s x 32, ka | `singbox-bw-ws` | 3,547 | 0.0135 | 0.0154 | 0.0194 | 0 |
| `64k`, 30s x 32, noka | `singbox-singbox-ws` | 2,006 | 0.0216 | 0.0237 | 0.0279 | 0 |
| `64k`, 30s x 32, noka | `singbox-bw-ws` | 1,601 | 0.0263 | 0.0285 | 0.0330 | 0 |

Confidence-check decision: keep the candidate, but classify it as a narrow
improvement rather than a broad WS parity fix. At higher concurrency and longer
duration Blackwire WS still trails sing-box WS keepalive/bulk rows. Blackwire
WS is competitive with Xray no-keepalive rows and remains error-free.

## Strict Native Server Gate Bootstrap (2026-05-30)

Purpose: first run of the strict native server gate added for broad server
performance work. This validates the gate/reporting path before selecting the
next optimization candidate. Private host/IP values are intentionally omitted.

Environment:

- Native Blackwire/Xray/sing-box/hey on the client VPS.
- Native nginx upstream on a separate VPS, listening on `:18080`.
- Docker and Python were not traffic participants; Python was used only for
  local report rendering.
- nginx preflight verified `/1k`, `/4k`, `/16k`, and `/64k` exact byte sizes.

Setup notes:

- Both VPS hosts had native nginx configured with fixed-size payload files.
- UFW was active and initially blocked `:18080`; opening `18080/tcp` was
  required before the strict preflight could pass.
- The passing benchmark direction was used for the gate; the reverse direction
  remained unavailable and was not used for performance claims.

Smoke gate:

```bash
BENCH_DURATION=5 BENCH_CONC=32 BENCH_CONCS=32 \
BENCH_PAYLOADS="1k 64k" BENCH_KEEPALIVE_MODES="on off" \
VPS_SCENARIO=server-gate-smoke make -C labs/realistic latency-vps
```

- Rows produced: `40/40`.
- Upstream label: `native-nginx`.
- Invalid/noisy rows were correctly marked `FAIL` by the report due to request
  errors or `hey` total duration far beyond the requested window.
- The invalid set was mostly no-keepalive and WS rows; do not optimize against
  those rows until they repeat cleanly.

Targeted repeat:

```bash
BENCH_DURATION=15 BENCH_CONC=32 BENCH_CONCS=32 \
BENCH_PAYLOADS=1k BENCH_KEEPALIVE_MODES=on \
VPS_SCENARIO=server-gate-smoke make -C labs/realistic latency-vps
```

All repeated `1k` keepalive rows completed with `0` errors and `0` non-200
responses:

| Variant | req/s | p50 | p95 | p99 | Decision |
|---|---:|---:|---:|---:|---|
| `xray-xray-tcp-1k-ka` | 19,294 | 1.60 ms | 2.70 ms | 3.50 ms | baseline |
| `xray-bw-compat-tcp-1k-ka` | 16,543 | 1.90 ms | 3.00 ms | 3.80 ms | gap: -14.3% req/s, +8.6% p99 |
| `xray-bw-fast-tcp-1k-ka` | 21,821 | 1.40 ms | 2.40 ms | 3.10 ms | win/no repeat concern |
| `singbox-singbox-tcp-1k-ka` | 18,631 | 1.70 ms | 2.80 ms | 3.50 ms | baseline |
| `singbox-bw-compat-tcp-1k-ka` | 13,920 | 2.20 ms | 3.50 ms | 4.50 ms | gap: -25.3% req/s, +28.6% p99 |
| `singbox-bw-fast-tcp-1k-ka` | 19,179 | 1.60 ms | 2.70 ms | 3.50 ms | near parity / needs repeat |
| `xray-xray-ws-1k-ka` | 18,074 | 1.70 ms | 2.90 ms | 3.70 ms | baseline |
| `xray-bw-ws-1k-ka` | 17,083 | 1.80 ms | 3.00 ms | 3.80 ms | small gap |
| `singbox-singbox-ws-1k-ka` | 19,357 | 1.60 ms | 2.70 ms | 3.50 ms | baseline |
| `singbox-bw-ws-1k-ka` | 17,711 | 1.80 ms | 2.80 ms | 3.60 ms | small gap |

Decision:

- Do not treat the short 5s no-keepalive and failing WS rows as optimization
  truth yet.
- The strongest clean server gap is **Compat TCP 1k keepalive**, especially
  `singbox-bw-compat-tcp-1k-ka`.
- Fast TCP is not the immediate target for `1k` keepalive; it matched or beat
  same-client baselines in this repeat.
- Next candidate should inspect shared Compat overhead before outbound relay:
  accept/dispatch/config path differences between Compat and Fast, connection
  setup instrumentation, and any Compat-only observability or wrapper cost.

Accepted candidate: adaptive splice for Compat profile.

Source change:

- `DefaultDispatcher` now uses adaptive splice for Compat profile instead of
  forcing splice immediately on every raw TCP relay.
- Fast profile behavior is unchanged: it still honors `fast.splice`.
- Rationale: the clean gap was small-response Compat TCP. Forcing splice before
  enough bytes have accumulated adds avoidable syscall/pipe overhead.

Validation:

```bash
cargo test -p blackwire-app dispatcher --quiet
cargo test -p blackwire-app --quiet
cargo test --workspace --all-targets
```

- All listed tests passed.
- `cargo fmt --all --check` was not used as an acceptance signal because
  unrelated pre-existing formatting drift exists outside this change; the
  touched dispatcher file was formatted with the workspace edition.

Config-only probe before source change (`1k`, keepalive on, 15s x 32):

| Variant | req/s change | p99 change | Errors | Decision |
|---|---:|---:|---:|---|
| `xray-bw-compat-tcp-1k-ka` | +14.2% | -10.5% | 0 | promote to source test |
| `singbox-bw-compat-tcp-1k-ka` | +43.3% | -24.4% | 0 | promote to source test |

Source candidate repeat (`1k`, keepalive on, 15s x 32):

| Variant | Baseline req/s | Candidate req/s | Repeat req/s | Baseline p99 | Candidate p99 | Repeat p99 | Decision |
|---|---:|---:|---:|---:|---:|---:|---|
| `xray-bw-compat-tcp-1k-ka` | 16,543 | 19,670 | 19,603 | 3.80 ms | 3.50 ms | 3.40 ms | accepted |
| `singbox-bw-compat-tcp-1k-ka` | 13,920 | 21,592 | 19,402 | 4.50 ms | 3.10 ms | 3.40 ms | accepted |

Regression probe (`64k`, keepalive on):

| Variant | Baseline | Candidate | Repeat | Decision |
|---|---|---|---|---|
| `xray-bw-compat-tcp-64k-ka` | 9,664 req/s, 6.40 ms p99 | 9,436 req/s, 7.10 ms p99 | 9,986 req/s, 6.70 ms p99 | neutral after repeat |
| `singbox-bw-compat-tcp-64k-ka` | 9,674 req/s, 6.40 ms p99 | 10,664 req/s, 6.10 ms p99 | 11,331 req/s, 5.80 ms p99 | accepted win |

Decision: accepted. This narrows the clean Compat TCP gap without errors or
non-200s. Do not claim a WS improvement from this change; wrapped WS rows do
not use raw TCP splice and observed WS movement is treated as run noise.

Post-commit subset gate:

```bash
BENCH_DURATION=5 BENCH_CONC=32 BENCH_CONCS="1 8 128" \
BENCH_PAYLOADS="1k 64k" BENCH_KEEPALIVE_MODES="on off" \
VPS_SCENARIO=server-gate-smoke make -C labs/realistic latency-vps
```

- Rows produced: `120/120`.
- Invalid/noisy rows: `7`, including competitor baseline rows with request
  errors or `hey` total duration far beyond the requested window. These rows
  were not used for acceptance.
- Scope note: this is the candidate subset gate, not the full 320-row gate.

Valid TCP Compat subset summary:

| Row | Result |
|---|---|
| Xray `1k ka`, concurrency `1/8/128` | win / near parity / win |
| Xray `1k noka`, concurrency `1/8/128` | win / mixed / mixed |
| Xray `64k ka`, concurrency `1/8/128` | win / mixed / win |
| Xray `64k noka`, concurrency `1/8/128` | win / win / mixed |
| sing-box `1k ka`, concurrency `1/8/128` | mixed / win / win |
| sing-box `1k noka`, concurrency `1/8/128` | skipped: competitor baseline invalid |
| sing-box `64k ka`, concurrency `1/8/128` | skipped invalid baseline at `1`; win / win at `8/128` |
| sing-box `64k noka`, concurrency `1/8/128` | skipped invalid baseline at `1`; win at `8`; gap at `128` |

Notable valid rows:

| Row | Blackwire Compat | Same-client baseline | Decision |
|---|---:|---:|---|
| `xray-bw-compat-tcp-1k-ka c128` | 23,046 req/s, 12.4 ms p99 | 16,870 req/s, 16.9 ms p99 | win |
| `xray-bw-compat-tcp-64k-noka c8` | 2,310 req/s, 6.3 ms p99 | 1,627 req/s, 9.8 ms p99 | win |
| `singbox-bw-compat-tcp-1k-ka c128` | 20,562 req/s, 13.8 ms p99 | 17,610 req/s, 16.1 ms p99 | win |
| `singbox-bw-compat-tcp-64k-noka c128` | 2,384 req/s, 91.8 ms p99 | 2,527 req/s, 91.5 ms p99 | remaining gap |

Decision after subset: keep the adaptive-splice Compat change. It improves or
matches most valid TCP Compat subset rows and has one remaining valid gap at
`singbox-bw-compat-tcp-64k-noka c128`. That row should be monitored in the full
gate, but it does not outweigh the repeated clean `1k` keepalive win and broad
Xray Compat improvements.

Follow-up repeat for the remaining `singbox-bw-compat-tcp-64k-noka c128` gap:

```bash
BENCH_DURATION=15 BENCH_CONC=128 BENCH_CONCS=128 \
BENCH_PAYLOADS=64k BENCH_KEEPALIVE_MODES=off \
VPS_SCENARIO=server-gate-smoke make -C labs/realistic latency-vps
```

- The row did not repeat cleanly.
- sing-box native TCP baseline failed with `229` request errors.
- sing-box to Blackwire Compat TCP failed with `129` request errors.
- sing-box to Blackwire Fast TCP failed with `12` request errors.
- Xray TCP rows in the same repeat stayed clean; `xray-bw-compat-tcp-64k-noka
  c128` beat `xray-xray-tcp-64k-noka c128` on req/s and p99 in that repeat.

Decision: mark the sing-box TCP `64k` no-keepalive concurrency `128` row
`NEEDS_REPEAT`/invalid for now. Do not optimize against it until the client
baseline is stable.

Rejected candidate: raise the TCP listener backlog from `128` to `1024`.

- Targeted native VPS subset: `64k`, no keepalive, concurrency `128`, `15s`.
- It did not clear the high-concurrency Fast Profile failures.
- `xray-bw-fast-tcp-64k-noka c128` still had request timeouts.
- `singbox-bw-fast-tcp-64k-noka c128` improved to zero errors in this run, but
  `singbox-bw-compat-tcp-64k-noka c128` still had request errors and the
  sing-box native TCP baseline was invalid with timeouts.

Decision: rejected. Do not accept a mixed backlog-only change; continue with
Fast Profile pool isolation because the failure shape is specific to Fast TCP
under bursty no-keepalive load.

Accepted candidate: make Fast Profile Freedom preconnect pooling opt-in and
disable it in the default Fast latency-lab server.

Config-only isolation changed the Fast lab server from adaptive Freedom pooling
to `pool: disabled` while keeping adaptive splice:

```bash
BENCH_DURATION=15 BENCH_CONC=128 BENCH_PAYLOADS=64k \
BENCH_KEEPALIVE_MODES=off VPS_SCENARIO=fast-only-matrix \
make -C labs/realistic latency-vps
```

Targeted native VPS result for `64k` no-keepalive concurrency `128`:

| Row | With adaptive pool | Pool disabled | Decision |
|---|---:|---:|---|
| `xray-bw-fast-tcp-64k-noka c128` | 767 req/s, 104.5 ms p99, 24 errors | 2,752 req/s, 81.6 ms p99, 0 errors | accept |
| `singbox-bw-fast-tcp-64k-noka c128` | 2,351 req/s, 91.8 ms p99, 0 errors | 2,895 req/s, 77.3 ms p99, 0 errors | accept |

Follow-up Fast-only subset at concurrency `32` with payloads `1k 64k` and
keepalive on/off also stayed clean with zero errors/timeouts/non-200s:

| Row | Pool disabled |
|---|---:|
| `xray-bw-fast-tcp-1k-ka c32` | 19,731 req/s, 3.5 ms p99 |
| `singbox-bw-fast-tcp-1k-ka c32` | 21,004 req/s, 3.3 ms p99 |
| `xray-bw-fast-tcp-64k-noka c32` | 2,282 req/s, 25.7 ms p99 |
| `singbox-bw-fast-tcp-64k-noka c32` | 2,735 req/s, 20.2 ms p99 |

Decision: accept. Pooling remains available through explicit config and
`blackwire-fast-lab-server-pooled.json`, but the default Fast Profile and the
trusted Fast lab gate no longer enable it until a future pool-specific change
can prove stable cold/warm/stale behavior.

Post-change verification of the exact patch on the same native VPS subset:

| Row | Result |
|---|---:|
| `xray-bw-fast-tcp-64k-noka c128` | 2,763 req/s, 79.9 ms p99, 0 errors |
| `singbox-bw-fast-tcp-64k-noka c128` | 2,604 req/s, 82.0 ms p99, 0 errors |

## Rejected WS Relay Buffer Growth Candidate (2026-05-30)

Candidate: grow the shared pooled relay buffer from `16 KiB` to `64 KiB` after
repeated large reads, so framed transports can emit larger WebSocket frames on
bulk flows without changing protocol wire format.

Local quick filter:

- `vless_ws bulk_relay/chunk_65536`: throughput improved by roughly `+22%`
  in Criterion quick mode.
- `vless_ws mixed_small_writes`: no statistically significant regression in
  quick mode; several rows moved positive.

VPS A/B gate:

- Environment: native Blackwire/Xray/sing-box processes with native nginx
  upstream. Host values redacted.
- Control: committed baseline `a817df7`.
- Candidate logs:
  - `labs/realistic/latency/reports/ws-relay-control-vps-20260530.log`
  - `labs/realistic/latency/reports/ws-relay-largeread-vps-20260530.log`
- Matrix: `1k`, `64k`; keepalive on/off; `5s x 32`.
- All rows completed with `0` errors and `0` non-200 responses.

Blackwire-server A/B rows:

| Row | Control req/s | Candidate req/s | Req/s change | Control p99 | Candidate p99 | Decision |
|---|---:|---:|---:|---:|---:|---|
| `xray-bw-ws 1k ka` | 17,203 | 17,961 | +4.4% | 0.0041 | 0.0036 | better |
| `xray-bw-ws 1k noka` | 2,207 | 2,301 | +4.3% | 0.0266 | 0.0249 | better |
| `xray-bw-ws 64k ka` | 5,267 | 6,060 | +15.0% | 0.0125 | 0.0110 | better |
| `xray-bw-ws 64k noka` | 2,027 | 1,588 | -21.7% | 0.0266 | 0.0350 | reject |
| `singbox-bw-ws 1k ka` | 17,811 | 13,564 | -23.8% | 0.0037 | 0.0049 | reject |
| `singbox-bw-ws 1k noka` | 2,270 | 2,164 | -4.7% | 0.0229 | 0.0238 | worse |
| `singbox-bw-ws 64k ka` | 6,557 | 7,386 | +12.6% | 0.0101 | 0.0093 | better |
| `singbox-bw-ws 64k noka` | 1,889 | 1,878 | -0.6% | 0.0273 | 0.0278 | neutral/slightly worse |

Decision: rejected. The bulk keepalive wins are real, but the candidate fails
the no-regression gate because it hurts Xray-client `64k` no-keepalive and
sing-box-client `1k` keepalive. Do not reintroduce generic relay-buffer growth
without a stronger classifier, such as per-direction observed frame/body size or
a transport-specific path that avoids small keepalive growth.

Additional local-only rejected WS micro-candidates:

- Tungstenite eager writes via `WebSocketConfig::write_buffer_size(0)`:
  `vless_ws bulk_relay/chunk_65536` regressed roughly `-10%` throughput in
  Criterion quick mode. Rejected before VPS.
- Replacing `Bytes::split_to` with `Bytes::advance` on WS reads:
  local quick rows regressed for both bulk and mixed-small paths. Rejected
  before VPS.
- Keeping the small WS write buffer allocation across flushes with
  `Bytes::copy_from_slice` plus `BytesMut::clear`: some larger mixed-small rows
  moved positive, but the bulk row regressed roughly `-18%`. Rejected before
  VPS.

## Latest serial quick verification (2026-05-26)

Command shape:

```bash
BENCH_QUICK=1 BENCH_BULK_ONLY=1 BENCH_ITER_TIMEOUT_MS=20000 BENCH_IO_TIMEOUT_MS=3000 \
  cargo bench -p blackwire-benches --bench e2e_<path> -- bulk_relay/steady_state/chunk_65536/65536 --quick
```

- `ss2022`: time `[2.2002 ms 2.2964 ms 2.3204 ms]`, thrpt `[26.935 MiB/s 27.217 MiB/s 28.406 MiB/s]`
- `vmess_grpc`: time `[2.3214 ms 2.3412 ms 2.3461 ms]`, thrpt `[26.639 MiB/s 26.696 MiB/s 26.924 MiB/s]`

Both paths completed without relay stalls after stream progress fixes.

## Shared-path batch (2026-05-31)

Commit scope:

- `crates/blackwire-transport/src/tcp.rs`
  - move listener buffer sizing to bind path (inherited by accepted sockets)
  - enforce connection-limit admission before per-connection socket tuning
- `crates/blackwire-app/src/dispatcher.rs`
  - reduce pooled first-write guard timeout `5ms -> 2ms`
  - replace per-connection heap guard buffer with fixed small stack buffer
- `crates/blackwire-protocol/src/freedom.rs`
  - remove duplicate hotness lock/estimate in pooled connect path

VPS median gate (3 runs, `gate-matrix`, `BENCH_DURATION=5`, `BENCH_CONCS=32`,
payloads `1k 64k`, keepalive `on off`, upstream `native nginx` on localhost):

- `xray-bw-fast-tcp-1k-ka`: `16291.3 req/s` vs `xray-xray-tcp-1k-ka` `15083.1` (`+8.0%`)
- `xray-bw-fast-tcp-1k-noka`: `2949.0` vs `575.6` (`+412.3%`)
- `xray-bw-fast-tcp-64k-ka`: `8861.1` vs `8533.6` (`+3.8%`)
- `xray-bw-fast-tcp-64k-noka`: `2281.5` vs `2064.7` (`+10.5%`)
- xray rows median errors: `0`

Known instability remained in sing-box no-keepalive baselines on this VPS
(`singbox->singbox` showed median errors), so sing-box noka rows are kept as
`NEEDS_REPEAT` for cross-client final claims.

Decision: accepted for shared-path progression under xray-focused gate; keep
sing-box noka as a separate stability follow-up.

## Shared-path accept-loop cut (2026-05-31)

Commit: `a2522cb`

Change:

- `crates/blackwire-transport/src/tcp.rs`
  - move accepted socket option tuning (`apply_socket_opts`) from the accept
    loop into the per-connection task after admission.
  - goal: keep accept loop focused on accept + limit checks under load.

VPS subset (`gate-matrix`, `5s`, `c32`, payloads `1k 64k`, keepalive `on off`,
upstream `127.0.0.1:18080` native nginx):

- `xray-bw-fast-tcp-1k-ka`: `18523.4` vs `xray-xray` `15135.0`
- `xray-bw-fast-tcp-1k-noka`: `2809.5` vs `xray-xray` `2562.5`
- `xray-bw-fast-tcp-64k-ka`: `8593.4` vs `xray-xray` `8140.7`
- `xray-bw-fast-tcp-64k-noka`: `2409.4` vs `xray-xray` `1998.7`
- xray rows errors: `0`

Decision: accepted in shared-path cycle (xray stable lanes improved). Sing-box
no-keepalive baseline remained unstable on this host and is tracked separately.
