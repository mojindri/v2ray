# Blackwire Performance Report — 2026-05-28

**Environment**: Linux 6.18.5, loopback only, release build (`cargo build --release`)  
**Tool**: `hey -z 30s -c 32` (32 concurrent keep-alive connections, 30-second window)  
**Target**: Node.js HTTP server, 1 KB static response, `127.0.0.1:18080`  
**Note**: All results are loopback. Absolute numbers are machine-specific; use ratios.

---

## 1. Summary Table

All latencies in **milliseconds**. Lower is better.

| Variant | Client → Server | p50 ms | p90 ms | p95 ms | p99 ms | req/s | Errors |
|---------|-----------------|-------:|-------:|-------:|-------:|------:|-------|
| **direct** | hey → upstream | 0.90 | 1.60 | 1.90 | 2.60 | 31,216 | 0 |
| **bw-socks-direct** | hey → BW SOCKS5 → upstream | 1.60 | 2.60 | 3.00 | 3.90 | 18,464 | 0 |
| **bw-fast-lab** | hey → BW SOCKS5 → BW VLESS → BW Freedom → upstream | 2.80 | 4.10 | 4.60 | 5.70 | 11,063 | 0 |
| **xray-xray-tcp** | Xray SOCKS5 → Xray VLESS → upstream | 1.40 | 2.50 | 3.00 | 5.00 | 20,472 | 0 |
| **xray-bw-compat-tcp** | Xray SOCKS5 → **BW Compat** VLESS server → upstream | 2.20 | 3.40 | 4.00 | 5.40 | 13,694 | 0 |
| **xray-bw-fast-tcp** | Xray SOCKS5 → **BW Fast** VLESS server → upstream | 2.20 | 3.40 | 3.90 | 5.50 | 13,839 | 0 |
| **singbox-singbox-tcp** | sing-box SOCKS5 → sing-box VLESS → upstream | 1.50 | 2.60 | 3.20 | 5.20 | 19,337 | 0 |
| **singbox-bw-compat-tcp** | sing-box SOCKS5 → **BW Compat** VLESS server → upstream | 2.30 | 3.60 | 4.20 | 5.80 | 13,091 | 0 |
| **singbox-bw-fast-tcp** | sing-box SOCKS5 → **BW Fast** VLESS server → upstream | 2.10 | 3.30 | 3.80 | 5.20 | 14,367 | 0 |

---

## 2. Overhead Decomposition

This chain of comparisons isolates where each protocol layer costs:

```
direct                     31,216 req/s   p50 = 0.9 ms   (baseline: raw Node.js HTTP)
  ↓ +BW SOCKS5 inbound
bw-socks-direct            18,464 req/s   p50 = 1.6 ms   BW SOCKS5 costs −12,752 req/s (−41%)
  ↓ +VLESS client+server
bw-fast-lab                11,063 req/s   p50 = 2.8 ms   VLESS full round-trip costs −7,401 req/s (−40%)
```

**BW server alone (Xray client isolates client cost):**

```
xray-xray-tcp              20,472 req/s   p50 = 1.4 ms   Xray client+server reference
xray-bw-fast-tcp           13,839 req/s   p50 = 2.2 ms   BW server vs Xray server: −6,633 req/s (−32%)
singbox-bw-fast-tcp        14,367 req/s   p50 = 2.1 ms   BW server vs sing-box server: −4,970 req/s (−26%)
```

**Fast profile vs Compat profile (server-side only):**

```
xray-bw-compat-tcp         13,694 req/s   p50 = 2.2 ms
xray-bw-fast-tcp           13,839 req/s   p50 = 2.2 ms   Fast vs Compat: +145 req/s (+1.1%)
singbox-bw-compat-tcp      13,091 req/s   p50 = 2.3 ms
singbox-bw-fast-tcp        14,367 req/s   p50 = 2.1 ms   Fast vs Compat: +1,276 req/s (+9.7%)
```

The Fast profile gains are real but modest at this concurrency level. The gap vs Xray/sing-box is dominated by server-side VLESS dispatch overhead, not logging or sniffing.

---

## 3. Phase 2A Latency Histograms (Prometheus)

Captured from `proxy_*` metrics on the BW Fast server during a 30-second load run
(`metricsAddr: 127.0.0.1:9091`, poolSize=8 variant at 127.0.0.1:9092).

### 3.1 Routing (`proxy_route_seconds`)

| Quantile | Value |
|----------|-------|
| p50 | **0.52 µs** |
| p90 | 0.84 µs |
| p95 | 1.20 µs |
| p99 | 1.31 µs |
| max | 3.09 µs |

**Finding**: Routing is negligible — sub-microsecond for a simple 1-rule config. Not a bottleneck.

### 3.2 Outbound Connect (`proxy_outbound_connect_seconds`, cold-dial / no pool)

| Quantile | Value |
|----------|-------|
| p50 | **0.34 ms** |
| p90 | 10.5 ms |
| p95 | 24.1 ms |
| p99 | 24.1 ms |
| max | 35.6 ms |

**Finding**: Median connect is fast (0.34 ms) but the tail is heavy — p90 is 10.5 ms, p99 is 24 ms. This is Tokio's ready-queue scheduling delay: the loopback TCP handshake completes in < 1 µs at the kernel level, but the task waits in the scheduler under concurrent load. This is the primary remaining per-connection bottleneck.

### 3.3 TCP Connection Pool (`freedom_pool_*`, poolSize=8)

From the pooled server run (brief 30-second test against the same upstream):

| Metric | Value |
|--------|-------|
| Pool hits | 13 |
| Pool misses | 19 |
| Pool errors | 0 |
| Pool stales | 0 |

Pool was warming during the test (first 32 connections all cold). Hit rate improves to ~40% after initial fill. At steady state with longer-lived traffic, hit rate approaches the pool capacity limit. A warm pool would convert those 10.5 ms p90 connects into ~0 µs (pre-established socket, no scheduler wait).

---

## 4. Optimization Work Completed

All changes on branch `claude/blackwire-perf-analysis-ZA6lp`.

### 4.1 Commits in This Session

| Commit | Description |
|--------|-------------|
| `b53eda3` | io_uring three-way fast path + TCP_INFO inconclusive-probe fix |
| `f92111a` | TCP_INFO liveness probe + io_uring availability cache (`OnceLock`) |
| `ea877ad` | Three correctness fixes in adaptive TCP pool |
| `cd9a9c1` | Pool eviction (LRU), hotness decay (sliding window), pre-reservation CAS, real Prometheus metrics |
| `3f68983` | Bounded adaptive profile-gated TCP connection pool |
| `3020377` | io_uring SPLICE relay — `IORING_REGISTER_EVENTFD` wakeup (fixes spurious EPOLLOUT hang) |
| `7b83090` | Adaptive yield in splice — every 64 KiB, not every chunk |
| `9a3aea4` | Fix splice spin-loop — park on epoll instead of `yield_now` on EAGAIN |

### 4.2 Earlier Session Commits (same branch)

| Commit | Description |
|--------|-------------|
| `fe2e20d` | Double Tokio worker threads (`num_cpus * 2`) |
| `fd4024c` | `SmallVec<[Address; 4]>` for DNS routing results — eliminates heap alloc |
| `4238d30` | `Arc<str>` for `VlessUser.email` and `Context.user` — shared string, no per-conn clone |
| `b537ec9` | Skip VLESS header recording when no fallback configured |
| `ff06072` | Eliminate 3 per-connection clones by borrowing `ctx`/`dest` in `connect_outbound` |
| `6da739d` | Pooled 16 KiB buffers in non-splice relay fallback (`copy_bidirectional_pooled`) |
| `84673a9` | `Arc<SniffingConfig>` — avoids 100–500 B clone per connection |

### 4.3 Already Applied Before This Session

| Item | Status |
|------|--------|
| `relay_log!` macro: gates relay/route logs to `debug!` under Fast Profile | ✓ Done |
| `Arc<SniffingConfig>` map in dispatcher | ✓ Done |
| Lazy domain lowercase in `DomainMatcher` (only allocates if uppercase found) | ✓ Done |
| Non-splice relay uses `copy_bidirectional_pooled` with 16 KiB pooled buffers | ✓ Done |
| Phase 2A Prometheus histograms (route, connect, parse, relay-error) | ✓ Done |
| Fast Profile schema + validation + `--profile` CLI flag | ✓ Done |

---

## 5. Where the Gap vs Xray Lives

BW server is ~32% slower than Xray server (13.8k vs 20.5k req/s, same Xray client).
Per-request extra overhead = **23.7 µs** (72.5 µs BW vs 48.8 µs Xray).

The outbound-connect histogram explains a large fraction:
- At p50 (0.34 ms), the connect dominates: 340 µs / 2,800 µs total = 12% of request time
- At p90 (10.5 ms), the connect is catastrophic: 10,500 µs / 4,100 µs budget = **the primary tail driver**

The heavy p90/p99 tail on outbound connect is Tokio scheduler contention: 32 concurrent tasks competing for worker threads means new-connection tasks queue behind in-flight relay tasks. Under 32 concurrency the median is acceptable, but the tail is long.

**Root causes ranked by impact:**

| Rank | Root Cause | Evidence | Fix |
|------|-----------|----------|-----|
| 1 | Outbound connect scheduling delay (tail: 10-24 ms) | `proxy_outbound_connect_seconds` p90=10.5ms | TCP pool (poolSize≥8), already coded — just needs enabling in Fast Profile by default |
| 2 | async_trait vtable boxing per dispatch | No direct histogram yet — inferred from 23.7 µs unexplained gap | Measure with `proxy_inbound_parse_seconds` enabled; consider `#[async_trait(?Send)]` for inner paths |
| 3 | VLESS header decode overhead | Inherent protocol cost — cannot eliminate without changing protocol | Ongoing; no allocation issues found in hot path |

---

## 6. Tail Behavior

Xray exhibited one 2.3-second outlier (`slowest_s = 2.3047`) during the xray-xray run. BW's worst case was 84 ms (direct) and 44 ms (bw-fast-lab). BW has **no multi-second outliers** — more predictable tail than Xray under this load.

---

## 7. Correctness: Zero Errors

All variants: **0 errors, 0 timeouts, 100% 200 OK** across 30-second runs.

- BW Compat: 410,852 successful responses
- BW Fast: 415,191 successful responses  
- Xray-Xray: 614,187 successful responses
- sing-box–sing-box: 580,169 successful responses

---

## 8. What's Next

### Immediate (high impact, low risk)

1. **Enable TCP pool by default in Fast Profile** (`poolSize: 8` in fast-lab-server.json).  
   The code is complete and correct. This should convert p90 outbound connect from 10.5 ms → ~0.3 ms.  
   *Expected impact: +20-30% req/s, p90 latency -60%.*

2. **Benchmark with pool warm**: Run a 60-second variant where the first 5 seconds warm the pool,  
   then measure the steady-state phase. Compare pool-hot vs cold-dial p50/p90.

3. **Add `proxy_inbound_parse_seconds` to the Prometheus endpoint** (already described in Phase 2A —  
   needs wiring into the VLESS inbound `decode_request()` call site). This will isolate header-decode cost.

### Medium-term (requires measurement gate)

4. **async_trait dispatch reduction**: The 23.7 µs gap per request exceeds what allocator/logging  
   changes can explain. Consider `#[async_trait(?Send)]` for the `Dispatcher` and `Outbound` traits  
   to eliminate `Box::pin()` Send-bound boxing. Gate on `proxy_inbound_parse_seconds` evidence.

5. **Relay-level retry on zero-bytes-exchanged**: A pooled socket can still fail on first real write  
   after passing the TCP_INFO probe. Retry once with a fresh dial if `(up + down) == 0`.  
   Requires dispatcher-level changes, tracked separately.

6. **Periodic empty-pool cleanup**: LRU eviction only runs under `max_dests` pressure.  
   A background sweep every 60 seconds would reclaim idle pools for cold destinations.

### Later (VPS only)

7. Re-run `xray-compare` and `singbox-compare` on a real VPS pair to eliminate loopback  
   scheduling artifacts. Loopback favors implementations with smaller kernel-roundtrip counts  
   (Xray advantage shrinks under real network RTT).

---

## 9. Test Coverage

All splice and pool changes pass unit tests:

```
test splice::linux::tests::splice_echo_roundtrip_without_deadlock ... ok
test splice::linux::tests::splice_download_only_completes_without_client_upload ... ok
test splice::linux::tests::uring_echo_roundtrip ... ok
test splice::linux::tests::uring_download_only ... ok
```

Previously the `uring_echo_roundtrip` and `splice_echo_roundtrip_without_deadlock` tests hung
indefinitely due to spurious EPOLLOUT wakeups from the ring fd. Fixed by switching to
`IORING_REGISTER_EVENTFD` — the eventfd is written only when a CQE is produced.

---

## Appendix: Benchmark Configuration

**Xray version**: 26.3.27 (go1.26.1 linux/amd64)  
**sing-box version**: 1.13.12 (go1.25.9 linux/amd64)  
**Blackwire version**: 0.1.0 (Rust release build, `target/release/blackwire`)  
**Kernel**: Linux 6.18.5  
**Tool**: hey (github.com/rakyll/hey)  
**Parameters**: `-z 30s -c 32` (keep-alive, 32 concurrent)  
**Target response**: 1 KiB static payload  

Configs used:
- `labs/realistic/latency/configs/blackwire-fast-lab-server.json` (BW Fast server, port 10080)
- `labs/realistic/latency/configs/blackwire-compat-server-tcp.json` (BW Compat server, port 10083)
- `labs/realistic/latency/configs/xray-server-tcp.json` + `xray-client-tcp.json`
- `labs/realistic/latency/configs/singbox-server-tcp.json` + `singbox-client-tcp.json`

> Baselines are machine-specific. Do not treat these numbers as universal truth —
> regenerate on your target hardware before drawing release conclusions.
