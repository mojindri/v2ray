# Fast Adaptive Splice Final Check

Date: 2026-05-29

Environment:

- Runner VPS: `91.107.176.118`
- Upstream VPS: `203.0.113.10`
- Upstream: nginx static payloads on `:18080`
- Client: sing-box SOCKS5 to VLESS
- Benchmark: `hey -z 30s -c 32`, 5s warmup, keepalive enabled
- Blackwire build: native Linux release build on runner VPS

## Fix

Fast adaptive splice previously switched to splice after cumulative bytes crossed the threshold on a keepalive TCP stream. That misclassified many small HTTP responses as one bulk stream.

The final policy now requires bulk-shaped reads before splice:

- Copy first.
- Use a 64 KiB adaptive copy buffer.
- Require at least 4 consecutive full-buffer reads.
- Then allow splice when bytes are >= 256 KiB, or when bytes are >= 64 KiB and stream age is >= 30ms.

This keeps tiny and mid-size keepalive responses on the copy path while still allowing splice for real bulk streams.

## Results

| Payload | sing-box p50 | sing-box p95 | sing-box p99 | sing-box req/s | Blackwire Fast p50 | Blackwire Fast p95 | Blackwire Fast p99 | Blackwire Fast req/s | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `4k-ka` | 1.90ms | 3.00ms | 3.80ms | 16,588 | 1.90ms | 3.00ms | 3.70ms | 16,610 | 0 |
| `16k-ka` | 2.10ms | 3.40ms | 4.30ms | 14,652 | 1.70ms | 2.80ms | 3.50ms | 17,840 | 0 |
| `64k-ka` | 2.90ms | 4.70ms | 5.80ms | 10,679 | 2.80ms | 4.40ms | 5.50ms | 11,073 | 0 |
| `1m-ka` | 21.10ms | 34.40ms | 42.70ms | 1,458 | 20.20ms | 31.90ms | 39.10ms | 1,532 | 0 |

Raw result folders:

- `adaptive-bulkread-4k16k-20260528T223502Z`
- `adaptive-bulkread-64k1m-20260528T224523Z`

## Micro Optimization Follow-up

The relay loop now uses biased polling and checks server-to-client reads first. The benchmark workload is download-heavy HTTP, so this reduces scheduling churn on the hot response path without changing protocol behavior.

Follow-up VPS result folders:

- `micro-downbiased-4k16k-20260528T230120Z`
- `micro-downbiased-64k1m-20260528T230410Z`

| Payload | sing-box p50 | sing-box p95 | sing-box p99 | sing-box req/s | Blackwire Fast p50 | Blackwire Fast p95 | Blackwire Fast p99 | Blackwire Fast req/s | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `4k-ka` | 1.80ms | 3.00ms | 3.80ms | 17,015 | 1.60ms | 2.70ms | 3.40ms | 19,232 | 0 |
| `16k-ka` | 2.10ms | 3.40ms | 4.20ms | 14,945 | 1.90ms | 3.10ms | 3.90ms | 16,001 | 0 |
| `64k-ka` | 2.90ms | 4.70ms | 5.90ms | 10,694 | 2.90ms | 4.50ms | 5.50ms | 10,866 | 0 |
| `1m-ka` | 20.00ms | 31.80ms | 39.50ms | 1,554 | 19.90ms | 29.50ms | 35.50ms | 1,571 | 0 |

The splice readiness detector was then tightened to track full-buffer streaks per direction. This prevents small upstream request reads from resetting downstream bulk evidence, and prevents combined upload+download byte totals from selecting splice unless one direction independently looks bulk-shaped.

Follow-up folder: `micro-directional-splice-4k1m-20260528T231401Z`

| Payload | sing-box p50 | sing-box p95 | sing-box p99 | sing-box req/s | Blackwire Fast p50 | Blackwire Fast p95 | Blackwire Fast p99 | Blackwire Fast req/s | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `4k-ka` | 1.80ms | 2.90ms | 3.70ms | 17,285 | 1.80ms | 2.90ms | 3.60ms | 17,392 | 0 |
| `1m-ka` | 20.60ms | 32.70ms | 39.90ms | 1,503 | 19.90ms | 28.20ms | 34.10ms | 1,590 | 0 |

The adaptive relay copy buffers were then moved from per-connection `Vec` allocations to the shared 64 KiB buffer pool. This keeps the same copy size while reducing allocator churn for short-lived Fast Profile TCP relays.

Follow-up folder: `micro-pooled-adaptive-buffers-4k1m-20260528T232400Z`

| Payload | sing-box p50 | sing-box p95 | sing-box p99 | sing-box req/s | Blackwire Fast p50 | Blackwire Fast p95 | Blackwire Fast p99 | Blackwire Fast req/s | Errors |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `4k-ka` | 1.80ms | 2.90ms | 3.70ms | 17,559 | 1.80ms | 2.90ms | 3.70ms | 17,836 | 0 |
| `1m-ka` | 20.80ms | 33.50ms | 41.40ms | 1,490 | 20.30ms | 30.80ms | 37.30ms | 1,536 | 0 |

## Verdict

The final adaptive splice policy passes the focused sing-box keepalive comparison for `4k`, `16k`, `64k`, and `1m` on this VPS lab. Blackwire Fast had zero request errors and matched or beat sing-box on p50, p95, p99, and req/s in these focused rows.

The previous failure mode was not general VLESS overhead. It was an adaptive relay policy bug: cumulative keepalive bytes caused premature splice selection for small responses.
