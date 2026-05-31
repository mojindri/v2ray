# Report Evidence

This file records high-signal evidence copied from local report artifacts. The
raw report files are intentionally ignored by git, so this page is the
repository-visible summary of those runs. Local raw paths are kept as provenance
for anyone with the same workspace artifacts.

## Local Production Matrix

Latest local production matrix summary:

| Field | Value |
| --- | --- |
| Local raw report | `reports/production/ci-matrix-local-20260523T223752Z.txt` |
| `local-fast` | PASS |
| `local-load` | PASS |
| `local-slowloris` | PASS |
| `local-prod` | PASS |
| `pcap-local` | PASS |
| `fingerprint-compare` | PASS |
| `netem-local` | PASS |

The earlier local matrix at
`reports/production/ci-matrix-local-20260523T195559Z.txt` also reports PASS for
the same local gates, except it does not include `pcap-local`.

## Local Load

Latest managed local load result:

| Field | Value |
| --- | --- |
| Local raw report | `reports/production/local-load.json` |
| Requests | `250` |
| Concurrency | `50` |
| Success rate | `1.0` |
| Requests per second | `403.237` |
| Latency p50 | `44.256` ms |
| Latency p95 | `98.893` ms |
| Latency p99 | `148.513` ms |
| Max latency | `178.743` ms |
| Sample failures | none |

The CI-matrix load log
`reports/production/ci-matrix-local-load-20260523T223752Z.log` reports the same
workload shape with `250/250` successful requests, `479.551` requests per
second, p95 `81.116` ms, and no sample failures. An older load run at
`reports/production/ci-matrix-local-load-20260523T195559Z.log` also succeeded
but was much slower, with p95 around `4061` ms.

## Slowloris Diagnostic

Latest local slowloris result:

| Field | Value |
| --- | --- |
| Local raw report | `reports/production/slowloris.json` |
| Clients | `25` |
| Closed | `25` |
| Still open after duration | `0` |
| Errors | `0` |
| Duration | `15.0` seconds |
| Interval | `1.0` second |

The matching config artifact is
`reports/production/slowloris-socks-direct.json`.

## VPS Memory Profile

Latest local Blackwire server memory profile:

| Field | Value |
| --- | --- |
| Scenario | Nginx target, 64 KiB payload memory profile |
| Local raw report | `benches/reports/flamegraphs/vps-20260531/memory-profile-nginx-64k-20260531T093038Z.log` |
| Sampled process | Blackwire server process, `server_pid=241597` |
| Peak RSS | `24568` KiB, about `24.0` MiB |
| Peak virtual size at RSS peak | `428452` KiB, about `418.4` MiB |
| Threads at RSS peak | `6` |
| File descriptors at RSS peak | `131` first peak sample, then `97` while RSS stayed flat |

The peak RSS appears in the raw report at the samples beginning with:

```text
1780219851.943333641 rss_kb=24568 vmsize_kb=428452 threads=6 fd=131
```

After the load phase, RSS dropped back to `17224` KiB with `15` file
descriptors, which indicates the profile did not end at the peak resource
level.

## Fuzz Smoke And Harness RSS

Local fuzz harness reports all reached `DONE` for their configured `32`
runs:

| Target | Local raw report | Result | Peak reported RSS |
| --- | --- | --- | --- |
| Hysteria2 frame | `reports/production/fuzz-hysteria2_frame.log` | `DONE`, 32 runs | `64` MiB |
| REALITY client hello | `reports/production/fuzz-reality_client_hello.log` | `DONE`, 32 runs | `63` MiB |
| ShadowTLS handshake | `reports/production/fuzz-shadowtls_handshake.log` | `DONE`, 32 runs | `63` MiB |
| Shadowsocks 2022 chunk | `reports/production/fuzz-ss2022_chunk.log` | `DONE`, 32 runs | `61` MiB |
| VLESS header | `reports/production/fuzz-vless_header.log` | `DONE`, 32 runs | `62` MiB |
| VMess AEAD header | `reports/production/fuzz-vmess_aead_header.log` | `DONE`, 32 runs | `62` MiB |

The largest RSS value in local fuzz reports is not a Blackwire server
runtime measurement. It is from the Hysteria2 fuzz harness:

| Field | Value |
| --- | --- |
| Local raw report | `reports/production/fuzz-hysteria2_frame.log` |
| Peak reported RSS | `64` MiB |
| Context | `target/aarch64-apple-darwin/release/hysteria2_frame` libFuzzer run |

Keep this separate from the server memory profile because fuzz binaries include
libFuzzer instrumentation and harness overhead.

The older local fuzz smoke report
`reports/production/fuzz-smoke-20260523T182117Z.log` says `No fuzz targets
found`; treat the individual fuzz target logs above as the useful local
fuzz evidence.

## Security Hygiene Logs

Security hygiene logs under `reports/production/security-*.log` complete their
local grep/dependency-inspection workflow, but most local runs also report:

```text
cargo-audit not installed. Install with: cargo install cargo-audit
cargo-deny not installed. Install with: cargo install cargo-deny
```

Treat these reports as partial hygiene evidence, not a complete dependency
vulnerability audit. Representative local raw report:
`reports/production/security-20260524T082023Z.log`.

## Network Emulation And Packet Capture

Local netem reports are best-effort on macOS Docker Desktop. They were
recorded as matrix PASS/SKIP rather than as proof of applied Linux `tc` shaping:

| Artifact | Result |
| --- | --- |
| `reports/production/netem-local-20260523T224638Z.log` | `SKIP: tc not available inside realistic-target-http-1.` |
| `reports/production/ci-matrix-netem-local-20260523T223752Z.log` | Matrix wrapper completed; inner netem reported `SKIP` because `tc` was unavailable |

Packet capture evidence is also limited in the local run:

| Artifact | Result |
| --- | --- |
| `reports/production/pcap-local-summary-20260523T195643Z.txt` | `WARN: pcap is empty or not created` |

## Bench And Optimization Reports

Long-form benchmark conclusions are already maintained in
`benches/perf-baseline.md`. The key local evidence from the benchmark logs
is:

| Area | Local raw report | Result |
| --- | --- | --- |
| Shared-path workspace tests | `benches/reports/test-workspace-shared-path-20260530.log` | Multiple workspace test groups report `test result: ok` |
| Shared-path quick bench baseline | `benches/reports/protocol-matrix-20260530T002407Z.log` | Completed Criterion quick protocol matrix |
| Shared-path allocation quick bench | `benches/reports/protocol-matrix-20260530T003107Z.log` | Completed; includes allocation-enabled quick bench data |
| Rejected pooled first-write experiment | `benches/reports/protocol-matrix-20260530T004558Z.log` and `benches/reports/shared-path-post-firstwrite-quick-20260530.log` | Criterion flagged several Trojan TCP short/mixed regressions; candidate was rejected |
| Pooled first-write focused test | `benches/reports/test-pooled-first-write-20260530.log` | `1 passed`, `0 failed`, but benchmark result rejected the experiment |
| macOS flamegraph attempt | `benches/reports/flamegraph-vless-tcp-bulk-20260530.log` | Blocked by profile collapse error; not authoritative |

WebSocket tuning logs under `benches/reports/ws-*.log` are experiment history.
Examples include:

| Artifact | Signal |
| --- | --- |
| `benches/reports/ws-relay-adaptive-bulk-20260530.log` | VLESS WS bulk median around `184.47` us, about `338.81` MiB/s |
| `benches/reports/ws-direct-frame-bulk-20260530.log` | VLESS WS direct-frame bulk median around `244.87` us, about `255.24` MiB/s |
| `benches/reports/ws-buffer-after-20260530.log` | VLESS WS bulk median around `187.62` us after buffer changes |

Several older protocol-matrix logs are failed or incomplete due to local
environment issues such as missing bench target names, early EOF, build errors,
or no disk space. Do not use those as release evidence without re-running the
gate.
