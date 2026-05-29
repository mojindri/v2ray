# Release Guide

## Support Contract

This is a pre-1.0 project. The table below is the release support contract.
Any area not listed as **Supported** carries an explicit caveat.

### Supported (safe to rely on)

Validated by CI, the e2e test suite, and the realistic lab mandatory matrix.

- VLESS over TCP, REALITY, WebSocket, HTTPUpgrade, SplitHTTP (stream-one + packet-up)
- VMess AEAD over TCP
- VMess over gRPC (Gun transport); END_STREAM propagation validated
- Trojan over TLS/TCP
- Shadowsocks 2022 (TCP + UDP SIP022)
- SOCKS5 inbound (TCP CONNECT + UDP ASSOCIATE), HTTP CONNECT inbound, Freedom outbound
- DNS resolver (system, DoH, DoT), FakeIP pool, DNS cache, `domain_strategy`
- HTTP + TLS sniffing with `destOverride`, `routeOnly`, `metadataOnly`
- Routing rules (domain, suffix, keyword, regex, IP/CIDR, port, source_ip, inboundTag, GeoIP/geosite)
- Load balancer with health-check failover
- Prometheus metrics (`/metrics`, `/healthz`, `/readyz`, `/version`)
- Config hot-reload: routing rules, VLESS user UUIDs, GeoIP/geosite data
- Native JSON config schema with fail-closed validation
- Per-inbound / global `max_connections` limits (TCP, mKCP, QUIC, Hysteria2)

### Partial (shipped with known gaps)

Do not treat these as production-ready without reading the notes.

| Area | Known gap |
| ---- | --------- |
| TUN transparent proxy | Linux-only, privileged tests only, no broad production validation. Do not use in production yet. |
| FakeDNS sniffing | FakeDNS path not wired in `analyze_peek()`; HTTP + TLS sniffing are Supported. |
| Handler API (gRPC) | Supported operations: `ListInbounds`, `ListOutbounds`, `GetInboundUsersCount`, `GetInboundUsers`, `AlterInbound` (VLESS add/remove). Unsupported (return UNIMPLEMENTED): `AddInbound`, `RemoveInbound`, `AddOutbound`, `RemoveOutbound`, `AlterOutbound`. |
| Structural hot-reload | Listener add/remove, port change, outbound add/remove, TLS material reload require an instance restart. |
| macOS | CI runs `macos-latest` tests; release artifacts are not certified. |

### Experimental (implemented; missing hostile-network or soak proof)

Treat these as unstable — they may be promoted or downgraded in later releases.

- REALITY (VLESS/REALITY e2e passes; live external-client interop run is `#[ignore]` without Docker setup)
- Hysteria2 (e2e passes; no hostile-network, UDP, or long-lived soak validation)
- ShadowTLS v3 (local e2e passes; no external sing-box / shadow-tls interop matrix)
- mKCP (local multi-session e2e; no loss/jitter lab, no external client proof)
- QUIC / V2Ray QUIC transport (sing-box PASS in matrix; Xray legacy QUIC client removed upstream)
- Stats API (gRPC) (wired; no soak or observability validation)
- SplitHTTP extras: Xmux, padding, `downloadSettings` are backlog items

### Unsupported (fail-closed or explicitly out of scope)

The following are not implemented. Attempting to configure them will fail
at config validation (before any traffic is handled) or return an error at runtime.

- `protocol: shadowtls` as an inbound or outbound — fails validation with a message to use `security: shadowtls` in `streamSettings` instead
- V2Ray / Xray JSON config import — interop is wire-level only; translate configs manually
- `AddInbound`, `RemoveInbound`, `AddOutbound`, `RemoveOutbound`, `AlterOutbound` via Handler API — use config reload / instance restart
- VMess legacy non-AEAD / alterId — only AEAD is implemented
- DNS, dokodemo, tun as inbound `protocol` values — not in the `Protocol` enum; deserialization fails
- Byte-identical browser TLS fingerprinting — functional interop ≠ identical ClientHello bytes
- Windows, OpenWrt, Android, iOS — not built or tested
- Standalone client app (TUN/system proxy UI)

---

## Release Gate Commands

Run these before tagging a release. Archive results in `labs/realistic/reports/`.

```sh
make verify-local           # fmt, check, clippy, unit+integration tests
make -C labs/realistic finalize   # stable + advanced-smoke + external-client Docker matrix
make fuzz-smoke             # short fuzz pass (6 targets)
make audit                  # cargo-audit vulnerability check
make deny                   # cargo-deny license/advisory policy
```

Optional (manual, not CI-gated):

```sh
# Heavy resource-stress paths — run once and archive results
cargo test -p tests --test resource_limits -- --include-ignored
cargo test -p tests --test leak_assertions -- --include-ignored

# Performance benchmark
make perf                   # Lima VM latency benchmark

# VPS validation
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make verify-remote
```

---

## Canary Plan

- Start with 5% traffic for 30 minutes.
- Use real traffic with normal auth mix and background bad-auth noise.
- Keep periodic config reload enabled during canary.

Helper:

```bash
bash tools/canary/run_canary.sh
```

### Required Dashboards / Alerts

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

---

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

---

## Promote-or-Keep-Experimental Checklist

A feature moves from Experimental/Partial to Supported **only** when all items below are met.

| Feature | Required proof before promotion |
| ------- | -------------------------------- |
| REALITY | Live external-client interop run archived (d1 test unignored) |
| Hysteria2 | Hostile-network (loss/jitter), UDP relay, long-lived stream, and soak run |
| TUN | Privileged Linux CI tests, route setup/cleanup, UDP NAT, rollback-on-failure |
| FakeDNS sniffing | `analyze_peek()` wired for FakeDNS; lab row proof for FakeDNS routing |
| Structural hot-reload | Listener add/remove, port change, outbound add/remove, TLS material reload, rollback on failed reload |
| SplitHTTP extras | Xmux, padding, `downloadSettings` implemented and tested |
| ShadowTLS v3 | External sing-box / shadow-tls interop matrix passing |
| mKCP | Loss/jitter lab + external client proof |
