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
- HTTP + TLS + FakeDNS sniffing with `destOverride`, `routeOnly`, `metadataOnly`
- Routing rules (domain, suffix, keyword, regex, IP/CIDR, port, source_ip, inboundTag, sniffed `protocol`, GeoIP/geosite)
- Load balancer with health-check failover
- Prometheus metrics (`/metrics`, `/healthz`, `/readyz`, `/version`)
- Config hot-reload: routing rules, VLESS user UUIDs, GeoIP/geosite data
- Structural config reload via automatic CLI instance rebuild with rollback
- Native JSON config schema with fail-closed validation
- Per-inbound / global `max_connections` limits (TCP, mKCP, QUIC, Hysteria2)
- Resource-risk smoke coverage in normal CI
- External-client failure pcaps captured and uploaded by CI
- TUN transparent proxy on Linux, covered by privileged CI tests; macOS utun and Windows Wintun device creation compile through native backends; Windows can use `tun.wintunFile`/`tun.wintun_file` to point at a bundled `wintun.dll`; full-device runtime startup still fails early through an explicit platform support contract until native routing and TCP redirection are implemented
- Handler API structural endpoint operations with rebuild rollback
- macOS release artifact build

### Experimental (implemented; missing hostile-network or soak proof)

Treat these as unstable — they may be promoted or downgraded in later releases.

- REALITY (d0 self-interop tests now in CI; d1 Xray-server interop requires Docker — still `#[ignore]`)
- Hysteria2 (TCP + UDP relay tested in CI; no hostile-network / loss-jitter or long-lived soak proof)
- ShadowTLS v3 (local e2e passes; no external sing-box / shadow-tls interop matrix)
- mKCP (local multi-session e2e; no loss/jitter lab, no external client proof)
- QUIC / V2Ray QUIC transport (sing-box PASS in matrix; Xray legacy QUIC client removed upstream)
- Stats API (gRPC) (uptime, RSS, task count wired; no soak or observability validation)

### Unsupported (fail-closed or explicitly out of scope)

The following are not implemented. Attempting to configure them will fail
at config validation (before any traffic is handled) or return an error at runtime.

- `protocol: shadowtls` as an inbound or outbound — fails validation with a message to use `security: shadowtls` in `streamSettings` instead
- V2Ray / Xray JSON config import — interop is wire-level only; translate configs manually
- Handler API structural endpoint RPCs use native blackwire endpoint JSON in `proxy_settings`; Xray core endpoint protobuf decoding is not implemented
- VMess legacy non-AEAD / alterId — only AEAD is implemented
- DNS, dokodemo, tun as inbound `protocol` values — not in the `Protocol` enum; deserialization fails
- Byte-identical browser TLS fingerprinting — functional interop ≠ identical ClientHello bytes
- OpenWrt, Android, iOS — not built or tested
- Windows full-device TUN/Wintun runtime — device backend and explicit `wintun.dll` path wiring are present, but runtime support still requires native routing and TCP redirection
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
| REALITY | Live external-client interop run archived (d1 test unignored, requires Docker) |
| Hysteria2 | Hostile-network (loss/jitter), long-lived stream, and soak run (UDP relay: tested) |
| TUN | Privileged Linux CI tests, route setup/cleanup, UDP NAT, rollback-on-failure |
| Structural hot-reload | Listener add/remove, port change, outbound add/remove, TLS material reload, rollback on failed reload |
| ShadowTLS v3 | External sing-box / shadow-tls interop matrix passing |
| mKCP | Loss/jitter lab + external client proof |
