# blackwire Feature Matrix

Last updated against the `blackwire-*` workspace crates, `tests/tests/` e2e
suite, `labs/realistic/` interop lab, and GitHub Actions (CI + cross-platform).

**Source of truth:** Wire behavior and “Supported” labels follow [Xray-core](https://github.com/XTLS/Xray-core) and [sing-box](https://github.com/SagerNet/sing-box) implementations plus real clients in the realistic lab — not blackwire’s schema or this table alone. See [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md).

Status labels:

| Label | Meaning |
|---|---|
| **Supported** | Wired in `blackwire-core` `Instance`, exercised by automated tests or the realistic lab mandatory matrix |
| **Experimental** | Implemented end-to-end but missing hostile-network coverage, external-client breadth, or production hardening |
| **Partial** | Code or schema exists; behavior, wiring, or observability is incomplete |
| **Unsupported** | Not implemented or explicitly stubbed |
| **Intentional deviation** | Differs from V2Ray/Xray by design |

Evidence shorthand: crate paths use `blackwire-{common,config,app,core,protocol,transport,tls,api,cli}`.

---

## Product scope

**blackwire** is a Rust-native **proxy server** that targets **wire compatibility**
with Xray-core and sing-box on selected protocol/transport pairs. Validation uses
in-process e2e tests, per-crate `production_readiness` tests, and (optionally)
Docker labs with real upstream clients — not mock peers alone.

| Area | Status | Notes |
|---|---|---|
| Xray / sing-box **wire interop** (as server) | **Experimental** | REALITY d1 interop is in `blackwire-transport/tests/interop.rs` (`#[ignore]` without `tests/interop`); mandatory green matrix in `labs/realistic/README.md` lists seven stable paths + REALITY |
| Native JSON config schema | **Supported** | `blackwire-config` — validated at load; fail-closed schema tests |
| V2Ray JSON config | **Unsupported** | Not a goal |
| Xray JSON config | **Unsupported** | Interop is wire-level only; configs must be translated |
| **Server mode** (listen for clients) | **Supported** | Primary product: `blackwire run` |
| **Local proxy mode** (SOCKS/HTTP in → outbound) | **Supported** | Same `Instance` stack; covered by e2e (`e2e_socks5_vless`, `e2e_http_connect`, etc.) |
| Standalone **client app** (TUN/system proxy UI) | **Unsupported** | No dedicated client binary or mobile/desktop shell; TUN is server-side transparent path |

---

## Protocols

Inbound handlers registered in `blackwire-core/src/instance/mod.rs`:
`Socks`, `Vless`, `Trojan`, `Vmess`, `Http`, `Shadowsocks`, `Hysteria2`.

Outbound handlers: `Freedom`, `Vless`, `Hysteria2`, `Trojan`, `Vmess`, `Shadowsocks`.

| Protocol | Inbound | Outbound | Status | Evidence / notes |
|---|---:|---:|---|---|
| SOCKS5 (TCP CONNECT) | Yes | No | **Supported** | `blackwire-protocol/socks.rs`; e2e `e2e_socks5_vless.rs` |
| SOCKS5 UDP ASSOCIATE | Yes | Partial | **Partial** | `socks5_udp.rs` + TCP control channel; lab scenario `vless-udp` for VLESS path |
| HTTP CONNECT | Yes | No | **Supported** | `http_connect.rs`, `blackwire-core/http.rs`; e2e `e2e_http_connect.rs` |
| Freedom / direct | No | Yes | **Supported** | `freedom.rs` — default direct outbound |
| VLESS (TCP) | Yes | Yes | **Supported** | `vless/`; golden + e2e matrix |
| VLESS UDP command | Yes | Partial | **Partial** | `vless/udp.rs` inbound relay; lab scenario pending |
| VLESS flow `xtls-rprx-vision` | Partial | Partial | **Partial** | Encoded on wire; inbound logs and continues without Vision splice (`vless/inbound.rs` TODO) |
| VMess AEAD | Yes | Yes | **Supported** | `vmess/`; legacy **alterId unsupported** |
| Trojan (TCP) | Yes | Yes | **Supported** | `trojan/`; e2e `e2e_trojan/` |
| Trojan UDP | No | No | **Unsupported** | No UDP associate path in trojan module |
| Shadowsocks 2022 | Yes | Yes | **Supported** | `ss2022/`; e2e `e2e_ss2022.rs`, `e2e_phase6_ss2022_local.rs` |
| SS2022 UDP relay | No | No | **Unsupported** | TCP stream cipher path only in crate |
| Hysteria2 | Yes | Yes | **Experimental** | `blackwire-transport/hysteria2/`, `blackwire-core/hysteria2.rs`; e2e `e2e_phase3_hysteria2.rs`; lab mandatory path; QUIC/UDP needs more hostility testing |
| ShadowTLS as `protocol` enum | No | No | **Unsupported** | Only `security: shadowtls` on TCP inbounds/outbounds |
| DNS / dokodemo / tun inbound protocol | No | No | **Unsupported** | Not in `Protocol` enum |

---

## Transports

Stack wired via `blackwire-core/outbound_transport.rs`, `ws_tls.rs`, and inbound
TCP accept in `instance/mod.rs`. Hysteria2 uses its own QUIC listener.

| Transport | Status | Evidence / notes |
|---|---|---|
| TCP | **Supported** | `blackwire-transport/tcp.rs` |
| TLS (rustls) | **Supported** | `transport/tls.rs` |
| WebSocket | **Supported** | `transport/ws.rs`; e2e `e2e_phase4_vless_ws.rs` |
| gRPC (Gun-style) | **Supported** | `transport/grpc.rs`; e2e `e2e_phase5_http_vmess_grpc.rs` |
| REALITY | **Experimental** | `transport/reality/`, `blackwire-core/reality.rs`; e2e `e2e_phase2_reality.rs`; transport-only tests `e2e_reality.rs`; Xray d1 interop ignored test |
| ShadowTLS v3 | **Experimental** | `transport/shadowtls/` (v3 only); e2e `e2e_phase7_shadowtls.rs`; lab advanced-features smoke, not mandatory green |
| mKCP | **Experimental** | `transport/mkcp/`; e2e `e2e_phase8_mkcp.rs`; lab advanced-features smoke |
| QUIC (`network: quic` for VLESS/VMess) | **Unsupported** | `NetworkType::Quic` in schema only; QUIC used inside Hysteria2, not generic stream stack |
| Hysteria2 (QUIC + HTTP/3 auth) | **Experimental** | `hysteria2/` — TCP stream proxy + UDP datagram path |
| TUN transparent proxy | **Partial** | `transport/tun/` when `config.tun` set; privileged tests `tun_priv.rs` (`#[ignore]` without root / `priv-test`) |
| HTTPUpgrade | **Partial** | Inbound `accept_httpupgrade` + outbound dial; lab row `vless-httpupgrade` (external-client proof pending) |
| SplitHTTP / xHTTP | **Unsupported** | `NetworkType::SplitHttp` in schema only; no transport implementation |

---

## DNS (`blackwire-app/dns`)

| Feature | Status | Notes |
|---|---|---|
| System resolver (empty `servers`) | **Supported** | `dns/resolver.rs` — hickory system config |
| Custom upstream (plain IP, UDP 53) | **Supported** | Parsed into hickory `NameServerConfig` |
| DoH / DoT upstream URLs | **Supported** | `https://` / `tls://` parsed in `dns/resolver.rs` (hickory) |
| FakeIP pool + restore on dispatch | **Supported** | `dns/fakeip.rs`, dispatcher; startup rejects invalid pool (`production_readiness`) |
| DNS response cache | **Supported** | `dns/cache.rs` |
| `domain_strategy` (routing) | **Partial** | `UseIP`/`UseIpv4`/`UseIpv6` resolve domain before routing in dispatcher; `IPIfNonMatch` not yet |
| Sniffing (`http` / `tls` / `fakedns`) | **Partial** | `blackwire-app/sniff.rs` + dispatcher destOverride; protocol routing rules; needs external-client lab |

---

## Routing (`blackwire-app`)

| Feature | Status | Notes |
|---|---|---|
| `domain` (exact) | **Supported** | `router.rs` + unit tests |
| `domain_suffix` | **Supported** | |
| `domain_keyword` | **Supported** | |
| `domain_regex` | **Supported** | `RegexSet` in `DomainMatcher` + `domain_regex_match` test |
| `ip` / CIDR | **Supported** | |
| `port` | **Supported** | |
| `source_ip` | **Supported** | |
| `inboundTag` | **Supported** | |
| `protocol` / sniffed domain rules | **Unsupported** | Sniffing not wired |
| GeoIP / geosite (`geoip:`, `geosite:`) | **Supported** | `geo/`; missing data files → empty matchers + warn |
| Balancers (random / roundRobin / latency) | **Supported** | `balancer.rs`; latency uses HTTP 204 health checks |
| Route to balancer tag | **Supported** | `production_readiness` tests |

---

## Operations

| Feature | Status | Notes |
|---|---|---|
| Config file load + validation | **Supported** | `blackwire-config` |
| `${ENV}` substitution | **Supported** | `env.rs` |
| File watch + validated reload notify | **Supported** | `ConfigManager::watch`; CLI subscribes |
| Hot-reload **routing rules** | **Supported** | `blackwire-core/reload.rs` — `LiveRouter::swap` |
| Hot-reload **VLESS user UUIDs** | **Supported** | Per-inbound registry refresh |
| Hot-reload **GeoIP/geosite data** | **Supported** | Reloaded with router rebuild |
| Hot-reload listeners / new tags / TLS keys | **Unsupported** | Documented in `reload.rs` — requires restart |
| Per-inbound / global `max_connections` | **Partial** | TCP accept path in `transport/tcp.rs` + config limits; not all protocols share the same limit surface |
| Prometheus HTTP (`metricsAddr`) | **Supported** | `metrics.rs` — `/metrics`, `/healthz`, `/readyz`, `/version` |
| Per-connection Prometheus counters | **Supported** | `record_connection_*` called from `dispatcher` after each relay |
| v2ray gRPC Stats / Handler API | **Unsupported** | `blackwire-api` is a Phase 6 stub; `stats` / `api` config keys unused in core |

---

## Security, quality, and CI

| Feature | Status | Notes |
|---|---|---|
| `make verify-local` (fmt, check, clippy, test) | **Supported** | Required on PRs via **CI / Rust** |
| Cross-platform `cargo test` | **Supported** | **Cross-platform** workflow: `ubuntu-latest`, `macos-latest`, `linux-arm64` on PRs |
| Fuzz targets (`fuzz/`) | **Supported** | REALITY, VMess, VLESS, Hysteria2, ShadowTLS, SS2022, stateful sequences |
| `make fuzz-smoke` | **Supported** | Short local smoke |
| `make fuzz-long` | **Experimental** | Optional; not CI-gated |
| `make audit` / `cargo-audit` | **Supported** | Weekly **Security / Dependency audit** schedule + manual |
| `make deny` / `cargo-deny` | **Supported** | `deny.toml` license/advisory policy |
| Adversarial integration tests | **Supported** | `tests/tests/adversarial_*.rs` — fragmentation, cancellation, backpressure, etc. |
| Leak / resource tests | **Partial** | `leak_assertions`, `resource_limits` (some `#[ignore]`) |
| External-client Docker lab | **Experimental** | `labs/realistic/` — mandatory matrix documented in lab README |
| TLS/REALITY byte-level fingerprint diff vs Chrome | **Unsupported** | Functional interop ≠ identical ClientHello bytes |
| Packet capture on failure | **Unsupported** | `run-pcap-local.sh` helper exists; not automated in CI |

---

## Platform support

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 | **Supported** | Primary dev and CI target |
| Linux aarch64 | **Supported** | CI job `Test (linux-arm64)` on `ubuntu-24.04-arm` |
| macOS (Apple Silicon / Intel) | **Partial** | CI runs `macos-latest` tests; release artifacts not certified |
| Windows | **Unsupported** | Not built or tested in CI |
| OpenWrt | **Unsupported** | Not targeted |
| Android / iOS native | **Unsupported** | Not targeted |

---

## Test coverage map (realistic expectations)

| Layer | What it proves |
|---|---|
| `tests/tests/e2e_*.rs` | Full `Instance` paths: SOCKS/HTTP → protocol → freedom (and variants) |
| `tests/tests/golden_vless.rs` | VLESS header bytes vs Xray vectors |
| `tests/tests/adversarial_*.rs` | Parser/state machine robustness under chaos |
| `crates/*/tests/production_readiness.rs` | Wiring guards, crypto edge cases, config fail-closed |
| `blackwire-transport/tests/interop.rs` | Live Xray/sing-box clients (`#[ignore]` by default) |
| `labs/realistic/` | Docker + optional two-VPS checklist |

**Not claimed:** full Xray feature parity, every `network`/`security` schema combination, or
production certification on all Experimental rows.

---

## Known intentional deviations

- Native JSON schema — not V2Ray/Xray config paste-compatible.
- VMess legacy non-AEAD / alterId — not implemented.
- DoH/DoT DNS upstreams — skipped at resolver build.
- XTLS Vision — flow recognized on wire; splice not implemented.
- `blackwire-api` gRPC management — deferred (stub crate).
- Full hot-reload of listeners, outbounds, and TLS material — requires process restart.

---

## Quick reference: lab mandatory green (local)

From `labs/realistic/README.md` — paths expected to pass in `make -C labs/realistic docker-full`:

- VLESS TCP  
- VLESS REALITY  
- VLESS over WebSocket  
- VMess over gRPC  
- Trojan over TLS  
- Shadowsocks 2022  
- Hysteria2  
- Xray REALITY interop  

**Advanced (smoke, not mandatory green):** ShadowTLS, mKCP, health/failover, DNS/geo routing guards.
