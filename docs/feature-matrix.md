# blackwire Feature Matrix

Last updated against the `blackwire-*` workspace crates, `tests/tests/` e2e
suite, `labs/realistic/` interop lab, and GitHub Actions (CI + cross-platform).

**Source of truth:** Wire behavior and “Supported” labels are validated against real Xray-core and sing-box clients in the realistic lab — not blackwire’s schema or this table alone. See [parity-status.md](parity-status.md) (matrix **SKIP** ≠ server unsupported).

**Release posture** (see [release.md](release.md) for the full support contract):

| Label | Release meaning |
| ----- | --------------- |
| **Supported** | Safe to rely on in production — tested by CI, e2e suite, and realistic lab |
| **Partial** | Shipped but has a known gap; read the notes before production use |
| **Experimental** | Implemented end-to-end; missing hostile-network, breadth, or soak coverage |
| **Unsupported** | Not implemented or explicitly fail-closed |

Status labels:


| Label                     | Meaning                                                                                                       |
| ------------------------- | ------------------------------------------------------------------------------------------------------------- |
| **Supported**             | Wired in `blackwire-core` `Instance`, exercised by automated tests or the realistic lab mandatory matrix      |
| **Experimental**          | Implemented end-to-end but missing hostile-network coverage, external-client breadth, or production hardening |
| **Partial**               | Code or schema exists; behavior, wiring, or observability is incomplete                                       |
| **Unsupported**           | Not implemented or explicitly stubbed                                                                         |
| **Intentional deviation** | Differs from V2Ray/Xray by design                                                                             |


Evidence shorthand: crate paths use `blackwire-{common,config,app,core,protocol,transport,tls,api,cli}`.

---

## Product scope

**blackwire** is a Rust-native **proxy server** that implements **selected wire-compatible
server paths** validated against Xray-core and sing-box clients. Compatibility is
proved by in-process e2e tests, per-crate `production_readiness` tests, and Docker
labs with real upstream clients — not spec claims or mock peers alone.

No claim of full Xray/sing-box feature parity is made. See the Unsupported rows and
[release.md](release.md) for what is explicitly out of scope.


| Area                                            | Status           | Notes                                                                                                                                                                                                                                                         |
| ----------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Xray / sing-box **wire interop** (as server)    | **Experimental** | REALITY d1 interop in `blackwire-transport/tests/interop.rs` (`#[ignore]` without `tests/interop`); Docker matrix **56 PASS / 8 SKIP** on 16 rows (+ `vless-splithttp-packet-up` Xray+hiddify wired, pending PASS) — see [parity-status.md](parity-status.md) |
| Native JSON config schema                       | **Supported**    | `blackwire-config` — validated at load; fail-closed schema tests                                                                                                                                                                                              |
| V2Ray JSON config                               | **Unsupported**  | Not a goal                                                                                                                                                                                                                                                    |
| Xray JSON config                                | **Unsupported**  | Interop is wire-level only; configs must be translated                                                                                                                                                                                                        |
| **Server mode** (listen for clients)            | **Supported**    | Primary product: `blackwire run`                                                                                                                                                                                                                              |
| **Local proxy mode** (SOCKS/HTTP in → outbound) | **Supported**    | Same `Instance` stack; covered by e2e (`e2e_socks5_vless`, `e2e_http_connect`, etc.)                                                                                                                                                                          |
| Standalone **client app** (TUN/system proxy UI) | **Unsupported**  | No dedicated client binary or mobile/desktop shell; TUN is server-side transparent path                                                                                                                                                                       |


---

## Protocols

Inbound handlers registered in `blackwire-core/src/instance/mod.rs`:
`Socks`, `Vless`, `Trojan`, `Vmess`, `Http`, `Shadowsocks`, `Hysteria2`.

Outbound handlers: `Freedom`, `Vless`, `Hysteria2`, `Trojan`, `Vmess`, `Shadowsocks`.


| Protocol                              | Inbound | Outbound | Status           | Evidence / notes                                                                                                                                         |
| ------------------------------------- | ------- | -------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| SOCKS5 (TCP CONNECT)                  | Yes     | No       | **Supported**    | `blackwire-protocol/socks.rs`; e2e `e2e_socks5_vless.rs`                                                                                                 |
| SOCKS5 UDP ASSOCIATE                  | Yes     | Partial  | **Supported**    | `socks5_udp.rs` + TCP control channel; e2e `e2e_socks5_udp.rs` PASS; lab scenario `vless-udp` for VLESS path                                             |
| HTTP CONNECT                          | Yes     | No       | **Supported**    | `http_connect.rs`, `blackwire-core/http.rs`; e2e `e2e_http_connect.rs`                                                                                   |
| Freedom / direct                      | No      | Yes      | **Supported**    | `freedom.rs` — default direct outbound                                                                                                                   |
| VLESS (TCP)                           | Yes     | Yes      | **Supported**    | `vless/`; golden + e2e matrix                                                                                                                            |
| VLESS UDP command                     | Yes     | Yes      | **Supported**    | `vless/udp.rs` inbound relay; matrix `vless-udp` Xray+sing-box **PASS**; outbound `Command::Udp`; e2e `e2e_vless_udp_outbound.rs` PASS                   |
| VLESS MUX command (0x03)              | Yes     | Yes      | **Supported**    | Mux.Cool + XUDP in `vless/mux.rs`; outbound client in `vless/mux_client.rs` (N logical streams over one VLESS conn); matrix `vless-mux` Xray **PASS**; `vless-udp` Xray XUDP **PASS** |
| VLESS flow `xtls-rprx-vision`         | Yes     | Yes      | **Supported**    | `vless/vision.rs` via common `VisionStream`; lab row `vless-vision` green; Linux raw TCP flows hand off to splice/adaptive splice after Vision direct-copy negotiation |
| VMess AEAD                            | Yes     | Yes      | **Supported**    | `vmess/`; legacy **alterId unsupported**                                                                                                                 |
| Trojan (TCP)                          | Yes     | Yes      | **Supported**    | `trojan/`; e2e `e2e_trojan/`                                                                                                                             |
| Trojan UDP                            | Yes     | Yes      | **Supported**    | Xray `CMD 0x03`; inbound: matrix `trojan-udp` Xray+sing-box **PASS**; outbound: `connect_trojan_on_stream_udp()`; e2e `e2e_trojan_udp_outbound.rs` PASS  |
| Shadowsocks 2022                      | Yes     | Yes      | **Supported**    | `ss2022/`; e2e `e2e_ss2022.rs`, `e2e_ss2022_local.rs`                                                                                                    |
| SS2022 UDP relay (SIP022)             | Yes     | Yes      | **Supported**    | `ss2022/udp.rs` (sing-box SIP022 wire); e2e `e2e_ss2022_udp.rs` PASS; matrix `ss2022-udp` Xray+sing-box **PASS**                                         |
| Hysteria2                             | Yes     | Yes      | **Experimental** | `blackwire-transport/hysteria2/`, `blackwire-core/hysteria2.rs`; e2e `e2e_hysteria2_vless.rs`; lab mandatory path; QUIC/UDP needs more hostility testing |
| ShadowTLS as `protocol` enum          | No      | No       | **Unsupported**  | Only `security: shadowtls` on TCP inbounds/outbounds                                                                                                     |
| DNS / dokodemo / tun inbound protocol | No      | No       | **Unsupported**  | Not in `Protocol` enum                                                                                                                                   |


---

## Transports

Stack wired via `blackwire-core/outbound_transport.rs`, `ws_tls.rs`, and inbound
TCP accept in `instance/mod.rs`. Hysteria2 uses its own QUIC listener.


| Transport                              | Status           | Evidence / notes                                                                                                                                                                                                                                                                                                                                                           |
| -------------------------------------- | ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TCP                                    | **Supported**    | `blackwire-transport/tcp.rs`                                                                                                                                                                                                                                                                                                                                               |
| TLS (rustls)                           | **Supported**    | `transport/tls.rs`                                                                                                                                                                                                                                                                                                                                                         |
| WebSocket                              | **Supported**    | `transport/ws.rs`; e2e `e2e_vless_ws.rs`                                                                                                                                                                                                                                                                                                                                   |
| gRPC (Gun-style)                       | **Supported**    | `transport/grpc.rs`; e2e `e2e_http_vmess_grpc.rs`; `grpc_stream_reset` in `e2e_hostility.rs` PASS (END_STREAM propagates to downstream) |
| REALITY                                | **Experimental** | `transport/reality/`, `blackwire-core/reality.rs`; e2e `e2e_reality_vless.rs`; transport-only tests `e2e_reality.rs`; Xray d1 interop ignored test                                                                                                                                                                                                                         |
| ShadowTLS v3                           | **Experimental** | Server: `transport/shadowtls/` + e2e. Matrix: both clients **SKIP** (Xray 26+ outbound model; sing-box inbound model) — not “unsupported on server”                                                                                                                                                                                                                        |
| mKCP                                   | **Experimental** | Server: `transport/mkcp/` + e2e. Matrix: both clients **SKIP** (sing-box no mKCP; Xray 26 finalmask) — not “unsupported on server”                                                                                                                                                                                                                                         |
| QUIC (`network: quic` for VLESS/VMess) | **Experimental** | Server: `v2rayquic.rs` + e2e. Matrix: **sing-box PASS**, Xray **SKIP** (Xray 26+ removed legacy QUIC client transport)                                                                                                                                                                                                                                                     |
| Hysteria2 (QUIC + HTTP/3 auth)         | **Experimental** | `hysteria2/` — TCP stream proxy + UDP datagram path                                                                                                                                                                                                                                                                                                                        |
| TUN transparent proxy                  | **Supported (Linux/macOS)** | Linux TUN runtime via `transport/tun/` when `config.tun` is set; route setup/cleanup and UDP NAT covered by privileged `tun_priv.rs`; Linux outbound sockets use `SO_MARK`; macOS utun runtime installs split default routes plus a PF anchor for TCP/DNS redirection and uses `tun.outboundInterface`/`tun.outbound_interface` for protected proxy egress; Windows Wintun device creation, split-route setup, and protected outbound interface binding compile through the native `tun` crate backend and can use `tun.wintunFile`/`tun.wintun_file` to point at a bundled `wintun.dll`; shared packet/NAT/session APIs and the runtime packet loop compile cross-platform; `current_tun_support()`/`ensure_tun_runtime_supported()` make full-device runtime support explicit; Windows still needs native TCP redirection |
| HTTPUpgrade                            | **Supported**    | Inbound/outbound + lab row `vless-httpupgrade` (Docker external-client matrix)                                                                                                                                                                                                                                                                                             |
| SplitHTTP / xHTTP                      | **Supported**    | **stream-one** (ALPN h2): matrix `vless-splithttp` Xray+sing-box **PASS**. **packet-up** (seq reorder, H2 `GET /split/<uuid>` + `POST /split/<uuid>/<seq>`): matrix `vless-splithttp-packet-up` **Xray PASS**; sing-box **SKIP** (upstream has no packet-up); in-process e2e `vless_splithttp_packet_up_h2_echo` **PASS**. Extra xHTTP fields parse for native config parity (`xmux`, `downloadSettings`, placement/chunk hints), H2 packet-up multiplex sessions are accepted, stream-up GET-with-`seq` is accepted, and configured x-padding emits the requested header. |


---

## External-client matrix SKIPs (reference)

Full table: [parity-status.md](parity-status.md). Summary: **SKIP** = no client run in the lab, not “blackwire lacks the feature.”


| Row                         | Server in blackwire | Client proof in matrix                              |
| --------------------------- | ------------------- | --------------------------------------------------- |
| `vless-quic`                | Yes                 | sing-box only (Xray 26+ removed legacy QUIC client) |
| `vless-splithttp`           | Yes                 | Xray+sing-box **PASS** (HTTP/2 stream-one)          |
| `vless-splithttp-packet-up` | Yes                 | PASS                                                |
| `vless-shadowtls`           | Yes                 | None (e2e only)                                     |
| `vless-mkcp`                | Yes                 | None (e2e only)                                     |


---

## DNS (`blackwire-app/dns`)


| Feature                               | Status        | Notes                                                                                                                                      |
| ------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| System resolver (empty `servers`)     | **Supported** | `dns/resolver.rs` — hickory system config                                                                                                  |
| Custom upstream (plain IP, UDP 53)    | **Supported** | Parsed into hickory `NameServerConfig`                                                                                                     |
| DoH / DoT upstream URLs               | **Supported** | `https://` / `tls://` parsed in `dns/resolver.rs` (hickory)                                                                                |
| FakeIP pool + restore on dispatch     | **Supported** | `dns/fakeip.rs`, dispatcher; startup rejects invalid pool (`production_readiness`)                                                         |
| DNS response cache                    | **Supported** | `dns/cache.rs`                                                                                                                             |
| `domain_strategy` (routing)           | **Supported** | Xray `AsIs` / `IPIfNonMatch` / `IPOnDemand` in `dispatcher` + `router` (see [routing docs](https://xtls.github.io/en/config/routing.html)) |
| Sniffing HTTP + TLS (`destOverride`, `routeOnly`, `metadataOnly`) | **Supported** | `blackwire-app/sniff.rs`; HTTP Host + TLS SNI detection; lab row `vless-sniff` green in Docker matrix |
| Sniffing FakeDNS                      | **Supported**    | `sniff_fakedns` wired in dispatcher; `"fakedns"` in `destOverride` reverses fake IP → domain, sets `sniffed_protocol = "fakedns"`; `apply_dest_override` handles `"fakedns"`; 4 unit tests PASS (`sniff::tests`) |


---

## Routing (`blackwire-app`)


| Feature                                   | Status        | Notes                                                                                                         |
| ----------------------------------------- | ------------- | ------------------------------------------------------------------------------------------------------------- |
| `domain` (exact)                          | **Supported** | `router.rs` + unit tests                                                                                      |
| `domain_suffix`                           | **Supported** |                                                                                                               |
| `domain_keyword`                          | **Supported** |                                                                                                               |
| `domain_regex`                            | **Supported** | `RegexSet` in `DomainMatcher` + `domain_regex_match` test                                                     |
| `ip` / CIDR                               | **Supported** |                                                                                                               |
| `port`                                    | **Supported** |                                                                                                               |
| `source_ip`                               | **Supported** |                                                                                                               |
| `inboundTag`                              | **Supported** |                                                                                                               |
| `protocol` / sniffed domain rules         | **Supported** | `sniffed_protocol` is carried from HTTP/TLS/FakeDNS sniffing into routing context; router protocol-rule tests + lab row `vless-sniff` |
| GeoIP / geosite (`geoip:`, `geosite:`)    | **Supported** | `geo/`; missing data files → empty matchers + warn                                                            |
| Balancers (random / roundRobin / latency) | **Supported** | `balancer.rs`; HTTP health probes; in-process failover e2e `e2e_health_failover.rs`                           |
| Health-check failover under fault         | **Supported** | In-process e2e `e2e_health_failover.rs` + Docker lab (`make -C labs/realistic health-failover`) both **PASS** |
| Route to balancer tag                     | **Supported** | `production_readiness` tests                                                                                  |


---

## Operations


| Feature                                    | Status           | Notes                                                                                                                                                                                                             |
| ------------------------------------------ | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Config file load + validation              | **Supported**    | `blackwire-config`                                                                                                                                                                                                |
| `${ENV}` substitution                      | **Supported**    | `env.rs`                                                                                                                                                                                                          |
| File watch + validated reload notify       | **Supported**    | `ConfigManager::watch`; CLI subscribes                                                                                                                                                                            |
| Hot-reload **routing rules**               | **Supported**    | `blackwire-core/reload.rs` — `LiveRouter::swap`                                                                                                                                                                   |
| Hot-reload **VLESS user UUIDs**            | **Supported**    | Per-inbound registry refresh                                                                                                                                                                                      |
| Hot-reload **GeoIP/geosite data**          | **Supported**    | Reloaded with router rebuild                                                                                                                                                                                      |
| Hot-reload listeners / new tags / TLS keys | **Supported**    | `requires_instance_restart` detects structural changes; CLI rebuilds the running `Instance` and rolls back to the prior config if rebuild fails (rebuild path, not in-place listener swap) |
| Per-inbound / global `max_connections`     | **Supported**    | TCP (`transport/tcp.rs`), mKCP, QUIC, and Hysteria2 accept loops all honour the 3-level hierarchy (`limits.maxConnections` per-inbound → per-inbound-class → global) |
| Prometheus HTTP (`metricsAddr`)            | **Supported**    | `metrics.rs` — `/metrics`, `/healthz`, `/readyz`, `/version`                                                                                                                                                      |
| Per-connection Prometheus counters         | **Supported**    | `record_connection_`* called from `dispatcher` after each relay                                                                                                                                                   |
| Stats API (gRPC)                           | **Experimental** | `blackwire-api` StatsService + `runtime_stats`; starts when `api` listen set                                                                                                                                      |
| Handler API (gRPC)                         | **Supported**    | `ListInbounds`, `ListOutbounds`, `GetInboundUsersCount`, `GetInboundUsers`, `AlterInbound` VLESS add/remove; structural `AddInbound`, `RemoveInbound`, `AddOutbound`, `RemoveOutbound`, `AlterOutbound` accept native blackwire endpoint JSON in `proxy_settings`, rebuild the running CLI instance, and roll back on rebuild failure |


---

## Security, quality, and CI


| Feature                                           | Status           | Notes                                                                               |
| ------------------------------------------------- | ---------------- | ----------------------------------------------------------------------------------- |
| `make verify-local` (fmt, check, clippy, test)    | **Supported**    | Required on PRs via **CI / Rust**                                                   |
| Cross-platform tests/checks                       | **Supported**    | **Cross-platform** workflow: Linux/macOS full tests, Linux arm64 full tests, Windows all-target compile check on PRs |
| Fuzz targets (`fuzz/`)                            | **Supported**    | REALITY, VMess, VLESS, Hysteria2, ShadowTLS, SS2022, stateful sequences             |
| `make fuzz-smoke`                                 | **Supported**    | Short local smoke                                                                   |
| `make fuzz-long`                                  | **Experimental** | Optional; not CI-gated                                                              |
| `make audit` / `cargo-audit`                      | **Supported**    | Weekly **Security / Dependency audit** schedule + manual                            |
| `make deny` / `cargo-deny`                        | **Supported**    | `deny.toml` license/advisory policy                                                 |
| Adversarial integration tests                     | **Supported**    | `tests/tests/adversarial_*.rs` — fragmentation, cancellation, backpressure, etc.    |
| Leak / resource tests                             | **Supported**    | `resource_smoke.rs` covers bad-auth bursts, FakeIP/DNS pressure, stream churn, mKCP churn, and connection-limit overflow in normal CI; heavier ignored suites remain optional stress tests |
| External-client Docker lab                        | **Supported**    | `labs/realistic/` — 15 protocols × 4 cases; `run-docker-matrix.sh`                  |
| External-client VPS lab                           | **Supported**    | Same `scenarios.env` as Docker; `run-vps-matrix.sh` (one server start per protocol) |
| TLS/REALITY byte-level fingerprint diff vs Chrome | **Unsupported**  | Functional interop ≠ identical ClientHello bytes                                    |
| Packet capture on failure                         | **Supported**    | `interop-smoke.yml` runs the Docker external-client matrix with `MATRIX_PCAP_ON_FAIL=1` and uploads `labs/realistic/reports/` artifacts |


---

## Platform support


| Platform                      | Status          | Notes                                                         |
| ----------------------------- | --------------- | ------------------------------------------------------------- |
| Linux x86_64                  | **Supported**   | Primary dev and CI target                                     |
| Linux aarch64                 | **Supported**   | CI job `Test (linux-arm64)` on `ubuntu-24.04-arm`             |
| macOS (Apple Silicon / Intel) | **Supported**   | CI runs `macos-latest` tests; core proxy runtime is supported; utun device creation, split default route setup, PF TCP/DNS redirection, and protected outbound interface binding are wired |
| Windows                       | **Partial**     | CI runs Windows workspace tests; core proxy runtime is intended to be portable; Wintun device creation, explicit `wintun.dll` path, split-route setup, and protected outbound interface binding are wired, but full-device TUN runtime is still gated until native TCP redirection exists |
| OpenWrt                       | **Unsupported** | Not targeted                                                  |
| Android / iOS native          | **Unsupported** | Not targeted                                                  |


---

## Test coverage map (realistic expectations)


| Layer                                    | What it proves                                                        |
| ---------------------------------------- | --------------------------------------------------------------------- |
| `tests/tests/e2e_*.rs`                   | Full `Instance` paths: SOCKS/HTTP → protocol → freedom (and variants) |
| `tests/tests/golden_vless.rs`            | VLESS header bytes vs Xray vectors                                    |
| `tests/tests/adversarial_*.rs`           | Parser/state machine robustness under chaos                           |
| `crates/*/tests/production_readiness.rs` | Wiring guards, crypto edge cases, config fail-closed                  |
| `blackwire-transport/tests/interop.rs`   | Live Xray/sing-box clients (`#[ignore]` by default)                   |
| `labs/realistic/`                        | Docker + optional two-VPS checklist                                   |


**Not claimed:** full Xray feature parity, every `network`/`security` schema combination, or
production certification on all Experimental rows.

---

## Known intentional deviations

- Native JSON schema — not V2Ray/Xray config paste-compatible.
- VMess legacy non-AEAD / alterId — not implemented.
- DoH/DoT DNS upstreams — skipped at resolver build.
- Handler API (gRPC) — structural add/remove/alter RPCs use native blackwire endpoint JSON in `proxy_settings` rather than Xray core endpoint protobufs.
- Full hot-reload of listeners, outbounds, and TLS material — requires process restart.

---

## Quick reference: gates (local)


| Gate                | Command                                          | What it proves                                                                        |
| ------------------- | ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| Stable integration  | `make -C labs/realistic stable`                  | In-process protocol matrix                                                            |
| Advanced smoke      | `make -C labs/realistic advanced-features-smoke` | ShadowTLS, mKCP, QUIC/SplitHTTP e2e, health guards + failover runtime                 |
| Health failover lab | `make -C labs/realistic health-failover`         | In-process failover e2e + optional Docker probe/echo services                         |
| External clients    | `make -C labs/realistic interop-server-docker`   | Xray/sing-box/hiddify → blackwire (**56 PASS / 8 SKIP** on 16 rows + packet-up wired) |
| Full finalize       | `make -C labs/realistic finalize`                | All of the above                                                                      |


See [labs/realistic/README.md](../labs/realistic/README.md) and [parity-status.md](parity-status.md).
