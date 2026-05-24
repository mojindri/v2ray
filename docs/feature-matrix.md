# proxy-rs Feature Matrix

Status labels:

| Label | Meaning |
|---|---|
| Supported | Expected to work and covered by local/interop tests |
| Experimental | Implemented but still needs more interop, load, or hostile-network testing |
| Partial | Some behavior exists, but compatibility or coverage is incomplete |
| Unsupported | Not implemented |
| Intentional deviation | Different from V2Ray/Xray by design |

## Product scope

**proxy-rs** is a Rust-native server that targets **wire compatibility** with
Xray-core and sing-box clients on supported protocol/transport combinations.
Validation runs against those upstream clients in local Docker labs and on real
VPS hosts — not mock peers alone.

| Area | Status | Notes |
|---|---|---|
| Xray / sing-box **wire interop** (server) | Supported | External-client matrix for REALITY, VLESS, Trojan, SS2022, etc. |
| Native config schema | Supported | Own JSON schema — not Xray JSON paste-compatible |
| V2Ray JSON config compatibility | Unsupported | Not a goal |
| Xray JSON config compatibility | Partial | Interop is wire-level; config must be translated to native schema |
| Client mode | Supported | Supported protocols only |
| Server mode | Supported | Primary focus — compatible with standard Xray/sing-box clients |

## Protocols

| Protocol | Client | Server | Status | Notes |
|---|---:|---:|---|---|
| SOCKS5 | N/A | Yes | Supported | TCP CONNECT; UDP ASSOCIATE partial/experimental |
| HTTP proxy / CONNECT | N/A | Yes | Supported | Proxy auth/header limits still need hardening |
| Freedom/direct | Yes | N/A | Supported | Direct outbound |
| VLESS | Yes | Yes | Supported | REALITY/TLS/WS/gRPC covered; XTLS Vision partial |
| VMess AEAD | Yes | Yes | Supported | Legacy alterId unsupported |
| Trojan | Yes | Yes | Supported | UDP associate partial |
| Shadowsocks 2022 | Yes | Yes | Supported | UDP coverage limited |
| Hysteria2 | Yes | Yes | Experimental | QUIC/UDP behavior needs hostility tests |

## Transports

| Transport | Status | Notes |
|---|---|---|
| TCP | Supported | Basic TCP transport |
| TLS | Supported | rustls provider |
| WebSocket | Supported | Xray interop exists |
| gRPC | Supported | Xray interop exists |
| REALITY | Experimental | Functional Xray d1 interop passes; byte-level fingerprint comparison still missing |
| ShadowTLS | Experimental | Implemented, needs more external-client interop |
| mKCP | Experimental | Implemented, needs hostility tests |
| QUIC/Hysteria2 | Experimental | Needs loss/jitter/bandwidth testing |
| HTTPUpgrade / xHTTP | Partial | Schema/research exists; runtime coverage must be verified |

## DNS

| Feature | Status | Notes |
|---|---|---|
| System resolver | Supported | |
| Custom DNS server | Supported | |
| UDP DNS | Supported | |
| TCP DNS | Partial | |
| FakeIP | Supported | More production edge cases needed |
| DNS cache | Supported | TTL respected |
| DoH | Unsupported | Not implemented |
| DoT | Unsupported | Not implemented |
| DNS leak tests | Partial | More direct-vs-proxied coverage needed |

## Routing

| Feature | Status | Notes |
|---|---|---|
| Domain match | Supported | |
| Full-domain match | Supported | |
| Suffix match | Supported | |
| Keyword match | Supported | |
| Regex match | Partial | Verify runtime/test coverage |
| IP CIDR match | Supported | |
| Port match | Supported | |
| Source IP match | Supported | |
| Inbound tag match | Supported | |
| Sniffed protocol/domain routing | Partial | More ambiguity tests needed |
| GeoIP / GeoSite | Supported | Requires data files |

## Security and production readiness

| Feature | Status | Notes |
|---|---|---|
| Fuzz smoke | Supported | `make fuzz-smoke` |
| Heavier fuzz | Experimental | `make fuzz-long` (`FUZZ_RUNS=…`), not scheduled/enforced |
| cargo-audit | Partial | `make audit` / `make security` (requires `cargo-audit`) |
| cargo-deny | Partial | `deny.toml` + `make deny` / `make security` (requires `cargo-deny`) |
| Connection limits | Partial | Basic TCP inbound limit support added; deeper global/account limits pending |
| Slowloris diagnostics | Partial | Diagnostic target exists; timeout enforcement still needs protocol-path hardening |
| Load testing | Partial | Managed local load helper exists; real benchmark thresholds still needed |
| Packet capture on failure | Unsupported | Needed for fingerprint/debugging |
| TLS/REALITY fingerprint comparison | Unsupported | Functional interop is not byte-level proof |

## Platform support

| Platform | Status | Notes |
|---|---|---|
| Linux x86_64 | Supported | Main target |
| Linux aarch64 | Partial | Needs CI verification |
| macOS Apple Silicon | Partial | Development works; not release-certified |
| Windows | Unsupported | Build/service/cert behavior not verified |
| OpenWrt | Unsupported | Not targeted |
| Android/iOS | Unsupported | Not targeted as native builds |

## Known intentional deviations

- Native config schema instead of V2Ray/Xray JSON compatibility.
- VMess legacy alterId support is not implemented.
- DoH/DoT are not implemented yet.
- Full V2Ray/Xray compatibility is not currently claimed.
