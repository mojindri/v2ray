# Xray / sing-box parity phases

Status on branch `feature/added_unsupported_features` (evidence: [feature-matrix.md](feature-matrix.md), [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md)).

## Shipped (code + tests + lab where applicable)

| Phase | Scope | Evidence |
|-------|--------|----------|
| **0** | Mandatory lab matrix, interop CI hooks | `labs/realistic/Makefile` `interop-server-docker`, lock + sequential matrix |
| **1** | VLESS UDP + SOCKS5 UDP | `vless-udp` row, `vless/udp.rs` |
| **2** | Sniffing, destOverride, protocol routing | `blackwire-app/sniff.rs`, dispatcher wiring |
| **3** | DoH / DoT / `udp://` DNS | `blackwire-app/dns/resolver.rs` |
| **4** | HTTPUpgrade + QUIC + SplitHTTP (minimal) | Rows `vless-httpupgrade`, `vless-quic`, `vless-splithttp`; transports in `blackwire-transport` |
| **5** | XTLS Vision (unpadding + direct-copy) | `vless/vision.rs`, `vless-vision` matrix row |
| **6** | Hot-reload routing/users; structural rebuild on file change | `reload.rs`, `blackwire-cli` watch loop |
| **7** | Stats gRPC API | `blackwire-api` StatsService + `runtime_stats` |
| **8** | Fast Docker matrix harness | `run-docker-matrix.sh` — 12 protocols, 46 PASS + 2 SKIP |

Local gate:

```bash
make -C labs/realistic finalize
```

## Partial / upstream-limited (documented SKIPs)

| Item | Notes |
|------|--------|
| **Xray legacy QUIC** | Xray 26+ removed QUIC transport; matrix SKIPs `xray-vless-quic`; sing-box proves row |
| **SplitHTTP / xHTTP** | Minimal PUT tunnel in blackwire; full client xHTTP framing TBD; matrix SKIPs positive clients; e2e `phase6_vless_splithttp_echo` |
| **Vision TLS splice** | Direct-copy when TLS records detected; not full kernel splice |
| **Handler gRPC** | Stats only; no add/remove inbound API |
| **VLESS MUX (0x03)** | Not decoded; probes fall through to fallback |

## Implemented in code (upstream-aligned)

| Phase | Status | Upstream reference |
|-------|--------|-------------------|
| **9** | Vision unpadding + direct-copy on TLS records | Xray `proxy/vless/encoding`, `vision.rs` |
| **10** | VLESS `CMD 0x03` decoded; relayed as TCP (Mux.Cool legacy) | Xray VLESS CMD table |
| **11** | Structural reload rebuilds `Instance` (Xray: listeners not hot-swapped) | Xray `HandlerService` / file reload |
| **12** | `IPIfNonMatch` + `IPOnDemand` routing | [Xray routing.domainStrategy](https://xtls.github.io/en/config/routing.html) |

## Remaining (post-merge backlog)

| Phase | Work |
|-------|------|
| **9b** | Full kernel TLS splice audit vs Xray relay |
| **10b** | Full Mux.Cool session demux (not only TCP relay) |
| **11b** | In-place listener rebind without full `Instance` rebuild |
| **12b** | Sniffing-specific external-client lab rows |
| **13** | ShadowTLS + mKCP mandatory matrix rows |
| **14** | Hysteria2 / REALITY hostility + promotion to Supported |
| **15** | Handler API, pcap-on-failure, fingerprint goldens |
| **16** | VPS matrix fast path + two-VPS promotion |

## Matrix rows (`scenarios.env`)

12 protocols × 4 cases = 48 lines; 2 SKIPs when upstream cannot run the client transport.
