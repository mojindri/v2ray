# Xray / sing-box parity status

Current status for wire parity with [Xray-core](https://github.com/XTLS/Xray-core) and [sing-box](https://github.com/SagerNet/sing-box). Evidence: [feature-matrix.md](feature-matrix.md), [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md).

**Strict rule:** In-tree or uncommitted code does **not** move a feature to **Supported** without step **4** in the [priority ladder](xray-parity-roadmap.md) (external-client matrix PASS), unless listed under intentional deviations.

## Local gates

```bash
make -C labs/realistic finalize          # stable + advanced smoke + external-client Docker matrix
make -C labs/realistic interop-server-docker   # matrix only
```

VPS promotion (`SSH_SERVER`, `SSH_CLIENT`):

```bash
make -C labs/realistic interop-server-vps
```

## Strict priority queue (work order)

See [xray-parity-roadmap.md](xray-parity-roadmap.md). Summary:

| Priority | Item | Matrix / proof today |
|----------|------|----------------------|
| **P0** | Trojan UDP (`CMD 0x03`, 8192 B frames) | `trojan-udp` Xray+sing-box **PASS** (`udp-socks-probe.sh` Python SOCKS5 UDP ASSOCIATE) |
| ~~**P0**~~ | ~~Mux.Cool TCP (`v1.mux.cool`)~~ | `vless-mux` Xray **PASS**; sing-box SKIP (smux ≠ Mux.Cool); outbound client shipped (PR #19) |
| **P1** | XUDP (GlobalID, session 0) | `vless-udp` Xray **PASS** (Mux.Cool session 0 + GlobalID); sing-box **PASS** (VLESS CMD UDP + xudp) |
| **P1** | SplitHTTP stream-one (HTTP/2 via ALPN h2) | `vless-splithttp` Xray+sing-box **PASS** |
| ~~**P2**~~ | ~~SplitHTTP packet-up (seq; H2 GET/POST)~~ | `vless-splithttp-packet-up` Xray **PASS**; sing-box **SKIP** (upstream has no packet-up) |
| ~~**P2**~~ | ~~SS2022 SIP022 UDP~~ | `ss2022-udp` Xray+sing-box **PASS** |

## Shipped with upstream client proof (matrix or documented SKIP)

| Area | Evidence |
|------|----------|
| External-client Docker matrix | `run-docker-matrix.sh` — 16 protocol rows (incl. `vless-splithttp-packet-up` Xray PASS; sing-box SKIP) |
| VLESS UDP command `0x02`, sniffing, DNS DoH/DoT | Lab rows per feature matrix |
| HTTPUpgrade, QUIC, SplitHTTP **stream-one** (HTTP/2) | Transports + e2e + `vless-splithttp` Xray+sing-box **PASS** |
| Vision, hot-reload, Stats gRPC | `vision.rs`, `reload.rs`, `blackwire-api` |
| Routing `IPIfNonMatch` / `IPOnDemand` | `router.rs`, `dispatcher.rs` |
| Trojan TCP, VMess, SS2022 TCP/UDP, REALITY, WS, gRPC | Matrix rows + e2e |
| Handler gRPC (VLESS user ops) | API listener user add/remove |

## External-client matrix SKIPs (not “unsupported in blackwire”)

| Lab row | blackwire server | Xray client | sing-box client | Why SKIP |
|---------|------------------|-------------|-----------------|----------|
| `vless-quic` | Yes | SKIP | PASS | Xray 26+ removed legacy QUIC transport |
| `vless-shadowtls` | Yes | SKIP | SKIP | Xray 26+ / sing-box model mismatch — server e2e |
| `vless-mkcp` | Yes | SKIP | SKIP | sing-box no mKCP; Xray 26 finalmask |
| `vless-splithttp-packet-up` | Yes | PASS | SKIP | Upstream [sing-box](https://github.com/SagerNet/sing-box) has no xHTTP `packet-up`; Xray proves row |

`vless-splithttp` uses **stream-one** only (both clients). `vless-splithttp-packet-up` is a separate row: **Xray PASS** is the matrix gate; stock sing-box is **SKIP** by design (same pattern as `vless-mux`).

## Accepted limits (not matrix blockers)

| Item | Notes |
|------|--------|
| Vision TLS splice | Direct-copy on TLS records; not kernel splice |
| Trojan UDP outbound | `connect_trojan_on_stream_udp()`; in-process e2e PASS; no external-client lab row |
| XUDP vs Mux.Cool UDP | XUDP: session `0` + GlobalID; Mux.Cool UDP: non-zero session id |
| Hot-reload listeners | `AddInbound`/`RemoveInbound` listener rebind UNIMPLEMENTED |
| Native JSON only | Xray/sing-box JSON not imported |

## Backlog (post–P0/P1)

| Item | Work |
|------|------|
| SplitHTTP packet-up extras (Xmux, padding, `downloadSettings`) | Optional; hiddify-sing-box manual |
| Kernel TLS (`SO_KTLS`) | Experimental, isolated opt-in via `BLACKWIRE_ENABLE_KTLS=1` (`force` for debugging); default TLS path stays on rustls locally; CI sets `BLACKWIRE_ENABLE_KTLS=1` on Linux |
| In-place listener rebind | P4 |

## Related

- [xray-parity-roadmap.md](xray-parity-roadmap.md)
- [labs/realistic/external-clients/README.md](../labs/realistic/external-clients/README.md)
- [external-client-failure-triage.md](external-client-failure-triage.md)
