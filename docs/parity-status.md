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
| **P0** | Mux.Cool TCP (`v1.mux.cool`) | `vless-mux` Xray **PASS**; sing-box SKIP (smux ≠ Mux.Cool) |
| **P1** | XUDP (GlobalID, session 0) | `vless-udp` Xray **PASS** (Mux.Cool session 0 + GlobalID); sing-box **PASS** (VLESS CMD UDP + xudp) |
| **P1** | SplitHTTP stream-one | `vless-splithttp` PASS |
| **P2** | SplitHTTP packet-up (sing-box完整) | **Not in matrix** — stub must not be labeled Supported |
| **P2** | SS2022 SIP022 UDP | Unsupported |

## Shipped with upstream client proof (matrix or documented SKIP)

| Area | Evidence |
|------|----------|
| External-client Docker matrix | `run-docker-matrix.sh` — 15 protocol rows |
| VLESS UDP command `0x02`, sniffing, DNS DoH/DoT | Lab rows per feature matrix |
| HTTPUpgrade, QUIC, SplitHTTP **stream-one** | Transports + e2e + `vless-splithttp` |
| Vision, hot-reload, Stats gRPC | `vision.rs`, `reload.rs`, `blackwire-api` |
| Routing `IPIfNonMatch` / `IPOnDemand` | `router.rs`, `dispatcher.rs` |
| Trojan TCP, VMess, SS2022 TCP, REALITY, WS, gRPC | Matrix rows + e2e |
| Handler gRPC (VLESS user ops) | API listener user add/remove |

## Wire in tree — not matrix-Supported yet (includes uncommitted batch)

| Area | Upstream | Proof today | Gap to Supported |
|------|----------|-------------|------------------|
| Trojan UDP ASSOCIATE | Xray `proxy/trojan` | `trojan/udp.rs`, `e2e_trojan_udp.rs` | Matrix row + SOCKS UDP probe (P0) |
| VLESS Mux.Cool demux | Mux.Cool spec | `vless/mux.rs`, `e2e_vless_mux.rs` | MUX/XUDP client matrix (P0/P1) |
| SplitHTTP packet-up stub | sing-box xHTTP (partial) | Code only if `mode: packet-up` | Full sing-box parity (P2); **not** matrix |
| Health-check failover | Xray balancer patterns | e2e + lab dir | Confirm matrix PASS |

## External-client matrix SKIPs (not “unsupported in blackwire”)

| Lab row | blackwire server | Xray client | sing-box client | Why SKIP |
|---------|------------------|-------------|-----------------|----------|
| `vless-quic` | Yes | SKIP | PASS | Xray 26+ removed legacy QUIC transport |
| `vless-shadowtls` | Yes | SKIP | SKIP | Xray 26+ / sing-box model mismatch — server e2e |
| `vless-mkcp` | Yes | SKIP | SKIP | sing-box no mKCP; Xray 26 finalmask |

`vless-splithttp` uses **stream-one** only (both clients). Do not set `mode: packet-up` in matrix until P2 is done.

## Accepted limits (not matrix blockers)

| Item | Notes |
|------|--------|
| Vision TLS splice | Direct-copy on TLS records; not kernel splice |
| Trojan UDP outbound | Inbound ASSOCIATE only; Xray `PacketWriter` outbound not wired |
| XUDP vs Mux.Cool UDP | XUDP: session `0` + GlobalID; Mux.Cool UDP: non-zero session id |
| SS2022 UDP | SIP022 UDP wire not implemented |
| Hot-reload listeners | `AddInbound`/`RemoveInbound` listener rebind UNIMPLEMENTED |
| Native JSON only | Xray/sing-box JSON not imported |

## Backlog (post–P0/P1)

| Item | Work |
|------|------|
| SOCKS UDP probe in matrix harness | Prove Trojan/VLESS UDP with real DNS datagram |
| SS2022 SIP022 UDP relay | P2 |
| SplitHTTP full packet-up | P2 — sing-box reference |
| Kernel TLS splice audit | P4 |
| In-place listener rebind | P4 |

## Related

- [xray-parity-roadmap.md](xray-parity-roadmap.md)
- [labs/realistic/external-clients/README.md](../labs/realistic/external-clients/README.md)
- [external-client-failure-triage.md](external-client-failure-triage.md)
