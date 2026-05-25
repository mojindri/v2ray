# Xray / sing-box parity status

Current status for wire parity with [Xray-core](https://github.com/XTLS/Xray-core) and [sing-box](https://github.com/SagerNet/sing-box). Evidence: [feature-matrix.md](feature-matrix.md), [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md).

## Local gates

```bash
make -C labs/realistic finalize          # stable + advanced smoke + external-client Docker matrix
make -C labs/realistic interop-server-docker   # matrix only
```

VPS promotion (`SSH_SERVER`, `SSH_CLIENT`):

```bash
make -C labs/realistic interop-server-vps
```

## Shipped in tree

| Area | Evidence |
|------|----------|
| External-client Docker matrix | `run-docker-matrix.sh` — 15 protocol rows, sequential clients |
| VPS matrix script parity | `run-vps-matrix.sh` — same `scenarios.env`, one server start per row |
| VLESS UDP, sniffing, DNS DoH/DoT | `blackwire-app`, lab rows where listed in feature matrix |
| HTTPUpgrade, QUIC, SplitHTTP (minimal server) | Transports + e2e; SplitHTTP clients not in matrix |
| Vision, hot-reload, Stats gRPC | `vision.rs`, `reload.rs`, `blackwire-api` StatsService |
| Routing `IPIfNonMatch` / `IPOnDemand` | `router.rs`, `dispatcher.rs` |
| VLESS MUX `0x03` decode | Relayed as TCP (not full Mux.Cool) |
| Sniffing lab row | `vless-sniff` on port `8452`, dedicated client configs |
| ShadowTLS / mKCP server configs | Lab rows + `advanced-features-smoke` e2e (clients skipped — see below) |
| Handler gRPC (VLESS user ops) | `ListInbounds`, `ListOutbounds`, `GetInboundUsersCount`, `GetInboundUsers`, `AlterInbound` add/remove VLESS user on API listener |

**Docker matrix (latest green run):** 15 protocols × 4 cases = 60 lines → **52 PASS, 8 SKIP, 0 FAIL** (`labs/realistic/reports/external-clients/summary.txt`).

## External-client matrix SKIPs (not “unsupported in blackwire”)

Matrix **SKIP** means no Xray/sing-box **client** config is run for that case. It does **not** mean the blackwire **server** lacks the transport.

| Lab row | blackwire server | Xray client | sing-box client | Why SKIP |
|---------|------------------|-------------|-----------------|----------|
| `vless-quic` | Yes | SKIP | PASS | Xray 26+ removed legacy QUIC transport; sing-box proves the row |
| `vless-splithttp` | Minimal PUT tunnel | SKIP | SKIP | Full xHTTP client framing not in matrix; e2e covers minimal server path |
| `vless-shadowtls` | Yes (v3) | SKIP | SKIP | Xray 26+ dropped `security: shadowtls` on VLESS outbound; sing-box uses a separate inbound model — server proven in integration e2e |
| `vless-mkcp` | Yes | SKIP | SKIP | sing-box has no mKCP V2Ray transport; Xray 26 uses `finalmask` — server proven in integration e2e |

Negative-auth cases for these rows still run where client configs exist (or skip when client is `-`).

## Accepted limits (not matrix blockers)

These match intentional Xray/sing-box deltas documented in [feature-matrix.md](feature-matrix.md). They are not open parity todos for the external-client gate.

| Item | Notes |
|------|--------|
| Vision TLS splice | Direct-copy on TLS records; not kernel splice |
| SplitHTTP / xHTTP | Minimal server tunnel; full client xHTTP not in matrix |
| VLESS MUX | `CMD 0x03` decoded; relayed as TCP until full Mux.Cool demux |
| Hot-reload listeners | Structural changes rebuild `Instance`; `AddInbound`/`RemoveInbound` RPCs return UNIMPLEMENTED |
| Handler listener RPCs | Add/remove inbound/outbound tags require config edit + reload (same as Xray panels that rewrite config) |

## Backlog (post-merge)

| Item | Work |
|------|------|
| Kernel TLS splice audit | Match Xray relay splice behavior |
| Full Mux.Cool demux | Beyond TCP relay for `CMD 0x03` |
| In-place listener rebind | Without full `Instance` rebuild |
| Hysteria2 / REALITY hostility | Hostile-network tests; promote to **Supported** in matrix |
| Handler listener rebind | In-place `AddInbound`/`RemoveInbound` without `Instance` rebuild |

## Related

- [xray-parity-roadmap.md](xray-parity-roadmap.md) — gap tracker (no numbered rollout)
- [labs/realistic/external-clients/README.md](../labs/realistic/external-clients/README.md)
- [external-client-failure-triage.md](external-client-failure-triage.md)
