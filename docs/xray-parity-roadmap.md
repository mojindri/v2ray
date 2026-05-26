# Xray / sing-box wire parity roadmap

Gap tracker ordered **strictly** by [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md). A row is not **Supported** until step **4** (external-client matrix PASS) unless documented as intentional deviation.

**Uncommitted / in-tree wire work** must match upstream bytes **before** docs or matrix labels claim interop.

---

## Priority ladder (strict)

| P | Item | Primary upstream | Step 4 gate | Uncommitted tree status |
|---|------|------------------|-------------|-------------------------|
| **P0** | Trojan UDP ASSOCIATE (`CMD 0x03`, framed packets, max 8192 B) | Xray `proxy/trojan` (`server.go`, `packet.go`) | New matrix row `trojan-udp` + SOCKS UDP probe (DNS to resolver); until probe exists: **Partial** only | Inbound relay + e2e; outbound still TCP-only |
| **P0** | VLESS Mux.Cool TCP (`CMD 0x03` / `v1.mux.cool`) | Xray `common/mux` + [Mux.Cool](https://xtls.github.io/en/development/protocols/muxcool.html) | Matrix row with mux client config (not plain `vless-udp` row) | TCP demux + e2e; not matrix-proven |
| **P1** | VLESS XUDP (session `0`, 8-byte GlobalID, Keep per-packet dest) | Xray compatibility doc + `proxy/vless` outbound XUDP | Extend `vless-udp` / mux clients; sing-box `xudp` | **Not started** — do not label mux UDP as XUDP |
| **P1** | SplitHTTP **stream-one** (lab profile) | Xray `splithttp` + sing-box HTTP transport | Existing `vless-splithttp` matrix PASS | Shipped in matrix |
| **P2** | SplitHTTP **packet-up** (seq, Xmux, padding, `downloadSettings`) | sing-box `transport/http` xHTTP | New row only after sing-box client PASS; no invented framing | **Not upstream-complete** — do not enable in matrix |
| **P2** | SS2022 UDP (SIP022) | Xray / sing-box shadowsocks 2022 UDP | New `ss2022-udp` row | **Unsupported** |
| **P3** | Trojan / VLESS UDP **outbound** (client role) | Xray outbound `PacketWriter` | Client-leg lab or in-process client instance | Trojan outbound: CONNECT only |
| **P3** | Health-check outbound failover | Xray balancer / observatory patterns | `health-failover` lab + e2e | In tree; verify matrix |
| **P4** | Kernel TLS splice, in-place Handler listener RPCs | Xray relay / Handler gRPC | Audit + optional panel parity | Backlog |

When Xray and sing-box disagree, add a second matrix row or document SKIP — never mark **Supported** from blackwire e2e alone.

---

## Done (matrix or documented SKIP)

| Focus | Status |
|-------|--------|
| CI interop smoke, external-client Docker matrix, Prometheus per-connection metrics | Done |
| VLESS UDP command `0x02` + lab `vless-udp` | Done (TCP curl probe; not full XUDP) |
| Sniffing, destOverride, `vless-sniff` | Done |
| DoH / DoT DNS upstream | Done |
| HTTPUpgrade + lab row | Done |
| QUIC server; matrix Xray SKIP / sing-box PASS | Done |
| SplitHTTP stream-one + `vless-splithttp` | Done |
| XTLS Vision + `vless-vision` | Experimental (splice TBD) |
| Hot-reload routing/users | Done |
| Stats + Handler gRPC (VLESS user ops) | Done |
| VPS matrix script aligned with Docker | Done |

---

## In progress (wire in tree ≠ Supported)

| Focus | Upstream alignment | Next gate |
|-------|-------------------|-----------|
| Trojan UDP inbound | Matches Xray framing; 8192 B cap | Matrix + UDP probe |
| Mux.Cool TCP + UDP sub-streams | Mux.Cool yes; XUDP no | MUX client matrix row |
| SplitHTTP packet-up stub | **Not** sing-box-complete | Remove from matrix; implement P2 or delete stub |
| Health failover | Xray-like selection | `health-failover` matrix |

---

## Verification

1. **Upstream source** — file:line in PR.
2. **Golden / vector** (optional).
3. **In-process e2e** — regression only.
4. **External client** — `make -C labs/realistic interop-server-docker`.

Related: [parity-status.md](parity-status.md), [feature-matrix.md](feature-matrix.md).
