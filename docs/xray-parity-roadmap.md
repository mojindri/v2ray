# Xray / sing-box wire parity roadmap

Gap tracker ordered **strictly** by [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md). A row is not **Supported** until step **4** (external-client matrix PASS) unless documented as intentional deviation.

**Uncommitted / in-tree wire work** must match upstream bytes **before** docs or matrix labels claim interop.

---

## Priority ladder (strict)


| P      | Item                                                             | Primary upstream                                                                             | Step 4 gate                                                      | Uncommitted tree status                               |
| ------ | ---------------------------------------------------------------- | -------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------- |
| ~~**P0**~~ | ~~Trojan UDP ASSOCIATE (`CMD 0x03`, framed packets, max 8192 B)~~    | Xray `proxy/trojan` (`server.go`, `packet.go`)                                               | **PASS** `trojan-udp` Xray+sing-box                              | **Supported** — matrix-proven                         |
| ~~**P0**~~ | ~~VLESS Mux.Cool TCP (`CMD 0x03` / `v1.mux.cool`)~~                  | Xray `common/mux` + [Mux.Cool](https://xtls.github.io/en/development/protocols/muxcool.html) | **PASS** `vless-mux` Xray; sing-box SKIP                         | **Supported** — matrix-proven                         |
| ~~**P1**~~ | ~~VLESS XUDP (session `0`, 8-byte GlobalID, Keep per-packet dest)~~  | Xray `common/xudp` + `common/mux/frame.go`                                                   | **PASS** `vless-udp` Xray+sing-box                               | **Supported** — matrix-proven                         |
| ~~**P1**~~ | ~~SplitHTTP **stream-one** (xHTTP over HTTP/2, ALPN h2)~~         | Xray `splithttp` + sing-box HTTP transport                                                   | **PASS** `vless-splithttp` Xray+sing-box                         | **Supported** — matrix-proven                         |
| ~~**P2**~~ | ~~SplitHTTP **packet-up** (seq; H2 GET/POST)~~                    | Xray `transport/internet/splithttp`                                                          | **PASS** `vless-splithttp-packet-up` Xray; sing-box **SKIP** (no packet-up) | **Supported** — Xray matrix-proven; in-process e2e PASS   |
| ~~**P2**~~ | ~~SS2022 UDP (SIP022)~~                                              | Xray / sing-box shadowsocks 2022 UDP                                                         | `ss2022-udp` Xray+sing-box                                       | **Supported** — matrix-proven                         |
| ~~**P3**~~ | ~~Trojan / VLESS UDP **outbound** (client role)~~            | Xray outbound `PacketWriter`                                                                 | Client-leg lab or in-process client instance                     | **Supported** — `connect_trojan_on_stream_udp()` + VLESS `Command::Udp`; in-process e2e PASS |
| ~~**P3**~~ | ~~Health-check outbound failover~~                               | Xray balancer / observatory patterns                                                         | `health-failover` lab + e2e                                      | **Supported** — in-process + Docker lab PASS          |
| **P4** | Kernel TLS (`SO_KTLS`)                                        | Linux `setsockopt TCP_ULP "tls"` + `SOL_TLS` key install after rustls handshake             | Linux kernel 4.17+; graceful fallback on old kernels             | Experimental opt-in via `BLACKWIRE_ENABLE_KTLS=1`; default TLS path stays on rustls after large-payload reset issues in CI |
| **P4** | In-place Handler listener RPCs                                    | Xray Handler gRPC                                                                            | Optional panel parity                                            | Backlog                                               |


When Xray and sing-box disagree, add a second matrix row or document SKIP — never mark **Supported** from blackwire e2e alone.

---

## Done (matrix or documented SKIP)


| Focus                                                                              | Status                                                                    |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| CI interop smoke, external-client Docker matrix, Prometheus per-connection metrics | Done                                                                      |
| VLESS UDP command `0x02` + lab `vless-udp`                                         | Done (TCP curl probe; not full XUDP)                                      |
| Sniffing, destOverride, `vless-sniff`                                              | Done                                                                      |
| DoH / DoT DNS upstream                                                             | Done                                                                      |
| HTTPUpgrade + lab row                                                              | Done                                                                      |
| QUIC server; matrix Xray SKIP / sing-box PASS                                      | Done                                                                      |
| **SplitHTTP / xHTTP stream-one** (HTTP/2 via ALPN h2)                              | **matrix `vless-splithttp` Xray+sing-box PASS**                           |
| XTLS Vision + `vless-vision`                                                       | Experimental (splice TBD)                                                 |
| Hot-reload routing/users                                                           | Done                                                                      |
| Stats + Handler gRPC (VLESS user ops)                                              | Done                                                                      |
| VPS matrix script aligned with Docker                                              | Done                                                                      |
| **Trojan UDP ASSOCIATE** (`CMD 0x03`, framed packets)                              | **matrix `trojan-udp` Xray+sing-box PASS** (Python SOCKS5 UDP ASSOCIATE) |
| **VLESS Mux.Cool TCP** (`CMD 0x03` / `v1.mux.cool`)                               | **matrix `vless-mux` Xray PASS**; sing-box SKIP (smux ≠ Mux.Cool)        |
| **VLESS XUDP** (session 0, 8-byte GlobalID, Keep per-packet dest)                 | **matrix `vless-udp` Xray+sing-box PASS** (xudp + Python UDP probe)      |
| **SS2022 UDP (SIP022)**                                                            | **matrix `ss2022-udp` Xray+sing-box PASS** (SOCKS5 UDP probe)            |
| **Health-check outbound failover**                                                 | in-process e2e + Docker lab (`health-failover`) **PASS**                  |
| **Trojan UDP outbound** (`connect_trojan_on_stream_udp`) + **VLESS UDP outbound** (`Command::Udp`) | in-process e2e `e2e_trojan_udp_outbound.rs` + `e2e_vless_udp_outbound.rs` **PASS** |
| **SplitHTTP packet-up** (seq; H2 GET/POST)                                                         | **matrix `vless-splithttp-packet-up` Xray PASS**; sing-box SKIP (upstream lacks packet-up) |


---

## In progress (wire in tree ≠ Supported)


| Focus                          | Upstream alignment               | Next gate                                       |
| ------------------------------ | -------------------------------- | ----------------------------------------------- |
| SplitHTTP packet-up extras (Xmux, padding, `downloadSettings`) | Xray / hiddify-sing-box `v2rayxhttp` | Optional follow-up; not required for P2 closure |


---

## Verification

1. **Upstream source** — file:line in PR.
2. **Golden / vector** (optional).
3. **In-process e2e** — regression only.
4. **External client** — `make -C labs/realistic interop-server-docker`.

Related: [parity-status.md](parity-status.md), [feature-matrix.md](feature-matrix.md).
