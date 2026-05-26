# External-client failure triage

When `labs/realistic/reports/external-clients/summary.txt` shows `FAIL`, work in this order.

## 1. Logs (always first)

| Artifact | Path |
|----------|------|
| Summary | `labs/realistic/reports/external-clients/summary.txt` |
| Per-case log | `labs/realistic/reports/external-clients/logs/<client>-<protocol>.log` |
| Config render | `labs/realistic/reports/external-clients/render.log` |
| Compose | `labs/realistic/reports/external-clients/compose.log` |

Re-run a single case (sequential — do not start a second matrix while one is running):

```bash
# After a full matrix once produced generated configs:
docker logs blackwire-server
docker logs xray-client          # or sing-box-client / hiddify-sing-box-client
```

Rendered configs live under `labs/realistic/external-clients/generated/`.

## 2. Upstream source of truth

Do **not** guess wire format from blackwire comments. Read upstream:

| Client / area | Primary Go source |
|---------------|-------------------|
| VLESS header (TCP/UDP/MUX) | [Xray `proxy/vless/encoding/encoding.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go) |
| VLESS inbound | [Xray `proxy/vless/inbound/inbound.go`](https://github.com/XTLS/Xray-core/blob/main/proxy/vless/inbound/inbound.go) |
| WebSocket + TLS | [Xray `transport/internet/websocket`](https://github.com/XTLS/Xray-core/tree/main/transport/internet/websocket), [`tls`](https://github.com/XTLS/Xray-core/tree/main/transport/internet/tls) |
| sing-box VLESS outbound | [sing-box `protocol/vless`](https://github.com/SagerNet/sing-box/tree/dev-next/protocol/vless) + [`docs/configuration/outbound/vless`](https://sing-box.sagernet.org/configuration/outbound/vless/) |
| sing-box XUDP / packet_encoding | [sing-box internals — compatibility](https://singbox-internals.hidandelion.com/implementation/compatibility.html) |
| Trojan UDP framing | [Xray `proxy/trojan`](https://github.com/XTLS/Xray-core/tree/main/proxy/trojan) |
| Mux.Cool | [Mux.Cool spec](https://xtls.github.io/en/development/protocols/muxcool.html) |
| SplitHTTP packet-up (client) | [hiddify-sing-box `transport/v2rayxhttp/client.go`](https://github.com/hiddify/hiddify-sing-box/blob/extended/transport/v2rayxhttp/client.go) + [`server.go`](https://github.com/hiddify/hiddify-sing-box/blob/extended/transport/v2rayxhttp/server.go) |

## 3. Common failure modes (this repo)

| Symptom | Likely cause | Where to fix |
|---------|--------------|--------------|
| `FAIL xray-vless-ws` / `sing-box-vless-ws` | TLS SNI/Host vs cert SAN, WS path, or server not listening yet | `configs/server/vless-ws.json`, `ws_tls.rs`, matrix `wait_for_server_port` |
| `FAIL *-vless-udp` (TCP curl test) | Server port not ready; or client uses **XUDP** while blackwire supports **UDP cmd 0x02** and **Mux 0x03** separately | `vless/codec.rs`, `vless/udp.rs`, `vless/mux.rs` |
| `FAIL *-trojan-udp` (TCP ok, udp probe) | SOCKS `udp: true` missing; Trojan `CMD 0x03` relay; or proxychains/dig probe failed | `trojan/udp.rs`, `trojan-udp.json` templates, `udp-socks-probe.sh` |
| `FAIL xray-vless-splithttp-packet-up` | Xray packet-up path; verify `"mode": "packet-up"` + `"uplinkHTTPMethod": "POST"` in client template; check H2 GET `/split/<uuid>` + POST `/split/<uuid>/<seq>` routing in `splithttp_accept_h2_packet_up` | `splithttp.rs`, `vless-splithttp-packet-up.json.tmpl` (xray) |
| `SKIP sing-box-vless-splithttp-packet-up` | Expected — upstream sing-box has no packet-up; row gate is Xray only (`scenarios.env` sing-box column `-`) | `scenarios.env`, `parity-status.md` |
| `FAIL hiddify-vless-splithttp-packet-up` (manual only) | Optional hiddify-sing-box fork; not a matrix gate | `ghcr.io/hiddify/hiddify-sing-box`, `splithttp.rs` |
| `FAIL *-vless-mux` | sing-box **smux** ≠ Mux.Cool (row SKIP for sing-box); or VLESS `CMD 0x03` read past address into mux stream | `vless-mux.json` (Xray only), `vless/codec.rs` `CMD_MUX`, `vless/mux.rs` |
| `FAIL negative-sing-box-* accepted` | Wrong credential still reaches target — compare sing-box auth bytes with Xray negative templates | `render-configs.sh` negative UUIDs; `VlessUserRegistry` |
| Intermittent PASS/FAIL | Race: client starts before `blackwire` binds | `run-docker-matrix.sh` `wait_for_server_port` |
| `DNS resolution failed for 'target-http'` in Docker matrix | `docker compose run` without service DNS aliases; freedom cannot resolve compose service name | Add `--use-aliases` on server/client `compose run` (see `run-docker-matrix.sh`) |
| `server port 4433 not open for hysteria2` | Hysteria2 is **QUIC/UDP**; `nc -z` probes **TCP** only | `wait_for_server_port` skips TCP for `hysteria2` (same as `run-vps-matrix.sh`) |
| `xray-client` name already in use | Stale container after aborted matrix | `cleanup_case` force-removes client containers |

### VLESS command bytes (Xray)

From Xray `encoding.go`:

- `0x01` — TCP (+ port/address)
- `0x02` — UDP (+ port/address)
- `0x03` — MUX (`v1.mux.cool`) — used by sing-box **xudp**; **not** the same as our `CMD_UDP`

blackwire implements **Mux.Cool** (`v1.mux.cool`, cmd `0x03`), **UDP cmd `0x02`**, and **XUDP** (session `0` + GlobalID in `vless/mux.rs`). Row `vless-udp` clients use Xray mux + sing-box `packet_encoding: xudp`. Row `trojan-udp` adds a **SOCKS UDP DNS probe** after TCP curl. Row `vless-mux` exercises Mux.Cool TCP only.

## 4. Closing the loop

1. Fix blackwire to match upstream **or** adjust lab client config to match what we implement today.
2. Re-run **one** failed row sequentially: `make -C labs/realistic interop-server-docker` (full matrix) or patch `scenarios.env` to only the failing row while debugging.
3. Update [feature-matrix.md](feature-matrix.md) only after external-client PASS per [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md).
