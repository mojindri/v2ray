# Xray / sing-box wire parity roadmap

Gap tracker for closing parity with upstream. **Source of truth:** [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md). **Current status:** [parity-status.md](parity-status.md).

## Done in repo

| Focus | Status |
|-------|--------|
| CI interop smoke, external-client Docker matrix, Prometheus per-connection metrics | Done |
| VLESS UDP framing + inbound relay | Done (lab row) |
| Sniffing, destOverride, protocol routing context | Done (`vless-sniff` lab row) |
| DoH / DoT / `udp://` DNS upstream URLs | Done |
| HTTPUpgrade + external-client row | Done |
| QUIC / SplitHTTP server paths + e2e | Done (client matrix SKIPs documented) |
| XTLS Vision unpadding + `vless-vision` lab row | Done (full splice TBD) |
| Hot-reload routing/users; structural instance rebuild | Done |
| Stats + Handler gRPC (VLESS user ops) | Done |
| VPS matrix script aligned with Docker harness | Done |

## In progress / partial

| Focus | Status |
|-------|--------|
| XTLS kernel splice vs Xray | Partial |
| Full Mux.Cool demux for VLESS `0x03` | Partial |
| Handler listener/outbound tag RPCs (in-place rebind) | Config reload path only |
| SplitHTTP full xHTTP client interop | Server minimal only |
| ShadowTLS / mKCP external-client proof | Server + e2e; matrix clients skipped by upstream/config |

## Verification

- PR CI: integration tests + `advanced-features-smoke`.
- Release gate: `make -C labs/realistic finalize` (includes external-client matrix).
- Feature matrix **Supported** label: requires external-client PASS (or documented single-client SKIP with other proof — see [parity-status.md](parity-status.md)).
