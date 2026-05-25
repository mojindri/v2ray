# Xray / sing-box wire parity roadmap

Implementation tracker for closing parity gaps. **Source of truth:** [xray-parity-source-of-truth.md](xray-parity-source-of-truth.md).

## Phases

| Phase | Focus | Status in repo |
|-------|--------|----------------|
| 0 | CI interop smoke, mandatory ShadowTLS/mKCP in `docker-full`, Prometheus per-connection metrics | Done |
| 1 | VLESS UDP framing + inbound relay | Initial (lab row pending) |
| 2 | Sniffing, destOverride, protocol routing rules | Initial |
| 3 | DoH/DoT/udp:// DNS upstream URLs | Done |
| 4 | HTTPUpgrade inbound + external-client row; SplitHTTP/xHTTP / QUIC TBD | Done |
| 5 | XTLS Vision unpadding + lab row `vless-vision` | In progress (splice/TLS direct-copy TBD) |
| 6 | Hot-reload listener diff helper | Partial |
| 7 | blackwire-api gRPC, pcap CI artifacts | Stub |

## Verification

- PR CI: **Interop smoke** workflow (`integration-tests` + advanced-features-smoke).
- Nightly: full `make -C labs/realistic interop-server-docker`.
- Feature matrix: update only after external-client PASS.

See the attached Cursor plan for full task breakdown and exit criteria.
