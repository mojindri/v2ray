# Changelog

All notable release-facing changes are documented here.

This project is pre-1.0. The support contract is owned by
[docs/release.md](docs/release.md), and detailed feature evidence is owned by
[docs/feature-matrix.md](docs/feature-matrix.md).

## 0.1.0-rc.3 - 2026-05-31

### Added

- Linux, macOS, and Windows TUN runtime support with focused privileged smoke coverage.
- Handler API structural operations using native blackwire endpoint JSON with CLI-driven instance rebuild and rollback.
- Fast Profile (`profile = "fast"` / `--profile fast`) for a narrower latency-first production path.
- External-client matrix coverage driven by `labs/realistic/external-clients/scenarios.env`.
- SplitHTTP packet-up, VLESS Vision, VLESS Mux/XUDP, Trojan UDP, SS2022 UDP, Hysteria2 TCP/UDP, QUIC, ShadowTLS v3 transport, and mKCP server-path coverage.
- Docs ownership map so release status, feature evidence, test tiers, and lab details have clear sources of truth.
- Release asset workflow for Linux, Linux arm64, macOS, and Windows binaries with SHA256 files.
- GHCR image publishing for Linux amd64/arm64 release tags, with rc tags kept separate from `latest`.
- Linux install script for GitHub Release assets with checksum verification and optional systemd unit installation.
- Installer support for `CONFIG_PATH` / `CONFIG_URL` with config validation before service start.
- Linux VPS bootstrap options for generated VLESS TCP / VLESS REALITY configs, firewall guidance, upgrade, and uninstall.
- Linux domain TLS bootstrap using generated Trojan TLS config with certbot or existing certificate paths.

### Changed

- README now acts as an entry point instead of duplicating the full release contract.
- Release/status docs now describe matrix SKIPs as upstream client-model limits where applicable, not automatic unsupported server paths.
- Testing docs now use `scenarios.env` as the source of truth instead of hard-coded matrix row/PASS/SKIP counts.
- Fast Profile keeps safety checks identical to compatibility mode while rejecting high-complexity hot-path features.
- Removed unused workspace dependencies from several crates.

### Experimental

- Stats API (gRPC) exposes runtime stats, but remains experimental until soak and observability validation are complete.
- Kernel TLS (`SO_KTLS`) remains isolated and opt-in.

### Unsupported

- V2Ray/Xray JSON config import.
- VMess legacy alterId / non-AEAD.
- Xray core endpoint protobuf decoding for Handler structural RPCs.
- DNS, dokodemo, or tun as inbound `protocol` values.
- Byte-identical browser TLS fingerprinting.
- OpenWrt, Android, iOS, and standalone desktop/mobile client app packaging.

### Validation

- Local markdown link check passes across repository docs.
- Documentation stale-count/status searches are clean.
- `cargo check --workspace --all-targets --locked` and
  `cargo clippy --workspace --all-targets -- -D warnings` passed after the cleanup pass.
