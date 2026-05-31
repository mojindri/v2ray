# Release Guide

## Support Contract

This is a pre-1.0 project. The table below is the release support contract.
Any area not listed as **Supported** carries an explicit caveat.

This file owns release support labels. Detailed feature evidence lives in
[feature-matrix.md](feature-matrix.md), and gate commands live in
[11-testing.md](11-testing.md) / [test-workflows.md](test-workflows.md).

### Supported (safe to rely on)

Validated by CI, the e2e test suite, and the realistic lab mandatory matrix.

- VLESS over TCP, REALITY, WebSocket, HTTPUpgrade, SplitHTTP (stream-one + packet-up)
- Hysteria2 (QUIC + HTTP/3 auth, TCP+UDP relay)
- V2Ray QUIC transport (`network: quic`) with matrix proof via sing-box and documented Xray legacy-client SKIP
- ShadowTLS v3 and mKCP server transports (server paths supported; external-client rows intentionally SKIP due upstream client-model limits)
- VMess AEAD over TCP
- VMess over gRPC (Gun transport); END_STREAM propagation validated
- Trojan over TLS/TCP
- Shadowsocks 2022 (TCP + UDP SIP022)
- SOCKS5 inbound (TCP CONNECT + UDP ASSOCIATE), HTTP CONNECT inbound, Freedom outbound
- DNS resolver (system, DoH, DoT), FakeIP pool, DNS cache, `domain_strategy`
- HTTP + TLS + FakeDNS sniffing with `destOverride`, `routeOnly`, `metadataOnly`
- Routing rules (domain, suffix, keyword, regex, IP/CIDR, port, source_ip, inboundTag, sniffed `protocol`, GeoIP/geosite)
- Load balancer with health-check failover
- Prometheus metrics (`/metrics`, `/healthz`, `/readyz`, `/version`)
- Config hot-reload: routing rules, VLESS user UUIDs, GeoIP/geosite data
- Structural config reload via automatic CLI instance rebuild with rollback
- Native JSON config schema with fail-closed validation
- Per-inbound / global `max_connections` limits (TCP, mKCP, QUIC, Hysteria2)
- Resource-risk smoke coverage in normal CI
- External-client failure pcaps captured and uploaded by CI
- TUN transparent proxy on Linux/macOS/Windows, covered by privileged CI smoke tests; Linux outbound sockets use `SO_MARK`; macOS utun runtime installs split default routes plus a PF anchor for TCP/DNS redirection and uses `tun.outboundInterface`/`tun.outbound_interface` for protected proxy egress; Windows Wintun device creation, split-route setup, packet-level TCP bridging to the local SOCKS listener, and protected outbound interface binding are wired (Windows full-device runtime requires `tun.outboundInterface`/`tun.outbound_interface`), and Windows can use `tun.wintunFile`/`tun.wintun_file` to point at a bundled `wintun.dll`; shared packet/NAT/session APIs and the runtime packet loop compile cross-platform; full-device runtime support is reported through an explicit platform support contract
- Handler API structural endpoint operations with rebuild rollback

### Experimental (implemented; missing hostile-network or soak proof)

Treat these as unstable — they may be promoted or downgraded in later releases.

- Stats API (gRPC) (uptime, RSS, task count wired; no soak or observability validation)

### Unsupported (fail-closed or explicitly out of scope)

The following are not implemented. Attempting to configure them will fail
at config validation (before any traffic is handled) or return an error at runtime.

- `protocol: shadowtls` as an inbound or outbound — fails validation with a message to use `security: shadowtls` in `streamSettings` instead
- V2Ray / Xray JSON config import — interop is wire-level only; translate configs manually
- Handler API structural endpoint RPCs use native blackwire endpoint JSON in `proxy_settings`; Xray core endpoint protobuf decoding is not implemented
- VMess legacy non-AEAD / alterId — only AEAD is implemented
- DNS, dokodemo, tun as inbound `protocol` values — not in the `Protocol` enum; deserialization fails
- Byte-identical browser TLS fingerprinting — functional interop ≠ identical ClientHello bytes
- OpenWrt, Android, iOS — not built or tested
- Standalone client app (TUN/system proxy UI)

---

## Release Gate Commands

Run these before tagging a release. Archive results in `labs/realistic/reports/`.

```sh
make verify-local           # fmt, check, clippy, unit+integration tests
make -C labs/realistic finalize   # stable + advanced-smoke + external-client Docker matrix
make fuzz-smoke             # short fuzz pass (6 targets)
make audit                  # cargo-audit vulnerability check
make deny                   # cargo-deny license/advisory policy
```

Optional (manual, not CI-gated):

```sh
# Heavy resource-stress paths — run once and archive results
cargo test -p tests --test resource_limits -- --include-ignored
cargo test -p tests --test leak_assertions -- --include-ignored

# Performance benchmark
make perf                   # Lima VM latency benchmark

# VPS validation
SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make verify-remote
```

Latest VPS gate evidence (2026-05-30): `make -C labs/realistic interop-server-vps` passed using two production VPS hosts (`SSH_SERVER=<server-host>`, `SSH_CLIENT=<client-host>`) with PASS/SKIP-only outcomes; `ss2022-udp` is PASS for both Xray and sing-box. See `labs/realistic/reports/external-clients-vps/summary.txt`.

---

## Release Assets

GitHub automatically attaches source archives to every release. Final product
downloads are produced by `.github/workflows/release-assets.yml`.

The workflow runs when a `v*` tag is pushed, or manually through
`workflow_dispatch` with a tag input. Tags containing `-` are created as
prereleases.

Expected assets:

- `blackwire-linux-x86_64.tar.gz`
- `blackwire-linux-arm64.tar.gz`
- `blackwire-macos.tar.gz`
- `blackwire-windows-x86_64.zip`
- one `.sha256` file for each archive

For the current release candidate:

```sh
git push origin HEAD
git push origin v0.1.0-rc.3
```

If the release already exists but only has GitHub source archives, run the
workflow manually for the tag:

```sh
gh workflow run release-assets.yml -f tag=v0.1.0-rc.3
```

## Container Image

`.github/workflows/container-image.yml` publishes the Docker image to GHCR when a
`v*` tag is pushed, or manually through `workflow_dispatch` with a tag input.

For prerelease tags such as `v0.1.0-rc.3`, the workflow publishes:

- `ghcr.io/<owner>/<repo>:v0.1.0-rc.3`
- `ghcr.io/<owner>/<repo>:0.1.0-rc.3`
- `ghcr.io/<owner>/<repo>:rc`

For stable tags such as `v0.1.0`, the workflow publishes:

- `ghcr.io/<owner>/<repo>:v0.1.0`
- `ghcr.io/<owner>/<repo>:0.1.0`
- `ghcr.io/<owner>/<repo>:latest`

The image is built for `linux/amd64` and `linux/arm64`, includes OCI labels,
uses the GitHub Actions Docker build cache, and requests SBOM/provenance
attestations from BuildKit.

## Install Script

`scripts/install.sh` installs Linux release assets from GitHub Releases. It
supports `linux/amd64` and `linux/arm64`, verifies the release `.sha256`, installs
the binary to `/usr/local/bin/blackwire`, creates `/etc/blackwire`, and installs
a systemd unit when systemd is available.

Prerelease install:

```sh
curl -fsSL https://raw.githubusercontent.com/mojindri/v2ray/v0.1.0-rc.3/scripts/install.sh \
  | VERSION=v0.1.0-rc.3 bash
```

Stable install, after a stable release is marked latest:

```sh
curl -fsSL https://raw.githubusercontent.com/mojindri/v2ray/main/scripts/install.sh | bash
```

By default, the installer does not start the service. To start immediately after
installing, create `/etc/blackwire/config.json` first and set `START_SERVICE=1`.
For mirrors or installer tests, set `BLACKWIRE_DOWNLOAD_BASE` to a directory URL
that contains the archive and matching `.sha256` file.

## Package Repositories

Debian/Ubuntu `.deb`, RPM, Arch, Homebrew, Winget, and Chocolatey publishing are
not automated yet. Keep those for a stable post-`v0.1.0` packaging pass after
config paths, service behavior, and upgrade policy are settled.

---

## Canary Plan

- Start with 5% traffic for 30 minutes.
- Use real traffic with normal auth mix and background bad-auth noise.
- Keep periodic config reload enabled during canary.

Helper:

```bash
bash tools/canary/run_canary.sh
```

### Required Dashboards / Alerts

Monitor:

- error rate
- p99 latency
- RSS
- fd count
- task count
- auth failures
- outbound timeout rate
- DNS failure rate
- session evictions

---

## Rollback

Rollback helper:

```bash
bash tools/canary/rollback.sh <previous-release-tag>
```

Rollback path:

1. shift traffic back to stable
2. redeploy previous release tag
3. restore last-known-good config snapshot
4. verify health and synthetic probes
5. verify memory/fd/task counters converge to baseline

---

## Promote-or-Keep-Experimental Checklist

A feature moves from Experimental/Partial to Supported **only** when all items below are met.

| Feature | Required proof before promotion |
| ------- | -------------------------------- |
| REALITY | Docker matrix `vless-reality` Xray+sing-box PASS; e2e + transport tests PASS; fail-fast handshake timeouts wired |
| Hysteria2 | Docker matrix `hysteria2` Xray+sing-box PASS; TCP+UDP e2e PASS; auth/stream timeout and UDP worker-cap hardening wired |
| TUN | Privileged Linux/macOS/Windows CI smoke tests, route setup/cleanup, UDP NAT, rollback-on-failure |
| Structural hot-reload | Listener add/remove, port change, outbound add/remove, TLS material reload, rollback on failed reload |
| ShadowTLS v3 | Documented exception: upstream clients SKIP this row; server path Supported with e2e PASS |
| mKCP | Documented exception: upstream clients SKIP this row; server path Supported with e2e PASS |
