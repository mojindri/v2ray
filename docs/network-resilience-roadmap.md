# Network resilience roadmap

This backlog tracks reliability and compatibility hardening for difficult
networks, including DNS poisoning, DNS hijack, SNI filtering, TLS/protocol
fingerprinting, active probing, IP blocking, throttling, UDP interference, and
path instability.

Blackwire already has useful building blocks: REALITY, TLS/WS/gRPC/SplitHTTP,
Hysteria2, DNS DoH/DoT, FakeIP, sniffing, domain routing strategies, health
checks, and adaptive balancers. This roadmap turns those pieces into an
operator-facing hardening package.

## Goals

- Provide practical presets for difficult networks without promising perfect
  unblockability.
- Keep behavior measurable through logs, metrics, and panel status.
- Favor conservative automatic fallback over aggressive flapping.
- Make generated client links compatible with common clients.
- Keep panel exposure separate from proxy exposure.

## Non-goals

- Guarantees against state-level blocking.
- Domain fronting claims unless a supported CDN/path explicitly allows it.
- Byte-identical browser TLS fingerprinting unless independently verified.
- Automatic evasion of provider abuse rules or local law.

## TODO

### P0 - REALITY deployment checks

- [ ] Add a config/panel check that validates REALITY required fields:
  - private/public key pair shape
  - non-empty short ID
  - believable `serverName`
  - reachable `dest`
  - compatible fingerprint value
- [ ] Add an operator test command for a deployed REALITY inbound:
  - connect from outside the VPS
  - verify valid auth succeeds
  - verify invalid auth falls through to fallback instead of obvious reset
- [ ] Add panel warnings for weak cover choices:
  - local/private fallback destination
  - fallback domain does not match expected TLS behavior
  - missing public subscription host
- [ ] Document recommended REALITY deployment patterns and bad patterns.

### P1 - DNS hardening

- [ ] Add DNS bootstrap hardening for DoH/DoT hostnames:
  - optional pinned bootstrap IPs
  - optional bootstrap resolver
  - clear logs when bootstrap resolution falls back to system DNS
- [ ] Add DNS-over-proxy option for outbound/client-side modes.
- [ ] Add tests for DoH/DoT resolver parsing and bootstrap failure behavior.
- [ ] Add panel presets:
  - system DNS
  - DoH
  - DoT
  - FakeIP for TUN/transparent mode
- [ ] Document DNS poisoning/hijack caveats and recommended configs.

### P2 - Path diversity package

- [ ] Add a panel workflow for multiple public paths:
  - primary REALITY
  - backup WS/gRPC/SplitHTTP
  - optional Hysteria2 where UDP works
- [ ] Generate adaptive balancer profiles from enabled paths.
- [ ] Show current selected profile, score, health, and cooldown in panel.
- [ ] Add operator test that checks each configured path from the server and
  from an external client when available.
- [ ] Add docs for single-VPS vs multi-VPS expectations.

### P3 - Transport diversity presets

- [ ] Add config examples for:
  - REALITY TCP primary
  - WebSocket over TLS fallback
  - gRPC over TLS fallback
  - SplitHTTP fallback
  - Hysteria2 optional UDP path
- [ ] Add panel templates for these paths with safe defaults.
- [ ] Validate generated share links against common clients where possible.
- [ ] Add docs explaining when UDP-based transports are a bad fit.

### P4 - Active probing resistance checks

- [ ] Add negative-auth integration tests for public deployment examples.
- [ ] Check invalid client behavior:
  - wrong UUID/password
  - wrong short ID
  - wrong SNI
  - malformed TLS/protocol header
- [ ] Verify failure paths do not expose clear proxy-specific banners.
- [ ] Add metrics/log counters for fallback vs authenticated success.

### P5 - Fingerprint and timing hardening

- [ ] Track TLS ClientHello compatibility against Xray/sing-box expectations.
- [ ] Add optional packet padding where supported by the transport.
- [ ] Add configurable handshake and idle timeout presets for hostile networks.
- [ ] Add latency/throughput sampling per adaptive profile when selected-path
  byte accounting is available.
- [ ] Document that byte-identical browser fingerprinting is not currently a
  supported guarantee.

### P6 - IP blocking and rotation operations

- [ ] Add panel status for public IP/domain reachability.
- [ ] Add optional external probe endpoints for reachability checks.
- [ ] Add docs for domain/IP rotation:
  - DNS TTL expectations
  - subscription URL stability
  - when a new VPS/path is required
- [ ] Add import/export for path profiles so operators can move users between
  VPS nodes.

### P7 - Public panel hardening

- [ ] Add panel warning when bound to a public interface without HTTPS.
- [ ] Add docs for HTTPS reverse proxy deployment.
- [ ] Add optional allowlist / trusted proxy settings.
- [ ] Add rate limits for login and subscription endpoints.
- [ ] Add audit log entries for config apply, user changes, and token rotation.

## Notes

For difficult networks, the practical package is not one magic transport. It is
REALITY plus DNS hardening, path diversity, adaptive fallback, compatible client
links, and clear observability. Single-node deployments can be hardened, but
multi-path or multi-VPS setups are the real answer to IP blocking and route
instability.
