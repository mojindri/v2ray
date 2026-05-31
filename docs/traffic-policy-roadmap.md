# Traffic policy roadmap

This is the backlog for abuse-prevention controls around public proxy/VPN
deployments. The first target is Xray/sing-box-style BitTorrent blocking through
protocol sniffing and routing, then broader rate/quota controls that still help
when protocol detection is bypassed.

## Goals

- Give operators a simple panel toggle for common abuse prevention.
- Keep the runtime behavior transparent: blocks should have clear log/metric
  reasons.
- Avoid heavy DPI. Sniff only the early bytes needed for routing decisions.
- Fail conservatively: if a policy is enabled but sniffing misses, connection
  limits and quotas should still cap damage.

## Non-goals

- Perfect detection of traffic hidden inside another encrypted tunnel.
- Full third-party DPI integration.
- Legal or copyright enforcement decisions inside the core runtime.

## TODO

### P0 - Xray/sing-box-style BitTorrent route block

- [ ] Add `bittorrent` as a first-class sniffed protocol value.
- [ ] Add TCP BitTorrent handshake sniffing:
  - first byte `19`
  - next 19 bytes equal `BitTorrent protocol`
- [ ] Preserve sniffed protocol metadata in the dispatcher/router path.
- [ ] Ensure existing route rules can match `protocol: ["bittorrent"]`.
- [ ] Add or document a `blackhole`/block outbound for rejected traffic.
- [ ] Add config example:
  - inbound sniffing enabled
  - routing rule `protocol: ["bittorrent"]`
  - outbound tag `block`
- [ ] Add unit tests for positive, partial, and near-miss TCP handshakes.
- [ ] Add integration test proving detected BitTorrent traffic routes to block.

### P1 - Panel policy toggle

- [ ] Add a Black UI toggle: `Block torrent/P2P abuse`.
- [ ] When enabled, generate/maintain the BitTorrent route rule safely.
- [ ] Ensure the toggle does not duplicate rules on repeated saves.
- [ ] Show recent policy-blocked events in the panel logs view.
- [ ] Validate that disabling the toggle removes only panel-managed policy rules.

### P2 - UDP policy

- [ ] Add per-inbound UDP allow/deny policy where protocol support permits it.
- [ ] Add per-user UDP allow/deny where user identity is known.
- [ ] Default panel-created public users to UDP disabled unless explicitly
  enabled.
- [ ] Add tests for UDP-denied behavior on SOCKS/VLESS/Trojan paths.

### P3 - uTP / UDP BitTorrent sniffing

- [ ] Add conservative uTP header sniffing for UDP BitTorrent.
- [ ] Add tests for valid uTP, short packets, and false-positive resistant
  near-misses.
- [ ] Route detected UDP BitTorrent with the same `protocol: ["bittorrent"]`
  rule.

### P4 - User and inbound limits

- [ ] Add per-user active connection counters.
- [ ] Add per-user max concurrent connections.
- [ ] Add per-user new-connection rate limit.
- [ ] Add per-inbound defaults that apply when user identity is unavailable.
- [ ] Emit metrics for limit hits by reason, inbound, and user where available.

### P5 - Quotas and speed caps

- [ ] Enforce per-user traffic quotas using selected-user accounting.
- [ ] Add optional speed caps per user or inbound.
- [ ] Persist quota counters across restart when the panel database is present.
- [ ] Expose quota state and reset controls in Black UI.

### P6 - Domain/rule-set support

- [ ] Add optional tracker/domain blocklist support.
- [ ] Keep blocklists operator-managed; do not hard-code legal policy into core.
- [ ] Add docs explaining that domain lists are supplemental, not sufficient.

## Notes

Xray and sing-box both support the core model this roadmap follows: sniff a
protocol, then let route rules match that sniffed protocol and send it to a
blocking outbound. Blackwire should mirror that operational shape first, then
layer UDP and quota controls for practical VPS abuse resistance.
