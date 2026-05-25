# Phase 8 Linux TUN Mode Example

This example shows the intended Linux TUN interception shape:

```text
applications
  -> Linux policy routing / TUN interface
  -> local redirect ports
  -> SOCKS5 or HTTP inbound
  -> routing rules
  -> proxy or direct outbound
```

The TUN defaults match the transport helper defaults: `blackwire-tun`, address
`198.18.0.1`, route table policy mark `0x1234`, TCP redirect port `7890`, and
DNS redirect port `5300`. Linux setup requires root or the needed network
capabilities because it creates a TUN device and installs `ip rule`, `ip route`,
and `iptables` rules.

Current caveat: the top-level `tun` schema is parsed and the Linux helper module
can create the device and install routes. The transport crate also has packet
parsing, UDP response packet synthesis, and NAT/session tracking primitives.
`blackwire-core` still deliberately rejects `tun` configs at startup because a safe
runtime still needs the privileged device loop, TCP stream reassembly, DNS
handling, and cleanup behavior. Enabling routes without that runtime would
blackhole real traffic, so this example documents the expected deployment shape
only.

Validate:

```sh
cargo run -q -p blackwire -- test -c examples/phase8-tun-local/config.json
cargo test -p blackwire-core --test production_readiness top_level_tun_config_is_rejected_until_packet_runtime_exists
```

Author: @moji.ndr
