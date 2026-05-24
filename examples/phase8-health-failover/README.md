# Phase 8 Health Checker + Failover Example

This example shows the intended health-checking load balancer shape:

```text
local app
  -> SOCKS5 inbound
  -> routing rule selects auto-proxy balancer
  -> health state filters dead outbounds
  -> latency strategy chooses the fastest alive outbound
  -> target site
```

The balancer watches `primary-vless` and `backup-ss2022`. When health checks mark
one path dead, new connections should fail over to the other path. If both paths
are dead, the balancer falls back to the first configured outbound so failures
stay explicit instead of disappearing silently.

Current caveat: balancer registration and background health-check tasks are now
wired into the main instance, but this example is still a narrow config/template
exercise rather than full failover proof under real load or multi-outbound fault
injection. Treat it as a starting point, not a production claim.

Validate:

```sh
cargo run -q -p blackwire -- test -c examples/phase8-health-failover/config.json
```

Author: @moji.ndr
