# Phase 7 DNS FakeIP + Geo Routing Example

This example shows the Phase 7 DNS and routing syntax:

```text
local clients
  -> SOCKS5 / HTTP CONNECT inbounds
  -> routing rules
  -> direct outbound for private/CN traffic
  -> proxy outbound for other traffic
```

It enables FakeIP allocation from `198.18.0.0/15` and demonstrates
`geoip:` / `geosite:` routing rule syntax.

Current caveat: GeoIP/GeoSite matchers exist in the router layer, but this config
does not yet specify external `geoip.dat` or `geosite.dat` paths. Without loaded
geo databases, literal domain/IP rules still work, while `geoip:` and `geosite:`
rules are templates for the intended deployment shape.

Validate:

```sh
cargo run -q -p blackwire -- test -c examples/phase7-dns-fakeip-routing/config.json
```
