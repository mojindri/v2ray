# Config For Dummies

This is the practical guide to the config format used in this repo.

If you keep forgetting what goes in:

- `inbounds`
- `outbounds`
- `routing`
- `streamSettings`
- `metricsAddr`

start here.

## First Principle

The config answers five questions:

1. What ports should this proxy listen on?
2. What protocol should each listener speak?
3. Where should traffic go out?
4. How should routing choose an outbound?
5. Should any transport wrapper like TLS, WebSocket, or REALITY be used?

Everything else is a detail under one of those five.

## The Smallest Useful Config

This is the smallest shape worth understanding:

```json
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": 1080
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    }
  ],
  "routing": {
    "rules": [
      {
        "outboundTag": "direct"
      }
    ]
  }
}
```

This means:

- listen locally on `127.0.0.1:1080`
- speak SOCKS5 to local clients
- send everything out directly

## Top-Level Fields

## `log`

Controls logging.

Common fields:

- `level`
  log level like `info` or `warning`

- `json`
  whether logs are JSON formatted in examples that include it

## `inbounds`

What the proxy accepts from clients.

Each inbound needs:

- `tag`
- `protocol`
- `listen`
- `port`

Optional:

- `settings`
- `streamSettings`
- `sniffing`

Think of an inbound as:

"Open this port, speak this client-facing protocol."

## `outbounds`

What the proxy uses when sending traffic onward.

Each outbound needs:

- `tag`
- `protocol`

Optional:

- `settings`
- `streamSettings`

Think of an outbound as:

"When routing chooses this tag, use this method to connect outward."

## `routing`

How the proxy decides which outbound tag to use.

Main field:

- `rules`

Each rule usually ends with:

- `outboundTag`

Optional matchers:

- `domain`
- `ip`
- `port`
- `inboundTag`

## `metricsAddr`

Optional HTTP server for metrics and health endpoints.

Example:

```json
"metricsAddr": "127.0.0.1:16090"
```

If set, the instance will try to bind a metrics server there during startup.

## Anatomy Of An Inbound

From the schema:

- `tag`: unique name
- `protocol`: `socks`, `http`, `vless`, `vmess`, `trojan`, `shadowsocks`, etc.
- `listen`: IP address only
- `port`: numeric port
- `settings`: protocol-specific JSON
- `streamSettings`: transport/security wrapper config

Important beginner point:

`listen` is not a domain name in the schema.
It is a real IP address.

## Anatomy Of An Outbound

From the schema:

- `tag`: route name
- `protocol`: `freedom`, `vless`, `vmess`, `trojan`, `shadowsocks`, etc.
- `settings`: protocol-specific JSON
- `streamSettings`: optional transport wrapper

## The Meaning Of `tag`

`tag` is just the name used to refer to an inbound or outbound elsewhere.

Examples:

- inbound tag appears in routing rule `inboundTag`
- outbound tag appears in routing rule `outboundTag`

Good tags are descriptive:

- `socks-in`
- `direct`
- `vless-reality-out`
- `ss2022-out`

## Common Inbound Examples

## SOCKS inbound

```json
{
  "tag": "socks-in",
  "protocol": "socks",
  "listen": "127.0.0.1",
  "port": 10080
}
```

Meaning:

- local apps can use this as a SOCKS5 proxy

## HTTP CONNECT inbound

```json
{
  "tag": "http-in",
  "protocol": "http",
  "listen": "127.0.0.1",
  "port": 8080
}
```

Meaning:

- local apps can use this as an HTTP CONNECT proxy

## VLESS inbound

```json
{
  "tag": "vless-in",
  "protocol": "vless",
  "listen": "127.0.0.1",
  "port": 10443,
  "settings": {
    "clients": [
      {
        "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
        "email": "user@example.test"
      }
    ]
  }
}
```

Meaning:

- accept VLESS clients
- allow the listed UUIDs

## Common Outbound Examples

## Freedom outbound

```json
{
  "tag": "direct",
  "protocol": "freedom"
}
```

Meaning:

- connect directly to the target destination

## VLESS outbound

```json
{
  "tag": "vless-out",
  "protocol": "vless",
  "settings": {
    "address": "127.0.0.1",
    "port": 10443,
    "users": [
      {
        "id": "a3482e88-686a-4a58-8126-99c9df64b7bf",
        "flow": ""
      }
    ]
  }
}
```

Meaning:

- when this outbound is chosen, connect to a VLESS server at `127.0.0.1:10443`

## Trojan outbound

Typical idea:

```json
{
  "tag": "trojan-out",
  "protocol": "trojan",
  "settings": {
    "address": "server.example.com",
    "port": 443,
    "password": "my-password"
  }
}
```

Meaning:

- use Trojan to reach that server

## Shadowsocks-2022 outbound

From the examples:

```json
{
  "tag": "ss2022-out",
  "protocol": "shadowsocks",
  "settings": {
    "address": "127.0.0.1",
    "port": 16388,
    "method": "2022-blake3-aes-256-gcm",
    "password": "local-ss2022-password"
  }
}
```

Meaning:

- use SS-2022 to reach the configured server

## `settings` Versus `streamSettings`

This distinction is very important.

## `settings`

Protocol-specific meaning.

Examples:

- VLESS user UUID
- Trojan password
- SS-2022 method/password

## `streamSettings`

Transport/security-specific meaning.

Examples:

- `network: "ws"`
- `security: "tls"`
- `security: "reality"`
- `wsSettings`
- `tlsSettings`
- `realitySettings`

Use this memory trick:

- `settings` = what the protocol needs
- `streamSettings` = how the bytes travel

## `streamSettings`

Main fields from the schema:

- `network`
- `security`
- `tlsSettings`
- `realitySettings`
- `wsSettings`
- `grpcSettings`
- `shadowTlsSettings`
- `kcpSettings`

## `network`

Examples:

- `tcp`
- `ws`
- `grpc`
- `quic`
- `kcp`

This chooses the transport style.

## `security`

Examples:

- `none`
- `tls`
- `reality`

This chooses the security/disguise wrapper.

## Example: VLESS over WebSocket

From the examples:

```json
"streamSettings": {
  "network": "ws",
  "security": "none",
  "wsSettings": {
    "path": "/vless-ws",
    "headers": {
      "Host": "localhost"
    }
  }
}
```

Meaning:

- use WebSocket as the transport
- no TLS wrapper in this local example
- use path `/vless-ws`

## Example: VLESS over REALITY

Client-side shape:

```json
"streamSettings": {
  "network": "tcp",
  "security": "reality",
  "realitySettings": {
    "publicKey": "...",
    "shortId": "0123456789abcdef",
    "serverName": "www.example.com",
    "fingerprint": "chrome"
  }
}
```

Meaning:

- underlying connection is TCP
- security wrapper is REALITY
- use these client-side REALITY credentials

Server-side shape:

```json
"streamSettings": {
  "network": "tcp",
  "security": "reality",
  "realitySettings": {
    "dest": "127.0.0.1:18080",
    "privateKey": "...",
    "shortIds": ["0123456789abcdef"],
    "serverName": "www.example.com",
    "maxTimeDiff": 120
  }
}
```

Meaning:

- validate REALITY clients with this private key and short IDs
- send failures to fallback `dest`

## `routing.rules`

A rule says:

"If these conditions match, use this outbound tag."

Minimal rule:

```json
{
  "outboundTag": "direct"
}
```

Meaning:

- use `direct` for everything

More specific rule:

```json
{
  "domain": ["suffix:example.com"],
  "outboundTag": "vless-out"
}
```

Meaning:

- traffic for `*.example.com` uses `vless-out`

You can also match:

- CIDRs in `ip`
- ports in `port`
- inbound tags in `inboundTag`

## A Good Beginner Config Progression

Do not start with the hardest config first.

Use this order:

1. SOCKS inbound + Freedom outbound
2. SOCKS inbound + VLESS outbound
3. VLESS inbound + Freedom outbound
4. add WebSocket
5. add TLS
6. add REALITY

That progression matches how the code is easiest to understand too.

## Real Example Paths In This Repo

Good starter examples:

- [examples/vless-client-server/client.json](/Users/mojnader/RustroverProjects/v2ray/examples/vless-client-server/client.json)
- [examples/vless-client-server/server.json](/Users/mojnader/RustroverProjects/v2ray/examples/vless-client-server/server.json)

REALITY examples:

- [examples/reality-client-server/client.json](/Users/mojnader/RustroverProjects/v2ray/examples/reality-client-server/client.json)
- [examples/reality-client-server/server.json](/Users/mojnader/RustroverProjects/v2ray/examples/reality-client-server/server.json)

WebSocket examples:

- [examples/vless-ws-local/client.json](/Users/mojnader/RustroverProjects/v2ray/examples/vless-ws-local/client.json)
- [examples/vless-ws-local/server.json](/Users/mojnader/RustroverProjects/v2ray/examples/vless-ws-local/server.json)

SS-2022 examples:

- [examples/ss2022-local/client.json](/Users/mojnader/RustroverProjects/v2ray/examples/ss2022-local/client.json)
- [examples/ss2022-local/server.json](/Users/mojnader/RustroverProjects/v2ray/examples/ss2022-local/server.json)

## Common Beginner Mistakes

## Mistake 1: confusing `settings` and `streamSettings`

Remember:

- protocol details go in `settings`
- transport/security details go in `streamSettings`

## Mistake 2: using a bad `tag`

Routing references tags literally.

If a routing rule says `outboundTag: "direct"`, there must actually be an outbound with tag `direct`.

## Mistake 3: treating `listen` like a hostname

In the schema, `listen` is an IP address.

## Mistake 4: using REALITY fields on the wrong side

Client and server use different REALITY fields:

- client uses `publicKey`, `shortId`, `serverName`, `fingerprint`
- server uses `privateKey`, `shortIds`, `dest`, `maxTimeDiff`

## Mistake 5: skipping `routing`

You usually want at least one rule or a sensible default path.

## Cheat Sheet

### Local SOCKS proxy

- inbound protocol: `socks`
- outbound protocol: `freedom`

### Client that sends traffic to a VLESS server

- inbound protocol: `socks`
- outbound protocol: `vless`

### Hide VLESS inside WebSocket

- outbound `protocol: "vless"`
- outbound `streamSettings.network: "ws"`

### Add REALITY disguise

- outbound `streamSettings.security: "reality"`

## Final Summary

Think of config like this:

- `inbounds`
  how clients enter

- `outbounds`
  how traffic leaves

- `routing`
  how to choose an outbound

- `settings`
  protocol-specific fields

- `streamSettings`
  transport/security-specific fields

- `metricsAddr`
  optional monitoring server

