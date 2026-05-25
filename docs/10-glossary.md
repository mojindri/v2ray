# Glossary

This is the plain-English dictionary for terms used in the repo.

## `Address`

The shared type representing a destination.

Can be:

- IPv4 + port
- IPv6 + port
- domain + port

Defined in:

- [crates/blackwire-common/src/address.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-common/src/address.rs)

## `BoxedStream`

The universal stream type passed between layers.

Important because:

- transports return it
- protocols consume it
- dispatcher relays it

## inbound

A client-facing protocol listener.

Examples:

- SOCKS inbound
- HTTP CONNECT inbound
- VLESS inbound

Think:

"How traffic enters our proxy."

## outbound

A server-facing connection method.

Examples:

- Freedom outbound
- VLESS outbound
- Trojan outbound

Think:

"How traffic leaves our proxy."

## protocol

The meaning of the bytes.

Examples:

- SOCKS5
- VLESS
- VMess
- Trojan
- SS-2022

## transport

How the bytes are carried or wrapped.

Examples:

- TCP
- TLS
- WebSocket
- gRPC
- REALITY

## `settings`

Protocol-specific config JSON.

Examples:

- VLESS user IDs
- Trojan password
- SS-2022 method/password

## `streamSettings`

Transport/security wrapper config.

Examples:

- `network`
- `security`
- `tlsSettings`
- `wsSettings`
- `realitySettings`

## `tag`

A string name used to refer to an inbound or outbound.

Examples:

- `socks-in`
- `direct`
- `vless-out`

Routing rules refer to outbound tags.

## `outboundTag`

The outbound tag that a routing rule chooses when the rule matches.

## `inboundTag`

A routing-rule filter limiting a rule to traffic that arrived through certain inbounds.

## dispatcher

The component that takes:

- context
- destination
- inbound stream

and then:

- asks the router for an outbound
- opens that outbound
- relays the bytes

Defined around:

- [crates/blackwire-app/src/dispatcher.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/dispatcher.rs)

## router

The component that decides which outbound tag should be used for a connection.

It does not open the connection itself.

## relay

The bidirectional copy loop between inbound and outbound streams.

This is the part that moves actual application data once setup is complete.

## REALITY

A disguise/authentication transport layer that hides auth inside a browser-like TLS `ClientHello` and then completes TLS 1.3 on success.

See:

- [docs/04-reality-for-dummies.md](/Users/mojnader/RustroverProjects/v2ray/docs/04-reality-for-dummies.md)

## fallback

The destination used when auth fails, especially for active-probe resistance.

Idea:

bad probes should see behavior that looks like a real service, not an obvious proxy rejection.

## `dest`

In configs, usually means destination address.

In REALITY server config specifically, `dest` is the fallback or cover-side destination depending on the interoperability context.

Always read it in context.

## SNI

Server Name Indication.

The hostname sent in the TLS handshake so the server knows which host the client claims to want.

In REALITY, this is part of the disguise story.

## `shortId` / `shortIds`

REALITY client/server auth identifiers.

- client uses `shortId`
- server allows a list in `shortIds`

These must match.

## `publicKey` / `privateKey`

In REALITY config:

- client uses server `publicKey`
- server holds `privateKey`

Used in the ECDH-based auth derivation.

## `fingerprint`

In REALITY config, the browser-like TLS fingerprint profile to mimic.

Current common example:

- `chrome`

## `cmd_key`

A VMess-derived key computed from the user UUID plus the VMess magic UUID string.

Used for auth ID and header encryption logic.

See:

- [crates/blackwire-protocol/src/vmess/auth.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vmess/auth.rs)

## auth ID

A VMess authentication value used so the server can identify and validate the client without sending a plain UUID directly.

## AAD

Additional Authenticated Data.

Used in AEAD encryption modes like AES-GCM.

Important in REALITY because the disguised token is authenticated against other parts of the `ClientHello`.

## AEAD

Authenticated Encryption with Associated Data.

A class of encryption modes that provide both confidentiality and integrity.

Examples in this repo:

- AES-GCM
- ChaCha20-Poly1305

## HKDF

Key derivation function used to derive structured key material from shared secrets.

Used in multiple places, including REALITY.

## ECDH

Elliptic Curve Diffie-Hellman.

A way for client and server to derive the same shared secret without sending the secret itself.

Used in REALITY.

## `ATYP`

Address type byte used in several proxy protocols.

Examples:

- IPv4
- domain
- IPv6

Used in SOCKS-like address encodings.

## `flow`

A protocol-specific VLESS user/connection field.

Usually empty in simple examples, but used for specialized behavior in some deployments.

## `metricsAddr`

Address where the metrics/health HTTP server listens.

Example:

- `127.0.0.1:16090`

## `network`

In `streamSettings`, the selected transport style.

Examples:

- `tcp`
- `ws`
- `grpc`
- `quic`
- `kcp`

## `security`

In `streamSettings`, the selected security/disguise wrapper.

Examples:

- `none`
- `tls`
- `reality`

## `wsSettings`

WebSocket transport config.

Usually includes:

- `path`
- optional `headers`

## `tlsSettings`

TLS wrapper config.

May include:

- `serverName`
- `allowInsecure`
- `alpn`
- cert/key file paths for server use

## `realitySettings`

REALITY wrapper config.

Client and server use different fields.

## `d0`

Self-interop REALITY test tier.

Meaning:

our client against our server.

## `d1`

Live Xray REALITY test tier.

Meaning:

our client against a real Xray server.

## `production_readiness`

Strict deterministic tests that check real safety/robustness properties, not just happy-path correctness.

Examples:

- malformed fixture handling
- startup validation
- partial writes
- flush behavior
- protocol constant compatibility

## `Instance`

The running assembled proxy runtime built by `blackwire-core`.

It owns listener tasks and startup composition.

Defined in:

- [crates/blackwire-core/src/instance.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/instance.rs)

## `ConfigManager`

The config owner that loads, validates, and hot-reloads config.

Defined in:

- [crates/blackwire-config/src/manager.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-config/src/manager.rs)

## `ConnectionHandler`

Lower-level handler trait used before the inbound protocol layer.

Useful for:

- TLS wrappers
- REALITY
- other transport/security pre-processing

## Final Memory Trick

If you are confused by a term, ask:

1. Is it about config shape?
2. Is it about protocol meaning?
3. Is it about transport wrapping?
4. Is it about runtime wiring?

That usually tells you which crate to look at next.

