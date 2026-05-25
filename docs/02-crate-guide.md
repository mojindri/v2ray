# Crate Guide

This document explains what each crate owns, why it exists, and what to read first.

## `blackwire-common`

### Purpose

This crate is the bottom of the dependency graph.

It holds the shared nouns that every other crate needs:

- `Address`
- `Network`
- `BoxedStream`
- `ProxyError`
- buffer helpers

### Why It Exists

Without this crate, every higher-level crate would duplicate base types or create circular dependencies.

### Read First

- `crates/blackwire-common/src/lib.rs`
- `crates/blackwire-common/src/address.rs`
- `crates/blackwire-common/src/stream.rs`
- `crates/blackwire-common/src/error.rs`

### What To Learn Here

- how destinations are represented
- what the universal stream type is
- what shared errors look like

## `blackwire-config`

### Purpose

Owns the JSON config schema and config lifecycle.

### Main Responsibilities

- deserialize JSON into Rust structs
- validate config
- support environment expansion
- support hot reload

### Read First

- `crates/blackwire-config/src/lib.rs`
- `crates/blackwire-config/src/schema.rs`
- `crates/blackwire-config/src/manager.rs`

### What To Learn Here

- which fields exist in config
- how `metricsAddr`, `streamSettings`, `routing`, `inbounds`, and `outbounds` map into typed data
- where startup errors come from when config is wrong

### Mental Note

No other crate should be inventing its own JSON parsing rules. They should consume typed config from here.

## `blackwire-app`

### Purpose

This is the application logic layer.

If `blackwire-core` is the assembler, `blackwire-app` is the brain.

### Main Responsibilities

- trait definitions
- dispatcher
- router
- relay
- DNS
- health checking
- balancer
- metrics

### Read First

- `crates/blackwire-app/src/features.rs`
- `crates/blackwire-app/src/dispatcher.rs`
- `crates/blackwire-app/src/router.rs`

### Most Important Concepts

#### `InboundHandler`

Accepts a stream, parses client protocol, extracts destination, calls dispatcher.

#### `OutboundHandler`

Given a destination, opens a remote stream ready for relay.

#### `ConnectionHandler`

Low-level connection wrapper used before the protocol layer, especially for things like REALITY/TLS wrapping.

#### `Dispatcher`

Bridges inbound and outbound sides.

#### `Router`

Picks outbound tag from route rules.

### What To Learn Here

- how route selection is separate from protocol decoding
- how relaying is separate from route selection
- how application logic does not need to know raw TLS/WebSocket details

## `blackwire-core`

### Purpose

This crate builds the running proxy instance.

It is the glue between config, protocols, transports, router, and listeners.

### Main Responsibilities

- build inbound handlers from config
- build outbound handlers from config
- build router rules
- build dispatcher
- bind listeners
- start listener tasks
- start metrics server

### Read First

- `crates/blackwire-core/src/lib.rs`
- `crates/blackwire-core/src/instance.rs`

### Supporting Modules

- `http.rs`
- `trojan.rs`
- `vmess.rs`
- `ss2022.rs`
- `reality.rs`
- `ws_tls.rs`
- `outbound_transport.rs`

These are adapter/wiring modules. They are less about raw protocol math and more about "build the right handler stack from config."

### What To Learn Here

- how config turns into concrete handlers
- where inbound wrapping decisions are made
- how fail-fast startup works
- how routing validation is enforced

### Important Boundary

`blackwire-core` should assemble components, not reimplement wire formats.

## `blackwire-protocol`

### Purpose

Implements proxy protocols.

These are the byte formats and handshakes that clients and remote proxy servers speak.

### Protocols In This Crate

- SOCKS5
- HTTP CONNECT
- Freedom
- VLESS
- VMess
- Trojan
- Shadowsocks-2022

There are also references to future/advanced pieces, but the main ownership is the protocols above.

### Read First

Start simple:

- `crates/blackwire-protocol/src/socks.rs`
- `crates/blackwire-protocol/src/freedom.rs`

Then move to:

- `crates/blackwire-protocol/src/vless/*`
- `crates/blackwire-protocol/src/trojan/*`
- `crates/blackwire-protocol/src/vmess/*`
- `crates/blackwire-protocol/src/ss2022/*`

### Internal Pattern

For most protocols you will see some mix of:

- `codec`
  exact wire encoding/decoding

- `inbound`
  server-side behavior

- `outbound`
  client-side behavior

- `registry` or auth helpers
  user/token lookup and validation

### What To Learn Here

- how destinations are encoded
- where auth is checked
- what becomes raw payload after header parsing
- which protocols are stateful and which are lightweight

### Beginner Advice

Do not start with VMess or SS-2022 if you are still learning the architecture.

Start with SOCKS and VLESS first.

## `blackwire-transport`

### Purpose

Implements transport and stream wrappers.

This crate is about carrying bytes, not interpreting proxy headers.

### Transports In This Crate

- TCP
- TLS
- WebSocket
- REALITY
- gRPC
- QUIC
- Hysteria2 transport helpers
- mKCP
- TUN
- ShadowTLS

### Read First

Start simple:

- `crates/blackwire-transport/src/tcp.rs`
- `crates/blackwire-transport/src/tls.rs`
- `crates/blackwire-transport/src/ws.rs`

Then advanced:

- `crates/blackwire-transport/src/reality.rs`
- `crates/blackwire-transport/src/reality/client.rs`
- `crates/blackwire-transport/src/reality/server.rs`
- `crates/blackwire-transport/src/grpc.rs`
- `crates/blackwire-transport/src/quic.rs`

### What To Learn Here

- how listeners and streams are created
- how wrappers preserve `AsyncRead + AsyncWrite`
- how partial-write handling is implemented
- how REALITY bridges custom auth and real TLS

### Important Boundary

The transport layer should not need to understand a VLESS UUID or Trojan token.

It should just produce a usable stream.

## `blackwire-tls`

### Purpose

Very specialized crate for browser-like TLS ClientHello construction.

### Why It Exists

REALITY needs a ClientHello that looks like a real browser, not like default `rustls`.

That means this crate must control:

- extension ordering
- key shares
- GREASE values
- browser fingerprint profile

### Read First

- `crates/blackwire-tls/src/lib.rs`
- `crates/blackwire-tls/src/client_hello.rs`
- `crates/blackwire-tls/src/profile.rs`

### What To Learn Here

- this crate is not a full TLS stack
- it is a raw ClientHello builder
- it exists mainly for REALITY camouflage

## `blackwire-cli`

### Purpose

This is the executable, `blackwire`.

### Main Responsibilities

- parse CLI arguments
- load config
- start `Instance`
- install signal handlers
- expose helper commands like UUID and X25519 generation

### Read First

- `crates/blackwire-cli/src/main.rs`

### What To Learn Here

- how a real run starts
- what command-line tools exist for operators

## `blackwire-api`

### Purpose

Planned management/stats API crate.

### Current Status

Mostly a stub right now.

### Why It Matters

It shows intended future direction:

- management interface
- stats exposure
- possible compatibility with v2ray-style management APIs

### Read First

- `crates/blackwire-api/src/lib.rs`

## `tests`

### Purpose

Cross-crate integration and interop coverage.

### Important Areas

- `tests/tests/*.rs`
  End-to-end and scenario-based tests.

- `tests/interop/README.md`
  REALITY/Xray interop notes.

### What To Learn Here

- what the project considers important enough to lock down
- which paths are covered by self-interop vs live Xray interop
- what "production readiness" means in this codebase

## Read Order By Goal

### If You Want To Understand Startup

Read:

1. `blackwire-cli`
2. `blackwire-config`
3. `blackwire-core`

### If You Want To Understand Routing

Read:

1. `blackwire-app/src/features.rs`
2. `blackwire-app/src/router.rs`
3. `blackwire-app/src/dispatcher.rs`

### If You Want To Understand A Plain Local Proxy

Read:

1. `blackwire-protocol/src/socks.rs`
2. `blackwire-protocol/src/freedom.rs`
3. `blackwire-core/src/instance.rs`

### If You Want To Understand REALITY

Read:

1. `blackwire-tls`
2. `blackwire-transport/src/reality.rs`
3. `blackwire-transport/src/reality/client.rs`
4. `blackwire-transport/src/reality/server.rs`
5. `tests/interop/README.md`

### If You Want To Understand Tests

Read:

1. crate-level `production_readiness` tests
2. `tests/tests/e2e_*`
3. `tests/interop/*`

## Final Summary

Use this ownership map:

- `blackwire-common`
  base shared types

- `blackwire-config`
  typed config and reload

- `blackwire-app`
  routing, dispatch, relay, metrics

- `blackwire-core`
  startup and composition

- `blackwire-protocol`
  proxy protocol byte semantics

- `blackwire-transport`
  stream-carrier implementations

- `blackwire-tls`
  browser-like ClientHello builder for REALITY

- `blackwire-cli`
  executable

- `blackwire-api`
  future management surface

- `tests`
  behavior proof

