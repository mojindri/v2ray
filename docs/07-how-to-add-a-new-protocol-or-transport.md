# How To Add A New Protocol Or Transport

This guide is for contributors.

The first decision is:

"Am I adding a protocol, or am I adding a transport?"

Do not mix them up.

## If You Are Adding A Protocol

A protocol defines what the bytes mean.

Examples already in the repo:

- SOCKS5
- VLESS
- VMess
- Trojan
- SS-2022

### A New Protocol Usually Belongs In

- `crates/blackwire-protocol`

### Typical Pieces You Need

Most protocols want some subset of:

- `codec`
  wire encode/decode

- `inbound`
  server-side handler

- `outbound`
  client-side handler

- auth/registry helpers
  user lookup, token validation, etc.

### The Inbound Job

An inbound handler should:

1. read and validate the protocol header
2. extract destination and user context
3. leave the stream positioned at the first payload byte
4. call the dispatcher

### The Outbound Job

An outbound handler should:

1. obtain the underlying stream
2. write the protocol header for the remote side
3. return a stream ready for relay

### Important Rule

Protocol code should not own TLS/WebSocket/REALITY details directly unless the protocol absolutely requires it.

Those are transport concerns.

## If You Are Adding A Transport

A transport defines how bytes are carried or wrapped.

Examples already in the repo:

- TCP
- TLS
- WebSocket
- gRPC
- QUIC
- REALITY
- mKCP
- TUN

### A New Transport Usually Belongs In

- `crates/blackwire-transport`

### A New Transport Should Usually Produce

- a listener or connector
- a stream wrapper that behaves like `AsyncRead + AsyncWrite`

### Important Rule

Transport code should not know about VLESS UUIDs or Trojan passwords.

It should carry bytes, not interpret protocol meaning.

## The Design Boundary

Use this decision rule:

### If the feature changes the first bytes of the proxy request itself

It is probably a protocol feature.

### If the feature wraps, encrypts, disguises, frames, or tunnels an existing byte stream

It is probably a transport feature.

## Step-By-Step: Adding A New Protocol

## 1. Create module(s) in `blackwire-protocol`

Pick a structure that matches existing patterns.

Examples:

- simple protocol:
  one file may be enough

- richer protocol:
  `codec.rs`, `inbound.rs`, `outbound.rs`

## 2. Reuse shared types

Use:

- `blackwire_common::Address`
- `blackwire_common::BoxedStream`
- `blackwire_common::ProxyError`

Do not invent parallel core types.

## 3. Implement inbound and/or outbound traits

Read:

- [crates/blackwire-app/src/features.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/features.rs)

Your new handler should fit those trait contracts cleanly.

## 4. Add builder/wiring in `blackwire-core`

`blackwire-core` is where config becomes concrete handler instances.

That means you will usually need to update:

- `crates/blackwire-core/src/instance.rs`

and possibly add a small helper module beside:

- `http.rs`
- `trojan.rs`
- `vmess.rs`
- `ss2022.rs`

## 5. Add config schema if needed

If the protocol needs new config fields, update:

- `blackwire-config`

Do not parse ad hoc JSON inside `blackwire-core`.

## 6. Add tests at three levels

### Unit tests

For codec correctness.

### Production-readiness tests

For malformed inputs, validation strictness, partial writes if you use a stream wrapper.

### Integration tests

For end-to-end behavior.

## Step-By-Step: Adding A New Transport

## 1. Create module in `blackwire-transport`

Examples to copy style from:

- [crates/blackwire-transport/src/tcp.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/tcp.rs)
- [crates/blackwire-transport/src/tls.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/tls.rs)
- [crates/blackwire-transport/src/ws.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/ws.rs)

## 2. Expose a clean stream abstraction

The transport should ideally end by giving upper layers a `BoxedStream`.

That is how it composes with protocols.

## 3. Preserve async correctness

This repo already caught several real bugs here.

Be careful about:

- partial `poll_write`
- `Poll::Pending`
- retaining frame state across flush
- shutdown semantics

If your transport writes framed messages, do not assume a single kernel write completes the whole frame.

## 4. Add core wiring if config can select it

If the transport is selectable by `streamSettings`, update the relevant `blackwire-core` glue.

Examples:

- `crates/blackwire-core/src/ws_tls.rs`
- `crates/blackwire-core/src/reality.rs`
- `crates/blackwire-core/src/outbound_transport.rs`

## 5. Add tests

At minimum:

- exact byte-preservation tests
- partial-write tests
- malformed input tests if parsing is involved
- integration test showing the transport stack around a real protocol

## When To Touch `blackwire-tls`

Only touch `blackwire-tls` if the feature specifically requires custom raw TLS handshake construction or fingerprint control.

That is a specialized area.

Most new protocols and transports should not need it.

## Naming And Placement Advice

### For protocol modules

Prefer names like:

- `codec`
- `inbound`
- `outbound`
- `auth`
- `registry`
- `stream`

### For transport modules

Prefer names matching the carrier itself:

- `tls`
- `ws`
- `grpc`
- `quic`
- `shadowtls`

That consistency matters because the repo is already large.

## How To Decide Where Config Logic Belongs

### `blackwire-config`

Owns:

- schema
- serde names
- validation structure

### `blackwire-core`

Owns:

- turning config structs into handler instances
- cross-crate glue

### protocol/transport crate

Owns:

- actual runtime behavior

If you find yourself parsing raw JSON deep inside a protocol module, you are probably putting code in the wrong place.

## Minimal Example: Adding A New Inbound Protocol

The path is usually:

1. create codec
2. create inbound handler implementing `InboundHandler`
3. add config schema if needed
4. update `blackwire-core` inbound builder
5. add tests

The inbound should end with:

- destination extracted
- dispatcher called

Not with custom routing logic inside the protocol module.

## Minimal Example: Adding A New Outbound Transport Wrapper

The path is usually:

1. create connect/accept wrapper
2. return `BoxedStream`
3. update `blackwire-core` transport selection path
4. add production-readiness tests for stream behavior

## How To Stay Sane While Contributing

Follow these constraints:

1. Keep protocol meaning in `blackwire-protocol`.
2. Keep transport wrapping in `blackwire-transport`.
3. Keep config shape in `blackwire-config`.
4. Keep runtime assembly in `blackwire-core`.
5. Keep routing/dispatch in `blackwire-app`.

If you violate those boundaries casually, the repo gets much harder to maintain.

## Good Templates To Copy

### For a simple inbound/outbound protocol

- SOCKS
- Freedom
- VLESS

### For a protocol with more crypto state

- Trojan
- VMess
- SS-2022

### For a transport wrapper

- TLS
- WebSocket

### For a specialized disguise transport

- REALITY

## Final Contributor Checklist

Before calling a new protocol or transport "done", check:

- config fields exist and are validated
- `blackwire-core` can build it
- trait boundaries are respected
- malformed input tests exist
- partial-write tests exist if you wrapped a stream
- integration example or e2e test exists
- docs mention where it fits

If those are true, the feature is probably integrated correctly.

