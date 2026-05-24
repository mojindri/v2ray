# Project Map

This document explains the project in plain language.

The short version:

- This repo is a v2ray/Xray-compatible proxy platform written in Rust.
- It can accept traffic from clients using protocols like SOCKS5, VLESS, VMess, Trojan, and Shadowsocks-2022.
- It can move that traffic over different transports like TCP, TLS, WebSocket, gRPC, QUIC, and REALITY.
- It can route connections to different outbounds based on rules.
- It is split into crates so protocol code, transport code, config code, and runtime wiring stay separate.

If you only remember one idea, remember this:

`client -> inbound protocol -> dispatcher/router -> outbound protocol -> remote server`

Everything in the repo exists to implement one piece of that path.

## What Problem This Repo Solves

A proxy server has to do several different jobs at once:

1. Accept a connection from a client.
2. Understand the protocol the client is speaking.
3. Figure out where the client wants to go.
4. Decide which outbound route should be used.
5. Open the outbound connection.
6. Relay bytes in both directions.
7. Optionally hide or disguise the traffic using transports like TLS, WebSocket, or REALITY.

Many proxy projects mix those concerns together. This repo tries to separate them.

That is why the workspace is split into crates with distinct ownership.

## The Big Mental Model

There are four layers you should keep separate in your head:

1. Config layer
   This is the JSON file and the code that parses and validates it.

2. Runtime wiring layer
   This is the code that turns config into a running instance with listeners, router, dispatcher, and handlers.

3. Protocol layer
   This is the code that understands proxy protocols like SOCKS5, VLESS, VMess, Trojan, and SS-2022.

4. Transport layer
   This is the code that moves bytes over TCP, TLS, WebSocket, gRPC, QUIC, REALITY, or TUN.

These are not the same thing.

Examples:

- VLESS is a protocol.
- WebSocket is a transport.
- REALITY is a transport/authentication disguise layer.
- Routing is application logic, not a transport and not a protocol.

## The Workspace At A Glance

The workspace root `Cargo.toml` declares these crates:

- `proxy-common`
  Shared types used everywhere.

- `proxy-config`
  Config schema, parsing, validation, and hot reload.

- `proxy-app`
  Router, dispatcher, DNS, metrics, health, relay helpers.

- `proxy-core`
  Builds the running instance from config and wires everything together.

- `proxy-protocol`
  Proxy protocols such as SOCKS5, VLESS, VMess, Trojan, and SS-2022.

- `proxy-transport`
  TCP, TLS, WebSocket, gRPC, QUIC, REALITY, mKCP, TUN, ShadowTLS.

- `proxy-tls`
  Raw TLS ClientHello builder used by REALITY client camouflage.

- `proxy-cli`
  The `blackwire` binary entrypoint.

- `proxy-api`
  Planned management/stats API crate. Currently mostly a stub.

- `tests`
  Integration tests and interop tests.

## How Startup Works

The startup path begins in `crates/proxy-cli/src/main.rs`.

The normal `run` command does this:

1. Initialize tracing/logging.
2. Load config through `proxy_config::ConfigManager`.
3. Start the config watcher for hot reload.
4. Build `proxy_core::Instance` from the current config.
5. Wait for signals or for the instance to exit.

`proxy_core::Instance::from_config()` is the main wiring function.

It does the important assembly work:

1. Build outbound handlers.
2. Build the router rules.
3. Build the dispatcher.
4. Build inbound handlers.
5. Wrap inbounds with transport/security layers if needed.
6. Bind listeners and spawn accept loops.
7. Optionally start the metrics server.

That function is the closest thing to the "composition root" of the whole system.

## What A Connection Looks Like Internally

Suppose a browser is configured to use local SOCKS5.

The flow is:

1. Browser connects to the SOCKS inbound listener.
2. `proxy-transport` accepts the raw TCP socket.
3. `proxy-protocol::socks` reads the SOCKS5 handshake.
4. SOCKS extracts the destination address, for example `example.com:443`.
5. SOCKS gives the stream and destination to the dispatcher.
6. The dispatcher asks the router which outbound tag to use.
7. The dispatcher gets the corresponding outbound handler.
8. The outbound connects to the target, either directly or through another proxy protocol.
9. The relay copies bytes both ways until one side closes.

That is the default pattern for almost every protocol in the repo.

## Inbound Vs Outbound

This distinction matters a lot.

- Inbound means "how traffic enters our proxy".
- Outbound means "how traffic leaves our proxy".

Examples:

- SOCKS is usually an inbound.
- Freedom is an outbound.
- VLESS can be both inbound and outbound.
- Trojan can be both inbound and outbound.

When reading the code, ask:

"Is this code decoding what a client sent to us, or encoding what we send to another server?"

That usually tells you whether you are in inbound or outbound logic.

## Protocol Vs Transport

Another critical distinction:

- A protocol says what the bytes mean.
- A transport says how the bytes are carried.

Examples:

- VLESS header fields are protocol.
- WebSocket framing is transport.
- Trojan token and address encoding are protocol.
- TLS encryption of the stream is transport.

The repo tries to keep these separate so code stays composable.

That is why protocol handlers generally work with `BoxedStream` and do not care whether the stream underneath is plain TCP, TLS, or WebSocket.

## The Most Important Shared Types

There are a few shared concepts that show up everywhere.

### `Address`

Defined in `proxy-common`.

Represents:

- IPv4 + port
- IPv6 + port
- domain + port

This exists because many proxy protocols receive unresolved domain names, not already-resolved IP addresses.

### `BoxedStream`

Also from `proxy-common`.

This is the universal byte-stream type used between layers.

The main architectural idea is:

- transports return streams
- protocol handlers consume streams
- dispatcher relays streams

Because everything speaks `BoxedStream`, layers can be swapped.

### `ProxyError`

Shared error type used across the workspace.

### `InboundHandler`, `OutboundHandler`, `ConnectionHandler`

Defined in `proxy-app::features`.

These traits are the main interfaces between the layers:

- `InboundHandler`
  Parses inbound protocol and hands off to dispatcher.

- `OutboundHandler`
  Opens outbound connection and returns a ready stream.

- `ConnectionHandler`
  Lower-level transport/security wrapper used before inbound protocol parsing.

## Why `proxy-core` Exists

A common beginner question is:

"Why not just put everything in one crate?"

Because startup wiring is not the same problem as protocol implementation.

`proxy-core` exists to:

- build all handlers from config
- glue protocol code to transport code
- glue routing code to outbound code
- own the running tasks

It should know how to assemble the system, but not own the low-level wire formats themselves.

## Why `proxy-tls` Exists Separately

Another common question:

"Why does REALITY need a separate TLS crate?"

Because REALITY needs to build raw browser-like `ClientHello` bytes before a normal Rust TLS stack takes over.

Normal `rustls` is good at being a TLS client.
REALITY needs something more specific:

- pretend to be Chrome
- preserve exact extension ordering and fingerprint shape
- hide REALITY token material inside TLS fields

That is why `proxy-tls` is focused on raw ClientHello construction.

## Why The Tests Are Split

There are several different kinds of tests in this repo.

### Unit tests

Inside individual crates.

These check isolated components like:

- header codecs
- parsers
- KDFs
- helper logic

### Production-readiness tests

These are stricter tests aimed at real behavior and edge cases:

- malformed fixed fixtures
- partial writes
- pending flush behavior
- startup safety
- validation strictness

These often catch bugs that normal unit tests miss.

### Integration tests

In the `tests` crate.

These exercise end-to-end flows across multiple crates.

### Interop tests

Especially under `tests/interop`.

These check behavior against real Xray expectations, especially around REALITY.

## What To Read First

If you want to understand the code in a practical order, use this path:

1. `crates/proxy-cli/src/main.rs`
   Shows startup.

2. `crates/proxy-core/src/instance.rs`
   Shows how the system is assembled.

3. `crates/proxy-app/src/features.rs`
   Shows the core traits.

4. `crates/proxy-app/src/dispatcher.rs`
   Shows how inbounds and outbounds connect.

5. `crates/proxy-app/src/router.rs`
   Shows how outbound selection works.

6. Pick one simple protocol pair:
   `crates/proxy-protocol/src/socks.rs` and `crates/proxy-protocol/src/freedom.rs`

7. Then move to more advanced layers:
   VLESS, Trojan, VMess, TLS, WebSocket, REALITY

## What To Ignore At First

If you are brand new to the repo, do not start with:

- QUIC internals
- mKCP
- TUN
- REALITY TLS transcript details
- hot reload edge cases

Those are real features, but they are not the best entry point.

Learn the plain TCP + SOCKS + Freedom path first.

## A Good Beginner Strategy

Read the repo in this order:

1. Understand one simple path end to end.
   Example: SOCKS inbound to Freedom outbound.

2. Understand one protocol wrapper.
   Example: VLESS outbound.

3. Understand one transport wrapper.
   Example: TLS or WebSocket.

4. Understand one advanced disguise flow.
   Example: REALITY.

That way you build the model gradually instead of trying to learn the entire codebase at once.

## If You Forget Everything Else

Use this simplified map:

- `proxy-common`
  shared nouns

- `proxy-config`
  typed config

- `proxy-app`
  decision-making and relay

- `proxy-core`
  startup and wiring

- `proxy-protocol`
  what the bytes mean

- `proxy-transport`
  how the bytes travel

- `proxy-tls`
  special fake-browser TLS builder for REALITY

- `proxy-cli`
  the executable

