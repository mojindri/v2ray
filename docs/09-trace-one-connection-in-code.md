# Trace One Connection In Code

This is the practical "show me the exact file path" guide.

We will trace the simplest useful path:

`browser -> SOCKS inbound -> dispatcher -> Freedom outbound -> destination`

That path is the best foundation for understanding everything else.

## Goal

Understand one full connection end to end with real file jumps.

## Step 0: Start At The Binary

Read:

- [crates/blackwire-cli/src/main.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-cli/src/main.rs)

What to notice:

- config is loaded
- `Instance::from_config(...)` is called
- the running instance is what actually starts listeners

If you want one mental anchor, this file is the front door.

## Step 1: See How The Runtime Is Built

Read:

- [crates/blackwire-core/src/instance.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/instance.rs)

This is the assembly line.

For our simple example:

1. outbound handlers are built first
2. router is built
3. dispatcher is built
4. inbound handlers are built
5. TCP listeners are bound
6. accept loops are spawned

For a plain SOCKS inbound, there is no TLS/REALITY/WebSocket wrapper in front.

## Step 2: Find The Core Traits

Read:

- [crates/blackwire-app/src/features.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/features.rs)

These traits define the architecture:

- `InboundHandler`
- `OutboundHandler`
- `ConnectionHandler`

For this trace:

- SOCKS implements `InboundHandler`
- Freedom implements `OutboundHandler`

## Step 3: Understand The Listener

Read:

- [crates/blackwire-transport/src/tcp.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/tcp.rs)

What happens here:

1. listener accepts a TCP connection
2. accepted socket is wrapped as a `BoxedStream`
3. connection is passed to the handler task

This transport layer does not know SOCKS5 semantics.
It only knows it accepted a stream.

## Step 4: Read The SOCKS Inbound

Read:

- [crates/blackwire-protocol/src/socks.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/socks.rs)

This is where the bytes start to mean something.

The important function flow is:

1. read greeting
2. choose auth method
3. read CONNECT request
4. parse destination
5. call dispatcher

Conceptually:

- before SOCKS parser: bytes are just bytes
- after SOCKS parser: the program knows the destination

That change is the whole purpose of an inbound protocol handler.

## Step 5: Understand The Shared Destination Type

Read:

- [crates/blackwire-common/src/address.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-common/src/address.rs)

The parsed destination becomes an `Address`.

That can be:

- IPv4 + port
- IPv6 + port
- domain + port

This type is passed around everywhere after parsing.

## Step 6: Follow The Dispatcher

Read:

- [crates/blackwire-app/src/dispatcher.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/dispatcher.rs)

This file answers:

"Once we know the destination, what happens next?"

The dispatcher:

1. builds a routing context
2. asks the router for an outbound tag
3. finds the outbound handler
4. asks that outbound to connect
5. relays bytes in both directions

This is the middle of the whole architecture.

## Step 7: Follow The Router

Read:

- [crates/blackwire-app/src/router.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/router.rs)

For our simplest path, the router often just picks the default outbound tag.

But this is where rule matching happens if routing is more complex.

The router does not open sockets.
It only chooses which outbound tag should be used.

That separation matters:

- router decides
- dispatcher executes

## Step 8: Read The Freedom Outbound

Read:

- [crates/blackwire-protocol/src/freedom.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/freedom.rs)

This is the simplest outbound in the repo.

It does:

1. resolve domain if needed
2. open direct TCP connection
3. return the stream

After that, the dispatcher can relay.

## Step 9: Relay

Relay logic lives under `blackwire-app`.

The dispatcher calls the relay helper to copy bytes:

- inbound -> outbound
- outbound -> inbound

This is the point where the proxy stops interpreting protocol headers and mostly becomes a stream pump.

## The Whole Path In One Sentence

For the simple SOCKS -> Freedom case:

- TCP accepts
- SOCKS parses destination
- dispatcher asks router
- router returns outbound tag
- Freedom dials target
- relay copies both ways

That is the simplest complete loop.

## How To Extend This Mental Trace

Once you understand the simple path, extend it one layer at a time.

## Add VLESS Outbound

Instead of Freedom, switch Step 8 to:

- [crates/blackwire-protocol/src/vless/outbound.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vless/outbound.rs)

Now the outbound:

1. connects to a remote VLESS server
2. writes a VLESS header
3. returns the stream

Everything before that is the same.

## Add WebSocket

Now add transport wrapping before the protocol write/read side.

Read:

- [crates/blackwire-transport/src/ws.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/ws.rs)

Now the path becomes:

- TCP connect
- WebSocket handshake
- VLESS header write
- relay

The protocol still sees a stream, but the stream is now WebSocket-backed.

## Add TLS

Read:

- [crates/blackwire-transport/src/tls.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/tls.rs)

Now the path becomes:

- TCP connect
- TLS handshake
- maybe WebSocket handshake
- VLESS header write
- relay

## Add REALITY

This is where the path changes the most.

Read:

- [docs/04-reality-for-dummies.md](/Users/mojnader/RustroverProjects/v2ray/docs/04-reality-for-dummies.md)
- [crates/blackwire-core/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/reality.rs)

On the server side, the path becomes:

- TCP accept
- REALITY auth
- local TLS accept
- VLESS inbound parse
- dispatcher
- outbound
- relay

That is why REALITY is more than just "another transport option."

## File Map By Question

If you ask:

### "Where does startup happen?"

Read:

- [crates/blackwire-cli/src/main.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-cli/src/main.rs)
- [crates/blackwire-core/src/instance.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/instance.rs)

### "Where is the client destination parsed?"

Read:

- [crates/blackwire-protocol/src/socks.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/socks.rs)
- [crates/blackwire-protocol/src/http_connect.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/http_connect.rs)
- [crates/blackwire-protocol/src/vless/codec.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vless/codec.rs)

### "Where is the outbound chosen?"

Read:

- [crates/blackwire-app/src/router.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/router.rs)
- [crates/blackwire-app/src/dispatcher.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/dispatcher.rs)

### "Where is the remote socket opened?"

Read:

- [crates/blackwire-protocol/src/freedom.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/freedom.rs)
- outbound modules for other protocols

### "Where do transport wrappers live?"

Read:

- [crates/blackwire-transport/src/tcp.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/tcp.rs)
- [crates/blackwire-transport/src/tls.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/tls.rs)
- [crates/blackwire-transport/src/ws.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/ws.rs)
- [crates/blackwire-transport/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality.rs)

## Best Follow-Up Exercises

After reading this, trace these next:

1. SOCKS inbound -> VLESS outbound
2. VLESS inbound -> Freedom outbound
3. VLESS over WebSocket
4. VLESS over REALITY

That gives you most of the repo’s architecture without drowning in every feature.

## Final Summary

If you can trace:

- startup in `main.rs`
- assembly in `instance.rs`
- parse in an inbound
- decision in `dispatcher.rs` and `router.rs`
- connect in an outbound

then you already understand the core of the project.

