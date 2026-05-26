# Request Lifecycle

This document answers one question:

"When a connection enters this proxy, what exactly happens to it?"

That question is the fastest way to understand the project.

## The Generic Lifecycle

Most TCP flows in this repo follow the same broad path:

1. A listener accepts a socket.
2. A transport/security wrapper may unwrap the stream.
3. An inbound protocol handler reads a protocol header.
4. The inbound extracts the destination address.
5. The inbound calls the dispatcher.
6. The dispatcher asks the router for an outbound tag.
7. The dispatcher asks that outbound to connect.
8. The outbound returns a ready stream.
9. The relay copies bytes in both directions.
10. Metrics and logs are recorded.

If you understand that ten-step model, you understand the architecture.

## The Three Main Roles

Before the detailed flows, keep these roles in mind:

### Listener / transport

Accepts raw network connections.

Examples:

- TCP listener
- TLS server acceptor
- WebSocket server upgrade
- REALITY authenticator

### Inbound protocol

Reads the client-side proxy protocol and learns where the client wants to go.

Examples:

- SOCKS5 inbound
- HTTP CONNECT inbound
- VLESS inbound
- Trojan inbound

### Outbound protocol

Creates the remote-side connection that will actually carry traffic out.

Examples:

- Freedom outbound
- VLESS outbound
- VMess outbound
- Trojan outbound
- SS-2022 outbound

## The Simplest Flow: SOCKS Inbound To Freedom Outbound

This is the best beginner example.

### Step 1: Client connects

Your browser or tool connects to a local TCP port.

That port belongs to a SOCKS inbound listener configured in `config.json`.

### Step 2: TCP transport accepts

`blackwire-transport` accepts the raw TCP socket and gives a stream to the configured connection handler.

In the plain case, there is no TLS or WebSocket wrapper. It is just a raw TCP stream.

### Step 3: SOCKS5 handshake

`blackwire-protocol::socks` reads:

- version
- auth methods
- CONNECT request
- destination address and port

After this, the protocol header is finished and the stream is positioned at the start of raw payload bytes.

### Step 4: Inbound calls dispatcher

SOCKS builds a `Context` and calls the dispatcher with:

- inbound tag
- source address
- destination `Address`
- current stream

### Step 5: Router chooses outbound

The dispatcher builds a routing context and asks the router for the outbound tag.

If no rule matches, the default outbound tag is used.

### Step 6: Outbound connects

If the selected outbound is Freedom:

- domain names are resolved if necessary
- a direct TCP connection to the destination is opened
- the resulting stream is returned

### Step 7: Relay

The dispatcher now has:

- inbound stream
- outbound stream

It relays bytes both ways until either side closes or errors.

That is the entire basic proxy loop.

## A Slightly More Advanced Flow: HTTP CONNECT Inbound To Freedom Outbound

This is very similar to SOCKS.

The difference is the inbound parser:

1. client sends `CONNECT host:port HTTP/1.1`
2. HTTP CONNECT parser extracts target
3. dispatcher takes over
4. Freedom connects
5. relay starts

The important idea:

Different inbound protocols can feed the same dispatcher and the same outbounds.

That is why the trait boundaries matter.

## VLESS Inbound Flow

VLESS inbound is more proxy-native than SOCKS.

The high-level path:

1. Client connects.
2. Any transport layer is unwrapped first.
3. VLESS inbound reads the VLESS request header.
4. It validates the user UUID.
5. It extracts command, destination, and optional flow string.
6. It passes the stream to the dispatcher.

After the VLESS header is parsed, the rest of the connection behaves like every other proxied stream: route, connect outbound, relay.

## VLESS Outbound Flow

VLESS outbound works in the opposite direction.

Instead of parsing a client request, it builds one:

1. Outbound receives destination from dispatcher.
2. Outbound opens an underlying transport stream.
3. Outbound encodes a VLESS request header.
4. Outbound writes the header onto the stream.
5. Outbound returns the stream.
6. Dispatcher relays bytes over that stream.

This is an important pattern:

- inbound decodes a header
- outbound encodes a header

## Trojan Flow

Trojan is similar in shape to VLESS, but its header is different.

On the inbound side:

1. Read Trojan token.
2. Validate token.
3. Read command byte and destination.
4. Hand stream to dispatcher.

On the outbound side:

1. Compute or reuse token.
2. Write Trojan header onto stream.
3. Return stream.

In production, Trojan usually sits on top of TLS.

So a real deployment often looks like:

`TCP listener -> TLS accept -> Trojan inbound -> dispatcher`

## VMess Flow

VMess is more complex than VLESS because it has more cryptography and framing.

High-level idea:

- inbound must authenticate using VMess auth ID logic
- outbound must create VMess auth/header bytes
- stream payloads are encrypted/framed rather than simply passed through

This means VMess has more stateful stream logic than VLESS.

If you are new to the repo, do not start with VMess.

Understand SOCKS and VLESS first.

## Where Transport Wrappers Enter

So far, the examples used plain TCP.

Now add a transport wrapper like TLS or WebSocket.

The important architectural rule is:

The transport wrapper runs before the inbound protocol parser.

Example:

`TCP listener -> TLS accept -> WebSocket accept -> VLESS inbound`

In that stack:

- TCP accepts raw socket
- TLS removes TLS encryption
- WebSocket removes frame layer
- VLESS now sees clean protocol bytes

The VLESS code does not need to know whether the bytes arrived over plain TCP or through TLS+WebSocket.

That is the point of using `BoxedStream`.

## REALITY Success Path

REALITY is more special than plain TLS.

It is not just "encrypt the stream."

It does two jobs:

1. hide authentication inside a browser-like TLS ClientHello
2. continue into a real TLS 1.3 handshake so the connection still looks legitimate

High-level success path:

1. TCP accepts a connection.
2. REALITY server reads the incoming ClientHello.
3. REALITY server extracts:
   - client X25519 key share
   - random bytes
   - encrypted token in `session_id`
4. REALITY server derives shared secret and decrypts token.
5. If auth is valid, it replays the ClientHello back into a local TLS acceptor.
6. Local TLS handshake completes.
7. Only then does the inbound protocol handler see application bytes.

That "replay the ClientHello into TLS" detail matters a lot.

It is why the success-path contract changed from auth-only shortcuts to the current full TLS 1.3 completion shape.

## REALITY Failure Path

If REALITY authentication fails, the server should not obviously reject the connection.

Instead:

1. the already-read bytes are replayed to a fallback destination
2. the connection is proxied there
3. the prober sees what looks like a normal HTTPS service

This is active-probe resistance.

That is why REALITY code cares about fallback behavior so much.

## The Dispatcher Phase In More Detail

The dispatcher lives in `blackwire-app`.

Its job is:

1. receive an already-parsed destination
2. ask router for outbound selection
3. get the outbound handler
4. connect through that outbound
5. relay bytes

The dispatcher should not know wire details of SOCKS, VLESS, Trojan, or REALITY.

It operates after the inbound header has been understood.

That separation is one of the key architectural boundaries of the project.

## What The Router Looks At

The router makes decisions based on a `RoutingContext`.

That includes things like:

- destination address
- destination port
- inbound tag
- network type
- user identity when available

Rules can match:

- domain patterns
- CIDR ranges
- ports
- inbound tags
- geosite
- geoip

The router returns an outbound tag, not a socket.

That distinction matters:

- router decides
- dispatcher executes

## What Hot Reload Changes

Hot reload does not mean the whole process restarts.

The intended model is:

- config manager watches the config file
- new config is parsed and validated
- atomic data like routing can be swapped
- new connections see new config
- in-flight connections finish on old state

Not every possible listener/property can be changed instantly in every architecture, but that is the intended design boundary.

## Why Production-Readiness Tests Matter

A connection lifecycle does not only need to work in the happy case.

It also has to survive:

- partial writes
- `Pending` in async flush paths
- malformed inputs
- invalid config
- bind failures
- strict protocol constants

That is why the repo has dedicated `production_readiness` tests.

Those tests are often checking lifecycle safety, not just correctness of a happy-path demo.

## Best Way To Trace A Real Flow Yourself

If you want to understand one path in code, use this recipe:

1. Start from `blackwire-cli/src/main.rs`.
2. Jump into `blackwire-core/src/instance.rs`.
3. See which inbound and outbound are built for your config.
4. Read that inbound handler.
5. Read `blackwire-app/src/dispatcher.rs`.
6. Read the chosen outbound handler.
7. If the config adds TLS/WS/REALITY, read the corresponding transport wrapper.

That is how to trace any connection without getting lost.

## One-Sentence Summary

Every connection in this repo is:

"accepted by a listener, optionally unwrapped by transports, decoded by an inbound protocol, routed by the dispatcher, connected by an outbound, and relayed until close."

