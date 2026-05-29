# Protocols And Transports

This document exists because names in proxy projects get confusing fast.

People often mix up:

- protocol
- transport
- encryption
- disguise
- routing
- inbound
- outbound

This guide separates them.

## First Principle

A protocol and a transport are not the same thing.

### Protocol

A protocol defines what the bytes mean.

Examples:

- SOCKS5
- HTTP CONNECT
- VLESS
- VMess
- Trojan
- Shadowsocks-2022

Protocols usually answer questions like:

- who is the user?
- what destination is requested?
- what command is being asked for?
- how is auth encoded?

### Transport

A transport defines how bytes are carried.

Examples:

- TCP
- TLS
- WebSocket
- gRPC
- QUIC
- REALITY
- mKCP
- TUN
- ShadowTLS

Transports usually answer questions like:

- is this over TCP or UDP?
- is there TLS wrapping?
- is there HTTP upgrade framing?
- is traffic disguised?

## Inbound Versus Outbound Again

This is protocol direction, not network direction.

### Inbound

How our server accepts and understands client traffic.

Examples:

- SOCKS inbound
- VLESS inbound
- Trojan inbound

### Outbound

How our server connects outward to the next server or final destination.

Examples:

- Freedom outbound
- VLESS outbound
- VMess outbound
- Trojan outbound

## Supported Protocols In This Repo

## SOCKS5

### What It Is

The standard local proxy protocol used by browsers and tools.

### Typical Use

Local machine talks to your proxy over SOCKS.

### What It Carries

- auth method negotiation
- CONNECT command
- destination address and port

### Why It Is Good For Learning

It is simple and easy to trace.

## HTTP CONNECT

### What It Is

An HTTP-style proxy method used mainly for tunneling HTTPS.

### Typical Use

Browser or corporate tooling connects to a proxy and asks for `CONNECT host:port`.

### Key Difference From SOCKS

It is text-based at the start, not binary.

## Freedom

### What It Is

Direct outbound connection to the destination.

### Typical Use

- default direct route
- LAN/local bypass
- testing the proxy pipeline without another proxy protocol

### Important Note

Freedom is not a disguise protocol. It is just direct TCP connect.

## VLESS

### What It Is

A lightweight proxy protocol from the v2ray/Xray ecosystem.

### Main Characteristics

- small header
- UUID-based user identification
- little framing overhead after header
- often paired with TLS, WebSocket, or REALITY

### Mental Model

VLESS says:

"Here is the user, here is the command, here is the destination, now start relaying."

### Why People Like It

It is simpler and lighter than VMess.

## VMess

### What It Is

An older v2ray protocol with more built-in cryptographic framing/auth logic.

### Main Characteristics

- auth ID logic
- command key derivation
- encrypted/framed chunks
- more moving parts than VLESS

### Mental Model

VMess is more stateful and more opinionated than VLESS.

### Beginner Warning

If you do not yet understand the architecture, VMess will feel noisy.

Learn VLESS first.

## Trojan

### What It Is

A proxy protocol designed to look close to normal TLS application traffic when used the intended way.

### Main Characteristics

- token derived from password
- command byte
- SOCKS-like address encoding
- usually expected to run on top of TLS

### Mental Model

Trojan is a small authenticated request header placed onto an already-established stream.

## Shadowsocks-2022

### What It Is

A modern Shadowsocks variant using stronger, more explicit crypto design.

### Main Characteristics

- session salt
- derived subkeys
- encrypted framing
- replay protection concerns

### Mental Model

It is less "send one plain header and relay raw bytes" and more "create an encrypted session format."

## Supported Transports In This Repo

## TCP

### What It Is

The simplest stream transport.

### Mental Model

Just a reliable byte stream.

Almost every other transport in this repo either starts with TCP or wraps something equivalent.

## TLS

### What It Is

Standard TLS encryption on top of TCP.

### Main Job

- authenticate server
- negotiate keys
- encrypt application data

### Important Repo Detail

TLS is a transport/security wrapper, not a proxy protocol by itself.

You can have:

- VLESS over TLS
- Trojan over TLS
- WebSocket over TLS

## WebSocket

### What It Is

HTTP upgrade from plain HTTP request/response into framed bidirectional messages.

### Why Proxy Projects Use It

Because WebSocket traffic often blends into normal web traffic better than custom raw protocols.

### Repo Mental Model

WebSocket wrapper makes a framed stream look like a normal byte stream to the protocol layer.

## gRPC

### What It Is

HTTP/2-based framing commonly used as a carrier for proxy traffic.

### Why Use It

It hides traffic inside HTTP/2 semantics and can work better with some CDNs/proxies.

### Repo Mental Model

The implementation wraps payload bytes inside gRPC-style frames but exposes a stream-like interface upward.

## QUIC

### What It Is

Modern UDP-based secure transport.

### Why It Matters Here

Hysteria2 and other modern transports may rely on QUIC semantics.

### Mental Model

Not just "faster TCP". It is a different transport family with different flow-control and handshake behavior.

## REALITY

### What It Is

A special transport/authentication disguise layer from the Xray ecosystem.

### What Makes It Different

REALITY is not just "TLS with a different cert."

It does all of these:

1. build a browser-like ClientHello
2. hide auth token material inside normal TLS fields
3. validate the disguised auth on the server
4. on success, continue into a real TLS 1.3 handshake
5. on failure, forward to fallback so probes see ordinary traffic

### The Important Repo Split

REALITY spans two crates:

- `blackwire-tls`
  builds the browser-like ClientHello

- `blackwire-transport`
  performs REALITY auth and handshake behavior

### Why It Is Hard

REALITY sits on the border between:

- fake browser fingerprinting
- custom auth
- normal TLS transcript rules
- Xray interoperability

That is why there are dedicated interop docs and tests.

## mKCP

### What It Is

KCP-style transport over UDP with its own framing/reliability behavior.

### Mental Model

Useful for hostile or lossy links, but not a beginner-friendly first read.

### Repo Status

The runtime has a UDP listener with per-peer KCP sessions, idle cleanup, and
local VLESS-over-mKCP e2e coverage. It still needs realistic loss/latency lab
validation before being treated as production-ready.

## TUN

### What It Is

A virtual network interface.

### Why It Exists

Instead of configuring an app to use SOCKS manually, TUN mode can capture traffic at the OS level and feed it into the proxy.

### Mental Model

TUN is not a protocol spoken by browsers.
It is an operating-system-level traffic capture/redirect mechanism.

### Repo Status

The repo can start a top-level `tun` runtime on Linux and has helpers for device
creation, route installation, cleanup, IP packet parsing, UDP response packet
synthesis, and flow/NAT session tracking. Packet parsing, UDP response
synthesis, flow/NAT session tracking, and the runtime packet loop are shared
cross-platform APIs. The full-device runtime backend is Linux/root-oriented
today. macOS utun and Windows Wintun device creation are wired through the
native `tun` crate backend, and Windows can use `tun.wintunFile`/`tun.wintun_file`
to point at a bundled `wintun.dll`. macOS/Windows still fail early through the
explicit TUN platform support contract when `config.tun` asks for a full-device
runtime. That contract keeps packet/NAT/session helpers portable while
preventing macOS/Windows from silently accepting a `tun` config before their
native routing and TCP redirection paths exist.

## ShadowTLS

### What It Is

Another disguise-oriented transport idea focused on looking TLS-like.

### Repo Role

Advanced transport area, not the first thing to learn. Current runtime support
implements ShadowTLS v3 ClientHello SessionID authentication, backend TLS
ApplicationData tainting, switch detection, and rolling-HMAC data frames for
VLESS/Trojan/VMess-style byte streams. It has local e2e coverage; external
interop against sing-box/shadow-tls deployments still needs realistic lab proof.

## Common Combinations

The repo is designed so protocols and transports can be composed.

Examples:

### SOCKS inbound over plain TCP

- transport: TCP
- protocol: SOCKS5 inbound

### VLESS outbound over TLS

- transport: TCP then TLS
- protocol: VLESS outbound

### VLESS inbound over REALITY

- transport path: TCP -> REALITY auth -> TLS 1.3 completion
- protocol: VLESS inbound

### VLESS over WebSocket over TLS

- transport path: TCP -> TLS -> WebSocket
- protocol: VLESS

### Trojan over TLS

- transport path: TCP -> TLS
- protocol: Trojan

## What Lives Where In Code

As a rule:

- destination encoding, auth tokens, UUID parsing, request headers:
  `blackwire-protocol`

- socket accept, TLS wrapping, WebSocket wrapping, REALITY handshake:
  `blackwire-transport`

- browser-like ClientHello construction for REALITY:
  `blackwire-tls`

- choosing outbound and relaying streams:
  `blackwire-app`

- building the stack from config:
  `blackwire-core`

## How To Read A Layered Stack

When you see a config like:

- protocol: VLESS
- security: TLS
- network: WS

Read it from outside to inside:

1. raw socket arrives
2. TLS unwrap happens
3. WebSocket unwrap happens
4. VLESS parser sees clean bytes

When sending outbound, think in reverse:

1. protocol writes bytes
2. WebSocket frames them
3. TLS encrypts them
4. TCP sends them

## Why This Separation Matters

Because otherwise every protocol implementation would need to know:

- how to parse TLS
- how to do WebSocket
- how to do QUIC
- how to do gRPC

That would be a mess.

Instead, the design is:

- transport produces a stream
- protocol consumes a stream

That makes the system extensible.

## Beginner Summary

If you are lost, ask these two questions:

1. Am I looking at bytes that describe a proxy request?
   If yes, you are probably in `blackwire-protocol`.

2. Am I looking at code that carries, wraps, disguises, encrypts, or accepts the stream?
   If yes, you are probably in `blackwire-transport` or `blackwire-tls`.

That one distinction will save you a lot of confusion.
