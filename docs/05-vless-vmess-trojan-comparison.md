# VLESS, VMess, And Trojan Comparison

This document answers:

"These three protocols all sound similar. What is the actual difference?"

Short answer:

- VLESS is the lightest and simplest.
- VMess is older and more cryptographically heavy.
- Trojan is conceptually small but is intended to live inside TLS and look like normal HTTPS.

## Quick Summary Table

| Protocol | Main identity style | Header complexity | Stream framing | Typical pairing |
|----------|---------------------|-------------------|----------------|-----------------|
| VLESS | UUID | low | minimal after header | TLS, WS, REALITY |
| VMess | UUID -> `cmd_key` -> auth ID | high | encrypted framed stream | TLS, WS, gRPC |
| Trojan | password -> token | medium | mostly simple after header | TLS |

## VLESS

### What It Optimizes For

Simplicity and low overhead.

### How It Identifies Users

With a 16-byte UUID in the header.

### What The Header Contains

In plain terms:

- version
- user UUID
- optional flow/addons
- command
- destination address and port

Then raw payload bytes follow.

### What That Means Operationally

Once the VLESS header is parsed, the rest of the stream is mostly just normal application traffic.

That is why VLESS feels lightweight in this repo.

### Why People Like It

- simple
- low overhead
- easy to combine with advanced transports
- common choice with REALITY

### Where To Read It

- [crates/blackwire-protocol/src/vless/mod.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vless/mod.rs)
- [crates/blackwire-protocol/src/vless/codec.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vless/codec.rs)
- [crates/blackwire-protocol/src/vless/inbound.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vless/inbound.rs)
- [crates/blackwire-protocol/src/vless/outbound.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vless/outbound.rs)

## VMess

### What It Optimizes For

A more integrated encrypted protocol format with explicit auth and per-stream cryptographic framing.

### How It Identifies Users

Indirectly.

It starts from the user UUID, but then derives a `cmd_key`.
That `cmd_key` is used for auth ID generation and later header/key derivation.

### What The Auth Looks Like

In this repo’s implementation:

- `cmd_key = MD5(uuid || magic-string)`
- auth ID is generated from timestamp + CRC + random
- auth ID is AES-encrypted

That is already more machinery than VLESS.

### What The Stream Looks Like

VMess is not just "header then raw bytes".

It has AEAD-encrypted stream chunk behavior.

That means there is more state and more room for subtle partial-write bugs.

### Why It Feels Heavier

Because it has:

- more crypto state
- more helper modules
- more framing logic
- more derived secrets

### Where To Read It

- [crates/blackwire-protocol/src/vmess.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vmess.rs)
- [crates/blackwire-protocol/src/vmess/auth.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vmess/auth.rs)
- [crates/blackwire-protocol/src/vmess/codec.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vmess/codec.rs)
- [crates/blackwire-protocol/src/vmess/stream.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/vmess/stream.rs)

## Trojan

### What It Optimizes For

Looking like normal TLS-carried traffic while keeping the protocol header relatively small.

### How It Identifies Users

With a password-derived token.

This repo computes:

- `token = lowercase_hex(SHA224(password))`

### What The Header Contains

In practical terms:

- auth token
- CRLF
- command byte
- destination address
- destination port
- CRLF

Then payload follows.

### Why Trojan Feels Different

Trojan is often described less as "a full proxy protocol family" and more as:

"a simple authenticated request format intended to live inside TLS"

That makes it conceptually simpler than VMess, but it depends more strongly on the surrounding TLS story.

### Where To Read It

- [crates/blackwire-protocol/src/trojan.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/trojan.rs)
- [crates/blackwire-protocol/src/trojan/codec.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/trojan/codec.rs)
- [crates/blackwire-protocol/src/trojan/inbound.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/trojan/inbound.rs)
- [crates/blackwire-protocol/src/trojan/outbound.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/trojan/outbound.rs)

## How To Think About Them In This Repo

### VLESS

Think:

"small request header, then mostly just relay"

### VMess

Think:

"auth math + encrypted header + encrypted framed stream"

### Trojan

Think:

"password token + simple request format inside TLS"

## Which One Is Easiest To Understand

For code reading:

1. VLESS
2. Trojan
3. VMess

That is the order I recommend.

## Which One Fits BEST With REALITY

In this codebase, VLESS is the most natural pairing with REALITY.

Why:

- VLESS is lightweight
- REALITY already provides the disguise/transport complexity
- combining a light protocol with a sophisticated transport keeps responsibilities clearer

That is why REALITY glue in [crates/blackwire-core/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/reality.rs) is specifically about VLESS over REALITY.

## Common Beginner Confusions

### "If VLESS is simpler, is it weaker?"

Not in the simplistic sense people often mean.

VLESS is simpler because it delegates more to the transport stack and carries less baggage in its own framing.

### "If Trojan looks like TLS, why not always use Trojan?"

Because "best" depends on ecosystem compatibility, operational goals, transport pairing, and implementation complexity.

Also, in this repo, REALITY is a more specialized disguise story than plain Trojan-over-TLS.

### "Is VMess obsolete?"

Not the right question.

The better question is:

"Do I need the complexity VMess brings, or is VLESS enough for the path I care about?"

For learning this codebase, VLESS is usually enough first.

## Which One Should You Read First

If your goal is understanding the project:

1. read SOCKS + Freedom first
2. then VLESS
3. then Trojan
4. then VMess
5. then REALITY transport

That order reduces confusion.

## One-Line Final Summary

- VLESS is the lightweight protocol.
- VMess is the heavy cryptographic protocol.
- Trojan is the simple TLS-oriented authenticated protocol.

