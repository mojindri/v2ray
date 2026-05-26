# REALITY For Dummies

This is the plain-English version of REALITY in this repo.

If REALITY currently feels like magic, read this first.

## The One-Sentence Idea

REALITY tries to make a proxy connection look like a real browser starting a real TLS connection to a real website.

That is the whole game.

## Why REALITY Exists

Normal proxy traffic can be easy to fingerprint.

A censor or active probe can look for:

- unusual TLS fingerprints
- obvious proxy protocol headers
- servers that react differently when given invalid auth

REALITY tries to avoid that by:

1. making the client send a browser-like TLS `ClientHello`
2. hiding auth information inside normal TLS fields
3. making failed probes fall through to a believable fallback
4. making successful connections continue as a real TLS 1.3 session

So the connection does not just "look TLS-ish".
It has to survive a real TLS-shaped interaction.

## What REALITY Is Not

REALITY is not:

- just "TLS with a special cert"
- just "send one fake packet"
- just "obfuscation without handshake completion"

In the current codebase, REALITY success means:

- disguised auth succeeds
- TLS 1.3 handshake completes
- application bytes flow after handshake

That is the important Phase 3 contract.

## The Two Sides

There are two sides in the repo:

### Client side

Main files:

- [crates/blackwire-transport/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality.rs)
- [crates/blackwire-transport/src/reality/client.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/client.rs)
- [crates/blackwire-tls/src/lib.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-tls/src/lib.rs)
- [crates/blackwire-tls/src/client_hello.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-tls/src/client_hello.rs)

Client responsibilities:

- build a Chrome-like `ClientHello`
- generate ephemeral key shares
- derive REALITY auth material
- encrypt token into `session_id`
- send the `ClientHello`
- continue the TLS 1.3 handshake

### Server side

Main files:

- [crates/blackwire-transport/src/reality/server.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/server.rs)
- [crates/blackwire-transport/src/reality/parser.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/parser.rs)
- [crates/blackwire-core/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/reality.rs)

Server responsibilities:

- read the incoming TLS record
- parse only the fields REALITY needs
- derive the same shared secret
- decrypt and validate token
- if valid, run the custom TLS 1.3 server handshake (`complete_tls13_server_handshake`)
- if invalid, forward to fallback

## What The ClientHello Is Doing

In a normal browser TLS handshake, the client sends:

- supported cipher suites
- key shares
- SNI
- extensions
- random bytes
- session ID

REALITY reuses that shape.

This repo’s REALITY client specifically hides data in:

- `key_share`
  carries the client ephemeral public key

- `random`
  supplies HKDF salt and AES-GCM nonce material

- `session_id`
  stores the encrypted REALITY token

That is why `blackwire-tls` exists at all: the code needs fine control over the raw `ClientHello`, not just a generic TLS library default.

## Why `blackwire-tls` Exists

Normal `rustls` is good at speaking TLS.

But REALITY needs more than "speak TLS correctly".
It needs "speak TLS in a way that looks like Chrome".

That means the code needs control over:

- extension order
- GREASE values
- key share ordering
- browser fingerprint details

That work lives in `blackwire-tls`.

## The Successful REALITY Flow

Here is the simplified success path.

### Step 1: Client generates key material

In [client.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/client.rs), the client generates:

- an `x25519` key share for REALITY auth and normal TLS
- a `secp256r1` key share so real servers that prefer P-256 can work

That dual offer matters because live Xray interop revealed real TLS behavior that selected P-256.

### Step 2: Client derives auth key

The client does ECDH against the server’s long-term public key and derives an auth key via HKDF.

Then it builds a token containing things like:

- protocol version
- timestamp
- short ID

That token is encrypted with AES-GCM.

### Step 3: Client builds browser-like `ClientHello`

The client builds a Chrome-like `ClientHello` with:

- realistic TLS layout
- real key shares
- chosen SNI

Then it patches the encrypted token into the `session_id` field.

### Step 4: Client sends the `ClientHello`

At this point the connection looks like a browser beginning TLS.

### Step 5: Server reads and parses

The server does not run a full TLS stack first.

It first reads:

- TLS record header
- `ClientHello` body

Then it extracts only the needed fields through the REALITY parser.

### Step 6: Server authenticates

The server:

- derives the same shared secret from client key share and server private key
- derives the auth key
- reconstructs the AAD
- decrypts the `session_id`
- validates timestamp and short ID

If that succeeds, the client is considered legitimate.

### Step 7: Server replays the `ClientHello` for Phase 3 post-auth TLS

After REALITY auth succeeds, the server does not hand plaintext bytes directly to
the protocol handler.

Instead:

- `RealityServer::accept_with_key()` returns a stream that **prepends** the original `ClientHello`
- `complete_tls13_server_handshake()` reads that replay, completes TLS 1.3 as server, and derives application keys
- `Tls13Stream` encrypts/decrypts application data for the VLESS inbound

This uses the **custom TLS 1.3 server path** in `tls13_server.rs`, not generic
`rustls` accept. Real Xray/sing-box clients (uTLS) require that path — including
the correct `CertificateVerify` signature input and REALITY cert HMAC.

Wiring lives in [crates/blackwire-core/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/reality.rs).

### Step 8: TLS 1.3 completes

Only after TLS finishes does the VLESS inbound see application bytes.

This is why old tests based on `accept_direct()` or generic `tls_accept()` became stale.

## The Failure Flow

If auth fails:

1. the server has already consumed some bytes
2. it opens the configured fallback destination
3. it replays the consumed bytes there
4. it proxies the connection to the fallback

This is active-probe resistance.

The goal is:

"A bad client should see something that looks like a real server, not an obvious proxy rejection."

## Why TLS 1.3 Completion Matters

This is the source of a lot of confusion.

People sometimes think:

"If the fake browser `ClientHello` looked right, REALITY is done."

That is not enough.

A real peer like Xray still expects:

- `ServerHello`
- transcript evolution
- traffic secret derivation
- `Finished`
- application data only after handshake

That is why the interop docs emphasize full TLS completion, not just auth token success.

See:

- [tests/interop/README.md](/Users/mojnader/RustroverProjects/v2ray/tests/interop/README.md)

## What `d0` And `d1` Mean

These terms come from the interop tests.

### `d0`

Self-interop.

Meaning:

- our REALITY client talks to our REALITY server
- checks internal consistency

### `d1`

Live Xray interop.

Meaning:

- our client talks to a real `xray-core` instance
- checks actual compatibility expectations

This distinction matters because code can pass `d0` and still fail against Xray.

## Why The Fallback `dest` Must Be Real HTTPS For Success Path

Another easy misunderstanding:

"Fallback server" and "cover destination" are not the same thing in the valid path.

For a valid REALITY success flow, Xray relays a real TLS handshake from the configured destination.

That means the destination used in live interop must actually speak TLS.

If it points to plain HTTP on port 80, the client cannot complete a real TLS handshake.

That is why the Xray interop harness uses a real HTTPS endpoint on `:443`.

## The Most Important Files

If you want to study REALITY in code, read in this order:

1. [crates/blackwire-transport/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality.rs)
   overview and module split

2. [crates/blackwire-transport/src/reality/client.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/client.rs)
   client build/send/handshake path

3. [crates/blackwire-transport/src/reality/server.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/server.rs)
   server auth and fallback path

4. [crates/blackwire-transport/src/reality/parser.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/parser.rs)
   field extraction

5. [crates/blackwire-transport/src/reality/tls13_server.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/tls13_server.rs)
   Phase 3 post-auth TLS 1.3 server handshake (ServerHello through Finished)

6. [crates/blackwire-core/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/reality.rs)
   how REALITY auth connects to TLS completion and VLESS

7. [docs/reality-interop.md](/Users/mojnader/RustroverProjects/v2ray/docs/reality-interop.md)
   interop notes (auth key, cert HMAC, CertificateVerify)

8. [tests/interop/README.md](/Users/mojnader/RustroverProjects/v2ray/tests/interop/README.md)
   what compatibility is actually being proven

## Beginner Summary

REALITY in this repo means:

- look like Chrome
- hide auth inside TLS fields
- if auth fails, look like a normal site
- if auth succeeds, become a real TLS 1.3 session

That last step is the part that turns REALITY from a packet trick into a usable transport.

