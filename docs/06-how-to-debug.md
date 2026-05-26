# How To Debug This Repo

This document is for the moment when something is broken and you need a sane workflow.

The repo is large enough that random debugging is inefficient.

Use a layered approach.

## Rule 1: Identify The Layer First

Before changing code, decide which layer the bug belongs to.

Ask:

### Is config malformed or startup failing?

Look at:

- `blackwire-config`
- `blackwire-core`

### Is routing or dispatch wrong?

Look at:

- `blackwire-app`

### Is a protocol header wrong?

Look at:

- `blackwire-protocol`

### Is TLS, WebSocket, REALITY, gRPC, QUIC, or stream wrapping wrong?

Look at:

- `blackwire-transport`
- `blackwire-tls` for REALITY `ClientHello`

This one decision saves a lot of wasted time.

## Rule 2: Run The Narrowest Test First

Do not start with the whole workspace if you already know the likely area.

Examples:

### Protocol bug

```bash
cargo test -p blackwire-protocol
```

### Transport bug

```bash
cargo test -p blackwire-transport
```

### Production-readiness edge case

```bash
cargo test -p blackwire-transport --test production_readiness --all-features
cargo test -p blackwire-protocol --test production_readiness --all-features
cargo test -p blackwire-core --test production_readiness --all-features
```

### Specific test name

```bash
cargo test reality_legitimate_client_can_authenticate_and_exchange_data -- --nocapture
```

This keeps the feedback loop short.

## Rule 3: Read The Test Before Reading The Code

Especially for failures in `production_readiness` and integration tests.

The test often tells you:

- what contract is expected
- what exact invariant is being enforced
- whether the failure is protocol correctness, validation strictness, or async behavior

Good places:

- [crates/blackwire-transport/tests/production_readiness.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/tests/production_readiness.rs)
- [crates/blackwire-protocol/tests/production_readiness.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/tests/production_readiness.rs)
- [crates/blackwire-core/tests/production_readiness.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/tests/production_readiness.rs)

## Rule 4: Distinguish "Stuck" From "Failed"

These are different classes of bugs.

### If a test fails quickly

Usually think:

- wrong constant
- wrong parsing
- wrong validation
- wrong expectation

### If a test hangs

Usually think:

- protocol deadlock
- both sides waiting on different stages
- missing timeout
- partial-write/flush state bug
- one side expecting plaintext while the other is still in TLS

This distinction mattered a lot in the REALITY test fixes.

## Common Bug Patterns In This Repo

## 1. Partial-write bugs

Symptoms:

- one-byte inner-write tests fail
- flush hangs
- exact byte comparisons fail

Where to look:

- stream wrappers in `blackwire-transport`
- encrypted/framed streams in `blackwire-protocol`

What usually went wrong:

- assuming `poll_write` writes the whole buffer
- dropping buffered bytes on `Pending`
- not preserving in-flight frame state across flush retries

## 2. Parser validation gaps

Symptoms:

- malformed fixture tests fail
- invalid config gets accepted
- empty or impossible fields slip through

Where to look:

- protocol codec
- config builder/wiring
- packet parsing code

Examples we already fixed in this repo:

- invalid IPv4 header acceptance
- empty HTTP CONNECT host acceptance
- bad routing rule acceptance

## 3. Stale tests after contract changes

Symptoms:

- old tests hang or assert the wrong shape after implementation evolved

Typical case:

- tests expecting raw post-auth bytes (auth-only / direct mode)
- implementation now completes TLS 1.3 before returning app stream

When this happens, do not blindly "fix code to satisfy old tests."
Decide whether the implementation contract or the test contract is the current truth.

## 4. Interop mismatches

Symptoms:

- self-interop passes but Xray interop fails
- live peer rejects a handshake shape

Where to look:

- `tests/interop/README.md`
- REALITY client/server code
- exact TLS group/key-share offers

The live peer can reveal requirements your self-interop does not enforce.

## Good Debugging Paths By Topic

## Startup failures

Read:

- [crates/blackwire-cli/src/main.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-cli/src/main.rs)
- [crates/blackwire-core/src/instance.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/instance.rs)

Check:

- config parse/validation
- listener bind behavior
- metrics bind behavior
- fail-fast startup expectations

## Routing issues

Read:

- [crates/blackwire-app/src/router.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/router.rs)
- [crates/blackwire-app/src/dispatcher.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-app/src/dispatcher.rs)

Check:

- domain rule compilation
- CIDR parsing
- outbound tag existence
- default outbound selection

## SOCKS / HTTP CONNECT issues

Read:

- [crates/blackwire-protocol/src/socks.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/socks.rs)
- [crates/blackwire-protocol/src/http_connect.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-protocol/src/http_connect.rs)

## VLESS / Trojan / VMess issues

Read:

- protocol `codec`, `inbound`, `outbound`
- tests around malformed fixed fixtures and roundtrips

## REALITY issues

Read:

- [docs/04-reality-for-dummies.md](/Users/mojnader/RustroverProjects/v2ray/docs/04-reality-for-dummies.md)
- [tests/interop/README.md](/Users/mojnader/RustroverProjects/v2ray/tests/interop/README.md)
- [crates/blackwire-transport/src/reality/client.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/client.rs)
- [crates/blackwire-transport/src/reality/server.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-transport/src/reality/server.rs)
- [crates/blackwire-core/src/reality.rs](/Users/mojnader/RustroverProjects/v2ray/crates/blackwire-core/src/reality.rs)

Look specifically for:

- handshake stage mismatches
- fallback behavior
- `ClientHello` layout
- TLS group selection

## How To Use Examples For Debugging

The `examples/` directory is useful when the full workspace feels too big.

Examples include:

- REALITY local demos
- Hysteria2 local demos
- VLESS+WebSocket local demos
- SS2022 local demos
- ShadowTLS demos
- TUN demos

Use the nearest example as a reduced reproduction case.

Good starting point:

- [examples/reality-client-server/README.md](/Users/mojnader/RustroverProjects/v2ray/examples/reality-client-server/README.md)
- [examples/vless-ws-local/README.md](/Users/mojnader/RustroverProjects/v2ray/examples/vless-ws-local/README.md)
- [examples/http-vmess-grpc-local/README.md](/Users/mojnader/RustroverProjects/v2ray/examples/http-vmess-grpc-local/README.md)

## Useful Commands

### Run one package

```bash
cargo test -p blackwire-transport
```

### Run one exact test target

```bash
cargo test -p blackwire-core --test production_readiness --all-features
```

### Run one named test with output

```bash
cargo test some_test_name -- --nocapture
```

### REALITY live interop

```bash
make -C tests/interop up
cargo test -p blackwire-transport --test interop d1 -- --ignored --nocapture
make -C tests/interop down
```

## A Practical Debugging Recipe

Use this sequence:

1. Reproduce with the narrowest failing test.
2. Read the failing test.
3. Identify the layer.
4. Read the smallest implementation file that owns that behavior.
5. Patch one thing only.
6. Rerun the narrow test.
7. Then rerun the package test.

This is much better than editing three crates at once and hoping.

## Final Rule

Never debug this repo by vague intuition like "REALITY is broken" or "routing is weird".

Always rephrase the problem into something concrete like:

- "the outbound tag is not validated during build"
- "the stream drops bytes when inner `poll_write` returns `Pending`"
- "the client is waiting for TLS while the server expects plaintext"

Once the bug is stated that specifically, the fix is usually obvious.

