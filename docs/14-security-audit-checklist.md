# Security audit checklist

## Attack surface

- Inbound protocol parsers.
- Outbound protocol builders.
- TLS/REALITY handshake code.
- DNS and FakeIP state.
- Config loader and hot reload.
- TUN/privileged Linux, macOS, and Windows paths.
- Metrics/admin API.
- Logs and reports.
- Docker/systemd deployment files.

## Questions that must have answers

- Can unauthenticated input allocate unbounded memory?
- Can malformed input panic, loop forever, or stall a Tokio task?
- Can auth be bypassed through partial reads, parser desync, or fallback confusion?
- Are UUID/password comparisons appropriate for secrets?
- Are secrets redacted from logs and reports?
- Are insecure config modes explicitly visible?
- Does config reload avoid mixed old/new routing state?
- Can stale FakeIP mappings misroute traffic?
- Does DNS failure behave deterministically?
- Does TUN setup clean up routes/interfaces after failure?
- Are TLS verification defaults safe?
- Are unsafe blocks documented and justified?
- Are dependency advisories tracked?

## Tooling

Run from the repo root:

```sh
make security          # audit + deny (when installed) + lab security script
make fuzz-smoke        # short nightly fuzz pass on parser targets
make verify-local      # includes clippy with -D warnings
```

Lab-only security script (also invoked by `make security`):

```sh
make -C labs/realistic security
```

Install optional tools:

```sh
cargo install cargo-audit
cargo install cargo-deny
cargo install cargo-fuzz
```

Then run longer fuzz campaigns:

```sh
make fuzz-long         # FUZZ_RUNS=100000 by default; override as needed
```

## Log redaction

Do not paste raw proxy logs or lab reports that may contain UUIDs, passwords,
private keys, or REALITY key material. When sharing failures, redact:

- inbound/outbound credentials and auth tokens
- `SSH_KEY` paths if they reveal account structure
- full `ClientHello` dumps unless explicitly needed for REALITY debugging

`REALITY_DEBUG_HELLO=1` enables extra handshake fields in debug logs — use only
in controlled environments.

See [12-production-readiness.md](12-production-readiness.md) and [test-workflows.md](test-workflows.md).
