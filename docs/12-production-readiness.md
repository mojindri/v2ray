# Production-readiness gates

This project already has normal CI, local realistic tests, and a two-VPS matrix. Those are necessary but not enough for production confidence.

Use these gates as separate signals:

| Gate | Purpose | Target |
|---|---|---|
| `make ci-load` | High-concurrency data-plane pressure | Many SOCKS -> outbound -> server -> HTTP requests |
| `make ci-soak` | Leak/degradation detection | Repeated load and health checks over hours/days |
| `make ci-fuzz-smoke` | Parser crash discovery | Malformed protocol inputs |
| `make ci-fingerprint` | TLS/REALITY fingerprint inspection | ClientHello capture and comparison |
| `make ci-dns-chaos` | DNS/FakeIP edge-case lab | NXDOMAIN, SERVFAIL, IPv4, IPv6, slow DNS |
| `make ci-security` | Security hygiene | unsafe/secret/dependency/audit review |
| `make ci-real-devices` | Manual real-client coverage | phones, OS clients, carrier paths |

## Recommended order

1. Make `make ci` pass.
2. Make `make ci-all` pass.
3. Make `make ci-vps` pass on two real VPSes.
4. Run `make ci-security` and resolve obvious issues.
5. Run `make ci-fuzz-smoke`; then run each fuzz target longer.
6. Run `make ci-load` with 100, 500, then 1000 concurrency.
7. Run `make ci-soak` for 1h, then 24h, then 72h.
8. Capture TLS fingerprints for REALITY/TLS paths.
9. Run DNS/FakeIP chaos cases.
10. Test real client devices.

## Pass/fail policy

Do not accept vague passes. Each production gate should emit a report and a threshold:

- Load: >= 99% success rate for the configured run.
- Soak: no monotonic RSS/fd growth, no repeated reconnect storms, no silent protocol death.
- Fuzz: zero crashes, zero timeouts, zero OOMs.
- Fingerprint: known and reviewed ClientHello differences only.
- DNS/FakeIP: deterministic behavior for NXDOMAIN, SERVFAIL, IPv4, IPv6, stale mappings, and config reload.
- Security: no secrets in repo, no known critical advisories, unsafe reviewed or removed.

## Blunt limitation

Passing these gates still does not prove censorship resistance, cryptographic correctness, or complete production safety. It proves you have repeatable evidence across stability, stress, parsers, DNS, fingerprints, and deployment assumptions.
