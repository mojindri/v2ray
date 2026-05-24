# Production-readiness gates

Normal CI, local realistic tests, and a two-VPS matrix are necessary but not
enough for production confidence. Use these gates as **separate signals**.

Targets below are the **actual** Make names (root or `labs/realistic`). There are
no `make ci-*` wrappers for most of these — use the commands directly or run
`make -C labs/realistic prod-readiness` for the bundled subset.

| Gate | Purpose | Command |
|---|---|---|
| Host Rust quality | fmt, check, clippy, test | `make verify-local` |
| Lab realism | Docker + Lima + external clients | `make verify-lab` |
| VPS matrix | public-network protocol coverage | `make verify-remote` |
| Load | high-concurrency data-plane pressure | `make -C labs/realistic load` or `make local-load` |
| Soak | leak/degradation over time | `make soak` or `make -C labs/realistic soak` |
| Fuzz smoke | parser crash discovery | `make fuzz-smoke` |
| Fuzz long | heavier parser campaigns | `make fuzz-long` (`FUZZ_RUNS=…`) |
| Fingerprint | TLS/REALITY ClientHello capture | `make -C labs/realistic fingerprint` or `verify-lab-lima` |
| DNS chaos | DNS/FakeIP edge cases | `make -C labs/realistic dns-chaos` |
| Security hygiene | audit, deny, secrets, unsafe scan | `make security` |
| Real devices | manual client checklist template | `make -C labs/realistic real-devices` |

Bundled helper (excludes fuzz by default):

```sh
make -C labs/realistic prod-readiness
make -C labs/realistic prod-readiness-with-fuzz
```

## Recommended order

1. `make verify-local`
2. `make verify-lab`
3. `SSH_SERVER=… SSH_CLIENT=… make verify-remote`
4. `make security` — resolve obvious findings
5. `make fuzz-smoke`; then `make fuzz-long` per target as needed
6. `make -C labs/realistic load` — ramp concurrency (100 → 500 → 1000)
7. `make soak` — start at 1h, then 24h, then 72h
8. `make verify-lab-lima` or `make -C labs/realistic fingerprint-total`
9. `make -C labs/realistic dns-chaos`
10. `make -C labs/realistic real-devices` — fill manual device matrix

For a single broad automated pass (not a full release soak):

```sh
make verify-sweep
```

## Pass/fail policy

Each gate should emit a report and a threshold:

- **Load:** ≥ 99% success for the configured run
- **Soak:** no monotonic RSS/fd growth; no reconnect storms; no silent protocol death
- **Fuzz:** zero crashes, timeouts, or OOMs in the campaign window
- **Fingerprint:** known and reviewed ClientHello differences only
- **DNS/FakeIP:** deterministic behavior for NXDOMAIN, SERVFAIL, IPv4/IPv6, stale mappings, reload
- **Security:** no secrets in repo; no unreviewed critical advisories; `unsafe` justified

## Blunt limitation

Passing these gates does not prove censorship resistance, full cryptographic
correctness, or complete production safety. They provide repeatable evidence
across stability, stress, parsers, DNS, fingerprints, and deployment assumptions.

See also: [test-workflows.md](test-workflows.md), [14-security-audit-checklist.md](14-security-audit-checklist.md).
