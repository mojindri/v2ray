# Security Policy

## Supported versions

This project is pre-1.0. Security fixes are handled on the main development branch unless a release branch is explicitly published.

| Version | Supported |
|---|---|
| main | Yes |
| tagged pre-1.0 releases | Best effort |
| old snapshots | No |

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Report privately to the project maintainer with:

- affected commit/tag
- affected protocol/transport
- reproduction steps
- config used
- logs with secrets redacted
- packet capture if relevant, with credentials removed
- whether the issue affects client mode, server mode, or both

## Security-sensitive areas

The highest-risk areas are:

- REALITY / TLS fingerprint behavior
- authentication and fallback handling
- parser behavior on malformed network input
- TUN mode and privileged networking
- DNS / FakeIP routing correctness
- config secrets and private key handling
- replay protection
- slow-client / slow-server resource exhaustion
- file descriptor exhaustion
- logging redaction

## Expected behavior

Security bugs include:

- authentication bypass
- panic/crash from remote input
- unbounded memory or task growth from remote input
- secret/private-key leakage in logs
- unsafe fallback behavior that exposes proxy identity
- incorrect TLS verification defaults
- DNS/FakeIP routing leaks
- malformed packet parser desynchronization
- privilege escalation in TUN or system integration

## Non-goals

This project does not currently claim:

- full V2Ray-core compatibility
- full Xray-core compatibility
- censorship-resistance proof
- byte-identical browser fingerprinting
- production-grade release hardening

## Disclosure

Until a formal process exists, coordinate disclosure directly with the maintainer. Give enough time to reproduce, patch, and release before public disclosure.
