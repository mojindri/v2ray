# Stability + Adversarial Test Report

Date: May 25, 2026  
Repo: `/Users/mojnader/RustroverProjects/v2ray`

## Scope

This report covers Task B implementation and execution status for stability/adversarial test categories.  
Only tests were added/updated. No runtime feature implementation was performed in this step.

## What Was Added

### Integration test suites (`tests/`)

- Fragmentation:
  - `tests/adversarial/fragmentation/protocols.rs`
  - `tests/tests/adversarial_fragmentation.rs`
- Backpressure:
  - `tests/adversarial/backpressure/mod.rs`
  - `tests/tests/adversarial_backpressure.rs`
- Cancellation/drop:
  - `tests/adversarial/cancellation/mod.rs`
  - `tests/tests/adversarial_cancellation.rs`
- Half-close:
  - `tests/adversarial/half_close/mod.rs`
  - `tests/tests/adversarial_half_close.rs`
- Upstream chaos:
  - `tests/adversarial/upstream_chaos/mod.rs`
  - `tests/tests/adversarial_upstream_chaos.rs`
- Large frames:
  - `tests/adversarial/large_frames/mod.rs`
  - `tests/tests/adversarial_large_frames.rs`
- Task pressure:
  - `tests/adversarial/task_pressure/mod.rs`
  - `tests/tests/adversarial_task_pressure.rs`
- Resource exhaustion (heavy, gated/ignored):
  - `tests/resource_limits/exhaustion.rs`
  - `tests/tests/resource_limits.rs`
- Reload-during-traffic:
  - `tests/reload/mod.rs`
  - `tests/tests/reload_during_traffic.rs`
- Security boundaries:
  - `tests/security/mod.rs`
  - `tests/tests/security_boundaries.rs`
- Observability:
  - `tests/observability/mod.rs`
  - `tests/tests/observability.rs`
- Socket/kernel behavior:
  - `tests/socket/mod.rs`
  - `tests/tests/socket_behavior.rs`
- Leak assertions:
  - `tests/common/leak_check.rs`
  - `tests/tests/leak_assertions.rs`
- Shared harness:
  - `tests/common/harness.rs`
- Loom:
  - `tests/loom/concurrency.rs`
  - `tests/tests/loom_concurrency.rs`

### Crate-level tests

- Proxy core fail-closed config tests:
  - `crates/proxy-core/tests/config_fail_closed.rs`
- Proxy config schema fail-closed tests:
  - `crates/proxy-config/tests/fail_closed_schema.rs`
- Proxy protocol fragmentation/stateful parser tests:
  - `crates/proxy-protocol/tests/fragmentation_parsers.rs`
  - `crates/proxy-protocol/tests/stateful_parsers.rs`

### Fuzz

- Stateful fuzz target:
  - `fuzz/fuzz_targets/stateful_sequences.rs`
  - plus bin registration in `fuzz/Cargo.toml`

## Build/Check Status

Successful compile checks:

- `cargo test -p integration-tests --no-run`
- `cargo test -p proxy-core --test config_fail_closed --no-run`
- `cargo test -p proxy-config --test fail_closed_schema --no-run`
- `cargo test -p proxy-protocol --test fragmentation_parsers --test stateful_parsers --no-run`
- `cargo check --manifest-path fuzz/Cargo.toml --bin stateful_sequences`

Heavy suites are intentionally `#[ignore]` and/or feature-gated (`heavy-tests`, `loom-tests`).

## Executed Results (Targeted)

Passed (targeted execution):

- `integration-tests`:
  - `adversarial_fragmentation`
  - `adversarial_backpressure`
  - `adversarial_cancellation`
  - `adversarial_half_close`
  - `adversarial_upstream_chaos`
  - `adversarial_task_pressure`
  - `socket_behavior`
  - `observability`
- `proxy-protocol`:
  - `fragmentation_parsers`
  - `stateful_parsers`

## Critical Findings (Serious Bugs/Gaps)

The following tests indicate fail-closed/reload safety problems that should be treated as high priority:

1. **Reload accepts unsafe config transitions (fail-open behavior)**
   - `tests/reload/mod.rs::invalid_reload_does_not_poison_runtime`
   - `tests/security/mod.rs::reload_cannot_enable_empty_vless_auth_set`
   - Meaning: invalid reload paths are accepted where rejection is expected.

2. **Startup validation too permissive for auth-related config**
   - `crates/proxy-core/tests/config_fail_closed.rs::empty_vless_clients_must_fail_startup`
   - `crates/proxy-core/tests/config_fail_closed.rs::empty_vmess_clients_must_fail_startup`
   - Meaning: instance startup currently allows inbounds with empty auth lists.

3. **TLS key material validation gap**
   - `crates/proxy-core/tests/config_fail_closed.rs::invalid_tls_key_material_must_fail_startup`
   - Meaning: malformed key material can pass a path expected to fail hard at startup.

4. **Schema-layer validation gap**
   - `crates/proxy-config/tests/fail_closed_schema.rs::invalid_outbound_port_zero_fails_validation`
   - Meaning: config schema validation does not currently reject this case as expected.

## Reproduction Commands

Run these to reproduce key findings:

```bash
cargo test -p integration-tests --test reload_during_traffic -- --nocapture
cargo test -p integration-tests --test security_boundaries -- --nocapture
cargo test -p proxy-core --test config_fail_closed -- --nocapture
cargo test -p proxy-config --test fail_closed_schema -- --nocapture
```

Run implemented stability suites:

```bash
cargo test -p integration-tests --test adversarial_fragmentation -- --nocapture
cargo test -p integration-tests --test adversarial_backpressure -- --nocapture
cargo test -p integration-tests --test adversarial_cancellation -- --nocapture
cargo test -p integration-tests --test adversarial_half_close -- --nocapture
cargo test -p integration-tests --test adversarial_upstream_chaos -- --nocapture
cargo test -p integration-tests --test adversarial_task_pressure -- --nocapture
cargo test -p integration-tests --test socket_behavior -- --nocapture
cargo test -p integration-tests --test observability -- --nocapture
```

Run heavy/loom suites:

```bash
cargo test -p integration-tests --features heavy-tests -- --ignored
cargo test -p integration-tests --features loom-tests --test loom_concurrency -- --nocapture
```

## Notes

- This report reflects current behavior as tested on May 25, 2026.
- The critical items above are real correctness/security boundary gaps, not cosmetic test instability.
