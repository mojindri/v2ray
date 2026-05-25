#!/usr/bin/env bash
set -euo pipefail

cargo audit
cargo deny check advisories licenses bans sources
cargo outdated --workspace || true
cargo geiger --all-features --workspace || true
cargo udeps --workspace --all-targets || true
