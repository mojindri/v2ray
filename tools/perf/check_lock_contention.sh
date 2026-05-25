#!/usr/bin/env bash
set -euo pipefail

echo "==> lock contention profiling helper"
echo "Targets: router, balancer, dns cache, fakeip, auth/user registry, metrics/logging"
echo ""

echo "1) tokio-console (if enabled in binary):"
echo "   RUSTFLAGS='--cfg tokio_unstable' RUST_LOG=info cargo run --release --bin blackwire -- run -c <config>"
echo "   tokio-console"
echo ""

echo "2) perf record (Linux):"
echo "   perf record -F 99 -g -- target/release/blackwire run -c <config>"
echo "   perf report"
echo ""

echo "3) flamegraph:"
echo "   cargo flamegraph --bin blackwire -- run -c <config>"
