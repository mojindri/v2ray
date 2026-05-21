# Makefile — shortcuts for common development tasks.
#
# Run `make help` to see all available commands.
# Run `make` (no arguments) to build the project.

.PHONY: all build test check fmt lint audit update-geoip clean help

# Default target: build in release mode.
all: build

## build: Compile the project in release mode.
build:
	cargo build --release --bin proxy-rs

## dev: Compile in debug mode (faster compile, slower binary).
dev:
	cargo build --bin proxy-rs

## test: Run all unit and integration tests.
test:
	cargo test --workspace

## check: Fast syntax check without producing a binary (useful during development).
check:
	cargo check --workspace

## fmt: Auto-format all source files.
fmt:
	cargo fmt --all

## fmt-check: Check formatting without modifying files (used in CI).
fmt-check:
	cargo fmt --all -- --check

## lint: Run Clippy with strict settings (same as CI).
lint:
	cargo clippy --workspace --all-features -- \
		-D warnings \
		-D clippy::unwrap_used \
		-D clippy::expect_used

## audit: Check for known security vulnerabilities in dependencies.
audit:
	cargo audit

## deny: Check dependency licenses and for duplicate crates.
deny:
	cargo deny check

## ci: Run everything that CI runs, in order.
ci: fmt-check lint test audit

## update-geoip: Download the latest GeoIP and GeoSite data files.
update-geoip:
	bash scripts/update-geoip.sh

## gen-keys: Generate a new REALITY X25519 keypair.
gen-keys:
	cargo run --bin proxy-rs -- x25519

## clean: Remove all build artifacts.
clean:
	cargo clean

## help: Show this help message.
help:
	@grep -E '^## ' Makefile | sed 's/^## /  /'
