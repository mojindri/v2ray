# Makefile — shortcuts for common development tasks.
#
# Run `make help` to see all available commands.
# Run `make` (no arguments) to build the project.

.PHONY: all build test check fmt lint audit update-geoip fuzz-build fuzz-smoke ci ci-all ci-prod-readiness ci-vps clean help

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

## fuzz-build: Build all cargo-fuzz targets with nightly.
fuzz-build:
	cargo +nightly fuzz build --manifest-path fuzz/Cargo.toml

## fuzz-smoke: Run each fuzz target for a short deterministic smoke pass.
fuzz-smoke:
	cargo +nightly fuzz run reality_client_hello --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run vmess_aead_header --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run vless_header --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run hysteria2_frame --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run shadowtls_handshake --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run ss2022_chunk --manifest-path fuzz/Cargo.toml -- -runs=100

## deny: Check dependency licenses and for duplicate crates.
deny:
	cargo deny check

## ci: Fast code-quality gate (fmt + lint + test + audit). Run before every push.
ci: fmt-check lint test audit

## ci-all: Run every local test tier, including the realistic lab and production-readiness helpers. Needs Docker.
ci-all:
	$(MAKE) -C labs/realistic ci
	$(MAKE) -C labs/realistic prod-readiness

## ci-prod-readiness: Run only the added local production-readiness helpers.
ci-prod-readiness:
	$(MAKE) -C labs/realistic prod-readiness

## ci-vps: Run ci-all + two-VPS protocol matrix + TUN privileged tests. Needs SSH_SERVER and SSH_CLIENT.
ci-vps:
	$(MAKE) -C labs/realistic ci-full

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

ci-fuzz-smoke:
	$(MAKE) -C labs/realistic fuzz-smoke

ci-prod-readiness-with-fuzz:
	$(MAKE) -C labs/realistic prod-readiness-with-fuzz
