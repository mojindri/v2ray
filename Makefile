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
	@if cargo --list | grep -q '^    audit$$'; then \
		cargo audit; \
	else \
		echo "cargo-audit not installed; skipping audit step"; \
	fi

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




ci-fuzz-total:
	$(MAKE) -C labs/realistic fuzz-total

# ── Simple one-place test entrypoints ─────────────────────────────────────────
.PHONY: local local-fast local-prod local-fuzz local-fuzz-total local-total vps vps-total vps-total-with-fuzz test-help

local: ci-all ## Full local gate. Excludes fuzz and VPS.

local-fast: ci ## Fast Rust-only local gate.

local-prod: ci-prod-readiness ## Production-readiness helpers only. Excludes fuzz and VPS.

local-fuzz: ci-fuzz-smoke ## Quick fuzz smoke. Opt-in.

local-fuzz-total: ci-fuzz-total ## Heavier fuzz pass. Override with FUZZ_RUNS=10000.

local-total: ci-all ci-prod-readiness ci-fuzz-smoke ## Everything local, including fuzz. Excludes VPS.

vps: ci-vps ## VPS-only SSH gate. Requires SSH_SERVER and SSH_CLIENT.

vps-total: ci ci-all ci-prod-readiness ci-vps ## All non-fuzz local gates, then VPS gate.

vps-total-with-fuzz: ci ci-all ci-prod-readiness ci-fuzz-smoke ci-vps ## All local gates including fuzz, then VPS gate.

test-help: ## Show the simple command names.
	@echo "Recommended commands:"
	@echo "  make local                - full local gate; no fuzz, no VPS"
	@echo "  make local-fast           - fast Rust-only checks"
	@echo "  make local-load           - managed local load test with proxy started automatically"
	@echo "  make local-slowloris      - slow-client diagnostic against managed local proxy"
	@echo "  make local-prod           - production-readiness helpers only; no fuzz"
	@echo "  make local-fuzz           - quick fuzz smoke only"
	@echo "  make local-fuzz-total     - heavier fuzz pass; override with FUZZ_RUNS=10000"
	@echo "  make local-total          - all local gates including fuzz; no VPS"
	@echo "  make vps                  - VPS-only SSH gate; requires SSH_SERVER and SSH_CLIENT"
	@echo "  make vps-total            - all non-fuzz local gates, then VPS gate"
	@echo "  make vps-total-with-fuzz  - all local gates including fuzz, then VPS gate"



local-load:
	$(MAKE) -C labs/realistic local-load


local-slowloris:
	$(MAKE) -C labs/realistic slowloris
