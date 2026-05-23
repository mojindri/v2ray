# Makefile — public task runner plus compatibility aliases.
#
# Public entrypoints:
#   make help
#   make check
#   make check-browser
#   make check-vps
#   make perf
#   make clean-generated
#
# Run `make help-internal` to inspect the broader target set.

-include .env.vm

.PHONY: all build dev test check check-browser check-vps perf perf-vps perf-all \
	fmt fmt-check lint audit deny update-geoip fuzz-build fuzz-smoke \
	ci ci-all ci-prod-readiness ci-vps clean clean-generated clean-all-generated \
	help help-internal test-help quick-help help-simple

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
ci: fmt-check lint test audit-optional deny-optional

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

## help-internal: Show annotated Make targets.
help-internal:
	@grep -E '^## ' Makefile | sed 's/^## /  /'

## help: Show the curated public command surface.
help:
	@echo "Public commands:"
	@echo "  make check          - strongest normal local validation gate"
	@echo "  make check-browser  - browser/TLS fingerprint validation in Lima Ubuntu VM"
	@echo "  make check-vps      - closest production-style validation on two VPS machines"
	@echo "  make perf           - performance benchmark in Lima VM"
	@echo "  make clean-generated - remove generated reports/logs/pcaps/bench outputs"
	@echo ""
	@echo "Useful basics:"
	@echo "  make build          - release build"
	@echo "  make test           - workspace tests"
	@echo "  make fmt-check      - formatting check"
	@echo "  make lint           - clippy gate"
	@echo ""
	@echo "Discovery:"
	@echo "  make test-help      - compatibility aliases and broader workflow map"
	@echo "  make help-internal  - annotated target list from this Makefile"
	@echo ""
	@echo "Compatibility aliases remain available, but the recommended public surface is small."

ci-fuzz-smoke:
	$(MAKE) -C labs/realistic fuzz-smoke

ci-prod-readiness-with-fuzz:
	$(MAKE) -C labs/realistic prod-readiness-with-fuzz




ci-fuzz-total:
	$(MAKE) -C labs/realistic fuzz-total

# Compatibility entrypoints. Keep these for scripts/docs, but do not expand the
# public surface further unless a new workflow genuinely needs it.
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


.PHONY: check check-browser check-all-local check-vps

check: local-total ## Alias: strongest normal local check.

check-browser: lima-fingerprint-total ## Alias: isolated Lima browser/fingerprint check.

check-all-local: local-total-with-lima ## Alias: local-total plus isolated Lima browser/fingerprint check.

check-vps: vps-total ## Alias: local gates plus VPS gate.


.PHONY: check-sequence check-sequence-with-vps

check-sequence: ## Run the recommended test sequence one after another, excluding VPS.
	@echo "==> [1/3] make check"
	$(MAKE) check
	@echo "==> [2/3] make check-browser"
	$(MAKE) check-browser
	@echo "==> [3/3] make check-all-local"
	$(MAKE) check-all-local
	@echo "==> check-sequence complete"

check-sequence-with-vps: check-sequence ## Run recommended local/Lima sequence, then VPS if SSH_SERVER/SSH_CLIENT are set.
	@if [ -z "$${SSH_SERVER:-}" ] || [ -z "$${SSH_CLIENT:-}" ]; then \
		echo "ERROR: SSH_SERVER and SSH_CLIENT are required for check-sequence-with-vps."; \
		echo "Example: SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 make check-sequence-with-vps"; \
		exit 1; \
	fi
	@echo "==> [4/4] make check-vps"
	$(MAKE) check-vps
	@echo "==> check-sequence-with-vps complete"

.PHONY: clean-reports clean-pcaps clean-lima-artifacts clean-generated clean-all-generated

clean-reports: ## Remove generated test reports/logs under labs/realistic/reports.
	rm -rf labs/realistic/reports

clean-pcaps: ## Remove generated pcap artifacts and fingerprint comparison outputs.
	rm -rf labs/realistic/reports/production/baselines
	rm -rf labs/realistic/reports/production/artifacts/pcaps
	rm -f labs/realistic/reports/production/fingerprint-compare.json
	rm -f labs/realistic/reports/production/fingerprint-compare.log
	rm -f labs/realistic/reports/production/fingerprint-verify.log

clean-lima-artifacts: ## Remove generated Lima lab configs/log references from this repo only; does not delete Lima VM.
	rm -f labs/realistic/reports/production/artifacts/configs/lima-*.yaml
	rm -f labs/realistic/reports/production/lima-browser-baseline*.log
	rm -f labs/realistic/reports/production/lima-browser-baseline-summary-*.txt
	rm -f labs/realistic/reports/production/artifacts/logs/lima-*.log

clean-generated: clean-reports clean-bench ## Remove generated repo reports/logs/pcaps/bench, but keep build cache and external VMs.

clean-all-generated: clean-generated ## Remove generated repo reports plus Rust build outputs.
	cargo clean



.PHONY: bench-vm-smoke bench-vm-total bench-vps-smoke bench-vps-total check-perf-vm check-perf-vps check-perf-total clean-bench

bench-vm-smoke:
	$(MAKE) -C labs/realistic bench-vm-smoke

bench-vm-total:
	$(MAKE) -C labs/realistic bench-vm-total

bench-vps-smoke:
	$(MAKE) -C labs/realistic bench-vps-smoke

bench-vps-total:
	$(MAKE) -C labs/realistic bench-vps-total

check-perf-vm: bench-vm-total ## Alias: full Lima VM performance benchmark.

check-perf-vps: bench-vps-total ## Alias: full VPS performance benchmark.

check-perf-total: check-perf-vm check-perf-vps ## Run VM perf first, then VPS perf.

perf: check-perf-vm ## Recommended public perf entrypoint: full Lima VM benchmark.

perf-vps: check-perf-vps ## Compatibility alias for the full VPS performance benchmark.

perf-all: check-perf-total ## Run VM perf first, then VPS perf.

clean-bench:
	rm -rf labs/realistic/reports/production/bench


test-help: ## Show compact command help.
	@echo "Recommended public workflow:"
	@echo "  1. make check"
	@echo "  2. make check-browser"
	@echo "  3. SSH_SERVER=<server-ip> SSH_CLIENT=<client-ip> make check-vps"
	@echo "  4. make perf"
	@echo ""
	@echo "Public commands:"
	@echo "  make check              - strongest normal local validation gate"
	@echo "  make check-browser      - isolated Lima browser/fingerprint validation"
	@echo "  make check-vps          - local gates plus VPS SSH/network validation"
	@echo "  make perf               - full Lima VM performance benchmark"
	@echo ""
	@echo "Compatibility aliases still available:"
	@echo "  make check-all-local    - local suite plus Lima browser/fingerprint validation"
	@echo "  make check-sequence     - explicit step-by-step logs for check/check-browser/check-all-local"
	@echo "  make check-sequence-with-vps - sequence above, then VPS"
	@echo "  make ci / ci-all / ci-vps"
	@echo "  make local-fast / local / local-prod / local-fuzz / local-fuzz-total / local-total"
	@echo "  make vps / vps-total / vps-total-with-fuzz"
	@echo "  make check-perf-vm / check-perf-vps / check-perf-total"
	@echo ""
	@echo "Diagnostics and cleanup:"
	@echo "  make clean-generated"
	@echo "  make clean-pcaps"
	@echo "  make clean-all-generated"
	@echo "  make help-internal"

quick-help: test-help ## Alias for compact command help.

help-simple: test-help ## Alias for compact command help.


local-load:
	$(MAKE) -C labs/realistic local-load


local-slowloris:
	$(MAKE) -C labs/realistic slowloris


audit-optional:
	@if command -v cargo-audit >/dev/null 2>&1; then \
		cargo audit; \
	else \
		echo "SKIP: cargo-audit not installed. Install with: cargo install cargo-audit"; \
	fi


deny-optional:
	@if command -v cargo-deny >/dev/null 2>&1; then \
		cargo deny check; \
	else \
		echo "SKIP: cargo-deny not installed. Install with: cargo install cargo-deny"; \
	fi


ci-strict: fmt-check lint-strict test audit deny


local-pcap:
	$(MAKE) -C labs/realistic pcap-local


local-fingerprint-compare:
	$(MAKE) -C labs/realistic fingerprint-compare


local-netem:
	$(MAKE) -C labs/realistic netem-local


local-hostility:
	$(MAKE) -C labs/realistic hostility-local


local-ci-matrix:
	$(MAKE) -C labs/realistic ci-matrix-local


local-chrome-baseline-real:
	$(MAKE) -C labs/realistic chrome-baseline-real


local-chrome-baseline-docker:
	$(MAKE) -C labs/realistic chrome-baseline-docker


local-fingerprint-total:
	$(MAKE) -C labs/realistic fingerprint-total


local-fingerprint-verify:
	$(MAKE) -C labs/realistic fingerprint-verify


vm-browser-setup:
	$(MAKE) -C labs/realistic vm-browser-setup


vm-browser-baseline:
	$(MAKE) -C labs/realistic vm-browser-baseline


vm-fingerprint-total:
	$(MAKE) -C labs/realistic vm-fingerprint-total

.PHONY: vm-start-default vm-wait-default vm-fingerprint-default local-total-with-vm vm-print-defaults

vm-start-default: ## Bootstrap/find VM launcher, create .env.vm template, then start VM if configured.
	@if [ ! -f .env.vm ]; then \
		printf '%s\n' \
		'VM_NAME=Ubuntu' \
		'VM_HOST=192.168.64.10' \
		'VM_USER=lab' \
		'VM_SSH_PORT=22' \
		'VM_TARGET_URL=https://www.cloudflare.com' \
		'VM_EXPECT_SNI=www.cloudflare.com' > .env.vm; \
		echo "Created .env.vm template. Edit VM_NAME/VM_HOST after VM exists."; \
	fi; \
	if [ -n "$${VM_START_CMD:-$(VM_START_CMD)}" ]; then \
		echo "Starting VM with VM_START_CMD..."; \
		eval "$${VM_START_CMD:-$(VM_START_CMD)}"; \
	elif [ -n "$${VM_NAME:-$(VM_NAME)}" ] && { command -v utmctl >/dev/null 2>&1 || [ -x /Applications/UTM.app/Contents/MacOS/utmctl ]; }; then \
		UTMCTL="$$(command -v utmctl 2>/dev/null || echo /Applications/UTM.app/Contents/MacOS/utmctl)"; \
		VM="$${VM_NAME:-$(VM_NAME)}"; \
		if "$$UTMCTL" list 2>/dev/null | grep -Fq "$$VM"; then \
			echo "Starting UTM VM: $$VM"; \
			"$$UTMCTL" start "$$VM" || true; \
		else \
			echo "ERROR: UTM is installed, but VM '$$VM' does not exist."; \
			echo "Available UTM VMs:"; \
			"$$UTMCTL" list 2>/dev/null || true; \
			echo "Create/import an Ubuntu VM in UTM, or edit .env.vm and set VM_NAME to an existing VM."; \
			exit 1; \
		fi; \
	elif [ -n "$${VM_NAME:-$(VM_NAME)}" ] && command -v prlctl >/dev/null 2>&1; then \
		echo "Starting Parallels VM: $${VM_NAME:-$(VM_NAME)}"; \
		prlctl start "$${VM_NAME:-$(VM_NAME)}" || true; \
	elif [ -n "$${VM_NAME:-$(VM_NAME)}" ] && command -v VBoxManage >/dev/null 2>&1 && VBoxManage --version >/dev/null 2>&1; then \
		echo "Starting VirtualBox VM: $${VM_NAME:-$(VM_NAME)}"; \
		VBoxManage startvm "$${VM_NAME:-$(VM_NAME)}" --type headless || true; \
	else \
		echo "No working VM launcher found or VM_NAME is empty."; \
		echo "If you use VirtualBox, VBoxManage must run successfully: VBoxManage --version"; \
		echo "If you use UTM, install it and set VM_NAME in .env.vm."; \
		echo "Current defaults: VM_NAME=$${VM_NAME:-$(VM_NAME)} VM_HOST=$${VM_HOST:-$(VM_HOST)} VM_USER=$${VM_USER:-$(VM_USER)}"; \
	fi

vm-wait-default: ## Wait until VM SSH is reachable. Uses VM_HOST/VM_USER/VM_SSH_PORT.
	@VM_HOST="$${VM_HOST:-$(VM_HOST)}"; \
	VM_USER="$${VM_USER:-$(VM_USER)}"; \
	VM_SSH_PORT="$${VM_SSH_PORT:-$(VM_SSH_PORT)}"; \
	VM_WAIT_SECONDS="$${VM_WAIT_SECONDS:-120}"; \
	if [ -z "$$VM_HOST" ]; then VM_HOST="192.168.64.10"; fi; \
	if [ -z "$$VM_USER" ]; then VM_USER="lab"; fi; \
	if [ -z "$$VM_SSH_PORT" ]; then VM_SSH_PORT="22"; fi; \
	echo "Waiting for VM SSH: $${VM_USER}@$${VM_HOST}:$${VM_SSH_PORT} ($${VM_WAIT_SECONDS}s max)"; \
	deadline=$$(( $$(date +%s) + VM_WAIT_SECONDS )); \
	while [ $$(date +%s) -lt $$deadline ]; do \
		if ssh -p "$${VM_SSH_PORT}" -o BatchMode=yes -o ConnectTimeout=3 "$${VM_USER}@$${VM_HOST}" 'echo VM_SSH_OK' >/dev/null 2>&1; then \
			echo "VM SSH is ready."; \
			exit 0; \
		fi; \
		sleep 3; \
	done; \
	echo "ERROR: VM SSH did not become reachable: $${VM_USER}@$${VM_HOST}:$${VM_SSH_PORT}"; \
	echo "Set VM_HOST to the real VM IP in .env.vm."; \
	exit 1

vm-fingerprint-default: vm-start-default vm-wait-default ## Start/wait for VM, then run VM fingerprint check with default VM env.
	VM_HOST=$${VM_HOST:-$(VM_HOST)} \
	VM_USER=$${VM_USER:-$(VM_USER)} \
	VM_SSH_PORT=$${VM_SSH_PORT:-$(VM_SSH_PORT)} \
	VM_TARGET_URL=$${VM_TARGET_URL:-$(VM_TARGET_URL)} \
	VM_EXPECT_SNI=$${VM_EXPECT_SNI:-$(VM_EXPECT_SNI)} \
	$(MAKE) vm-fingerprint-total

local-total-with-vm: local-total vm-fingerprint-default ## Run local-total, then start/wait VM fingerprint check.

vm-print-defaults: ## Print VM defaults loaded from .env.vm and environment.
	@echo "VM_NAME=$${VM_NAME:-$(VM_NAME)}"
	@echo "VM_START_CMD=$${VM_START_CMD:-$(VM_START_CMD)}"
	@echo "VM_HOST=$${VM_HOST:-$(VM_HOST)}"
	@echo "VM_USER=$${VM_USER:-$(VM_USER)}"
	@echo "VM_SSH_PORT=$${VM_SSH_PORT:-$(VM_SSH_PORT)}"
	@echo "VM_TARGET_URL=$${VM_TARGET_URL:-$(VM_TARGET_URL)}"
	@echo "VM_EXPECT_SNI=$${VM_EXPECT_SNI:-$(VM_EXPECT_SNI)}"
	@echo "VM launchers:"
	@echo "  utmctl=$$(command -v utmctl 2>/dev/null || { test -x /Applications/UTM.app/Contents/MacOS/utmctl && echo /Applications/UTM.app/Contents/MacOS/utmctl; } || true)"
	@echo "  prlctl=$$(command -v prlctl 2>/dev/null || true)"
	@echo "  VBoxManage=$$(if command -v VBoxManage >/dev/null 2>&1 && VBoxManage --version >/dev/null 2>&1; then command -v VBoxManage; else echo 'not working'; fi)"



.PHONY: lima-browser-baseline lima-fingerprint-total local-total-with-lima

lima-browser-baseline:
	$(MAKE) -C labs/realistic lima-browser-baseline

lima-fingerprint-total:
	$(MAKE) -C labs/realistic lima-fingerprint-total

local-total-with-lima: local-total lima-fingerprint-total ## Run local-total, then fully automated Lima browser fingerprint check.
