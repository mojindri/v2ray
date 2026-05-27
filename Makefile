# Makefile — public verification workflow + compatibility aliases.
#
# Canonical entrypoints:
#   make help
#   make verify-local
#   make verify-lab
#   make verify-remote
#   make verify-sweep
#   make verify-release
#
# Run `make help-compat` for deprecated aliases and `make help-internal` for atoms.

-include .env.vm
include make/verify.mk
include make/aliases.mk

.PHONY: all build dev test fmt fmt-check lint lint-strict audit deny update-geoip fuzz-build \
	fmt fmt-check lint audit audit-optional deny-optional fuzz-smoke \
	clean clean-generated clean-all-generated clean-reports clean-pcaps clean-lima-artifacts clean-bench \
	bench bench-build bench-xray bench-singbox bench-smoke \
	bench-protocol bench-protocol-quick bench-flamegraph \
	help help-compat help-internal bench-vm-smoke bench-vm-total bench-vps-smoke bench-vps-total \
	perf perf-vps lima-stop lima-browser-baseline lima-fingerprint-total \
	local-load local-slowloris local-pcap local-fingerprint-compare local-netem local-hostility \
	local-ci-matrix local-chrome-baseline-real local-chrome-baseline-docker \
	local-fingerprint-total local-fingerprint-verify vm-browser-setup vm-browser-baseline \
	vm-fingerprint-total vm-start-default vm-wait-default vm-fingerprint-default \
	vm-print-defaults local-total-with-vm gen-keys ci-strict

# Default target: build in release mode.
all: build

## build: Compile the project in release mode.
build:
	cargo build --release --bin blackwire

## dev: Compile in debug mode (faster compile, slower binary).
dev:
	cargo build --bin blackwire

## test: Run all unit and integration tests.
test:
	cargo test --workspace

## fmt: Auto-format all source files.
fmt:
	cargo fmt --all

## fmt-check: Check formatting without modifying files (used in CI).
fmt-check:
	cargo fmt --all -- --check

## lint: Run Clippy with -D warnings (same gate as verify-local).
lint:
	cargo clippy --workspace --all-targets -- -D warnings

## lint-strict: Clippy with unwrap/expect denies (production-path hygiene).
lint-strict:
	cargo clippy --workspace --all-targets -- \
		-D warnings \
		-D clippy::unwrap_used \
		-D clippy::expect_used

## audit: Check for known security vulnerabilities in dependencies.
audit:
	@command -v cargo-audit >/dev/null || (echo "ERROR: cargo-audit not installed. Install with: cargo install cargo-audit"; exit 1)
	cargo audit

## deny: Check dependency licenses and for duplicate crates.
deny:
	@command -v cargo-deny >/dev/null || (echo "ERROR: cargo-deny not installed. Install with: cargo install cargo-deny"; exit 1)
	cargo deny check

## fuzz-build: Build all cargo-fuzz targets with nightly.
fuzz-build:
	@command -v cargo-fuzz >/dev/null || (echo "ERROR: cargo-fuzz not installed. Install with: cargo install cargo-fuzz"; exit 1)
	@rustup run nightly cargo --version >/dev/null 2>&1 || (echo "ERROR: nightly toolchain required for fuzz. Install with: rustup toolchain install nightly"; exit 1)
	cargo +nightly fuzz build --manifest-path fuzz/Cargo.toml

## fuzz-smoke: Run each fuzz target for a short deterministic smoke pass.
fuzz-smoke:
	@command -v cargo-fuzz >/dev/null || (echo "ERROR: cargo-fuzz not installed. Install with: cargo install cargo-fuzz"; exit 1)
	@rustup run nightly cargo --version >/dev/null 2>&1 || (echo "ERROR: nightly toolchain required for fuzz. Install with: rustup toolchain install nightly"; exit 1)
	cargo +nightly fuzz run reality_client_hello --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run vmess_aead_header --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run vless_header --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run hysteria2_frame --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run shadowtls_handshake --manifest-path fuzz/Cargo.toml -- -runs=100
	cargo +nightly fuzz run ss2022_chunk --manifest-path fuzz/Cargo.toml -- -runs=100

## update-geoip: Download the latest GeoIP and GeoSite data files.
update-geoip:
	bash scripts/update-geoip.sh

## gen-keys: Generate a new REALITY X25519 keypair.
gen-keys:
	cargo run --bin blackwire -- x25519

## clean: Remove all build artifacts.
clean:
	cargo clean

## help-internal: Show annotated Make targets.
help-internal:
	@grep -E '^## ' Makefile | sed 's/^## /  /'

## help: Show canonical public verification commands.
help:
	@echo "Canonical verification:"
	@echo "  make verify-local    - host-only Rust (fmt, check, clippy, test)"
	@echo "  make verify-lab      - Docker + Lima production-like checks (no VPS)"
	@echo "  make verify-remote   - real VPS over SSH (needs SSH_SERVER, SSH_CLIENT)"
	@echo "  make verify-sweep    - local + lab + security + fuzz-smoke (+ remote if env set)"
	@echo "  make verify-release  - sweep + perf + soak + long fuzz (slow)"
	@echo ""
	@echo "Common atoms:"
	@echo "  make build           - release build"
	@echo "  make fmt-check       - formatting check"
	@echo "  make lint            - clippy with -D warnings (verify-local gate)"
	@echo "  make lint-strict     - clippy + unwrap/expect denies"
	@echo "  make test            - workspace tests"
	@echo "  make security        - audit/deny + lab security helpers"
	@echo "  make fuzz-smoke      - short nightly fuzz pass"
	@echo "  make advanced-features-smoke - lab: ShadowTLS, mKCP, QUIC/SplitHTTP e2e (host only)"
	@echo "  make health-failover       - lab: balancer failover e2e (+ Docker when available)"
	@echo "  make finalize        - lab: stable + advanced smoke + Docker external-client matrix"
	@echo "  make interop-server-docker   - lab: Xray/sing-box clients -> our server (Docker)"
	@echo "  make bench           - Docker latency benchmark: xray + singbox + blackwire"
	@echo "  make bench-xray      - Docker benchmark: xray series only"
	@echo "  make bench-singbox   - Docker benchmark: singbox series only"
	@echo "  make perf            - Lima VM benchmark"
	@echo "  make perf-remote     - VPS benchmark (needs SSH_SERVER/SSH_CLIENT)"
	@echo "  make clean-generated - remove reports/logs/pcaps/bench outputs"
	@echo ""
	@echo "Discovery:"
	@echo "  make help-compat     - deprecated aliases (check, ci-all, vps, …)"
	@echo "  make help-internal   - annotated atomic targets"
	@echo "  docs/test-workflows.md"

## help-compat: Show deprecated aliases and their canonical replacements.
help-compat:
	@echo "Deprecated aliases (still work, print a hint when run):"
	@echo "  make check              -> verify-check-compat"
	@echo "  make check-browser      -> verify-lab-lima"
	@echo "  make check-vps          -> verify-check-compat + verify-remote"
	@echo "  make check-all-local    -> verify-check-compat + verify-lab-lima"
	@echo "  make ci / local-fast    -> verify-local"
	@echo "  make ci-all / local     -> labs/realistic ci (verify-lab superset)"
	@echo "  make local-total        -> verify-check-compat"
	@echo "  make ci-vps / vps       -> verify-remote"
	@echo "  make perf / check-perf-vm -> bench-vm-total"
	@echo "  make perf-vps           -> perf-remote"
	@echo ""
	@echo "See docs/make-target-inventory.md for the full mapping."

# Compatibility aliases (ci, ci-all, check, vps, …) live in make/aliases.mk.

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



.PHONY: bench bench-build bench-xray bench-singbox bench-smoke \
        bench-vm-smoke bench-vm-total bench-vps-smoke bench-vps-total check-perf-vm check-perf-vps check-perf-total clean-bench

## bench: Docker benchmark — build image + run full xray/singbox/blackwire comparison + print report
bench:
	$(MAKE) -C labs/realistic bench

## bench-build: Build the blackwire-bench Docker image
bench-build:
	$(MAKE) -C labs/realistic bench-build

## bench-xray: Docker benchmark — Xray client vs Xray / Blackwire Compat / Blackwire Fast servers
bench-xray:
	$(MAKE) -C labs/realistic bench-xray

## bench-singbox: Docker benchmark — sing-box client vs sing-box / Blackwire Compat / Blackwire Fast servers
bench-singbox:
	$(MAKE) -C labs/realistic bench-singbox

## bench-smoke: Docker benchmark — Blackwire only (direct / socks / vless loopback)
bench-smoke:
	$(MAKE) -C labs/realistic bench-smoke

bench-vm-smoke:
	$(MAKE) -C labs/realistic bench-vm-smoke

bench-vm-total:
	$(MAKE) -C labs/realistic bench-vm-total

bench-vps-smoke:
	$(MAKE) -C labs/realistic bench-vps-smoke

bench-vps-total:
	$(MAKE) -C labs/realistic bench-vps-total

check-perf-vm: bench-vm-total ## Deprecated: use make perf (see help-compat).

check-perf-vps: bench-vps-total ## Deprecated: use make perf-remote.

check-perf-total: check-perf-vm check-perf-vps

perf: bench-vm-total ## Lima VM performance benchmark.

perf-vps: bench-vps-total ## VPS performance benchmark (needs SSH_SERVER/SSH_CLIENT).

clean-bench:
	rm -rf labs/realistic/reports/production/bench benches/reports

## bench-protocol: Run full e2e protocol bench matrix (Criterion).
bench-protocol:
	bash benches/scripts/run-protocol-matrix.sh

## bench-protocol-quick: Smaller payloads + all five protocol paths.
bench-protocol-quick:
	BENCH_QUICK=1 bash benches/scripts/run-protocol-matrix.sh

## bench-flamegraph: Profile one path (PROTO=vless_tcp SCENARIO=bulk).
bench-flamegraph:
	bash benches/scripts/flamegraph-protocol.sh "$(PROTO)" "$(SCENARIO)"


# lab / VM convenience wrappers (internal; see make help-internal)

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



.PHONY: lima-browser-baseline lima-fingerprint-total local-total-with-lima lima-stop

lima-browser-baseline:
	$(MAKE) -C labs/realistic lima-browser-baseline

lima-fingerprint-total:
	$(MAKE) -C labs/realistic lima-fingerprint-total

local-total-with-lima: local-total lima-fingerprint-total ## Run local-total, then fully automated Li   ma browser fingerprint check.

lima-stop: ## Stop the default Lima VM instance. Override with LIMA_INSTANCE=<name>.
	@INSTANCE="$${LIMA_INSTANCE:-blackwire-browser}"; \
	if ! command -v limactl >/dev/null 2>&1; then \
		echo "ERROR: limactl not found."; \
		exit 1; \
	fi; \
	echo "Stopping Lima VM: $$INSTANCE"; \
	limactl stop "$$INSTANCE"
