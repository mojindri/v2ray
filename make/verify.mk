# Canonical verification targets (verify-local, verify-lab, verify-remote, …).
# Included from the root Makefile.

.PHONY: verify-local verify-lab verify-lab-docker verify-lab-lima verify-lab-fingerprint \
	verify-remote verify-remote-smoke verify-remote-protocols verify-remote-fingerprint \
	verify-remote-fallback verify-remote-performance-smoke \
	verify-sweep verify-release verify-check-compat \
	lab-docker-preflight lab-docker-up lab-docker-test lab-docker-down \
	lab-lima-preflight lab-lima-test-fingerprint lab-lima-down \
	remote-preflight remote-deploy remote-test-smoke remote-test-protocols \
	remote-test-fingerprint remote-test-fallback remote-collect remote-clean \
	security fuzz-long perf-remote soak

LAB_DIR := labs/realistic
REPORT_DOCKER := $(LAB_DIR)/reports/external-clients/summary.txt
REPORT_LIMA := $(LAB_DIR)/reports/production

# ── verify-local: host-only Rust validation ───────────────────────────────────

verify-local:
	@echo "==> [verify-local 1/4] fmt-check"
	$(MAKE) fmt-check
	@echo "==> [verify-local 2/4] cargo check"
	cargo check --workspace --all-targets
	@echo "==> [verify-local 3/4] clippy"
	cargo clippy --workspace --all-targets -- -D warnings
	@echo "==> [verify-local 4/4] tests"
	cargo test --workspace --all-targets
	@echo "==> verify-local complete"

# Compatibility shape for the old `make check` (local-total, no Lima/VPS).
verify-check-compat: verify-local
	@echo "==> [verify-check-compat] lab Docker + production helpers + fuzz-smoke"
	$(MAKE) verify-lab-docker
	$(MAKE) -C $(LAB_DIR) prod-readiness
	$(MAKE) fuzz-smoke
	@echo "==> verify-check-compat complete"

# ── verify-lab: Docker / Lima, no VPS ───────────────────────────────────────

verify-lab: verify-lab-docker verify-lab-lima
	@echo "==> verify-lab complete (reports under $(LAB_DIR)/reports/)"

verify-lab-docker: lab-docker-preflight lab-docker-test
	@echo "==> verify-lab-docker complete"
	@echo "    Docker external-client summary: $(REPORT_DOCKER)"

verify-lab-lima: lab-lima-preflight lab-lima-test-fingerprint
	@echo "==> verify-lab-lima complete"
	@echo "    Lima artifacts: $(REPORT_LIMA)/"

verify-lab-fingerprint: verify-lab-lima

lab-docker-preflight:
	@echo "==> [lab-docker-preflight] checking Docker"
	@command -v docker >/dev/null || (echo "ERROR: docker required for verify-lab-docker"; exit 1)
	@docker info >/dev/null 2>&1 || (echo "ERROR: docker daemon is not running"; exit 1)
	@echo "    Docker OK"

lab-docker-up:
	@echo "==> [lab-docker-up] starting lab target services"
	$(MAKE) -C $(LAB_DIR) docker-up

lab-docker-test: lab-docker-up
	@echo "==> [lab-docker-test] stable integration matrix"
	$(MAKE) -C $(LAB_DIR) stable
	@echo "==> [lab-docker-test] interop-docker (server-compat + client-compat)"
	$(MAKE) -C $(LAB_DIR) interop-docker
	@echo "==> [lab-docker-test] advanced features + negative-auth smoke"
	$(MAKE) -C $(LAB_DIR) advanced-features-smoke
	$(MAKE) -C $(LAB_DIR) negative-auth

lab-docker-down:
	@echo "==> [lab-docker-down] stopping lab containers"
	$(MAKE) -C $(LAB_DIR) docker-down

lab-lima-preflight:
	@echo "==> [lab-lima-preflight] checking Lima"
	@command -v limactl >/dev/null || (echo "ERROR: limactl required for verify-lab-lima"; exit 1)
	@echo "    limactl OK (instance: $${LIMA_INSTANCE:-blackwire-browser})"

lab-lima-test-fingerprint:
	@echo "==> [lab-lima-test-fingerprint] browser TLS baseline (mutates Lima VM packages/network)"
	$(MAKE) -C $(LAB_DIR) lima-fingerprint-total
	@echo "    Reports: $(REPORT_LIMA)/lima-browser-baseline*.log"

lab-lima-down:
	$(MAKE) lima-stop

# ── verify-remote: real VPS over SSH ──────────────────────────────────────────

verify-remote: remote-preflight remote-test-smoke remote-test-protocols \
	remote-test-fingerprint remote-test-fallback remote-performance-smoke remote-collect
	@echo "==> verify-remote complete (logs under $(LAB_DIR)/reports/)"

remote-preflight:
	@test -n "$${SSH_SERVER:-}" || (echo "ERROR: SSH_SERVER required"; exit 1)
	@test -n "$${SSH_CLIENT:-}" || (echo "ERROR: SSH_CLIENT required"; exit 1)
	@echo "==> [remote-preflight] VPS targets (commands mutate remote hosts)"
	@echo "    server: $${SSH_SERVER}"
	@echo "    client: $${SSH_CLIENT}"
	@echo "    user:   $${SSH_USER:-root}"
	$(MAKE) -C $(LAB_DIR) vps-preflight

remote-deploy:
	@echo "==> [remote-deploy] rsync lab bundle + run setup scripts on BOTH VPS hosts"
	@test -n "$${SSH_SERVER:-}" || (echo "ERROR: SSH_SERVER required"; exit 1)
	@test -n "$${SSH_CLIENT:-}" || (echo "ERROR: SSH_CLIENT required"; exit 1)
	@echo "    server: $${SSH_SERVER}  (installs blackwire, TUN/netem tooling)"
	@echo "    client: $${SSH_CLIENT}  (installs blackwire client + matrix runner)"
	SSH_SERVER="$${SSH_SERVER}" $(MAKE) -C $(LAB_DIR) vps-server-setup
	SSH_CLIENT="$${SSH_CLIENT}" $(MAKE) -C $(LAB_DIR) vps-client-setup

remote-test-smoke:
	@echo "==> [remote-test-smoke] SSH connectivity only"
	@test -n "$${SSH_SERVER:-}" || (echo "ERROR: SSH_SERVER required"; exit 1)
	@test -n "$${SSH_CLIENT:-}" || (echo "ERROR: SSH_CLIENT required"; exit 1)
	@KEY_OPT=""; PORT_OPT=""; EXTRA_OPTS="$${SSH_EXTRA_OPTS:-}"; USER="$${SSH_USER:-root}"; \
	if [ -n "$${SSH_KEY:-}" ]; then KEY_OPT="-i $${SSH_KEY}"; fi; \
	if [ -n "$${SSH_PORT:-}" ]; then PORT_OPT="-p $${SSH_PORT}"; fi; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}" 'echo server_ok'; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_CLIENT}" 'echo client_ok'

remote-test-protocols:
	@echo "==> [remote-test-protocols] full protocol matrix from CLIENT VPS"
	@test -n "$${SSH_CLIENT:-}" || (echo "ERROR: SSH_CLIENT required"; exit 1)
	@echo "    runs on client: $${SSH_CLIENT} against server: $${SSH_SERVER}"
	$(MAKE) -C $(LAB_DIR) vps-test

remote-test-fingerprint:
	@echo "==> [remote-test-fingerprint] interop-server-vps (Xray/sing-box external clients)"
	@test -n "$${SSH_SERVER:-}" || (echo "ERROR: SSH_SERVER required"; exit 1)
	@test -n "$${SSH_CLIENT:-}" || (echo "ERROR: SSH_CLIENT required"; exit 1)
	$(MAKE) -C $(LAB_DIR) interop-server-vps

remote-test-fallback:
	@echo "==> [remote-test-fallback] TUN privileged tests on SERVER VPS (sudo)"
	@test -n "$${SSH_SERVER:-}" || (echo "ERROR: SSH_SERVER required"; exit 1)
	@echo "    server: $${SSH_SERVER} (requires Linux root/sudo)"
	$(MAKE) -C $(LAB_DIR) vps-tun

remote-collect:
	@echo "==> [remote-collect] netem results from SERVER VPS"
	@test -n "$${SSH_SERVER:-}" || (echo "ERROR: SSH_SERVER required"; exit 1)
	$(MAKE) -C $(LAB_DIR) vps-netem
	@echo "    collected under $(LAB_DIR)/reports/"

remote-clean:
	@echo "==> [remote-clean] no automatic VPS teardown (manual cleanup on hosts)"
	@echo "    stop services on VPS manually if needed; local reports: make clean-generated"

verify-remote-smoke: remote-preflight remote-test-smoke
verify-remote-protocols: remote-preflight remote-test-protocols
verify-remote-fingerprint: remote-preflight remote-test-fingerprint
verify-remote-fallback: remote-preflight remote-test-fallback
verify-remote-performance-smoke: remote-preflight
	@echo "==> [verify-remote-performance-smoke] VPS benchmark (mutates remote load)"
	$(MAKE) perf-remote

# ── verify-sweep / verify-release ─────────────────────────────────────────────

verify-sweep: verify-local verify-lab security fuzz-smoke
	@if [ -n "$${SSH_SERVER:-}" ] && [ -n "$${SSH_CLIENT:-}" ]; then \
		echo "==> [verify-sweep] SSH_SERVER/SSH_CLIENT set — running verify-remote"; \
		$(MAKE) verify-remote; \
	else \
		echo "==> [verify-sweep] skipping verify-remote (set SSH_SERVER and SSH_CLIENT to include VPS)"; \
	fi
	@echo "==> verify-sweep complete"

verify-release:
	@echo "==> verify-release: slow gate (sweep + perf + soak + long fuzz)"
	$(MAKE) verify-sweep
	$(MAKE) perf
	@if [ -n "$${SSH_SERVER:-}" ] && [ -n "$${SSH_CLIENT:-}" ]; then \
		$(MAKE) perf-remote; \
	else \
		echo "==> [verify-release] skipping perf-remote (SSH_SERVER/SSH_CLIENT not set)"; \
	fi
	$(MAKE) soak
	$(MAKE) fuzz-long
	@echo "==> verify-release complete"

# ── Support targets ───────────────────────────────────────────────────────────

security:
	@echo "==> [security] dependency and hygiene checks"
	$(MAKE) audit-optional
	$(MAKE) deny-optional
	$(MAKE) -C $(LAB_DIR) security

fuzz-long:
	@echo "==> [fuzz-long] FUZZ_RUNS=$${FUZZ_RUNS:-100000} (requires nightly + cargo-fuzz)"
	@command -v cargo-fuzz >/dev/null || (echo "ERROR: cargo-fuzz not installed. Install with: cargo install cargo-fuzz"; exit 1)
	@rustup run nightly cargo --version >/dev/null 2>&1 || (echo "ERROR: nightly toolchain required for fuzz. Install with: rustup toolchain install nightly"; exit 1)
	FUZZ_RUNS=$${FUZZ_RUNS:-100000} $(MAKE) -C $(LAB_DIR) fuzz-total

perf-remote:
	@test -n "$${SSH_SERVER:-}" || (echo "ERROR: SSH_SERVER required"; exit 1)
	@test -n "$${SSH_CLIENT:-}" || (echo "ERROR: SSH_CLIENT required"; exit 1)
	@echo "==> [perf-remote] full VPS benchmark (mutates $${SSH_SERVER} / $${SSH_CLIENT})"
	$(MAKE) bench-vps-total

soak:
	@echo "==> [soak] bounded soak loop (tune $(LAB_DIR)/configs/soak.env)"
	$(MAKE) -C $(LAB_DIR) soak
