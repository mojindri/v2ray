# Compatibility aliases for pre-refactor Make target names.
# Each alias prints a deprecation hint, then runs the canonical workflow.

.PHONY: local local-fast local-prod local-fuzz local-fuzz-total local-total \
	vps vps-total vps-total-with-fuzz \
	check check-browser check-all-local check-vps \
	check-sequence check-sequence-with-vps \
	ci ci-all ci-prod-readiness ci-vps \
	ci-fuzz-smoke ci-fuzz-total ci-prod-readiness-with-fuzz \
	check-perf-vm check-perf-vps check-perf-total \
	test-help quick-help help-simple

local-fast:
	@echo "Deprecated alias: use make verify-local"
	$(MAKE) verify-local

ci: local-fast

local:
	@echo "Deprecated alias: use make verify-lab (includes labs/realistic ci + prod-readiness)"
	$(MAKE) -C labs/realistic ci
	$(MAKE) -C labs/realistic prod-readiness

ci-all: local

local-prod:
	@echo "Deprecated alias: use make -C labs/realistic prod-readiness"
	$(MAKE) -C labs/realistic prod-readiness

ci-prod-readiness: local-prod

local-fuzz:
	@echo "Deprecated alias: use make fuzz-smoke"
	$(MAKE) fuzz-smoke

ci-fuzz-smoke: local-fuzz

local-fuzz-total:
	@echo "Deprecated alias: use make fuzz-long"
	$(MAKE) fuzz-long

ci-fuzz-total: local-fuzz-total

local-total:
	@echo "Deprecated alias: use make verify-check-compat"
	$(MAKE) verify-check-compat

check: local-total

check-browser:
	@echo "Deprecated alias: use make verify-lab-lima"
	$(MAKE) verify-lab-lima

check-all-local:
	@echo "Deprecated alias: use make verify-check-compat verify-lab-lima"
	$(MAKE) verify-check-compat
	$(MAKE) verify-lab-lima

local-total-with-lima: check-all-local

check-sequence:
	@echo "Deprecated alias: use make verify-check-compat && make verify-lab-lima"
	@echo "==> [check-sequence 1/2] verify-check-compat"
	$(MAKE) verify-check-compat
	@echo "==> [check-sequence 2/2] verify-lab-lima"
	$(MAKE) verify-lab-lima

check-sequence-with-vps: check-sequence
	@test -n "$${SSH_SERVER:-}" || (echo "ERROR: SSH_SERVER required"; exit 1)
	@test -n "$${SSH_CLIENT:-}" || (echo "ERROR: SSH_CLIENT required"; exit 1)
	@echo "Deprecated alias: use make verify-remote"
	@echo "==> [check-sequence-with-vps] verify-remote"
	$(MAKE) verify-remote

vps:
	@echo "Deprecated alias: use make verify-remote (legacy exact gate: make -C labs/realistic ci-full)"
	$(MAKE) verify-remote

ci-vps: vps

check-vps:
	@echo "Deprecated alias: use make verify-check-compat verify-remote"
	$(MAKE) verify-check-compat
	$(MAKE) verify-remote

vps-total: check-vps

vps-total-with-fuzz:
	@echo "Deprecated alias: use make verify-check-compat verify-remote (fuzz already in verify-check-compat)"
	$(MAKE) verify-check-compat
	$(MAKE) verify-remote

ci-prod-readiness-with-fuzz:
	@echo "Deprecated alias: use make -C labs/realistic prod-readiness-with-fuzz"
	$(MAKE) -C labs/realistic prod-readiness-with-fuzz

check-perf-vm:
	@echo "Deprecated alias: use make perf"
	$(MAKE) perf

check-perf-vps:
	@echo "Deprecated alias: use make perf-remote"
	$(MAKE) perf-remote

check-perf-total:
	@echo "Deprecated alias: use make perf perf-remote"
	$(MAKE) perf
	$(MAKE) perf-remote

perf-all: check-perf-total

test-help quick-help help-simple:
	@echo "See: make help  |  make help-compat  |  docs/test-workflows.md"
