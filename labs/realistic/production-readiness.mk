# Production-readiness targets for the existing labs/realistic layout.
# This file is included by labs/realistic/Makefile.

.PHONY: load soak fuzz-smoke fuzz-total fingerprint dns-chaos security real-devices prod-readiness prod-readiness-with-fuzz

LOAD_ENV ?= configs/load.env
SOAK_ENV ?= configs/soak.env
PROD_REPORTS ?= reports/production

load: ## Run local SOCKS->HTTP load smoke; skips cleanly if no proxy is listening.
	@mkdir -p $(PROD_REPORTS)
	bash scripts/run-load.sh $(LOAD_ENV) $(PROD_REPORTS) 2>&1 | tee $(PROD_REPORTS)/load.log

soak: ## Run short bounded soak loop; tune configs/soak.env for longer runs.
	@mkdir -p $(PROD_REPORTS)
	bash scripts/run-soak.sh $(SOAK_ENV) $(PROD_REPORTS) 2>&1 | tee $(PROD_REPORTS)/soak.log

fuzz-smoke: ## Run short cargo-fuzz smoke if cargo-fuzz is installed.
	@mkdir -p $(PROD_REPORTS)
	bash scripts/run-fuzz-smoke.sh $(PROD_REPORTS) 2>&1 | tee $(PROD_REPORTS)/fuzz-smoke.log

fingerprint: ## Print/capture TLS fingerprint helper output.
	@mkdir -p $(PROD_REPORTS)
	bash scripts/run-fingerprint-check.sh $(PROD_REPORTS) 2>&1 | tee $(PROD_REPORTS)/tls-fingerprint.log

dns-chaos: ## Run DNS/FakeIP chaos helper smoke.
	@mkdir -p $(PROD_REPORTS)
	python3 scripts/dns_chaos_server.py --zones configs/dns-chaos-zones.json --smoke 2>&1 | tee $(PROD_REPORTS)/dns-chaos.log

security: ## Run dependency/security hygiene checks.
	@mkdir -p $(PROD_REPORTS)
	bash scripts/run-security-checks.sh $(PROD_REPORTS) 2>&1 | tee $(PROD_REPORTS)/security.log

real-devices: ## Write/print real-device/manual-carrier test checklist.
	@mkdir -p $(PROD_REPORTS)
	bash scripts/real-device-checklist.sh $(PROD_REPORTS) 2>&1 | tee $(PROD_REPORTS)/real-devices.log

prod-readiness: load soak fingerprint dns-chaos security real-devices report-summary ## Run production-readiness helpers, excluding fuzz.

fuzz-total: ## Run heavier fuzz pass. Override with FUZZ_RUNS=10000.
	FUZZ_RUNS=$${FUZZ_RUNS:-5000} bash scripts/run-fuzz-smoke.sh reports/production 2>&1 | tee reports/production/fuzz-total.log

prod-readiness-with-fuzz: load soak fuzz-smoke fingerprint dns-chaos security real-devices report-summary ## Run production-readiness helpers including fuzz smoke.

