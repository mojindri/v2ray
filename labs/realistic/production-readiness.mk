# Production-readiness targets for the existing labs/realistic layout.
# This file is included by labs/realistic/Makefile.

.PHONY: load soak fuzz-smoke fuzz-total fingerprint dns-chaos security real-devices prod-readiness prod-readiness-with-fuzz local-load slowloris pcap-local fingerprint-compare netem-local netem-vps hostility-local ci-matrix-local chrome-baseline-real chrome-baseline-docker fingerprint-total fingerprint-verify vm-browser-setup vm-browser-baseline vm-fingerprint-total lima-browser-baseline lima-fingerprint-total bench-vm-smoke bench-vm-total bench-vps-smoke bench-vps-total

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



local-load: ## Start a managed local proxy and run HTTP load through SOCKS.
	bash scripts/run-local-load-managed.sh reports/production 2>&1 | tee reports/production/local-load.log


slowloris: ## Run slow-client/slowloris diagnostic against a managed local proxy.
	bash scripts/run-slowloris.sh reports/production 2>&1 | tee reports/production/slowloris.log


pcap-local: ## Run local Docker/interop pcap capture helper.
	bash scripts/run-pcap-local.sh reports/production 2>&1 | tee reports/production/pcap-local.log


fingerprint-compare: ## Compare TLS/REALITY fingerprint artifacts when captures exist.
	python3 scripts/compare-fingerprints.py --reports reports/production 2>&1 | tee reports/production/fingerprint-compare.log


netem-local: ## Run local Docker network-hostility smoke if Docker supports tc/netem.
	bash scripts/run-netem-local.sh reports/production 2>&1 | tee reports/production/netem-local.log


netem-vps: ## Run VPS/Linux netem matrix through existing VPS helper.
	$(MAKE) vps-netem


hostility-local: netem-local slowloris ## Run local hostility diagnostics.


ci-matrix-local: ## Run local Makefile-only CI matrix.
	bash scripts/run-ci-matrix-local.sh reports/production 2>&1 | tee reports/production/ci-matrix-local.log


chrome-baseline-real: ## Capture real macOS Chrome TLS baseline. Prompts sudo first; does not auto-open Chrome unless CHROME_OPEN_BROWSER=1.
	bash scripts/run-chrome-baseline-real.sh reports/production 2>&1 | tee reports/production/chrome-baseline-real.log


chrome-baseline-docker: ## Capture Docker Chromium TLS baseline without host sudo.
	bash scripts/run-chrome-baseline-docker.sh reports/production 2>&1 | tee reports/production/chrome-baseline-docker.log


fingerprint-total: chrome-baseline-real fingerprint-verify ## Capture real Chrome baseline, then strictly verify fingerprints.


fingerprint-verify: ## Strict fingerprint verification: requires artifact pcaps, baseline pcaps, and expected Chrome SNI.
	python3 scripts/compare-fingerprints.py --reports reports/production --strict --expect-baseline-sni "$${CHROME_EXPECT_SNI:-www.cloudflare.com}" 2>&1 | tee reports/production/fingerprint-verify.log


vm-browser-setup: ## Install browser/tcpdump/tshark tools on VM over SSH. Requires VM_HOST.
	bash scripts/run-vm-browser-setup.sh reports/production 2>&1 | tee reports/production/vm-browser-setup.log


vm-browser-baseline: ## Capture verified browser baseline inside VM. Requires VM_HOST.
	bash scripts/run-vm-browser-baseline.sh reports/production 2>&1 | tee reports/production/vm-browser-baseline.log


vm-fingerprint-total: vm-browser-baseline ## Fully automated VM browser baseline + strict fingerprint verify. Requires VM_HOST.


lima-browser-baseline: ## Fully automated Lima Ubuntu VM browser baseline. Installs Lima if needed.
	@set -o pipefail; \
	bash scripts/run-lima-browser-baseline.sh reports/production 2>&1 | tee reports/production/lima-browser-baseline.log; \
	test $${PIPESTATUS[0]} -eq 0

lima-fingerprint-total: lima-browser-baseline ## Fully automated Lima VM browser baseline + strict fingerprint verify.


bench-vm-smoke: ## Quick Lima VM performance benchmark.
	bash scripts/run-bench-vm.sh smoke reports/production

bench-vm-total: ## Full Lima VM performance benchmark report.
	bash scripts/run-bench-vm.sh total reports/production

bench-vps-smoke: ## Quick VPS performance benchmark. Requires SSH_SERVER and SSH_CLIENT.
	bash scripts/run-bench-vps.sh smoke reports/production

bench-vps-total: ## Full VPS performance benchmark report. Requires SSH_SERVER and SSH_CLIENT.
	bash scripts/run-bench-vps.sh total reports/production
