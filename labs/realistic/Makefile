SHELL := /bin/bash

ROOT := ../..
REPORTS := reports

.PHONY: help build docker-up stable xray phase78 negative-auth restart-smoke stress report-summary realistic-all docker-full docker-down vm-pack clean

help:
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

build: ## Build the proxy-rs Docker image used by the lab
	docker build -f $(ROOT)/deploy/docker/Dockerfile -t proxy-rs:latest $(ROOT)

docker-up: build ## Start deterministic target services
	docker compose -f docker-compose.yml up -d target-http target-echo

stable: ## Run the stable Rust integration matrix
	@mkdir -p $(REPORTS)
	cd $(ROOT) && cargo test -p integration-tests 2>&1 | tee labs/realistic/$(REPORTS)/stable-matrix.log

xray: ## Run required live Xray REALITY interop
	@mkdir -p $(REPORTS)
	cd $(ROOT)/tests/interop && docker compose up -d nginx-fallback xray-server
	cd $(ROOT) && cargo test -p proxy-transport --test interop d1 -- --ignored --nocapture 2>&1 | tee labs/realistic/$(REPORTS)/xray-reality.log

phase78: ## Run Phase 7/8 local realism checks (ShadowTLS v3, mKCP, health/failover, geo/FakeIP guards)
	@mkdir -p $(REPORTS)
	cd $(ROOT) && cargo test -p integration-tests phase7_vless_over_shadowtls_v3_transfers_data 2>&1 | tee labs/realistic/$(REPORTS)/phase78-shadowtls.log
	cd $(ROOT) && cargo test -p integration-tests phase8_vless_over_mkcp 2>&1 | tee labs/realistic/$(REPORTS)/phase78-mkcp.log
	cd $(ROOT) && cargo test -p proxy-core --test production_readiness balancer_rejects_missing_selector_outbound 2>&1 | tee labs/realistic/$(REPORTS)/phase78-health.log
	cd $(ROOT) && cargo test -p proxy-core --test production_readiness balancer_rejects_unsupported_health_check_scheme 2>&1 | tee -a labs/realistic/$(REPORTS)/phase78-health.log
	cd $(ROOT) && cargo test -p proxy-core --test production_readiness routing_rule_can_target_registered_balancer 2>&1 | tee -a labs/realistic/$(REPORTS)/phase78-health.log
	cd $(ROOT) && cargo test -p proxy-core --test production_readiness routing_geo_database_paths_are_loaded_nonfatally_when_missing 2>&1 | tee labs/realistic/$(REPORTS)/phase78-geo-fakeip.log
	cd $(ROOT) && cargo test -p proxy-core --test production_readiness dns_fakeip_rejects_invalid_pool_at_startup 2>&1 | tee -a labs/realistic/$(REPORTS)/phase78-geo-fakeip.log

negative-auth: ## Run negative-auth scenarios that should be rejected/fallback
	@mkdir -p $(REPORTS)
	cd $(ROOT) && cargo test -p integration-tests reality_wrong_key_triggers_fallback 2>&1 | tee labs/realistic/$(REPORTS)/negative-auth.log
	cd $(ROOT) && cargo test -p integration-tests trojan_wrong_password_is_rejected 2>&1 | tee -a labs/realistic/$(REPORTS)/negative-auth.log
	cd $(ROOT) && cargo test -p integration-tests server_rejects_wrong_password 2>&1 | tee -a labs/realistic/$(REPORTS)/negative-auth.log
	cd $(ROOT) && cargo test -p integration-tests vmess_unknown_uuid_rejected 2>&1 | tee -a labs/realistic/$(REPORTS)/negative-auth.log

restart-smoke: ## Restart target services and re-run smoke e2e checks
	@mkdir -p $(REPORTS)
	docker compose -f docker-compose.yml up -d target-http target-echo
	cd $(ROOT) && cargo test -p integration-tests e2e_socks5_to_vless_to_freedom_transfers_data 2>&1 | tee labs/realistic/$(REPORTS)/restart-smoke.log
	cd $(ROOT) && cargo test -p integration-tests reality_legitimate_client_can_authenticate_and_exchange_data 2>&1 | tee -a labs/realistic/$(REPORTS)/restart-smoke.log
	docker compose -f docker-compose.yml down -v
	docker compose -f docker-compose.yml up -d target-http target-echo
	cd $(ROOT) && cargo test -p integration-tests e2e_socks5_to_vless_to_freedom_transfers_http 2>&1 | tee -a labs/realistic/$(REPORTS)/restart-smoke.log
	cd $(ROOT) && cargo test -p integration-tests phase5_http_connect_vmess_grpc_transfers_data 2>&1 | tee -a labs/realistic/$(REPORTS)/restart-smoke.log
	docker compose -f docker-compose.yml down -v

stress: ## Repeat high-signal data-plane tests to catch flaky behavior
	@mkdir -p $(REPORTS)
	cd $(ROOT) && bash -lc 'set -euo pipefail; \
		for i in 1 2 3 4 5; do \
			echo "=== stress iteration $$i ==="; \
			cargo test -p integration-tests phase8_vless_over_mkcp_transfers_data; \
			cargo test -p integration-tests phase7_vless_over_shadowtls_v3_transfers_data; \
			cargo test -p integration-tests e2e_socks5_to_vless_to_freedom_transfers_data; \
		done' 2>&1 | tee labs/realistic/$(REPORTS)/stress.log

report-summary: ## Build a compact summary from report logs
	@mkdir -p $(REPORTS)
	@echo "realistic lab summary - $$(date -u +%Y-%m-%dT%H:%M:%SZ)" > $(REPORTS)/summary.txt
	@for f in $(REPORTS)/*.log; do \
		if [ -f "$$f" ]; then \
			echo "" >> $(REPORTS)/summary.txt; \
			echo "[$$(basename "$$f")]" >> $(REPORTS)/summary.txt; \
			grep -E "FAILED|error:" "$$f" | tail -n 20 >> $(REPORTS)/summary.txt || true; \
			grep -E "test result:" "$$f" | grep -v "0 passed; 0 failed;" | tail -n 12 >> $(REPORTS)/summary.txt || true; \
		fi; \
	done
	@echo "Wrote $(REPORTS)/summary.txt"

realistic-all: docker-full phase78 negative-auth restart-smoke stress report-summary ## Run full realistic baseline + Phase 7/8 verification bundle

docker-full: docker-up stable xray ## Run the full local realistic baseline

docker-down: ## Stop lab and interop containers
	-docker compose -f docker-compose.yml down -v
	-cd $(ROOT)/tests/interop && docker compose down -v

vm-pack: ## Prepare the two-VPS instructions bundle
	@mkdir -p $(REPORTS)
	@tar -czf $(REPORTS)/vps-lab-bundle.tgz vps configs scripts README.md Makefile
	@echo "Wrote $(REPORTS)/vps-lab-bundle.tgz"

clean: docker-down ## Remove generated reports
	rm -rf $(REPORTS)
