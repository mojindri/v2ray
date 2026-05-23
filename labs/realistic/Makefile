SHELL := /bin/bash

ROOT := ../..
REPORTS := reports

.PHONY: help build docker-up stable xray phase78 negative-auth restart-smoke stress report-summary realistic-all docker-full docker-down vm-pack vps-configs vps-server-setup vps-client-setup vps-test vps-tun ci ci-full clean

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

vm-pack: ## Pack the full VPS bundle (configs + scripts + service files + README)
	@mkdir -p $(REPORTS)
	@tar -czf $(REPORTS)/vps-lab-bundle.tgz vps configs scripts README.md Makefile
	@echo "Wrote $(REPORTS)/vps-lab-bundle.tgz"
	@echo "scp $(REPORTS)/vps-lab-bundle.tgz root@<SERVER>:/root/"
	@echo "ssh root@<SERVER> 'tar xzf vps-lab-bundle.tgz && bash scripts/server-setup.sh configs/matrix.env'"

vps-configs: ## Expand JSON templates locally using configs/matrix.env (requires envsubst)
	@if [ ! -f configs/matrix.env ]; then \
		echo "ERROR: configs/matrix.env not found. Copy configs/matrix.env.example and fill in values."; exit 1; fi
	@mkdir -p $(REPORTS)/generated-configs
	@for f in configs/server/*.json; do \
		envsubst < "$$f" > "$(REPORTS)/generated-configs/server-$$(basename $$f)"; \
	done
	@for f in configs/client/*.json; do \
		envsubst < "$$f" > "$(REPORTS)/generated-configs/client-$$(basename $$f)"; \
	done
	@echo "Expanded configs written to $(REPORTS)/generated-configs/"

vps-server-setup: ## Print server provisioning command (run from dev machine with SSH_SERVER set)
	@echo ""
	@echo "Run on the SERVER VPS:"
	@echo "  1. scp -r labs/realistic root@\$${SSH_SERVER}:/root/lab"
	@echo "  2. ssh root@\$${SSH_SERVER} 'bash /root/lab/scripts/server-setup.sh /root/lab/configs/matrix.env'"
	@echo ""
	@echo "Or if SSH_SERVER is set, run:"
	@echo "  SSH_SERVER=1.2.3.4 make vps-server-setup"
	@if [ -n "$${SSH_SERVER:-}" ]; then \
		rsync -av --exclude='reports' . root@$${SSH_SERVER}:/root/lab/; \
		ssh root@$${SSH_SERVER} 'bash /root/lab/scripts/server-setup.sh /root/lab/configs/matrix.env'; \
	fi

vps-client-setup: ## Print client provisioning command (run from dev machine with SSH_CLIENT set)
	@echo ""
	@echo "Run on the CLIENT VPS:"
	@echo "  1. scp -r labs/realistic root@\$${SSH_CLIENT}:/root/lab"
	@echo "  2. ssh root@\$${SSH_CLIENT} 'bash /root/lab/scripts/client-setup.sh /root/lab/configs/matrix.env'"
	@echo ""
	@if [ -n "$${SSH_CLIENT:-}" ]; then \
		rsync -av --exclude='reports' . root@$${SSH_CLIENT}:/root/lab/; \
		ssh root@$${SSH_CLIENT} 'bash /root/lab/scripts/client-setup.sh /root/lab/configs/matrix.env'; \
	fi

vps-test: ## Run protocol matrix from the CLIENT VPS (SSH_CLIENT must be set)
	@if [ -z "$${SSH_CLIENT:-}" ]; then \
		echo "ERROR: SSH_CLIENT not set. Example: SSH_CLIENT=5.6.7.8 make vps-test"; exit 1; fi
	@mkdir -p $(REPORTS)
	ssh root@$${SSH_CLIENT} 'bash /root/lab/scripts/run-matrix.sh /root/lab/configs/matrix.env'
	scp root@$${SSH_CLIENT}:/root/lab/reports/vps-matrix-\*.log $(REPORTS)/ 2>/dev/null || true
	@echo "Results copied to $(REPORTS)/"

vps-tun: ## Run TUN privileged tests on the SERVER VPS (SSH_SERVER must be set, Linux+root)
	@if [ -z "$${SSH_SERVER:-}" ]; then \
		echo "ERROR: SSH_SERVER not set. Example: SSH_SERVER=1.2.3.4 make vps-tun"; exit 1; fi
	@mkdir -p $(REPORTS)
	ssh root@$${SSH_SERVER} 'cd /root && sudo -E bash /root/lab/scripts/run-tun-priv.sh'
	scp root@$${SSH_SERVER}:/root/lab/reports/vps-tun-\*.log $(REPORTS)/ 2>/dev/null || true
	@echo "TUN test results copied to $(REPORTS)/"

ci: ## Run EVERYTHING local: unit, integration, prod-readiness, Docker, Xray d0+d1, phase78, stress, negative-auth, restart-smoke
	@mkdir -p $(REPORTS)
	@echo "=== [1/10] workspace unit tests ===" | tee $(REPORTS)/ci.log
	cd $(ROOT) && cargo test --workspace --all-features 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	@echo "=== [2/10] integration tests ===" | tee -a $(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p integration-tests 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	@echo "=== [3/10] production readiness ===" | tee -a $(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p proxy-core     --test production_readiness --all-features 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p proxy-protocol --test production_readiness --all-features 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p proxy-transport --test production_readiness --all-features 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	@echo "=== [4/10] Docker baseline ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) docker-up
	@echo "=== [5/10] phase 7/8 bundle ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) phase78
	@echo "=== [6/10] stress loop ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) stress
	@echo "=== [7/10] negative-auth ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) negative-auth
	@echo "=== [8/10] restart-smoke ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) restart-smoke
	@echo "=== [9/10] Xray d0 self-interop ===" | tee -a $(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p proxy-transport --test interop d0 -- --ignored --nocapture 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	@echo "=== [10/10] Xray d1 live interop ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) xray
	$(MAKE) docker-down
	$(MAKE) report-summary
	@echo "" | tee -a $(REPORTS)/ci.log
	@echo "==> ci complete. Check $(REPORTS)/ci.log and $(REPORTS)/summary.txt" | tee -a $(REPORTS)/ci.log
	@grep -c "FAILED\|^error" $(REPORTS)/ci.log && echo "FAILURES DETECTED" && exit 1 || echo "All tiers passed."

ci-full: ci ## Run ci + VPS matrix + TUN (requires SSH_SERVER and SSH_CLIENT)
	@if [ -z "$${SSH_SERVER:-}" ] || [ -z "$${SSH_CLIENT:-}" ]; then \
		echo "ERROR: SSH_SERVER and SSH_CLIENT must be set for ci-full."; \
		echo "Example: SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 make ci-full"; \
		exit 1; fi
	@echo "=== [VPS] protocol matrix ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) vps-test
	@echo "=== [VPS] TUN privileged tests ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) vps-tun
	$(MAKE) report-summary
	@echo "==> ci-full complete."

clean: docker-down ## Remove generated reports
	rm -rf $(REPORTS)
