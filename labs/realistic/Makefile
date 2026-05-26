SHELL := /bin/bash
.SHELLFLAGS := -euo pipefail -c

ROOT := ../..
REPORTS := reports
# Local interop: native Docker arch (fast on Apple Silicon). VPS deploy: make build-amd64.
DOCKER_PLATFORM ?=
LINUX_BIN := $(ROOT)/target/linux-amd64/blackwire
DOCKER_PLATFORM_FLAG := $(if $(DOCKER_PLATFORM),--platform $(DOCKER_PLATFORM),)
SSH_USER ?= root
SSH_PORT ?= 22
SSH_KEY ?=
SSH_EXTRA_OPTS ?=

.PHONY: help build build-amd64 build-linux-bin docker-up stable ship finalize interop-docker interop-server-docker interop-client-reality interop-server-vps \
	xray advanced-features-smoke health-failover negative-auth restart-smoke stress report-summary realistic-all docker-full docker-down \
	vm-pack vps-configs external-clients-docker external-clients-vps external-clients-report \
	vps-server-setup vps-client-setup vps-preflight vps-test vps-tun vps-netem ci ci-full clean

help:
	@grep -h -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-24s %s\n", $$1, $$2}'

ship: finalize ## Alias: full local parity gate before push/PR

finalize: stable advanced-features-smoke interop-server-docker ## Full local gate: unit/e2e + advanced smoke + external-client matrix
	@echo "finalize: PASS"

build: ## Build blackwire:latest (native platform; fast local interop on arm64 Mac)
	@mkdir -p $(REPORTS)
	docker build $(DOCKER_PLATFORM_FLAG) \
		-f $(ROOT)/deploy/docker/Dockerfile \
		-t blackwire:latest $(ROOT) | tee $(REPORTS)/docker-build-image.txt
	@echo "Built blackwire:latest $$(docker image inspect blackwire:latest --format '{{.Os}}/{{.Architecture}}')"

build-amd64: ## Cross-build blackwire:latest for linux/amd64 (Hetzner x86_64 VPS)
	$(MAKE) build DOCKER_PLATFORM=linux/amd64

build-linux-bin: build-amd64 ## Extract linux/amd64 binary for scp to VPS (no cargo on server)
	@mkdir -p $(dir $(LINUX_BIN))
	@cid=$$(docker create --platform linux/amd64 blackwire:latest); \
	 docker cp "$$cid:/usr/local/bin/blackwire" "$(LINUX_BIN)"; \
	 docker rm "$$cid" >/dev/null
	@file "$(LINUX_BIN)"
	@echo "Wrote $(LINUX_BIN)"
	@echo "  scp -i id_hetzner $(LINUX_BIN) root@<SERVER>:/usr/local/bin/blackwire"

docker-up: build ## Start deterministic target services
	docker compose -f docker-compose.yml up -d target-http target-echo

stable: ## Run the stable Rust integration matrix
	@mkdir -p $(REPORTS)
	cd $(ROOT) && cargo test -p integration-tests 2>&1 | tee labs/realistic/$(REPORTS)/stable-matrix.log

# External-client matrix: sequential only (one client at a time; see external-clients/README.md).
interop-server-docker: build ## Server-compat: Xray/sing-box clients -> our server (Docker)
	@mkdir -p $(REPORTS)/external-clients
	@bash external-clients/scripts/run-docker-matrix.sh $(REPORTS)/external-clients configs/matrix.env
	@bash external-clients/scripts/report.sh

interop-client-reality: ## Client-compat: our Rust REALITY client -> live Xray-core (d1)
	@mkdir -p $(REPORTS)
	cd $(ROOT)/tests/interop && docker compose up -d nginx-fallback xray-server
	cd $(ROOT) && cargo test -p blackwire-transport --test interop d1 -- --ignored --nocapture 2>&1 | tee labs/realistic/$(REPORTS)/interop-client-reality.log

interop-docker: ## Both interop legs: server-compat + client-compat (Docker)
	@echo "==> [interop-docker 1/2] server-compat (Xray/sing-box -> our server)"
	$(MAKE) interop-server-docker
	@echo "==> [interop-docker 2/2] client-compat (our Rust client -> Xray server)"
	$(MAKE) interop-client-reality

xray: ## Deprecated: use make interop-client-reality
	@echo "Deprecated alias: use make interop-client-reality"
	$(MAKE) interop-client-reality

advanced-features-smoke: ## Smoke tests: ShadowTLS, mKCP, QUIC/SplitHTTP VLESS, health/failover, DNS/geo routing guards
	@set -euo pipefail; \
	log="$(CURDIR)/$(REPORTS)/advanced-features-smoke.log"; \
	mkdir -p "$(CURDIR)/$(REPORTS)"; \
	: > "$$log"; \
	cd "$(ROOT)"; \
	run() { \
	  echo "=== [advanced-features-smoke] $$1 ===" | tee -a "$$log"; \
	  shift; \
	  cargo test --locked "$$@" 2>&1 | tee -a "$$log"; \
	}; \
	run "VLESS QUIC" -p integration-tests --test e2e_phase6_vless_quic phase6_vless_quic_echo; \
	run "VLESS SplitHTTP" -p integration-tests --test e2e_phase6_vless_splithttp phase6_vless_splithttp_echo; \
	run "ShadowTLS v3" -p integration-tests --test e2e_phase7_shadowtls phase7_vless_over_shadowtls_v3_transfers_data; \
	run "mKCP" -p integration-tests --test e2e_phase8_mkcp phase8_vless_over_mkcp; \
	run "health / failover guards" -p blackwire-core --test production_readiness balancer_rejects_missing_selector_outbound; \
	run "health / failover guards" -p blackwire-core --test production_readiness balancer_rejects_unsupported_health_check_scheme; \
	run "health / failover guards" -p blackwire-core --test production_readiness routing_rule_can_target_registered_balancer; \
	run "health / failover runtime" -p integration-tests --test e2e_health_failover health_failover_routes_to_backup_when_primary_unhealthy; \
	run "DNS / geo / FakeIP guards" -p blackwire-core --test production_readiness routing_geo_database_paths_are_loaded_nonfatally_when_missing; \
	run "DNS / geo / FakeIP guards" -p blackwire-core --test production_readiness dns_fakeip_rejects_invalid_pool_at_startup

health-failover: ## Health-check balancer failover (in-process e2e + optional Docker probe/echo services)
	@set -euo pipefail; \
	log="$(CURDIR)/$(REPORTS)/health-failover.log"; \
	mkdir -p "$(CURDIR)/$(REPORTS)"; \
	: > "$$log"; \
	echo "=== [health-failover] in-process failover e2e ===" | tee -a "$$log"; \
	cd "$(ROOT)" && cargo test --locked -p integration-tests --test e2e_health_failover health_failover_routes_to_backup_when_primary_unhealthy -- --nocapture 2>&1 | tee -a "$$log"; \
	if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then \
	  echo "=== [health-failover] Docker lab ===" | tee -a "$$log"; \
	  bash "$(CURDIR)/health-failover/run.sh" 2>&1 | tee -a "$$log"; \
	else \
	  echo "=== [health-failover] skipping Docker lab (docker unavailable) ===" | tee -a "$$log"; \
	fi

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

realistic-all: docker-full advanced-features-smoke negative-auth restart-smoke stress report-summary ## Full local baseline + advanced-feature smoke tests

docker-full: docker-up stable advanced-features-smoke interop-docker ## Stable matrix + ShadowTLS/mKCP smoke + Docker interop

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

external-clients-docker: build ## Atom: run external-client matrix only (prefer interop-server-docker)
	@mkdir -p $(REPORTS)/external-clients
	@bash external-clients/scripts/run-docker-matrix.sh $(REPORTS)/external-clients configs/matrix.env

interop-server-vps: ## Server-compat: Xray/sing-box clients -> our server (VPS)
	@mkdir -p $(REPORTS)/external-clients-vps
	@bash external-clients/scripts/run-vps-matrix.sh $(REPORTS)/external-clients-vps configs/matrix.env
	@bash external-clients/scripts/report.sh

external-clients-vps: ## Atom: run external-client matrix on VPS only (prefer interop-server-vps)
	@mkdir -p $(REPORTS)/external-clients-vps
	@bash external-clients/scripts/run-vps-matrix.sh $(REPORTS)/external-clients-vps configs/matrix.env

external-clients-report: ## Summarize latest external-client compatibility report
	@bash external-clients/scripts/report.sh

vps-server-setup: ## Print server provisioning command (run from dev machine with SSH_SERVER set)
	@echo ""
	@echo "Run on the SERVER VPS:"
	@echo "  1. scp -P $${SSH_PORT:-$(SSH_PORT)} $$(if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then printf -- '-i %s ' "$${SSH_KEY:-$(SSH_KEY)}"; fi)-r labs/realistic $${SSH_USER:-$(SSH_USER)}@\$${SSH_SERVER}:/root/lab"
	@echo "  2. ssh -p $${SSH_PORT:-$(SSH_PORT)} $$(if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then printf -- '-i %s ' "$${SSH_KEY:-$(SSH_KEY)}"; fi)$${SSH_USER:-$(SSH_USER)}@\$${SSH_SERVER} 'bash /root/lab/scripts/server-setup.sh /root/lab/configs/matrix.env'"
	@echo ""
	@echo "Or if SSH_SERVER is set, run:"
	@echo "  SSH_SERVER=1.2.3.4 SSH_KEY=~/.ssh/id_hetzner make vps-server-setup"
	@if [ -n "$${SSH_SERVER:-}" ]; then \
		KEY_OPT=""; PORT_OPT=""; SCP_PORT_OPT=""; EXTRA_OPTS="$${SSH_EXTRA_OPTS:-$(SSH_EXTRA_OPTS)}"; USER="$${SSH_USER:-$(SSH_USER)}"; \
		if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then KEY_OPT="-i $${SSH_KEY:-$(SSH_KEY)}"; fi; \
		if [ -n "$${SSH_PORT:-$(SSH_PORT)}" ]; then PORT_OPT="-p $${SSH_PORT:-$(SSH_PORT)}"; SCP_PORT_OPT="-p $${SSH_PORT:-$(SSH_PORT)}"; fi; \
		rsync -av -e "ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS" --exclude='reports' . "$$USER@$${SSH_SERVER}:/root/lab/"; \
		ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}" 'bash /root/lab/scripts/server-setup.sh /root/lab/configs/matrix.env'; \
	fi

vps-client-setup: ## Print client provisioning command (run from dev machine with SSH_CLIENT set)
	@echo ""
	@echo "Run on the CLIENT VPS:"
	@echo "  1. scp -P $${SSH_PORT:-$(SSH_PORT)} $$(if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then printf -- '-i %s ' "$${SSH_KEY:-$(SSH_KEY)}"; fi)-r labs/realistic $${SSH_USER:-$(SSH_USER)}@\$${SSH_CLIENT}:/root/lab"
	@echo "  2. ssh -p $${SSH_PORT:-$(SSH_PORT)} $$(if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then printf -- '-i %s ' "$${SSH_KEY:-$(SSH_KEY)}"; fi)$${SSH_USER:-$(SSH_USER)}@\$${SSH_CLIENT} 'bash /root/lab/scripts/client-setup.sh /root/lab/configs/matrix.env'"
	@echo ""
	@if [ -n "$${SSH_CLIENT:-}" ]; then \
		KEY_OPT=""; PORT_OPT=""; EXTRA_OPTS="$${SSH_EXTRA_OPTS:-$(SSH_EXTRA_OPTS)}"; USER="$${SSH_USER:-$(SSH_USER)}"; \
		if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then KEY_OPT="-i $${SSH_KEY:-$(SSH_KEY)}"; fi; \
		if [ -n "$${SSH_PORT:-$(SSH_PORT)}" ]; then PORT_OPT="-p $${SSH_PORT:-$(SSH_PORT)}"; fi; \
		rsync -av -e "ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS" --exclude='reports' . "$$USER@$${SSH_CLIENT}:/root/lab/"; \
		ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_CLIENT}" 'bash /root/lab/scripts/client-setup.sh /root/lab/configs/matrix.env'; \
	fi

vps-preflight: ## Validate VPS connectivity and required remote artifacts before running VPS checks
	@if [ -z "$${SSH_SERVER:-}" ] || [ -z "$${SSH_CLIENT:-}" ]; then \
		echo "ERROR: SSH_SERVER and SSH_CLIENT must be set for VPS checks."; \
		echo "Example: SSH_SERVER=1.2.3.4 SSH_CLIENT=5.6.7.8 make vps-preflight"; \
		exit 1; \
	fi
	@set -euo pipefail; \
	KEY_OPT=""; PORT_OPT=""; EXTRA_OPTS="$${SSH_EXTRA_OPTS:-$(SSH_EXTRA_OPTS)}"; USER="$${SSH_USER:-$(SSH_USER)}"; \
	if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then KEY_OPT="-i $${SSH_KEY:-$(SSH_KEY)}"; fi; \
	if [ -n "$${SSH_PORT:-$(SSH_PORT)}" ]; then PORT_OPT="-p $${SSH_PORT:-$(SSH_PORT)}"; fi; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_CLIENT}" 'test -x /root/lab/scripts/run-matrix.sh && test -f /root/lab/configs/matrix.env && command -v /usr/local/bin/blackwire >/dev/null' || { \
		echo "ERROR: CLIENT VPS is not ready (/root/lab, matrix.env, or /usr/local/bin/blackwire missing)."; \
		echo "Run: SSH_CLIENT=$${SSH_CLIENT} SSH_KEY=$${SSH_KEY:-$(SSH_KEY)} make vps-client-setup"; \
		exit 1; \
	}; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}" 'test -x /root/lab/scripts/run-tun-priv.sh && test -x /root/lab/scripts/run-netem.sh && command -v /usr/local/bin/blackwire >/dev/null && command -v cargo >/dev/null && command -v tc >/dev/null' || { \
		echo "ERROR: SERVER VPS is not ready (scripts, blackwire, cargo, or tc missing)."; \
		echo "Run: SSH_SERVER=$${SSH_SERVER} SSH_KEY=$${SSH_KEY:-$(SSH_KEY)} make vps-server-setup"; \
		exit 1; \
	}; \
	echo "VPS preflight passed."

vps-test: ## Run protocol matrix from the CLIENT VPS (SSH_CLIENT must be set)
	@if [ -z "$${SSH_CLIENT:-}" ]; then \
		echo "ERROR: SSH_CLIENT not set. Example: SSH_CLIENT=5.6.7.8 make vps-test"; exit 1; fi
	@mkdir -p $(REPORTS)
	@set -euo pipefail; \
	KEY_OPT=""; PORT_OPT=""; SCP_PORT_OPT=""; EXTRA_OPTS="$${SSH_EXTRA_OPTS:-$(SSH_EXTRA_OPTS)}"; USER="$${SSH_USER:-$(SSH_USER)}"; \
	if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then KEY_OPT="-i $${SSH_KEY:-$(SSH_KEY)}"; fi; \
	if [ -n "$${SSH_PORT:-$(SSH_PORT)}" ]; then PORT_OPT="-p $${SSH_PORT:-$(SSH_PORT)}"; SCP_PORT_OPT="-P $${SSH_PORT:-$(SSH_PORT)}"; fi; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_CLIENT}" 'test -x /root/lab/scripts/run-matrix.sh' || { \
		echo "ERROR: /root/lab/scripts/run-matrix.sh missing on CLIENT VPS."; \
		echo "Run: SSH_CLIENT=$${SSH_CLIENT} SSH_KEY=$${SSH_KEY:-$(SSH_KEY)} make vps-client-setup"; \
		exit 1; \
	}; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_CLIENT}" 'bash /root/lab/scripts/run-matrix.sh /root/lab/configs/matrix.env'; \
	scp $$SCP_PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_CLIENT}:/root/lab/reports/vps-matrix-\*.log" $(REPORTS)/ 2>/dev/null || true
	@echo "Results copied to $(REPORTS)/"

vps-netem: ## Run tc netem network-condition tests on the SERVER VPS (SSH_SERVER must be set, Linux+root+iproute2)
	@if [ -z "$${SSH_SERVER:-}" ]; then \
		echo "ERROR: SSH_SERVER not set. Example: SSH_SERVER=1.2.3.4 make vps-netem"; exit 1; fi
	@mkdir -p $(REPORTS)
	@set -euo pipefail; \
	KEY_OPT=""; PORT_OPT=""; SCP_PORT_OPT=""; EXTRA_OPTS="$${SSH_EXTRA_OPTS:-$(SSH_EXTRA_OPTS)}"; USER="$${SSH_USER:-$(SSH_USER)}"; \
	if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then KEY_OPT="-i $${SSH_KEY:-$(SSH_KEY)}"; fi; \
	if [ -n "$${SSH_PORT:-$(SSH_PORT)}" ]; then PORT_OPT="-p $${SSH_PORT:-$(SSH_PORT)}"; SCP_PORT_OPT="-P $${SSH_PORT:-$(SSH_PORT)}"; fi; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}" 'command -v cargo >/dev/null && command -v tc >/dev/null && test -x /root/lab/scripts/run-netem.sh' || { \
		echo "ERROR: SERVER VPS missing prerequisites for netem (cargo/tc/script)."; \
		echo "Run: SSH_SERVER=$${SSH_SERVER} SSH_KEY=$${SSH_KEY:-$(SSH_KEY)} make vps-server-setup"; \
		exit 1; \
	}; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}" 'sudo bash /root/lab/scripts/run-netem.sh /root/lab/reports'; \
	scp $$SCP_PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}:/root/lab/reports/vps-netem-*.log" $(REPORTS)/ 2>/dev/null || true
	@echo "netem results copied to $(REPORTS)/"

vps-tun: ## Run TUN privileged tests on the SERVER VPS (SSH_SERVER must be set, Linux+root)
	@if [ -z "$${SSH_SERVER:-}" ]; then \
		echo "ERROR: SSH_SERVER not set. Example: SSH_SERVER=1.2.3.4 make vps-tun"; exit 1; fi
	@mkdir -p $(REPORTS)
	@set -euo pipefail; \
	KEY_OPT=""; PORT_OPT=""; SCP_PORT_OPT=""; EXTRA_OPTS="$${SSH_EXTRA_OPTS:-$(SSH_EXTRA_OPTS)}"; USER="$${SSH_USER:-$(SSH_USER)}"; \
	if [ -n "$${SSH_KEY:-$(SSH_KEY)}" ]; then KEY_OPT="-i $${SSH_KEY:-$(SSH_KEY)}"; fi; \
	if [ -n "$${SSH_PORT:-$(SSH_PORT)}" ]; then PORT_OPT="-p $${SSH_PORT:-$(SSH_PORT)}"; SCP_PORT_OPT="-P $${SSH_PORT:-$(SSH_PORT)}"; fi; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}" 'command -v cargo >/dev/null && test -x /root/lab/scripts/run-tun-priv.sh' || { \
		echo "ERROR: SERVER VPS missing prerequisites for TUN tests (cargo/script)."; \
		echo "Run: SSH_SERVER=$${SSH_SERVER} SSH_KEY=$${SSH_KEY:-$(SSH_KEY)} make vps-server-setup"; \
		exit 1; \
	}; \
	ssh $$PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}" 'cd /root && sudo -E bash /root/lab/scripts/run-tun-priv.sh'; \
	scp $$SCP_PORT_OPT $$KEY_OPT $$EXTRA_OPTS "$$USER@$${SSH_SERVER}:/root/lab/reports/vps-tun-\*.log" $(REPORTS)/ 2>/dev/null || true
	@echo "TUN test results copied to $(REPORTS)/"

ci: ## Run EVERYTHING local: unit, integration, prod-readiness, Docker, Xray d0+d1, advanced-features-smoke, stress, negative-auth, restart-smoke
	@mkdir -p $(REPORTS)
	@echo "=== [1/10] workspace unit tests ===" | tee $(REPORTS)/ci.log
	cd $(ROOT) && cargo test --workspace --all-features 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	@echo "=== [2/10] integration tests ===" | tee -a $(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p integration-tests 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	@echo "=== [3/10] production readiness ===" | tee -a $(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p blackwire-core     --test production_readiness --all-features 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p blackwire-protocol --test production_readiness --all-features 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p blackwire-transport --test production_readiness --all-features 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	@echo "=== [4/10] Docker baseline ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) docker-up
	@echo "=== [5/10] advanced features smoke ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) advanced-features-smoke
	@echo "=== [6/10] stress loop ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) stress
	@echo "=== [7/10] negative-auth ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) negative-auth
	@echo "=== [8/10] restart-smoke ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) restart-smoke
	@echo "=== [9/10] interop d0 self-consistency ===" | tee -a $(REPORTS)/ci.log
	cd $(ROOT) && cargo test -p blackwire-transport --test interop d0 -- --ignored --nocapture 2>&1 | tee -a labs/realistic/$(REPORTS)/ci.log
	@echo "=== [10/10] interop-docker (server + client legs) ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) interop-docker
	$(MAKE) docker-down
	$(MAKE) report-summary
	@echo "" | tee -a $(REPORTS)/ci.log
	@echo "==> ci complete. Check $(REPORTS)/ci.log and $(REPORTS)/summary.txt" | tee -a $(REPORTS)/ci.log
	@grep -c "FAILED\|^error" $(REPORTS)/ci.log && echo "FAILURES DETECTED" && exit 1 || echo "All tiers passed."

ci-full: ## Run ci + VPS matrix + TUN (requires SSH_SERVER and SSH_CLIENT)
	$(MAKE) vps-preflight
	$(MAKE) ci
	@echo "=== [VPS] protocol matrix ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) vps-test
	@echo "=== [VPS] TUN privileged tests ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) vps-tun
	@echo "=== [VPS] netem network conditions ===" | tee -a $(REPORTS)/ci.log
	$(MAKE) vps-netem
	$(MAKE) report-summary
	@echo "==> ci-full complete."

clean: docker-down ## Remove generated reports
	rm -rf $(REPORTS)


# Local production-readiness add-on targets.
-include production-readiness.mk

# VM integration (default .env.vm, UTM/Parallels/VirtualBox).
-include .env.vm

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
	elif [ -n "$${VM_NAME:-$(VM_NAME)}" ] && [ -x /Applications/UTM.app/Contents/MacOS/utmctl ]; then \
		echo "Starting UTM VM: $${VM_NAME:-$(VM_NAME)}"; \
		/Applications/UTM.app/Contents/MacOS/utmctl start "$${VM_NAME:-$(VM_NAME)}" || true; \
	elif [ -n "$${VM_NAME:-$(VM_NAME)}" ] && command -v utmctl >/dev/null 2>&1; then \
		echo "Starting UTM VM: $${VM_NAME:-$(VM_NAME)}"; \
		utmctl start "$${VM_NAME:-$(VM_NAME)}" || true; \
	elif [ -n "$${VM_NAME:-$(VM_NAME)}" ] && command -v prlctl >/dev/null 2>&1; then \
		echo "Starting Parallels VM: $${VM_NAME:-$(VM_NAME)}"; \
		prlctl start "$${VM_NAME:-$(VM_NAME)}" || true; \
	elif [ -n "$${VM_NAME:-$(VM_NAME)}" ] && command -v VBoxManage >/dev/null 2>&1 && VBoxManage --version >/dev/null 2>&1; then \
		echo "Starting VirtualBox VM: $${VM_NAME:-$(VM_NAME)}"; \
		VBoxManage startvm "$${VM_NAME:-$(VM_NAME)}" --type headless || true; \
	else \
		echo "No working VM launcher found or VM_NAME is empty."; \
		echo "If you use VirtualBox, your VBoxManage must run successfully: VBoxManage --version"; \
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
