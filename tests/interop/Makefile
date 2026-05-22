# Xray-core differential interop test runner
#
# Quick-start (d0 self-tests — no docker needed):
#   cargo test --test interop d0 -- --ignored --nocapture
#
# Full matrix (d0 + d1):
#   make up
#   cargo test --test interop -- --ignored --nocapture
#   make down
#
# With JA3 fingerprint capture:
#   make up
#   make pcap        # run in a separate terminal
#   cargo test --test interop d1 -- --ignored --nocapture
#   make analyze     # after Ctrl-C on make pcap

SHELL       := /bin/bash
KEYS_DIR    := keys
CONFIGS_DIR := configs
SCRIPTS_DIR := scripts
PCAPS_DIR   := pcaps
REPORTS_DIR := reports

PRIVATE_KEY := $(KEYS_DIR)/private.key
PUBLIC_KEY  := $(KEYS_DIR)/public.key
SHORT_ID    := $(KEYS_DIR)/short_id.txt

XRAY_SERVER_CFG := $(CONFIGS_DIR)/xray-server.json
XRAY_CLIENT_CFG := $(CONFIGS_DIR)/xray-client.json

# Chrome 131 JA3 — used by assert_ja3.sh
CHROME_131_JA3 := 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0

.PHONY: help keys configs up test pcap analyze down clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	    | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

# ── Keys ─────────────────────────────────────────────────────────────────────

keys: $(PRIVATE_KEY) ## Generate x25519 keypair via Xray-core docker image (once)

$(PRIVATE_KEY):
	@mkdir -p $(KEYS_DIR)
	@echo "Generating x25519 keypair via Xray-core…"
	@docker run --rm ghcr.io/xtls/xray-core:latest x25519 \
	    | tee $(KEYS_DIR)/keypair.txt
	@grep "^PrivateKey:" $(KEYS_DIR)/keypair.txt \
	    | awk '{print $$2}' | tr -d '[:space:]' > $(PRIVATE_KEY)
	@grep "PublicKey)" $(KEYS_DIR)/keypair.txt \
	    | awk '{print $$3}' | tr -d '[:space:]' > $(PUBLIC_KEY)
	@printf 'aabbccdd00000001' > $(SHORT_ID)
	@echo ""
	@echo "Private key : $$(cat $(PRIVATE_KEY))"
	@echo "Public key  : $$(cat $(PUBLIC_KEY))"
	@echo "Short ID    : $$(cat $(SHORT_ID))"
	@echo ""
	@echo "Keys written to $(KEYS_DIR)/.  Optionally commit them for reproducible runs."

# ── Configs ──────────────────────────────────────────────────────────────────

configs: $(XRAY_SERVER_CFG) $(XRAY_CLIENT_CFG) ## Render Xray JSON configs from templates

$(XRAY_SERVER_CFG): $(CONFIGS_DIR)/xray-server.json.tmpl $(PRIVATE_KEY)
	@mkdir -p $(CONFIGS_DIR)
	REALITY_PRIVATE_KEY="$$(cat $(PRIVATE_KEY))" \
	REALITY_SHORT_ID="$$(cat $(SHORT_ID))" \
	envsubst < $< > $@
	@echo "Generated $@"

$(XRAY_CLIENT_CFG): $(CONFIGS_DIR)/xray-client.json.tmpl $(PUBLIC_KEY)
	@mkdir -p $(CONFIGS_DIR)
	REALITY_PUBLIC_KEY="$$(cat $(PUBLIC_KEY))" \
	REALITY_SHORT_ID="$$(cat $(SHORT_ID))" \
	envsubst < $< > $@
	@echo "Generated $@"

# ── Docker lifecycle ──────────────────────────────────────────────────────────

up: configs ## Start Xray server + nginx fallback, wait for port 8443
	docker compose up -d
	@bash $(SCRIPTS_DIR)/wait_for_port.sh 8443

down: ## Stop and remove containers + volumes
	docker compose down -v

# ── Tests ─────────────────────────────────────────────────────────────────────

test: up ## Run the full interop test matrix
	@mkdir -p $(REPORTS_DIR)
	@echo "Running interop tests…"
	@cd ../.. && cargo test --test interop -- --ignored --nocapture \
	    2>&1 | tee tests/interop/$(REPORTS_DIR)/test.log
	@echo ""
	@echo "Report: $(REPORTS_DIR)/test.log"

# d0 self-tests only — no docker needed
selftest: ## Run d0 self-interop tests (no docker required)
	@cd ../.. && cargo test --test interop d0 -- --ignored --nocapture

# ── Fingerprint capture ───────────────────────────────────────────────────────

pcap: ## Capture traffic on port 8443 (Ctrl-C to stop, then run 'make analyze')
	@mkdir -p $(PCAPS_DIR)
	@bash $(SCRIPTS_DIR)/run_pcap.sh $(PCAPS_DIR)/capture.pcap

analyze: ## Extract JA3 from last pcap and assert it matches Chrome 131
	@mkdir -p $(REPORTS_DIR)
	@bash $(SCRIPTS_DIR)/assert_ja3.sh \
	    $(PCAPS_DIR)/capture.pcap \
	    "$(CHROME_131_JA3)" \
	    | tee $(REPORTS_DIR)/ja3.txt

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean: down ## Remove all generated files (keys, configs, pcaps, reports)
	rm -rf $(KEYS_DIR) \
	    $(CONFIGS_DIR)/xray-server.json $(CONFIGS_DIR)/xray-client.json \
	    $(PCAPS_DIR) $(REPORTS_DIR)
