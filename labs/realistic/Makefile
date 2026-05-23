SHELL := /bin/bash

ROOT := ../..
REPORTS := reports

.PHONY: help build docker-up stable xray docker-full docker-down vm-pack clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

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
