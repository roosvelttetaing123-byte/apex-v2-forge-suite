FORGE_VERSION := $(strip $(shell tr -d '\r\n' < VERSION))
IMAGE_NAME ?= forge-suite
IMAGE_TAG ?= $(IMAGE_NAME):$(FORGE_VERSION)
IMAGE_DIGEST ?=
VCS_REF ?= unknown
PYTHON_IMAGE := python:3.13.9-slim-bookworm@sha256:b685a4fa58bb19d1814d78a1ec0f0208f351452724f78b20212c984d6e124a34
NODE_IMAGE := node:20.19.5-bookworm-slim@sha256:9e70124bd00f47dd023e349cd587132ae61892acc0e47ed641416c3e18f401c3
NPM_VERSION := 10.8.2
BUILD_MANIFEST ?= build/forge-build-manifest.json
PYTHON ?= python3

.PHONY: install test test-short compile coverage lint quality frontend sbom clean update-cve-db intel-sync dashboard c2 docker docker-up docker-c2 docker-down build-manifest version help

# ── Canonical release identity ────────────────────────────────────────
version:
	@printf '%s\n' "$(FORGE_VERSION)"

# ── Install ───────────────────────────────────────────────────────────
install:
	bash install.sh

# ── Testing ───────────────────────────────────────────────────────────
# Exit code is preserved — do NOT pipe through tail or any filter.
test:
	$(PYTHON) -m pytest tests/ -v --tb=short --strict-markers --timeout=60 --forge-qualification

test-short:
	$(PYTHON) -m pytest tests/ -v --tb=short --strict-markers --timeout=60 -x

compile:
	find . -name '*.py' ! -path './apex-ui/*' ! -path './.git/*' -print0 | \
	    xargs -0 $(PYTHON) -m py_compile

coverage:
	mkdir -p build/quality
	$(PYTHON) -m pytest tests/ --cov=common --cov=webforge/core --cov=netforge/data \
	    --cov-report=term-missing --cov-report=xml:build/coverage.xml \
	    --cov-report=json:build/coverage.json --tb=short --forge-qualification
	$(PYTHON) scripts/run_quality_gates.py coverage --coverage-json build/coverage.json

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m mypy
	$(PYTHON) scripts/verify_supply_chain.py

quality:
	$(PYTHON) scripts/run_quality_gates.py static

frontend:
	cd apex-ui && npm ci --ignore-scripts --no-audit --no-fund
	cd apex-ui && npm run contracts:check
	cd apex-ui && npm run typecheck
	cd apex-ui && npm test
	cd apex-ui && npm run audit:ci
	cd apex-ui && npm run build

sbom:
	$(PYTHON) scripts/generate_sbom.py --output build/forge-sbom.cdx.json
	$(PYTHON) scripts/verify_sbom.py --input build/forge-sbom.cdx.json

# ── Intelligence ──────────────────────────────────────────────────────
update-cve-db:
	python3 forge.py intel sync --cve

intel-sync:
	python3 forge.py intel sync --all

# ── Dashboard ─────────────────────────────────────────────────────────
dashboard:
	python3 forge.py dashboard

dashboard-tui:
	python3 forge.py dashboard --tui

# ── C2 ────────────────────────────────────────────────────────────────
c2:
	python3 forge.py c2 server --port 8443

# ── Docker ────────────────────────────────────────────────────────────
docker:
	docker build \
	    --build-arg FORGE_VERSION="$(FORGE_VERSION)" \
	    --build-arg VCS_REF="$(VCS_REF)" \
	    --build-arg PYTHON_IMAGE="$(PYTHON_IMAGE)" \
	    --build-arg NODE_IMAGE="$(NODE_IMAGE)" \
	    --tag "$(IMAGE_TAG)" .

docker-up:
	FORGE_VERSION="$(FORGE_VERSION)" FORGE_VCS_REF="$(VCS_REF)" docker compose up -d forge-dashboard

docker-c2:
	FORGE_VERSION="$(FORGE_VERSION)" FORGE_VCS_REF="$(VCS_REF)" docker compose --profile local-lab-c2 up -d forge-c2

docker-down:
	FORGE_VERSION="$(FORGE_VERSION)" FORGE_VCS_REF="$(VCS_REF)" docker compose down

build-manifest:
	mkdir -p "$(dir $(BUILD_MANIFEST))"
	python3 scripts/generate_build_manifest.py \
	    --output "$(BUILD_MANIFEST)" \
	    --image-ref "$(IMAGE_TAG)" \
	    --image-digest "$(IMAGE_DIGEST)" \
	    --python-image "$(PYTHON_IMAGE)" \
	    --node-image "$(NODE_IMAGE)" \
	    --npm-version "$(NPM_VERSION)" \
	    --vcs-ref "$(VCS_REF)"

# ── Cleanup ───────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf webforge/results/* netforge/results/* adforge/results/* aiforge/results/* 2>/dev/null || true

# ── Help ──────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  Forge Suite $(FORGE_VERSION) — Makefile targets"
	@echo "  ═══════════════════════════════════════"
	@echo ""
	@echo "  install        Install all dependencies"
	@echo "  test           Run full test suite (exit code reflects pass/fail)"
	@echo "  test-short     Run common/ + tests/ only, stop on first failure"
	@echo "  compile        Syntax-check core modules with py_compile"
	@echo "  coverage       Run common/ + tests/ with coverage report"
	@echo "  lint           Run bandit security linter"
	@echo "  intel-sync     Sync all intel sources (NVD, ExploitDB, Nuclei, ATT&CK)"
	@echo "  update-cve-db  Sync CVE database only"
	@echo "  dashboard      Launch War Room dashboard (web)"
	@echo "  dashboard-tui  Launch War Room dashboard (terminal TUI)"
	@echo "  c2             Start C2 team server"
	@echo "  docker         Build Docker image"
	@echo "  docker-up      Start the dashboard via docker compose"
	@echo "  docker-c2      Start the opt-in local-lab C2 profile"
	@echo "  docker-down    Stop all services"
	@echo "  build-manifest Write deterministic build input metadata"
	@echo "  version        Print the canonical VERSION value"
	@echo "  clean          Remove caches and results"
	@echo ""
