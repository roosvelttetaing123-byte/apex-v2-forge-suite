.PHONY: install test lint clean update-cve-db intel-sync dashboard c2 docker docker-up docker-down help

# ── Install ───────────────────────────────────────────────────────────
install:
	bash install.sh

# ── Testing ───────────────────────────────────────────────────────────
test:
	python3 -m pytest webforge/ netforge/ adforge/ aiforge/ common/ forge_c2/ -v --tb=short 2>&1 | tail -60

lint:
	python3 -m bandit -r webforge/ netforge/ adforge/ aiforge/ common/ forge_c2/ -ll -q

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
	docker build -t forge-suite:5.0.0 .

docker-up:
	docker compose up -d

docker-down:
	docker compose down

# ── Cleanup ───────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	rm -rf webforge/results/* netforge/results/* adforge/results/* aiforge/results/* 2>/dev/null || true

# ── Help ──────────────────────────────────────────────────────────────
help:
	@echo ""
	@echo "  Forge Suite v5 APEX — Makefile targets"
	@echo "  ═══════════════════════════════════════"
	@echo ""
	@echo "  install        Install all dependencies"
	@echo "  test           Run test suite"
	@echo "  lint           Run bandit security linter"
	@echo "  intel-sync     Sync all intel sources (NVD, ExploitDB, Nuclei, ATT&CK)"
	@echo "  update-cve-db  Sync CVE database only"
	@echo "  dashboard      Launch War Room dashboard (web)"
	@echo "  dashboard-tui  Launch War Room dashboard (terminal TUI)"
	@echo "  c2             Start C2 team server"
	@echo "  docker         Build Docker image"
	@echo "  docker-up      Start all services via docker compose"
	@echo "  docker-down    Stop all services"
	@echo "  clean          Remove caches and results"
	@echo ""
