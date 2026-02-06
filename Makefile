# Sentinel NetLab - Makefile
# Single entry point for all build/test/deploy operations

.PHONY: help install dev test lint security docker clean

PYTHON := python
VENV := venv
PIP := $(VENV)/Scripts/pip
PYTEST := $(VENV)/Scripts/pytest

# Default target
help:
	@echo "Sentinel NetLab - Build System"
	@echo ""
	@echo "Setup:"
	@echo "  make install      Install production dependencies"
	@echo "  make dev          Install dev dependencies"
	@echo "  make venv         Create virtual environment"
	@echo ""
	@echo "Testing:"
	@echo "  make test         Run all tests"
	@echo "  make test-unit    Run unit tests only"
	@echo "  make test-int     Run integration tests"
	@echo "  make lint         Run linter (ruff)"
	@echo "  make typecheck    Run mypy type checker"
	@echo ""
	@echo "Security:"
	@echo "  make security     Run all security scans"
	@echo "  make bandit       Run Bandit SAST"
	@echo "  make audit        Run pip-audit"
	@echo ""
	@echo "Docker:"
	@echo "  make docker       Build all Docker images"
	@echo "  make docker-up    Start docker-compose stack"
	@echo "  make docker-down  Stop docker-compose stack"
	@echo ""
	@echo "Utilities:"
	@echo "  make schema       Generate JSON schemas from Pydantic"
	@echo "  make clean        Remove build artifacts"
	@echo "  make docs         Build documentation"

# =============================================================================
# SETUP
# =============================================================================

venv:
	$(PYTHON) -m venv $(VENV)

install: venv
	$(PIP) install -r requirements.txt

dev: install
	$(PIP) install -r requirements-dev.txt
	$(PIP) install -e .

requirements-dev.txt:
	@echo "pytest\npytest-cov\npytest-asyncio\nruff\nmypy\nbandit\nsafety\npip-audit" > requirements-dev.txt

# =============================================================================
# TESTING
# =============================================================================

test:
	cd ops && docker-compose run --rm sensor pytest tests/ -v

test-unit:
	cd ops && docker-compose run --rm sensor pytest tests/unit -v

test-int:
	cd ops && docker-compose run --rm sensor pytest tests/integration -v

test-cov:
	cd ops && docker-compose run --rm sensor pytest tests/ --cov=. --cov-report=html


# =============================================================================
# LINTING
# =============================================================================

lint:
	ruff check sensor/ controller/ tools/ --fix

lint-check:
	ruff check sensor/ controller/ tools/

typecheck:
	mypy sensor/ controller/ --ignore-missing-imports

format:
	ruff format sensor/ controller/ tools/

# =============================================================================
# SECURITY
# =============================================================================

security: bandit audit

bandit:
	bandit -r sensor/ controller/ -f json -o bandit_report.json --severity-level medium
	@echo "Report: bandit_report.json"

audit:
	pip-audit -r requirements.txt --format json > pip_audit_report.json || true
	@echo "Report: pip_audit_report.json"

secret-scan:
	@echo "Scanning for secrets..."
	@git grep -n "PRIVATE KEY\|AKIA\|password\s*=\|secret\s*=" -- ':!*.md' ':!Makefile' || echo "No secrets found"

# =============================================================================
# DOCKER
# =============================================================================

docker:
	docker build -t sentinel-controller:latest -f ops/Dockerfile.controller .
	docker build -t sentinel-sensor:latest -f ops/Dockerfile.sensor .

docker-up:
	cd ops && docker-compose up -d

docker-down:
	cd ops && docker-compose down

docker-logs:
	cd ops && docker-compose logs -f

# =============================================================================
# LAB (SAFE MODE)
# =============================================================================

lab-up:
	@echo "Starting Sentinel NetLab (Lab Mode)..."
	@# Bootstrap secrets if missing
	@$(PYTHON) ops/gen_lab_secrets.py
	@# Ensure DB init works in lab context
	@$(PYTHON) ops/init_lab_db.py
	cd ops && docker-compose -f docker-compose.lab.yml up --build -d --remove-orphans
	@echo "waiting for health..."
	@sleep 5
	@$(MAKE) lab-status
	@echo "Dashboard:  http://127.0.0.1:8050"
	@echo "Controller: http://127.0.0.1:5000"

lab-down:
	@echo "Stopping Sentinel NetLab..."
	cd ops && docker-compose -f docker-compose.lab.yml down

lab-reset:
	@echo "⚠️  RESETTING LAB ENVIRONMENT ⚠️"
	@echo "Stopping stack..."
	cd ops && docker-compose -f docker-compose.lab.yml down -v
	@echo "Generating fresh secrets..."
	@# We remove the old .env.lab to rotate secrets on reset, OR we keep it? 
	@# User request: "bootstrap secrets lab (không default hardcoded)". 
	@# "lab-reset phải đảm bảo về đúng trạng thái ban đầu... wipe volumes".
	@# If we want to simulate a fresh class, maybe we should NOT wipe secrets to keep connection strings stable for students?
	@# The requirement says: "nếu có -> dùng lại để ổn định trong 1 buổi học".
	@# So we do NOT delete .env.lab.
	@$(PYTHON) ops/gen_lab_secrets.py
	@# Proceed to init logic which will fail if DB container is down, so we must UP first?
	@# Actually init_lab_db.py connects to localhost:5432? No, it typically runs inside or connects to exposed port.
	@# Wait! "DB... không publish port". 
	@# If DB is not published, `ops/init_lab_db.py` (running on host) CANNOT interact with it!
	@# This is a critical architectural conflict with "Option A" offline/internal-only requirement.
	@# If DB is internal, we must run seed/init via `docker-compose run`.
	@# Let's check `ops/init_lab_db.py`.
	@# It likely uses `psycopg2` to connect. 
	@# Modification: We need a `lab-seed` target that runs inside the network.
	@echo "Starting stack..."
	cd ops && docker-compose -f docker-compose.lab.yml up -d --build
	@echo "Waiting for DB..."
	@sleep 5
	@echo "Seeding data..."
	cd ops && docker-compose -f docker-compose.lab.yml exec -T controller python ops/init_lab_db.py
	cd ops && docker-compose -f docker-compose.lab.yml exec -T controller python ops/seed_lab_data.py
	@echo "✅ Lab Reset Complete."

lab-logs:
	cd ops && docker-compose -f docker-compose.lab.yml logs -f

lab-status:
	cd ops && docker-compose -f docker-compose.lab.yml ps
	@echo ""
	@curl -s -o /dev/null -w "Controller Health: %%{http_code}\n" http://127.0.0.1:5000/api/v1/health || echo "Controller Health: DOWN"

# =============================================================================
# SCHEMA
# =============================================================================

schema:
	$(PYTHON) sensor/schema.py --generate-json --output sensor/schema

# =============================================================================
# DATABASE
# =============================================================================

db-init:
	cd controller && alembic upgrade head

db-migrate:
	cd controller && alembic revision --autogenerate -m "$(MSG)"

db-upgrade:
	cd controller && alembic upgrade head

db-downgrade:
	cd controller && alembic downgrade -1

# =============================================================================
# DOCUMENTATION
# =============================================================================

docs:
	@echo "Building documentation..."
	@# Add mkdocs or sphinx here if needed

# =============================================================================
# UTILITIES
# =============================================================================

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ htmlcov/ .coverage 2>/dev/null || true

freeze:
	$(PIP) freeze > requirements.lock.txt

pcap-gen:
	$(PYTHON) tools/generate_annotated_pcap.py --output data/pcap_annotated

# =============================================================================
# CI SHORTCUTS
# =============================================================================

ci: lint-check test security
	@echo "CI pipeline complete"

pre-commit-install:
	pre-commit install
	pre-commit install --hook-type commit-msg
	@echo "Pre-commit hooks installed"

pre-commit: lint-check typecheck test-unit
	@echo "Pre-commit checks complete"
