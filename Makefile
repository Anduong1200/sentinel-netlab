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

test: test-unit test-int

test-unit:
	cd sensor && PYTHONPATH=. $(PYTEST) ../tests/unit/ -v --tb=short

test-int:
	cd sensor && PYTHONPATH=. $(PYTEST) ../tests/integration/ -v --tb=short

test-cov:
	cd sensor && PYTHONPATH=. $(PYTEST) ../tests/ -v --cov=. --cov-report=html --cov-report=xml

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
