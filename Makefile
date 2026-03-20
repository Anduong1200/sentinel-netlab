# Sentinel NetLab - Makefile
# Single entry point for all build/test/deploy operations

.PHONY: help install dev test test-local test-replay lint lint-check lint-replay typecheck typecheck-replay-strict format format-check security bandit bandit-check audit docker clean compose-check quality-check ci-replay

PYTHON := python
VENV := venv
ifeq ($(OS),Windows_NT)
VENV_BIN := $(VENV)/Scripts
else
VENV_BIN := $(VENV)/bin
endif
PIP := $(VENV_BIN)/pip
PYTEST := $(VENV_BIN)/pytest
VENV_PYTHON := $(VENV_BIN)/python
RUFF := $(shell if [ -x "$(VENV_BIN)/ruff" ]; then echo "$(VENV_BIN)/ruff"; else echo "ruff"; fi)
MYPY := $(shell if [ -x "$(VENV_BIN)/mypy" ]; then echo "$(VENV_BIN)/mypy"; else echo "mypy"; fi)
BANDIT := $(shell if [ -x "$(VENV_BIN)/bandit" ]; then echo "$(VENV_BIN)/bandit"; else echo "bandit"; fi)
PIP_AUDIT := $(shell if [ -x "$(VENV_BIN)/pip-audit" ]; then echo "$(VENV_BIN)/pip-audit"; else echo "pip-audit"; fi)
# Replay/mock regression files kept strict to guarantee CI-safe, hardware-free validation.
REPLAY_TYPECHECK_FILES := sensor/capture_driver.py sensor/replay/pcap_reader.py tests/unit/test_capture_driver.py tests/integration/test_scenarios.py tests/detectors/test_pcap_regression.py
REPLAY_TEST_FILES := tests/unit/test_capture_driver.py tests/integration/test_scenarios.py tests/detectors/test_pcap_regression.py
REPLAY_SOURCE_DIRS := sensor controller common algos ml dashboard
REPLAY_BANDIT_EXCLUDES := tests,notebooks,tools,examples
# Prefer Docker Compose v2 (`docker compose`), fallback to legacy (`docker-compose`).
DOCKER_COMPOSE := $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; elif command -v docker-compose >/dev/null 2>&1; then echo "docker-compose"; else echo ""; fi)
LAB_ENV_FILE := --env-file .env.lab

compose-check:
	@if [ -z "$(DOCKER_COMPOSE)" ]; then echo "ERROR: Docker Compose is not installed."; echo "Install plugin: sudo apt-get install docker-compose-plugin"; echo "Or run with explicit binary: make DOCKER_COMPOSE=docker-compose <target>"; exit 127; fi
	@if ! docker info >/dev/null 2>&1; then echo "ERROR: Docker daemon is not running or not accessible."; echo "Try: sudo systemctl start docker"; echo "If permission issue: sudo usermod -aG docker $$USER && newgrp docker"; exit 125; fi
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
	@echo "  make test-local   Run all tests without Docker"
	@echo "  make test-unit    Run unit tests only"
	@echo "  make test-int     Run integration tests"
	@echo "  make test-replay  Run Mock/PCAP replay regression suite"
	@echo "  make lint         Run linter (ruff)"
	@echo "  make lint-replay  Lint replay/mock regression files"
	@echo "  make typecheck    Run mypy type checker"
	@echo "  make typecheck-replay-strict  Run strict mypy on replay/mock stack"
	@echo "  make quality-check  Run lint, format, and type checks"
	@echo ""
	@echo "Security:"
	@echo "  make security     Run all security scans"
	@echo "  make bandit       Run Bandit SAST"
	@echo "  make bandit-check Run Bandit SAST in fail-fast mode"
	@echo "  make audit        Run pip-audit"
	@echo "  make ci-replay    Run the replay/security gate used in CI"
	@echo ""
	@echo "Docker:"
	@echo "  make docker       Build all Docker images"
	@echo "  make docker-up    Start docker compose stack"
	@echo "  make docker-down  Stop docker compose stack"
	@echo "  make lab-gen-runtime-tokens SENSOR_ID=sensor-real-01  Auto-create dashboard/sensor tokens and update ops/.env.lab"
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
	$(VENV_PYTHON) -m pip install --upgrade pip setuptools wheel
	$(VENV_PYTHON) -m pip install -e ".[sensor,controller,dashboard,ml]"

dev: install
	$(VENV_PYTHON) -m pip install -e ".[dev]"

requirements-dev.txt:
	@echo "pytest\npytest-cov\npytest-asyncio\nruff\nmypy\nbandit\nsafety\npip-audit" > requirements-dev.txt

# =============================================================================
# TESTING
# =============================================================================

test: compose-check
	cd ops && $(DOCKER_COMPOSE) -f docker-compose.dev.yml run --rm mock-sensor pytest tests/ -v

test-local:
	$(PYTEST) tests/ -v

test-unit: compose-check
	cd ops && $(DOCKER_COMPOSE) -f docker-compose.dev.yml run --rm mock-sensor pytest tests/unit -v

test-int: compose-check
	cd ops && $(DOCKER_COMPOSE) -f docker-compose.dev.yml run --rm mock-sensor pytest tests/integration -v

test-cov: compose-check
	cd ops && $(DOCKER_COMPOSE) -f docker-compose.dev.yml run --rm mock-sensor pytest tests/ --cov=. --cov-report=html

test-replay:
	$(PYTEST) $(REPLAY_TEST_FILES) -q


# =============================================================================
# LINTING
# =============================================================================

lint:
	$(RUFF) check . --fix

lint-check:
	$(RUFF) check .

lint-replay:
	$(RUFF) check $(REPLAY_TYPECHECK_FILES)

typecheck:
	$(MYPY) .

typecheck-replay-strict:
	$(MYPY) --strict --follow-imports=silent $(REPLAY_TYPECHECK_FILES)

format:
	$(RUFF) format .

format-check:
	$(RUFF) format --check .

quality-check: lint-check format-check typecheck

ci-replay: lint-replay typecheck-replay-strict test-replay bandit-check

# =============================================================================
# SECURITY
# =============================================================================

security: bandit-check audit

bandit-check:
	$(BANDIT) -r $(REPLAY_SOURCE_DIRS) -ll -x $(REPLAY_BANDIT_EXCLUDES)

bandit:
	$(BANDIT) -r $(REPLAY_SOURCE_DIRS) -f json -o bandit_report.json --severity-level medium -x $(REPLAY_BANDIT_EXCLUDES)
	@echo "Report: bandit_report.json"

audit:
	$(PIP_AUDIT) --format json > pip_audit_report.json || true
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

docker-up: compose-check
	cd ops && $(DOCKER_COMPOSE) -f docker-compose.dev.yml up -d

docker-down: compose-check
	cd ops && $(DOCKER_COMPOSE) -f docker-compose.dev.yml down

docker-logs: compose-check
	cd ops && $(DOCKER_COMPOSE) -f docker-compose.dev.yml logs -f

# =============================================================================
# LAB (SAFE MODE)
# =============================================================================

lab-up: compose-check
	@echo "Starting Sentinel NetLab (Lab Mode)..."
	@# Bootstrap secrets if missing
	@$(PYTHON) ops/gen_lab_secrets.py
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml up --build -d --remove-orphans
	@echo "Waiting for health..."
	@sleep 10
	@# Ensure DB init works in lab context
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml exec -T controller python ops/init_lab_db.py
	@$(MAKE) lab-status
	@echo "Dashboard:  http://127.0.0.1:8080"
	@echo "Controller: http://127.0.0.1:8080/api/v1"

lab-down: compose-check
	@echo "Stopping Sentinel NetLab..."
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml down

lab-reset: compose-check
	@echo "⚠️  RESETTING LAB ENVIRONMENT ⚠️"
	@echo "Stopping stack..."
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml down -v
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
	@# If DB is internal, we must run seed/init via `$(DOCKER_COMPOSE) -f docker-compose.dev.yml run`.
	@# Let's check ops/init_lab_db.py.
	@# It likely uses `psycopg2` to connect. 
	@# Modification: We need a `lab-seed` target that runs inside the network.
	@echo "Starting stack..."
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml up -d --build
	@echo "Waiting for DB..."
	@sleep 5
	@echo "Seeding data..."
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml exec -T controller python ops/init_lab_db.py
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml exec -T controller python ops/seed_lab_data.py
	@echo "✅ Lab Reset Complete."

lab-logs: compose-check
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml logs -f

lab-status: compose-check
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml ps
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

lab-gen-runtime-tokens: compose-check
	@if [ -z "$(SENSOR_ID)" ]; then echo "Usage: make lab-gen-runtime-tokens SENSOR_ID=sensor-real-01"; exit 2; fi
	$(PYTHON) ops/gen_lab_runtime_tokens.py --sensor-id $(SENSOR_ID)
	cd ops && $(DOCKER_COMPOSE) $(LAB_ENV_FILE) -f docker-compose.lab.yml up -d dashboard
