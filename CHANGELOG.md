# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Unified Pydantic schema (`sensor/schema.py`) as single source of truth
- Centralized logging with JSON structured output (`sensor/logging_config.py`)
- Domain-specific error classes (`sensor/errors.py`)
- Plugin architecture for detectors (`sensor/detector_base.py`)
- Comprehensive test fixtures (`tests/conftest.py`)
- Unified YAML configuration format (`config.example.yaml`)
- Makefile for consolidated build/test/deploy commands
- GitHub Actions security scanning workflow (TruffleHog, Gitleaks, CodeQL)
- PR template and issue templates
- Architecture documentation with diagrams (`docs/architecture.md`)
- Threat model with STRIDE analysis (`docs/threat_model.md`)
- Operational handbook with SOPs (`docs/operational_handbook.md`)
- Quickstart guide (`docs/quickstart.md`)
- Authorization template for active testing (`AUTHORIZATION_TEMPLATE.md`)
- Contributing guide (`CONTRIBUTING.md`)
- Code of Conduct (`CODE_OF_CONDUCT.md`)
- Hardware compatibility matrix (`docs/hardware_compatibility.md`)
- Grafana dashboard JSON (`ops/grafana/dashboards/sentinel_dashboard.json`)
- Prometheus alert rules (`ops/alert_rules.yml`)

### Changed
- Enhanced controller API with Pydantic validation
- Improved mTLS support configuration
- Added sequence number validation for replay protection
- Consolidated CI pipeline with lint, test, security, and build jobs

### Security
- Added HMAC-SHA256 message signing for sensor→controller
- Added timestamp validation to prevent replay attacks
- Added monotonic sequence number validation
- Implemented per-sensor rate limiting
- Added secret scanning in CI pipeline

## [0.2.0] - 2026-01-15

### Added
- WIDS detectors: Evil Twin, Deauth Flood, Rogue AP
- Risk scoring engine
- Controller API with RBAC
- Docker Compose production stack
- Prometheus metrics integration

### Changed
- Refactored sensor architecture for modularity
- Improved frame parser performance

### Fixed
- Channel hopping race condition
- Memory leak in buffer manager

## [0.1.0] - 2026-01-01

### Added
- Initial release
- Basic frame capture and parsing
- Mock mode for testing without hardware
- Simple REST API
- SQLite storage

---

## Version Guidelines

- **MAJOR**: Breaking API changes, major architecture changes
- **MINOR**: New features, significant improvements
- **PATCH**: Bug fixes, documentation updates

[Unreleased]: https://github.com/anduong1200/sentinel-netlab/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/anduong1200/sentinel-netlab/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/anduong1200/sentinel-netlab/releases/tag/v0.1.0
